use std::future::Future;
use std::io::{Error, ErrorKind, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_util::Stream;
use reqwest::header::{CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, ReadBuf};

const UPSTREAM_READ_CHUNK_SIZE: usize = 64 * 1024;

/// How many times in a row a resumed connection may deliver nothing before the
/// read fails. Each is waited for longer than the last, from `RESUME_DELAY` up
/// to `RESUME_MAX_DELAY`.
const RESUME_ATTEMPTS: u32 = 8;
const RESUME_DELAY: Duration = Duration::from_secs(1);
const RESUME_MAX_DELAY: Duration = Duration::from_secs(30);

type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>;
type PendingHttpOpen = Pin<Box<dyn Future<Output = std::io::Result<OpenedHttpStream>> + Send>>;

struct ActiveHttpStream {
    next_offset: u64,
    end_offset: u64,
    stream: ByteStream,
    /// Whether this connection has brought any bytes yet.
    delivered: bool,
}

struct OpenedHttpStream {
    start: u64,
    len: u64,
    stream: ByteStream,
}

pub struct HttpRead<'t> {
    client: reqwest::Client,
    url: String,
    len: u64,
    pos: u64,
    transferred: u64,
    pending_open: Option<PendingHttpOpen>,
    active: Option<ActiveHttpStream>,
    pending_chunk: Option<Bytes>,
    pending_chunk_offset: usize,
    progress: Option<Box<dyn FnMut(u64, u64) + Send + 't>>,
    /// Resumes in a row that delivered nothing. A server that accepts the
    /// request and then closes the connection used to be asked again at once,
    /// for ever.
    empty_resumes: u32,
    resume_delay: Duration,
    resume_max_delay: Duration,
}

impl<'t> HttpRead<'t> {
    pub async fn open<Progress>(
        client: reqwest::Client,
        url: impl Into<String>,
        progress: Option<Progress>,
    ) -> std::io::Result<Self>
    where
        Progress: FnMut(u64, u64) + Send + 't,
    {
        let url = url.into();
        let initial = open_http_stream(client.clone(), url.clone(), None).await?;

        Ok(Self {
            client,
            url,
            len: initial.len,
            pos: 0,
            transferred: 0,
            pending_open: None,
            active: Some(ActiveHttpStream {
                next_offset: initial.start,
                end_offset: initial.len,
                stream: initial.stream,
                delivered: false,
            }),
            pending_chunk: None,
            pending_chunk_offset: 0,
            progress: progress.map(|v| Box::new(v) as Box<dyn FnMut(u64, u64) + Send + 't>),
            empty_resumes: 0,
            resume_delay: RESUME_DELAY,
            resume_max_delay: RESUME_MAX_DELAY,
        })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn begin_open_stream(&mut self, start: u64) {
        let client = self.client.clone();
        let url = self.url.clone();
        let range_start = if start == 0 { None } else { Some(start) };
        let delay = if self.empty_resumes == 0 {
            Duration::ZERO
        } else {
            self.resume_delay
                .saturating_mul(1u32 << (self.empty_resumes - 1).min(16))
                .min(self.resume_max_delay)
        };
        self.pending_open = Some(Box::pin(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            open_http_stream(client, url, range_start).await
        }));
    }

    /// The stream ended or failed before the end of the file. Count it if it
    /// brought nothing, and stop once that has happened too often.
    fn lost_stream(&mut self, delivered: bool, why: String) -> std::io::Result<()> {
        self.active = None;
        if delivered {
            self.empty_resumes = 0;
            return Ok(());
        }
        self.empty_resumes += 1;
        if self.empty_resumes > RESUME_ATTEMPTS {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                format!(
                    "the download stopped at byte {} of {}: {RESUME_ATTEMPTS} resumed \
                     connections in a row delivered nothing ({why})",
                    self.pos, self.len
                ),
            ));
        }
        Ok(())
    }

    fn poll_open_if_needed(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.active.is_none() && self.pending_open.is_none() {
            let pos = self.pos;
            self.begin_open_stream(pos);
        }

        let Some(fut) = self.pending_open.as_mut() else {
            return Poll::Ready(Ok(()));
        };

        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending_open = None;
                let opened = result?;
                self.len = opened.len;
                self.active = Some(ActiveHttpStream {
                    next_offset: opened.start,
                    end_offset: opened.len,
                    stream: opened.stream,
                    delivered: false,
                });
                Poll::Ready(Ok(()))
            }
        }
    }

    fn copy_from_pending_chunk(&mut self, buf: &mut ReadBuf<'_>) -> usize {
        let Some(chunk) = self.pending_chunk.as_ref() else {
            return 0;
        };

        let available = &chunk[self.pending_chunk_offset..];
        if available.is_empty() || buf.remaining() == 0 {
            return 0;
        }

        let to_copy = available.len().min(buf.remaining());
        buf.put_slice(&available[..to_copy]);
        self.pending_chunk_offset += to_copy;
        self.pos += to_copy as u64;

        self.transferred += to_copy as u64;
        let transferred = self.transferred;
        if let Some(progress) = self.progress.as_mut() {
            progress(transferred, self.len);
        }

        if self.pending_chunk_offset >= chunk.len() {
            self.pending_chunk = None;
            self.pending_chunk_offset = 0;
        }

        to_copy
    }
}

impl AsyncSeek for HttpRead<'_> {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> std::io::Result<()> {
        let next = match position {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::Current(n) => self.pos.checked_add_signed(n),
            SeekFrom::End(n) => self.len.checked_add_signed(n),
        }
        .filter(|n| *n <= self.len)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid HTTP seek"))?;
        if next != self.pos {
            self.active = None;
            self.pending_chunk = None;
            self.pending_chunk_offset = 0;
            self.empty_resumes = 0;
            self.pos = next;
            self.begin_open_stream(next);
        }
        Ok(())
    }
    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<u64>> {
        Poll::Ready(Ok(self.pos))
    }
}

impl<'t> AsyncRead for HttpRead<'t> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 || self.pos >= self.len {
            return Poll::Ready(Ok(()));
        }

        loop {
            if self.copy_from_pending_chunk(buf) > 0 {
                return Poll::Ready(Ok(()));
            }

            match self.as_mut().poll_open_if_needed(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }

            let Some(active) = self.active.as_mut() else {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "missing active http stream",
                )));
            };

            match active.stream.as_mut().poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(chunk))) => {
                    active.next_offset += chunk.len() as u64;
                    if !chunk.is_empty() {
                        active.delivered = true;
                    }
                    if active.next_offset > active.end_offset {
                        return Poll::Ready(Err(Error::new(
                            ErrorKind::InvalidData,
                            "received more bytes than expected from http stream",
                        )));
                    }
                    self.pending_chunk = Some(chunk);
                    self.pending_chunk_offset = 0;
                }
                Poll::Ready(Some(Err(err))) => {
                    let delivered = active.delivered;
                    if let Err(err) = self.lost_stream(delivered, err.to_string()) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
                Poll::Ready(None) => {
                    let delivered = active.delivered;
                    if self.pos >= self.len {
                        self.active = None;
                        return Poll::Ready(Ok(()));
                    }
                    if let Err(err) = self.lost_stream(delivered, "connection closed".into()) {
                        return Poll::Ready(Err(err));
                    }
                    continue;
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum CacheReadState {
    Idle,
    Seeking { offset: u64 },
    Reading { started_len: usize },
}

#[derive(Clone, Copy, Debug)]
enum CacheWriteState {
    Idle,
    Seeking {
        offset: u64,
    },
    Writing,
    /// Written, but not yet visible to the reader. See [`PrefixCacheFile`].
    Flushing,
}

pub struct PrefixCacheFile<R> {
    upstream: R,
    len: u64,
    pos: u64,
    cache_reader: File,
    cache_writer: File,
    /// How much of the prefix is **on disk**, not how much has been handed to
    /// the writer.
    ///
    /// The distinction is the whole correctness of this type. Reads come from
    /// `cache_reader` and writes go through `cache_writer`, two handles on one
    /// path, and `tokio::fs::File` buffers: `poll_write` returning `Ok(n)`
    /// means n bytes were accepted, not that any syscall has happened. Counting
    /// them here at that moment lets a read seek to an offset the file has not
    /// reached, which comes back as zero bytes and is reported as
    /// "cache ended before cached_len" -- a failed download, intermittently,
    /// depending on whether the flush happened to have landed.
    cached_len: u64,
    /// Accepted by the writer and not yet flushed. Added to `cached_len` only
    /// once the flush completes.
    unflushed: u64,
    pending_seek: Option<u64>,
    pending_chunk: Option<Vec<u8>>,
    pending_chunk_offset: usize,
    cache_read_state: CacheReadState,
    cache_write_state: CacheWriteState,
    cache_write_pos: u64,
    upstream_buf: Vec<u8>,
}

impl<R> PrefixCacheFile<R>
where
    R: AsyncRead + Unpin,
{
    pub async fn new(
        upstream: R,
        len: u64,
        cache_path: impl AsRef<std::path::Path>,
    ) -> std::io::Result<Self> {
        Self::open_cache(upstream, len, cache_path.as_ref(), 0).await
    }

    async fn open_cache(
        upstream: R,
        len: u64,
        cache_path: &std::path::Path,
        cached_len: u64,
    ) -> std::io::Result<Self> {
        let cache_writer = OpenOptions::new()
            .create(true)
            .truncate(cached_len == 0)
            .read(true)
            .write(true)
            .open(cache_path)
            .await?;
        let cache_reader = OpenOptions::new().read(true).open(cache_path).await?;

        Ok(Self {
            upstream,
            len,
            pos: 0,
            cache_reader,
            cache_writer,
            cached_len,
            unflushed: 0,
            pending_seek: None,
            pending_chunk: None,
            pending_chunk_offset: 0,
            cache_read_state: CacheReadState::Idle,
            cache_write_state: CacheWriteState::Idle,
            cache_write_pos: 0,
            upstream_buf: vec![0u8; UPSTREAM_READ_CHUNK_SIZE],
        })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn cached_len(&self) -> u64 {
        self.cached_len
    }

    fn poll_copy_from_cache(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<usize>> {
        if self.pos >= self.cached_len || buf.remaining() == 0 {
            return Poll::Ready(Ok(0));
        }

        loop {
            match self.cache_read_state {
                CacheReadState::Idle => {
                    let pos = self.pos;
                    AsyncSeek::start_seek(Pin::new(&mut self.cache_reader), SeekFrom::Start(pos))?;
                    self.cache_read_state = CacheReadState::Seeking { offset: pos };
                }
                CacheReadState::Seeking { offset } => {
                    match AsyncSeek::poll_complete(Pin::new(&mut self.cache_reader), cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(actual)) => {
                            if actual != offset {
                                self.cache_read_state = CacheReadState::Idle;
                                return Poll::Ready(Err(Error::new(
                                    ErrorKind::InvalidData,
                                    "cache seek completed at unexpected position",
                                )));
                            }
                            self.cache_read_state = CacheReadState::Reading {
                                started_len: buf.filled().len(),
                            };
                        }
                        Poll::Ready(Err(err)) => {
                            self.cache_read_state = CacheReadState::Idle;
                            return Poll::Ready(Err(err));
                        }
                    }
                }
                CacheReadState::Reading { started_len } => {
                    match AsyncRead::poll_read(Pin::new(&mut self.cache_reader), cx, buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(())) => {
                            let read = buf.filled().len() - started_len;
                            self.cache_read_state = CacheReadState::Idle;
                            if read == 0 {
                                return Poll::Ready(Err(Error::new(
                                    ErrorKind::UnexpectedEof,
                                    "cache ended before cached_len",
                                )));
                            }
                            self.pos += read as u64;
                            return Poll::Ready(Ok(read));
                        }
                        Poll::Ready(Err(err)) => {
                            self.cache_read_state = CacheReadState::Idle;
                            return Poll::Ready(Err(err));
                        }
                    }
                }
            }
        }
    }

    fn poll_flush_pending_chunk(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let Some(chunk) = self.pending_chunk.as_ref().cloned() else {
            self.cache_write_state = CacheWriteState::Idle;
            return Poll::Ready(Ok(()));
        };

        loop {
            match self.cache_write_state {
                CacheWriteState::Idle => {
                    let cached_len = self.cached_len;
                    if self.cache_write_pos == cached_len {
                        self.cache_write_state = CacheWriteState::Writing;
                    } else {
                        AsyncSeek::start_seek(
                            Pin::new(&mut self.cache_writer),
                            SeekFrom::Start(cached_len),
                        )?;
                        self.cache_write_state = CacheWriteState::Seeking { offset: cached_len };
                    }
                }
                CacheWriteState::Seeking { offset } => {
                    match AsyncSeek::poll_complete(Pin::new(&mut self.cache_writer), cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(actual)) => {
                            if actual != offset {
                                self.cache_write_state = CacheWriteState::Idle;
                                return Poll::Ready(Err(Error::new(
                                    ErrorKind::InvalidData,
                                    "cache write seek completed at unexpected position",
                                )));
                            }
                            self.cache_write_pos = actual;
                            self.cache_write_state = CacheWriteState::Writing;
                        }
                        Poll::Ready(Err(err)) => {
                            self.cache_write_state = CacheWriteState::Idle;
                            return Poll::Ready(Err(err));
                        }
                    }
                }
                CacheWriteState::Writing => {
                    let pending_offset = self.pending_chunk_offset;
                    match AsyncWrite::poll_write(
                        Pin::new(&mut self.cache_writer),
                        cx,
                        &chunk[pending_offset..],
                    ) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(0)) => {
                            self.cache_write_state = CacheWriteState::Idle;
                            return Poll::Ready(Err(Error::new(
                                ErrorKind::WriteZero,
                                "cache write returned zero",
                            )));
                        }
                        Poll::Ready(Ok(written)) => {
                            self.pending_chunk_offset += written;
                            self.unflushed += written as u64;
                            self.cache_write_pos += written as u64;
                            if self.pending_chunk_offset >= chunk.len() {
                                // Not Idle, and `cached_len` deliberately not
                                // advanced yet: the bytes are in a buffer, and
                                // the reader is a different handle that cannot
                                // see them until they reach the file.
                                self.cache_write_state = CacheWriteState::Flushing;
                                continue;
                            }
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Err(err)) => {
                            self.cache_write_state = CacheWriteState::Idle;
                            return Poll::Ready(Err(err));
                        }
                    }
                }
                CacheWriteState::Flushing => {
                    match AsyncWrite::poll_flush(Pin::new(&mut self.cache_writer), cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(())) => {
                            // Now, and only now, is the prefix this long as far
                            // as anything reading the file is concerned.
                            self.cached_len += self.unflushed;
                            self.unflushed = 0;
                            self.pending_chunk = None;
                            self.pending_chunk_offset = 0;
                            self.cache_write_state = CacheWriteState::Idle;
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Err(err)) => {
                            self.cache_write_state = CacheWriteState::Idle;
                            return Poll::Ready(Err(err));
                        }
                    }
                }
            }
        }
    }

    fn poll_fill_from_upstream(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        if self.pending_chunk.is_some() {
            return Poll::Ready(Ok(true));
        }

        let mut upstream_buf = std::mem::take(&mut self.upstream_buf);
        if upstream_buf.is_empty() {
            upstream_buf.resize(UPSTREAM_READ_CHUNK_SIZE, 0);
        }
        let mut read_buf = ReadBuf::new(&mut upstream_buf);
        let poll = match AsyncRead::poll_read(Pin::new(&mut self.upstream), cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                if read_buf.filled().is_empty() {
                    Poll::Ready(Ok(false))
                } else {
                    let chunk = read_buf.filled().to_vec();
                    self.pending_chunk = Some(chunk);
                    self.pending_chunk_offset = 0;
                    Poll::Ready(Ok(true))
                }
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        };
        self.upstream_buf = upstream_buf;
        poll
    }
}

impl<R> AsyncRead for PrefixCacheFile<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 || self.pos >= self.len {
            return Poll::Ready(Ok(()));
        }

        match self.as_mut().poll_copy_from_cache(cx, buf) {
            Poll::Ready(Ok(read)) if read > 0 => return Poll::Ready(Ok(())),
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        let target_end = self.len.min(
            self.pos
                .saturating_add(buf.remaining() as u64)
                .max(self.pos.saturating_add(1)),
        );

        loop {
            if self.cached_len >= target_end {
                match self.as_mut().poll_copy_from_cache(cx, buf) {
                    Poll::Ready(Ok(read)) => {
                        if read == 0 {
                            return Poll::Ready(Err(Error::new(
                                ErrorKind::UnexpectedEof,
                                "cached prefix did not reach requested read position",
                            )));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            match self.as_mut().poll_flush_pending_chunk(cx) {
                Poll::Ready(Ok(())) => {
                    if self.pending_chunk.is_some() || self.cached_len >= target_end {
                        continue;
                    }
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }

            match self.as_mut().poll_fill_from_upstream(cx) {
                Poll::Ready(Ok(true)) => continue,
                Poll::Ready(Ok(false)) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "upstream ended before requested prefix was cached",
                    )));
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<R: AsyncRead + AsyncSeek + Unpin> PrefixCacheFile<R> {
    /// Bind a saved prefix to a fresh copy of the remote header page. Parsing
    /// must still verify its signature, hash tree and every metadata page.
    /// A changed package or length starts with an empty cache.
    pub async fn resumable(
        mut upstream: R,
        len: u64,
        path: impl AsRef<std::path::Path>,
    ) -> std::io::Result<Self> {
        let path = path.as_ref();
        let probe_len = len.min(4096) as usize;
        let mut fresh = vec![0; probe_len];
        upstream.read_exact(&mut fresh).await?;
        let mut cached_len = 0;
        if let Ok(mut existing) = File::open(path).await {
            let size = existing.metadata().await?.len();
            if size >= probe_len as u64 && size <= len {
                let mut saved = vec![0; probe_len];
                if existing.read_exact(&mut saved).await.is_ok() && saved == fresh {
                    cached_len = size;
                }
            }
        }
        upstream.seek(SeekFrom::Start(cached_len)).await?;
        Self::open_cache(upstream, len, path, cached_len).await
    }

    /// An authenticated metadata check refused saved data. Retry from the
    /// network once, before any game file is replaced.
    pub async fn restart(&mut self) -> std::io::Result<()> {
        self.upstream.seek(SeekFrom::Start(0)).await?;
        self.cache_writer.set_len(0).await?;
        self.cache_writer.seek(SeekFrom::Start(0)).await?;
        self.cache_reader.seek(SeekFrom::Start(0)).await?;
        self.pos = 0;
        self.cached_len = 0;
        self.unflushed = 0;
        self.pending_seek = None;
        self.pending_chunk = None;
        self.pending_chunk_offset = 0;
        self.cache_read_state = CacheReadState::Idle;
        self.cache_write_state = CacheWriteState::Idle;
        self.cache_write_pos = 0;
        Ok(())
    }
}

impl<R> AsyncSeek for PrefixCacheFile<R>
where
    R: AsyncRead + Unpin,
{
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> std::io::Result<()> {
        let next = match position {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::Current(delta) => {
                if delta >= 0 {
                    self.pos.checked_add(delta as u64)
                } else {
                    self.pos.checked_sub(delta.unsigned_abs())
                }
            }
            SeekFrom::End(delta) => {
                if delta >= 0 {
                    self.len.checked_add(delta as u64)
                } else {
                    self.len.checked_sub(delta.unsigned_abs())
                }
            }
        }
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid seek"))?;

        self.pending_seek = Some(next);
        Ok(())
    }

    fn poll_complete(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<u64>> {
        let next = self.pending_seek.take().unwrap_or(self.pos);
        if next > self.len {
            return Poll::Ready(Err(Error::new(
                ErrorKind::InvalidInput,
                "seek past remote end",
            )));
        }

        self.pos = next;
        Poll::Ready(Ok(self.pos))
    }
}

async fn open_http_stream(
    client: reqwest::Client,
    url: String,
    start: Option<u64>,
) -> std::io::Result<OpenedHttpStream> {
    let mut request = client.get(url);
    if let Some(start) = start {
        request = request.header(RANGE, format!("bytes={start}-"));
    }

    let response = request
        .send()
        .await
        .map_err(http_err)?
        .error_for_status()
        .map_err(http_err)?;

    let (actual_start, len) = match start {
        None => {
            if response.status() != reqwest::StatusCode::OK {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("expected 200 OK, got {}", response.status()),
                ));
            }
            let len = response
                .headers()
                .get(CONTENT_LENGTH)
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing Content-Length"))?
                .to_str()
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?
                .parse::<u64>()
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            (0, len)
        }
        Some(expected_start) => {
            if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("expected 206 Partial Content, got {}", response.status()),
                ));
            }
            let content_range = response
                .headers()
                .get(CONTENT_RANGE)
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing Content-Range"))?
                .to_str()
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            let (range, total) = content_range
                .split_once('/')
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid Content-Range"))?;
            let range = range.strip_prefix("bytes ").ok_or_else(|| {
                Error::new(ErrorKind::InvalidData, "invalid Content-Range prefix")
            })?;
            let (start_s, _) = range.split_once('-').ok_or_else(|| {
                Error::new(ErrorKind::InvalidData, "invalid Content-Range bounds")
            })?;
            let actual_start = start_s
                .parse::<u64>()
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            if actual_start != expected_start {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("range resume mismatch: expected {expected_start}, got {actual_start}"),
                ));
            }
            let len = total
                .parse::<u64>()
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            (actual_start, len)
        }
    };

    Ok(OpenedHttpStream {
        start: actual_start,
        len,
        stream: Box::pin(response.bytes_stream()),
    })
}

fn http_err(err: reqwest::Error) -> std::io::Error {
    Error::other(err)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::SeekFrom;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::{HttpRead, PrefixCacheFile};

    #[derive(Clone, Debug)]
    struct RequestRecord {
        range: Option<String>,
    }

    #[derive(Clone)]
    struct ServerConfig {
        body: Arc<Vec<u8>>,
        first_body_limit: Option<usize>,
        resume_start_adjustment: i64,
        /// Cut every resumed response to this many bytes of body.
        resume_body_limit: Option<usize>,
        requests: Arc<Mutex<Vec<RequestRecord>>>,
        request_count: Arc<AtomicUsize>,
    }

    struct TestServer {
        url: String,
        requests: Arc<Mutex<Vec<RequestRecord>>>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl TestServer {
        fn request_ranges(&self) -> Vec<Option<String>> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|r| r.range.clone())
                .collect()
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    async fn spawn_server(
        body: Vec<u8>,
        first_body_limit: Option<usize>,
        resume_start_adjustment: i64,
    ) -> io::Result<TestServer> {
        spawn_server_with(body, first_body_limit, resume_start_adjustment, None).await
    }

    async fn spawn_server_with(
        body: Vec<u8>,
        first_body_limit: Option<usize>,
        resume_start_adjustment: i64,
        resume_body_limit: Option<usize>,
    ) -> io::Result<TestServer> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let config = ServerConfig {
            body: Arc::new(body),
            first_body_limit,
            resume_start_adjustment,
            resume_body_limit,
            requests: requests.clone(),
            request_count: Arc::new(AtomicUsize::new(0)),
        };

        let handle = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let config = config.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, config).await;
                });
            }
        });

        Ok(TestServer {
            url: format!("http://{addr}/file"),
            requests,
            handle,
        })
    }

    async fn handle_connection(mut stream: TcpStream, config: ServerConfig) -> io::Result<()> {
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
            request.extend_from_slice(&buf[..n]);
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        let request_text = String::from_utf8_lossy(&request);
        let range_header = request_text.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("range") {
                Some(value.trim().to_owned())
            } else {
                None
            }
        });
        config.requests.lock().unwrap().push(RequestRecord {
            range: range_header.clone(),
        });

        let request_index = config.request_count.fetch_add(1, Ordering::SeqCst);
        let body_len = config.body.len() as u64;

        let (status_line, response_headers, response_body) = match range_header {
            None => {
                let body = if request_index == 0 {
                    if let Some(limit) = config.first_body_limit {
                        config.body[..limit.min(config.body.len())].to_vec()
                    } else {
                        config.body.as_ref().clone()
                    }
                } else {
                    config.body.as_ref().clone()
                };
                (
                    "HTTP/1.1 200 OK\r\n".to_owned(),
                    format!("Content-Length: {body_len}\r\nConnection: close\r\n"),
                    body,
                )
            }
            Some(range) => {
                let start = parse_range_start(&range)?;
                let adjusted_start = if config.resume_start_adjustment == 0 {
                    start
                } else {
                    (start as i64 + config.resume_start_adjustment) as u64
                };
                let mut body = config.body[adjusted_start as usize..].to_vec();
                let content_length = body.len();
                if let Some(limit) = config.resume_body_limit {
                    body.truncate(limit);
                }
                (
                    "HTTP/1.1 206 Partial Content\r\n".to_owned(),
                    format!(
                        "Content-Length: {content_length}\r\nContent-Range: bytes {adjusted_start}-{}/{body_len}\r\nConnection: close\r\n",
                        body_len.saturating_sub(1)
                    ),
                    body,
                )
            }
        };

        stream.write_all(status_line.as_bytes()).await?;
        stream.write_all(response_headers.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
        stream.write_all(&response_body).await?;
        stream.shutdown().await?;
        Ok(())
    }

    fn parse_range_start(range: &str) -> io::Result<u64> {
        let value = range
            .strip_prefix("bytes=")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid range prefix"))?;
        let (start, _) = value
            .split_once('-')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid range bounds"))?;
        start
            .parse::<u64>()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }

    fn cache_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("xodus-streaming4-{name}-{nanos}.bin"))
    }

    fn test_body() -> Vec<u8> {
        (0..16384).map(|i| (i % 251) as u8).collect()
    }

    async fn open_cached_reader<'t>(
        server: &TestServer,
        cache: &PathBuf,
    ) -> PrefixCacheFile<HttpRead<'t>> {
        let http = HttpRead::open(reqwest::Client::new(), &server.url, Some(|_, _| {}))
            .await
            .unwrap();
        let len = http.len();
        PrefixCacheFile::new(http, len, cache).await.unwrap()
    }

    #[tokio::test]
    async fn metadata_resume_reuses_saved_prefix_and_ranges_only_the_missing_tail() {
        let body = test_body();
        let server = spawn_server(body.clone(), None, 0).await.unwrap();
        let cache = cache_path("resume-prefix");
        std::fs::write(&cache, &body[..8192]).unwrap();
        let count = Arc::new(Mutex::new(0));
        let observed = count.clone();
        let http = HttpRead::open(
            reqwest::Client::new(),
            &server.url,
            Some(move |n, _| *observed.lock().unwrap() = n),
        )
        .await
        .unwrap();
        let mut file = PrefixCacheFile::resumable(http, body.len() as u64, &cache)
            .await
            .unwrap();
        assert_eq!(file.cached_len(), 8192);
        let mut got = vec![];
        file.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, body);
        assert_eq!(*count.lock().unwrap(), 4096 + 8192);
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].range.as_deref(), Some("bytes=8192-"));
        std::fs::remove_file(cache).unwrap();
    }

    #[tokio::test]
    async fn metadata_resume_discards_a_different_package_and_can_restart_corrupt_cache() {
        let body = test_body();
        let cache = cache_path("resume-changed");
        let mut old = body[..8192].to_vec();
        old[100] ^= 1;
        std::fs::write(&cache, &old).unwrap();
        let mut file = PrefixCacheFile::resumable(
            std::io::Cursor::new(body.clone()),
            body.len() as u64,
            &cache,
        )
        .await
        .unwrap();
        assert_eq!(file.cached_len(), 0);
        let mut got = vec![];
        file.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, body);
        drop(file);
        // Matching header alone is not validation. The caller checks the
        // signed hash tree, then restarts once if any saved page is corrupt.
        let mut bad = body[..8192].to_vec();
        bad[5000] ^= 1;
        std::fs::write(&cache, bad).unwrap();
        let mut file = PrefixCacheFile::resumable(
            std::io::Cursor::new(body.clone()),
            body.len() as u64,
            &cache,
        )
        .await
        .unwrap();
        assert_eq!(file.cached_len(), 8192);
        file.restart().await.unwrap();
        let mut fresh = vec![];
        file.read_to_end(&mut fresh).await.unwrap();
        assert_eq!(fresh, body);
        std::fs::remove_file(cache).unwrap();
    }

    #[tokio::test]
    async fn metadata_resume_revalidates_the_authenticated_tree_before_accepting_cache() {
        let package = crate::xvd::testing::package();
        let cache = cache_path("resume-authentication");
        let mut corrupt = package.bytes.clone();
        corrupt[package.tree_start + 32] ^= 1;
        std::fs::write(&cache, corrupt).unwrap();
        let mut reader = PrefixCacheFile::resumable(
            std::io::Cursor::new(package.bytes.clone()),
            package.bytes.len() as u64,
            &cache,
        )
        .await
        .unwrap();
        assert_eq!(reader.cached_len(), package.bytes.len() as u64);
        assert!(
            crate::xvd::XvdFile::parse_verified(&mut reader)
                .await
                .is_err()
        );
        reader.restart().await.unwrap();
        assert!(
            crate::xvd::XvdFile::parse_verified(&mut reader)
                .await
                .is_ok()
        );
        std::fs::remove_file(cache).unwrap();
    }

    #[tokio::test]
    async fn cached_prefix_read_completes() {
        let body = test_body();
        let server = spawn_server(body.clone(), None, 0).await.unwrap();
        let cache = cache_path("small-prefix");
        let mut file = open_cached_reader(&server, &cache).await;

        let mut buf = [0u8; 64];
        file.read_exact(&mut buf).await.unwrap();

        assert_eq!(&buf[..], &body[..64]);
        assert!(file.cached_len() >= 64);
        let _ = std::fs::remove_file(cache);
    }

    /// The invariant the whole type rests on: `cached_len` counts bytes a
    /// *different* handle can read, not bytes handed to a buffer.
    ///
    /// Breaking it produced an intermittent failed download -- a read would
    /// seek inside the claimed prefix, get nothing, and report "cache ended
    /// before cached_len". Checked against the file's real length on disk,
    /// through a separate open, because that is exactly what the reader is.
    #[tokio::test]
    async fn cached_len_never_exceeds_what_is_on_disk() {
        let body = test_body();
        let server = spawn_server(body.clone(), None, 0).await.unwrap();
        let cache = cache_path("durable-prefix");
        let mut file = open_cached_reader(&server, &cache).await;

        // Read in small pieces so the check runs many times across many writes:
        // one big read would flush once and prove almost nothing.
        let mut buf = [0u8; 16];
        for _ in 0..16 {
            file.read_exact(&mut buf).await.unwrap();
            let on_disk = std::fs::metadata(&cache).unwrap().len();
            assert!(
                file.cached_len() <= on_disk,
                "claimed {} cached with only {on_disk} in the file",
                file.cached_len()
            );
        }
        let _ = std::fs::remove_file(cache);
    }

    #[tokio::test]
    async fn cached_backward_seek_uses_prefix() {
        let body = test_body();
        let server = spawn_server(body.clone(), None, 0).await.unwrap();
        let cache = cache_path("backward-seek");
        let mut file = open_cached_reader(&server, &cache).await;

        let mut first = [0u8; 128];
        file.read_exact(&mut first).await.unwrap();
        file.seek(SeekFrom::Start(32)).await.unwrap();
        let mut second = [0u8; 64];
        file.read_exact(&mut second).await.unwrap();

        assert_eq!(&first[..], &body[..128]);
        assert_eq!(&second[..], &body[32..96]);
        assert_eq!(server.request_ranges(), vec![None]);
        let _ = std::fs::remove_file(cache);
    }

    #[tokio::test]
    async fn cached_reader_resumes_http_source() {
        let body = test_body();
        let server = spawn_server(body.clone(), Some(96), 0).await.unwrap();
        let cache = cache_path("resume");
        let mut file = open_cached_reader(&server, &cache).await;

        let mut buf = [0u8; 256];
        file.read_exact(&mut buf).await.unwrap();

        assert_eq!(&buf[..], &body[..256]);
        let ranges = server.request_ranges();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], None);
        assert_eq!(ranges[1].as_deref(), Some("bytes=96-"));
        let _ = std::fs::remove_file(cache);
    }

    #[tokio::test]
    async fn cached_reader_propagates_resume_mismatch() {
        let server = spawn_server(test_body(), Some(96), 1).await.unwrap();
        let cache = cache_path("resume-mismatch");
        let mut file = open_cached_reader(&server, &cache).await;

        let mut buf = [0u8; 256];
        let err = file.read_exact(&mut buf).await.unwrap_err();
        assert!(err.to_string().contains("range resume mismatch"));
        let _ = std::fs::remove_file(cache);
    }

    /// A server that takes the resumed request and then sends nothing used to
    /// be asked again straight away, for ever: the read never returned and the
    /// process spun. It now waits between attempts and gives up.
    #[tokio::test]
    async fn resumes_that_bring_nothing_are_given_up_on() {
        let server = spawn_server_with(test_body(), Some(96), 0, Some(0))
            .await
            .unwrap();
        let mut http = HttpRead::open(reqwest::Client::new(), &server.url, Some(|_, _| {}))
            .await
            .unwrap();
        http.resume_delay = std::time::Duration::from_millis(1);
        http.resume_max_delay = std::time::Duration::from_millis(4);

        let mut buf = vec![0u8; 256];
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            http.read_exact(&mut buf),
        )
        .await
        .expect("still resuming after 20 s");
        let err = result.unwrap_err();
        assert!(err.to_string().contains("delivered nothing"), "{err}");
        // The first request and then one per allowed resume, plus the one
        // that tipped it over.
        assert_eq!(
            server.request_ranges().len(),
            1 + super::RESUME_ATTEMPTS as usize + 1
        );
    }
}
