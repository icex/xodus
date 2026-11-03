use std::cmp::min;
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{self, Error, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use aes::cipher::KeyInit;
use aes::{Aes128Dec, Aes128Enc};
use futures_util::StreamExt;
use msixvc_common::parse::{BinaryParse, BinaryTryParse};
use reqwest::StatusCode;
use reqwest::header::{CONTENT_RANGE, RANGE};
use sha2::{Digest, Sha256};
use tokio::fs::OpenOptions;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::task::block_in_place;
use tokio::time::{sleep, timeout};
use tokio_util::io::SyncIoBridge;
use uuid::Uuid;
use zerocopy::IntoBytes;

use crate::crypt::{TweakGenerator, decrypt_page_xts};
use crate::layout::{Bytes, PAGE_SIZE};
use crate::models::xvd::layout::XvdLayout;
use crate::models::xvd::{
    HASH_ENTRIES_IN_PAGE, HASH_ENTRY_LENGTH, XvcInfo, XvcRegionHeader, XvcRegionId, XvdHashEntry,
    XvdHeader, XvdSegmentMetadataHeader, XvdSegmentMetadataSegment, XvdSegmentMetadataSegmentFlags,
    XvdUserDataHeader, XvdUserDataPackageFileEntry, XvdUserDataPackageFilesHeader,
};
use crate::streaming_ntfs::collect_ntfs_stream_layouts;

pub struct SyncSubstream<R> {
    inner: R,
    start: u64,
    len: u64,
    pos: u64,
}

impl<R> Debug for SyncSubstream<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncSubstream")
            .field("start", &self.start)
            .field("len", &self.len)
            .field("pos", &self.pos)
            .finish_non_exhaustive()
    }
}

impl<R> SyncSubstream<R> {
    pub fn new(inner: R, start: u64, len: u64) -> Self {
        Self {
            inner,
            start,
            len,
            pos: 0,
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

impl<R: Read + Seek> Read for SyncSubstream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }

        let remaining = usize::try_from(self.len - self.pos)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "remaining range too large"))?;
        let to_read = remaining.min(buf.len());

        self.inner.seek(SeekFrom::Start(self.start + self.pos))?;
        let read = self.inner.read(&mut buf[..to_read])?;
        self.pos += read as u64;
        Ok(read)
    }
}

impl<R: Seek> Seek for SyncSubstream<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let next = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(delta) => {
                if delta >= 0 {
                    self.pos.checked_add(delta as u64).ok_or_else(|| {
                        Error::new(ErrorKind::InvalidInput, "invalid relative seek")
                    })?
                } else {
                    self.pos.checked_sub(delta.unsigned_abs()).ok_or_else(|| {
                        Error::new(ErrorKind::InvalidInput, "invalid relative seek")
                    })?
                }
            }
            SeekFrom::End(delta) => {
                if delta >= 0 {
                    self.len.checked_add(delta as u64).ok_or_else(|| {
                        Error::new(ErrorKind::InvalidInput, "invalid end-relative seek")
                    })?
                } else {
                    self.len.checked_sub(delta.unsigned_abs()).ok_or_else(|| {
                        Error::new(ErrorKind::InvalidInput, "invalid end-relative seek")
                    })?
                }
            }
        };

        if next > self.len {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "seek past substream end",
            ));
        }

        self.pos = next;
        Ok(self.pos)
    }
}

impl<R: Write + Seek> Write for SyncSubstream<R> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }

        let remaining = usize::try_from(self.len - self.pos)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "remaining range too large"))?;
        let to_write = remaining.min(buf.len());

        self.inner.seek(SeekFrom::Start(self.start + self.pos))?;
        let written = self.inner.write(&buf[..to_write])?;
        self.pos += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct XvdEncryptionInfo {
    encrypted_sections: Vec<EncryptedSectionInfo>,
}

// The gpt crate requires the device to implement Debug,
// but the content key must not be debuged
impl Debug for XvdEncryptionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XvdEncryptionInfo")
            .field("encrypted_sections", &self.encrypted_sections)
            .finish_non_exhaustive() // prints ", .." to signal redacted fields
    }
}

struct XvdStream<'t, R> {
    inner: R,
    offset: u64,
    end_offset: u64,

    encryption_info: Option<XvdEncryptionInfo>,

    /// When set, every page is checked against the package's hash tree before
    /// any of it is handed out. The filesystem metadata read through this
    /// stream decides which files are written and where, so it is held to the
    /// same standard as the files themselves.
    hashes: Option<&'t HashTree>,
    /// Pages already read and checked, so that the filesystem parser's habit of
    /// reading a record at a time does not mean hashing a page per record.
    checked_pages: HashMap<u64, Box<[u8; PAGE_SIZE]>>,
}

/// How many checked pages [`XvdStream`] keeps. A megabyte: enough for the
/// parser's back-and-forth between an index and the records it names.
const CHECKED_PAGE_CACHE: usize = 256;

impl<R> Debug for XvdStream<'_, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XvdStream")
            .field("offset", &self.offset)
            .field("end_offset", &self.end_offset)
            .field("encryption_info", &self.encryption_info)
            .field("checked", &self.hashes.is_some())
            .finish_non_exhaustive()
    }
}

impl<'t, R> XvdStream<'t, R> {
    fn new(inner: R, offset: u64, end_offset: u64, hashes: Option<&'t HashTree>) -> Self {
        XvdStream {
            inner,
            offset,
            end_offset,
            encryption_info: None,
            hashes,
            checked_pages: HashMap::new(),
        }
    }

    fn len(&self) -> u64 {
        self.end_offset - self.offset
    }

    fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Seek> XvdStream<'_, R> {
    fn current_relative_pos(&mut self) -> std::io::Result<u64> {
        let absolute = self.inner.stream_position()?;
        absolute
            .checked_sub(self.offset)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "stream before virtual start"))
    }
}

impl<R: Read + Seek> Read for XvdStream<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let current = self.current_relative_pos()?;
        if current >= self.len() {
            return Ok(0);
        }

        let remaining = usize::try_from(self.len() - current)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "remaining range too large"))?;
        let to_read = remaining.min(buf.len());

        let Some(hashes) = self.hashes else {
            return self.inner.read(&mut buf[..to_read]);
        };

        // Whole pages only: a page is what the hash tree vouches for, so a
        // read is served from a page that has been checked, never from bytes
        // that merely happen to be in the cache file.
        let absolute = self.offset + current;
        let page = absolute / PAGE_SIZE as u64;
        let within = (absolute % PAGE_SIZE as u64) as usize;
        if !self.checked_pages.contains_key(&page) {
            let mut data = Box::new([0u8; PAGE_SIZE]);
            self.inner.seek(SeekFrom::Start(page * PAGE_SIZE as u64))?;
            self.inner.read_exact(&mut data[..])?;
            hashes.check(page, &data)?;
            if self.checked_pages.len() >= CHECKED_PAGE_CACHE {
                self.checked_pages.clear();
            }
            self.checked_pages.insert(page, data);
        }
        let data = &self.checked_pages[&page];
        let n = to_read.min(PAGE_SIZE - within);
        buf[..n].copy_from_slice(&data[within..within + n]);
        self.inner.seek(SeekFrom::Start(absolute + n as u64))?;
        Ok(n)
    }
}

impl<R: Seek> Seek for XvdStream<'_, R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_relative = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::Current(delta) => {
                let current = self.current_relative_pos()?;
                if delta >= 0 {
                    current.checked_add(delta as u64)
                } else {
                    current.checked_sub(delta.unsigned_abs())
                }
                .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid relative seek"))?
            }
            SeekFrom::End(delta) => {
                let len = self.len();
                if delta >= 0 {
                    len.checked_add(delta as u64)
                } else {
                    len.checked_sub(delta.unsigned_abs())
                }
                .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid end-relative seek"))?
            }
        };

        if new_relative > self.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "seek past virtual device end",
            ));
        }

        self.inner
            .seek(SeekFrom::Start(self.offset + new_relative))?;
        Ok(new_relative)
    }
}

impl<R> Write for XvdStream<'_, R> {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(Error::new(
            ErrorKind::PermissionDenied,
            "XvdStream is read-only",
        ))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub struct XvdFile {
    header: XvdHeader,
    layout: XvdLayout,
    encrypted_section_infos: Vec<EncryptedSectionInfo>,
    hashes: HashTree,
    /// Whether the hash tree was checked against the header when the package
    /// was parsed. Only then is it worth checking pages against: a tree that
    /// was not checked vouches for nothing.
    verified: bool,
}

#[derive(Debug)]
pub struct EncryptedSectionInfo {
    section_offset: u64,
    section_length: u64,

    header_id: XvcRegionId,
    vduid: Uuid,

    first_segment_index: u32,
}

pub struct UserPackageFile {
    pub offset: u64,
    pub length: u64,
}

pub struct SegmentFile {
    pub offset: u64,
    pub length: u64,
    pub data_hashs: Vec<[u8; 20]>,
    pub keep_encrypted: bool,
}

/// A page whose contents do not hash to what the package's hash tree says.
#[derive(Debug, thiserror::Error)]
#[error("page {page} of the package does not match its hash tree")]
pub struct PageHashMismatch {
    pub page: u64,
}

/// The level-0 entries of the package's hash tree: for every page from the
/// start of the user data to the end of the drive, the truncated SHA-256 of
/// the page as stored, and the data unit its encryption tweak uses.
///
/// Read once, in full, when the package is parsed. That is no more than the
/// old per-region read did -- the regions cover nearly the whole drive -- and
/// it means a page can be checked wherever it is read.
struct HashTree {
    /// The absolute page number of hashed page 0.
    first_page: u64,
    hashes: Vec<[u8; 20]>,
    units: Vec<u32>,
}

fn page_digest(page: &[u8]) -> [u8; 20] {
    let digest = Sha256::digest(page);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[..20]);
    out
}

impl HashTree {
    fn index(&self, page: u64) -> Option<usize> {
        let index = usize::try_from(page.checked_sub(self.first_page)?).ok()?;
        (index < self.hashes.len()).then_some(index)
    }

    fn unit(&self, page: u64) -> Option<u32> {
        self.index(page).map(|i| self.units[i])
    }

    /// The hashes of `count` pages starting at absolute page `first`.
    fn range(&self, first: u64, count: u64) -> Option<&[[u8; 20]]> {
        if count == 0 {
            return Some(&[]);
        }
        let start = self.index(first)?;
        let end = start.checked_add(usize::try_from(count).ok()?)?;
        self.hashes.get(start..end)
    }

    fn check(&self, page: u64, data: &[u8; PAGE_SIZE]) -> io::Result<()> {
        let Some(index) = self.index(page) else {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("page {page} lies outside the part of the package its hash tree covers"),
            ));
        };
        if page_digest(data) != self.hashes[index] {
            return Err(Error::new(
                ErrorKind::InvalidData,
                PageHashMismatch { page },
            ));
        }
        Ok(())
    }

    /// Read the tree, top level first. With `verify`, the top page must hash
    /// to what the header records and every page below must hash to its entry
    /// in the level above, so the level-0 hashes kept at the end are exactly as
    /// trustworthy as the header.
    async fn load<Reader>(
        file: &mut Reader,
        header: &XvdHeader,
        layout: &XvdLayout,
        verify: bool,
    ) -> Result<HashTree, Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        if !header.volume_flags.is_data_integrity_enabled() {
            return Err(Box::new(Error::new(
                ErrorKind::InvalidData,
                "the package has no hash tree (data integrity is off), so nothing in it can be checked",
            )));
        }
        if header.volume_flags.is_resiliency_enabled() {
            return Err(Box::new(Error::new(
                ErrorKind::Unsupported,
                "the package uses a resilient hash tree, which is not supported",
            )));
        }

        let tree = &layout.hash_tree_layout;
        let levels = [tree.level0, tree.level1, tree.level2, tree.level3];
        let top = tree.top_level() as usize;
        let base = layout.hash_tree.start.to_bytes().0;

        // The hashes the pages of the level being read must have. The top
        // level's single page is vouched for by the header instead.
        let mut expected: Vec<[u8; 20]> = Vec::new();
        let mut hashes: Vec<[u8; 20]> = Vec::new();
        let mut units: Vec<u32> = Vec::new();
        let mut page = [0u8; PAGE_SIZE];

        for level in (0..=top).rev() {
            let this = levels[level];
            let entries = this.num_hashes.0 as usize;
            let mut found: Vec<[u8; 20]> = Vec::with_capacity(entries);
            if level == 0 {
                units.reserve_exact(entries);
            }

            file.seek(SeekFrom::Start(base + this.page_range.start.to_bytes().0))
                .await?;
            let mut reader = BufReader::with_capacity(64 * PAGE_SIZE, &mut *file);
            for index in 0..this.num_pages().0 as usize {
                reader.read_exact(&mut page).await?;
                if verify {
                    let matches = if level == top {
                        Sha256::digest(page)[..] == header.top_hash_block_hash[..]
                    } else {
                        expected.get(index) == Some(&page_digest(&page))
                    };
                    if !matches {
                        return Err(Box::new(Error::new(
                            ErrorKind::InvalidData,
                            format!(
                                "the package's hash tree is damaged: page {index} of level {level} \
                                 does not match {}",
                                if level == top {
                                    "the package header"
                                } else {
                                    "the level above it"
                                }
                            ),
                        )));
                    }
                }
                let in_page = (entries - found.len()).min(HASH_ENTRIES_IN_PAGE);
                let (in_use, _) =
                    page[..in_page * HASH_ENTRY_LENGTH].as_chunks::<HASH_ENTRY_LENGTH>();
                for entry in in_use {
                    let entry = XvdHashEntry::from_slice(entry);
                    found.push(entry.block_hash);
                    if level == 0 {
                        units.push(entry.unit);
                    }
                }
            }
            if found.len() != entries {
                return Err(Box::new(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "hash tree level {level} holds {} entries, expected {entries}",
                        found.len()
                    ),
                )));
            }
            if level == 0 {
                hashes = found;
            } else {
                expected = found;
            }
        }

        Ok(HashTree {
            first_page: layout.user_data.start.0 as u64,
            hashes,
            units,
        })
    }
}

/// Turn a path as the package spells it into one that can only name something
/// inside the directory it is joined to.
///
/// The names come from the package itself -- its segment metadata and its NTFS
/// directory -- so they are not trusted to be well formed. Only plain names
/// survive: a name that is empty, that starts or ends with a separator, that
/// has an empty, `.` or `..` component, or that holds a NUL or a colon (which
/// covers both drive letters and alternate streams) is refused outright rather
/// than cleaned up, because a package that needs cleaning up is not one to
/// install from.
pub fn package_relative_path(name: &str) -> io::Result<PathBuf> {
    let refuse = |why: &str| {
        Err(Error::new(
            ErrorKind::InvalidData,
            format!("unsafe file name in package {name:?}: {why}"),
        ))
    };
    if name.is_empty() {
        return refuse("it is empty");
    }
    let mut path = PathBuf::new();
    for component in name.split(['\\', '/']) {
        match component {
            "" => return refuse("it has an empty component or a leading or trailing separator"),
            "." | ".." => return refuse("it steps outside its folder"),
            c if c.contains(['\0', ':']) => {
                return refuse("it holds a drive, stream or NUL character");
            }
            c => path.push(c),
        }
    }
    Ok(path)
}

/// How long and how often a download keeps asking before it gives up.
#[derive(Clone, Debug)]
pub struct RetryPolicy {
    /// The wait before the first retry, doubled for each one after it.
    pub first_delay: Duration,
    /// The longest wait between two attempts.
    pub max_delay: Duration,
    /// Give up once this long has passed without a single good page.
    pub give_up_after: Duration,
    /// How long one request, or the gap between two chunks, may take.
    pub stall: Duration,
    /// How many times one page may arrive damaged before the download fails.
    pub bad_page_limit: u32,
}

impl Default for RetryPolicy {
    /// Patient with a connection that drops -- five minutes of nothing before
    /// giving up, retrying at most every thirty seconds -- and not at all with
    /// an answer that will not change, like a 404.
    fn default() -> Self {
        RetryPolicy {
            first_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            give_up_after: Duration::from_secs(300),
            stall: Duration::from_secs(5),
            bad_page_limit: 3,
        }
    }
}

impl RetryPolicy {
    fn delay(&self, failures: u32) -> Duration {
        let doublings = failures.saturating_sub(1).min(16);
        self.first_delay
            .saturating_mul(1u32 << doublings)
            .min(self.max_delay)
    }
}

type ByteStream =
    std::pin::Pin<Box<dyn futures_util::Stream<Item = reqwest::Result<bytes::Bytes>> + Send>>;

enum RangeError {
    /// Worth asking again: the network, a timeout, the server being busy.
    Retry(String),
    /// Asking again will get the same answer.
    Fatal(String),
}

/// Ask for `start..=end` of `url`, and accept only that range back.
async fn open_range(
    client: &reqwest::Client,
    url: &str,
    start: u64,
    end: u64,
    stall: Duration,
) -> Result<ByteStream, RangeError> {
    let request = client
        .get(url)
        .header(RANGE, format!("bytes={start}-{end}"))
        .send();
    let response = match timeout(stall, request).await {
        Err(_) => return Err(RangeError::Retry(format!("no answer within {stall:?}"))),
        Ok(Err(err)) => return Err(RangeError::Retry(err.to_string())),
        Ok(Ok(response)) => response,
    };
    let status = response.status();
    if status == StatusCode::PARTIAL_CONTENT {
        // A server that answers a different range than the one asked for would
        // have its bytes written at the wrong place.
        let starts_right = response
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("bytes "))
            .and_then(|v| v.split_once('-'))
            .and_then(|(s, _)| s.parse::<u64>().ok())
            == Some(start);
        if !starts_right {
            return Err(RangeError::Retry(format!(
                "the server answered a different range than bytes={start}-{end}"
            )));
        }
        return Ok(Box::pin(response.bytes_stream()));
    }
    let message = format!("the server answered {status} for bytes={start}-{end}");
    if status.is_server_error()
        || status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
    {
        Err(RangeError::Retry(message))
    } else {
        // A 403, 404 or 416 means the object is not there for us, and a 200
        // means the server ignores ranges; neither changes by asking again.
        Err(RangeError::Fatal(message))
    }
}

impl XvdFile {
    pub fn content_id(&self) -> uuid::Uuid {
        self.header.vduid
    }

    fn non_encrypted_prefix_len(&self, start: u64, len: u64) -> u64 {
        let end = start.saturating_add(len);
        let mut prefix_len = len;

        for section in &self.encrypted_section_infos {
            let section_start = section.section_offset;
            let section_end = section
                .section_offset
                .saturating_add(section.section_length);

            if section_end <= start || section_start >= end {
                continue;
            }

            if start >= section_start {
                return 0;
            }

            prefix_len = section_start.saturating_sub(start);
            break;
        }

        prefix_len
    }

    pub async fn parse_file(path: String) -> Result<Self, Box<dyn std::error::Error>> {
        let mut file = OpenOptions::new().read(true).open(path.clone()).await?;
        Self::parse(&mut file).await
    }

    /// Parse a package without checking it: for a container already on disk,
    /// which was checked when it was downloaded.
    pub async fn parse<Reader>(file: Reader) -> Result<Self, Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        Self::parse_ex(file, false).await
    }

    /// Parse a package and check it against itself before trusting any of it.
    ///
    /// The header's top hash vouches for the hash tree, the hash tree for every
    /// page after it. The metadata pages -- the file table, the segment
    /// metadata, the region table that says what is encrypted -- are checked
    /// here, the filesystem pages as they are read, and the data pages of every
    /// file as it is downloaded or extracted. What none of this covers is the
    /// header itself: its signature is not checked, so the header is only as
    /// good as the connection it came over.
    pub async fn parse_verified<Reader>(file: Reader) -> Result<Self, Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        Self::parse_ex(file, true).await
    }

    async fn parse_ex<Reader>(
        mut file: Reader,
        verify: bool,
    ) -> Result<Self, Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        let xvd_header = {
            let mut buf = XvdHeader::buffer();
            file.read_exact(&mut buf).await?;
            XvdHeader::try_from_array(&buf)?
        };
        if xvd_header.number_of_hashed_pages().0 == 0 {
            return Err(Box::new(Error::new(
                ErrorKind::InvalidData,
                "the package header describes no data",
            )));
        }

        let layout = xvd_header.layout();
        let hashes = HashTree::load(&mut file, &xvd_header, &layout, verify).await?;

        if verify {
            // Everything between the hash tree and the drive: the user data
            // with its file table and segment metadata, and the XVC info with
            // the region table. Small, and read in full below anyway.
            let first = layout.user_data.start.0 as u64;
            let count = xvd_header.number_of_metadata_pages().0 as u64;
            file.seek(SeekFrom::Start(first * PAGE_SIZE as u64)).await?;
            let mut page = [0u8; PAGE_SIZE];
            for n in first..first + count {
                file.read_exact(&mut page).await?;
                hashes.check(n, &page)?;
            }
        }

        let mut region_headers: Vec<XvcRegionHeader> = Vec::new();

        // TODO: Check if we have proper content type
        if layout.xvc_info.len > Bytes(0) {
            file.seek(std::io::SeekFrom::Start(layout.xvc_info.start.to_bytes().0))
                .await?;

            let xvc_info = {
                let mut buf = XvcInfo::buffer();
                file.read_exact(&mut buf).await?;
                XvcInfo::from_array(&buf)
            };

            let region_count = xvc_info.region_count;

            if xvc_info.version >= 1 {
                let mut buf = XvcRegionHeader::buffer();
                for _ in 0..region_count {
                    file.read_exact(&mut buf).await?;
                    let region_header = XvcRegionHeader::try_from_array(&buf)?;
                    region_headers.push(region_header);
                }
            }
        }

        let mut enc_sections: Vec<EncryptedSectionInfo> = vec![];
        for h in region_headers {
            match h.key_id.get() {
                None => continue,
                Some(0) => (),
                Some(n) => {
                    return Err(Box::new(Error::new(
                        ErrorKind::Unsupported,
                        format!("region encrypted with key {n}: only key 0 is supported"),
                    )));
                }
            }

            // Every page of an encrypted region needs its data unit to be
            // decrypted at all, so a region the tree does not cover is a
            // damaged package, not something to discover halfway through a file.
            let first = h.offset.0 as u64;
            if hashes.range(first, h.length.0 as u64).is_none() {
                return Err(Box::new(Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "encrypted region at page {first} ({} pages) lies outside the hash tree",
                        h.length.0
                    ),
                )));
            }

            enc_sections.push(EncryptedSectionInfo {
                section_offset: h.offset.to_bytes().0,
                section_length: h.length.to_bytes().0,
                header_id: h.region_id,
                vduid: xvd_header.vduid,
                first_segment_index: h.first_segment_index,
            });
        }
        Ok(XvdFile {
            header: xvd_header,
            layout,
            encrypted_section_infos: enc_sections,
            hashes,
            verified: verify,
        })
    }

    pub async fn parse_user_package_files<Reader>(
        &self,
        mut file: Reader,
    ) -> Result<HashMap<String, UserPackageFile>, Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        let mut files = HashMap::new();

        let user_data_offset = self.layout.user_data.start.0 as u64;
        file.seek(SeekFrom::Start(user_data_offset)).await?;
        let user_data_header = {
            let mut buf = XvdUserDataHeader::buffer();
            file.read_exact(&mut buf).await?;
            XvdUserDataHeader::from_array(&buf)
        };
        if user_data_header.t == 0 {
            let mut off = user_data_offset + user_data_header.length as u64;
            file.seek(SeekFrom::Start(off)).await?;
            let user_data_package_files_header = {
                let mut buf = XvdUserDataPackageFilesHeader::buffer();
                file.read_exact(&mut buf).await?;
                XvdUserDataPackageFilesHeader::from_array(&buf)
            };
            off += XvdUserDataPackageFilesHeader::SIZE as u64;
            let mut buf = XvdUserDataPackageFileEntry::buffer();
            for _ in 0..user_data_package_files_header.file_count {
                file.seek(SeekFrom::Start(off)).await?;
                file.read_exact(&mut buf).await?;
                let user_data_package_file_entry = XvdUserDataPackageFileEntry::from_array(&buf);
                off += XvdUserDataPackageFileEntry::SIZE as u64;
                let o = user_data_package_file_entry.offset;
                let s: u32 = user_data_package_file_entry.size;
                let fullname = user_data_package_file_entry.file_path;
                let end = fullname
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(fullname.len());
                let pfull_name: String = String::from_utf16(&fullname[..end])?;

                files.insert(
                    pfull_name,
                    UserPackageFile {
                        offset: user_data_offset + XvdUserDataHeader::SIZE as u64 + o as u64,
                        length: s as u64,
                    },
                );
            }
        }
        Ok(files)
    }

    pub async fn parse_segment_metadata<Reader>(
        &self,
        file: Reader,
        segment_metadata: &UserPackageFile,
    ) -> Result<HashMap<String, SegmentFile>, Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        let mut file = BufReader::with_capacity(segment_metadata.length as usize, file);
        file.seek(SeekFrom::Start(segment_metadata.offset)).await?;
        let segment_header = {
            let mut buf = XvdSegmentMetadataHeader::buffer();
            file.read_exact(&mut buf).await?;
            XvdSegmentMetadataHeader::try_from_array(&buf)?
        };
        let paths_offset =
            segment_header.header_length as u64 + segment_header.segment_count as u64 * 0x10;

        let mut segments = Vec::with_capacity(segment_header.segment_count as usize);
        let mut buf = XvdSegmentMetadataSegment::buffer();
        for _ in 0..segment_header.segment_count {
            file.read_exact(&mut buf).await?;
            let segment = XvdSegmentMetadataSegment::from_array(&buf);
            segments.push(segment);
        }

        let mut files = HashMap::new();

        for section in &self.encrypted_section_infos {
            let segment_page_start = section.section_offset.div_ceil(PAGE_SIZE as u64);
            let mut page_offset = segment_page_start;
            for segment_no in section.first_segment_index..segment_header.segment_count {
                let segment = &segments[segment_no as usize];
                let s = segment.path_length;
                let mut buf = vec![0u16, 0];
                buf.resize(s as usize, 0);
                file.seek(SeekFrom::Start(
                    segment_metadata.offset + paths_offset + segment.path_offset as u64,
                ))
                .await?;
                file.read_exact(buf.as_mut_bytes()).await?;
                let file_name: String = String::from_utf16(buf.as_slice())?;
                let page_length = if segment.filesize == 0 {
                    1
                } else {
                    segment.filesize.div_ceil(PAGE_SIZE as u64)
                };
                if page_offset * (PAGE_SIZE as u64)
                    >= section.section_offset + section.section_length
                {
                    break;
                }
                let data_hashs: Vec<[u8; 20]> = self
                    .hashes
                    .range(page_offset, segment.filesize.div_ceil(PAGE_SIZE as u64))
                    .ok_or_else(|| {
                        Error::new(
                            ErrorKind::InvalidData,
                            format!("{file_name} lies outside the package's hash tree"),
                        )
                    })?
                    .into();
                files.insert(
                    file_name,
                    SegmentFile {
                        offset: page_offset * PAGE_SIZE as u64,
                        length: segment.filesize,
                        data_hashs,
                        keep_encrypted: segment
                            .flags
                            .contains(XvdSegmentMetadataSegmentFlags::KEEP_ENCRYPTED_ON_DISK),
                    },
                );
                page_offset += page_length;
            }
        }
        Ok(files)
    }

    pub fn populate_segment_hashes(
        &self,
        files: &mut HashMap<String, SegmentFile>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (name, file) in files.iter_mut() {
            if !file.data_hashs.is_empty() {
                continue;
            }

            let Some(section) = self.encrypted_section_infos.iter().find(|section| {
                file.offset >= section.section_offset
                    && file.offset < section.section_offset + section.section_length
            }) else {
                continue;
            };

            let file_end = file.offset.saturating_add(file.length);
            let section_end = section
                .section_offset
                .saturating_add(section.section_length);
            if file_end > section_end {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "segment file spans beyond encrypted section: {} ({}..{} > {}..{})",
                        name, file.offset, file_end, section.section_offset, section_end
                    ),
                )
                .into());
            }

            let page_offset = file.offset.div_ceil(PAGE_SIZE as u64);
            let page_count = file.length.div_ceil(PAGE_SIZE as u64);
            let Some(hashes) = self.hashes.range(page_offset, page_count) else {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "missing data hashes for {}: need {} pages from page {}",
                        name, page_count, page_offset
                    ),
                )
                .into());
            };

            file.data_hashs = hashes.into();
        }

        Ok(())
    }

    pub async fn parse_ntfs_segment_metadata<Reader>(
        &self,
        file: Reader,
        only_plain: bool,
    ) -> Result<HashMap<String, SegmentFile>, Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        let drive_data_offset = self.layout.drive_data.start.to_bytes().0;
        let drive_size = self.header.drive_size;
        let drive_plain_len = self.non_encrypted_prefix_len(drive_data_offset, drive_size.0);

        // Checked only for a package parsed with `parse_verified`; see there.
        let hashes = self.verified.then_some(&self.hashes);

        block_in_place(|| {
            let block_size = 4096;
            let drive = SyncSubstream::new(
                XvdStream::new(
                    SyncIoBridge::new(file),
                    drive_data_offset,
                    drive_data_offset + drive_plain_len,
                    hashes,
                ),
                0,
                drive_plain_len,
            );

            let gp = gpt::GptConfig::new()
                .writable(false)
                .logical_block_size(if block_size == 512 {
                    gpt::disk::LogicalBlockSize::Lb512
                } else if block_size == 4096 {
                    gpt::disk::LogicalBlockSize::Lb4096
                } else {
                    todo!("unsupported block_size: {}", block_size)
                })
                .open_from_device(drive)?;

            let (_, part) = gp
                .partitions()
                .iter()
                .find(|(_, part)| part.is_used())
                .ok_or_else(|| {
                    io::Error::new(ErrorKind::NotFound, "no used GPT partition found")
                })?;

            let part_start = part.bytes_start(*gp.logical_block_size())?;
            let part_len = part.bytes_len(*gp.logical_block_size())?;

            let bridge = gp.take_device().into_inner().into_inner();
            let partition_offset = drive_data_offset + part_start;
            let partition_plain_len = self.non_encrypted_prefix_len(partition_offset, part_len);
            let mut fs = SyncSubstream::new(
                XvdStream::new(
                    bridge,
                    partition_offset,
                    partition_offset + partition_plain_len,
                    hashes,
                ),
                0,
                partition_plain_len,
            );

            let reports = collect_ntfs_stream_layouts(&mut fs)?;
            let mut files = HashMap::new();

            for report in reports {
                if report.path.starts_with('$') || report.path.contains(':') {
                    continue;
                }
                if report.resident_data || report.data_runs.len() != 1 {
                    continue;
                }

                let Some(data_run) = report.data_runs.first() else {
                    continue;
                };
                let Some(start) = data_run.start else {
                    continue;
                };

                if only_plain && partition_offset + start >= drive_data_offset + drive_plain_len {
                    continue;
                }

                files.insert(
                    report.path.replace("/", "\\"),
                    SegmentFile {
                        offset: partition_offset + start,
                        length: report.value_length,
                        data_hashs: vec![],
                        keep_encrypted: !only_plain
                            && report.path.to_ascii_lowercase().ends_with(".exe"),
                    },
                );
            }

            self.populate_segment_hashes(&mut files)?;

            Ok(files)
        })
    }

    /// The pieces both decrypting paths need: the section a file lies in (if
    /// it is to be decrypted) and the ciphers for it.
    fn file_crypto(
        &self,
        sfile: &SegmentFile,
        full_key: [u8; 32],
        decrypt: bool,
    ) -> Option<(&EncryptedSectionInfo, TweakGenerator, Aes128Enc, Aes128Dec)> {
        let s = self.encrypted_section_infos.iter().find(|s| {
            sfile.offset >= s.section_offset && sfile.offset < s.section_offset + s.section_length
        })?;
        if !decrypt {
            return None;
        }
        let mut tweak_key = [0u8; 16];
        let mut data_key = [0u8; 16];
        tweak_key.copy_from_slice(&full_key[..16]);
        data_key.copy_from_slice(&full_key[16..]);
        Some((
            s,
            TweakGenerator::new(s.header_id, s.vduid),
            Aes128Enc::new((&tweak_key).into()),
            Aes128Dec::new((&data_key).into()),
        ))
    }

    /// Decrypt one page of a file in place, given its absolute page number.
    fn decrypt_page(
        &self,
        page: &mut [u8; PAGE_SIZE],
        absolute_page: u64,
        crypto: &(&EncryptedSectionInfo, TweakGenerator, Aes128Enc, Aes128Dec),
    ) -> io::Result<()> {
        let (_, tweak, tweak_cipher, data_cipher) = crypto;
        let unit = self.hashes.unit(absolute_page).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("missing data unit for page {absolute_page}"),
            )
        })?;
        decrypt_page_xts(page, tweak.with_data_unit(unit), tweak_cipher, data_cipher);
        Ok(())
    }

    fn first_page_of(sfile: &SegmentFile) -> io::Result<u64> {
        if !sfile.offset.is_multiple_of(PAGE_SIZE as u64) {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("file at offset {} does not start on a page", sfile.offset),
            ));
        }
        Ok(sfile.offset / PAGE_SIZE as u64)
    }

    pub async fn download_file_http<Writer, Progress>(
        &self,
        client: &reqwest::Client,
        url: &str,
        out: &mut Writer,
        sfile: &SegmentFile,
        full_key: [u8; 32],
        progress: Progress,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        Writer: AsyncWrite + Unpin,
        Progress: FnMut(u64, u64),
    {
        self.download_file_http_with(
            client,
            url,
            out,
            sfile,
            full_key,
            progress,
            &RetryPolicy::default(),
        )
        .await
    }

    /// Download one file's pages with a ranged GET, resuming where a dropped
    /// connection left off.
    ///
    /// Every page is checked against the hash tree before it is decrypted or
    /// written (for a package parsed with `parse_verified`). A damaged page is
    /// fetched again, a few times, and then the file fails: a proxy that
    /// mangles the stream would otherwise be written straight into the game.
    ///
    /// A connection that drops is retried with a growing wait, and given up on
    /// once no good page has arrived for `policy.give_up_after`; an answer
    /// that will not change (a 404, a server that ignores ranges) fails at
    /// once. Neither used to end: the request was repeated without a pause for
    /// as long as it kept failing, and a write that failed was retried every
    /// thirty seconds forever, so a full disk hung the install instead of
    /// stopping it.
    #[allow(clippy::too_many_arguments)]
    pub async fn download_file_http_with<Writer, Progress>(
        &self,
        client: &reqwest::Client,
        url: &str,
        out: &mut Writer,
        sfile: &SegmentFile,
        full_key: [u8; 32],
        mut progress: Progress,
        policy: &RetryPolicy,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        Writer: AsyncWrite + Unpin,
        Progress: FnMut(u64, u64),
    {
        if sfile.length == 0 {
            return Ok(());
        }

        let first_page = Self::first_page_of(sfile)?;
        let crypto = self.file_crypto(sfile, full_key, !sfile.keep_encrypted);
        let page_count = sfile.length.div_ceil(PAGE_SIZE as u64);
        let last_byte = sfile.offset + page_count * PAGE_SIZE as u64 - 1;

        let mut page = [0u8; PAGE_SIZE];
        let mut remaining = sfile.length;
        let mut done_pages: u64 = 0;
        let mut stream: Option<ByteStream> = None;
        let mut pending = bytes::BytesMut::new();
        let mut reported: u64 = 0;

        let mut failures: u32 = 0;
        let mut last_good = Instant::now();
        let mut last_error = String::new();
        let mut bad_page: Option<(u64, u32)> = None;

        while done_pages < page_count {
            let Some(s) = stream.as_mut() else {
                if failures > 0 {
                    if last_good.elapsed() >= policy.give_up_after {
                        return Err(Box::new(Error::new(
                            ErrorKind::TimedOut,
                            format!(
                                "gave up after {:?} without progress ({} of {} bytes): {last_error}",
                                policy.give_up_after,
                                done_pages * PAGE_SIZE as u64,
                                sfile.length
                            ),
                        )));
                    }
                    sleep(policy.delay(failures)).await;
                }
                let start = sfile.offset + done_pages * PAGE_SIZE as u64 + pending.len() as u64;
                match open_range(client, url, start, last_byte, policy.stall).await {
                    Ok(opened) => stream = Some(opened),
                    Err(RangeError::Fatal(message)) => {
                        return Err(Box::new(Error::other(message)));
                    }
                    Err(RangeError::Retry(message)) => {
                        failures += 1;
                        last_error = message;
                    }
                }
                continue;
            };

            match timeout(policy.stall, s.next()).await {
                Ok(Some(Ok(data))) => pending.extend_from_slice(&data),
                Ok(Some(Err(err))) => {
                    stream = None;
                    failures += 1;
                    last_error = err.to_string();
                }
                Ok(None) => {
                    stream = None;
                    failures += 1;
                    last_error = "the connection closed early".to_owned();
                }
                Err(_) => {
                    stream = None;
                    failures += 1;
                    last_error = format!("no data for {:?}", policy.stall);
                }
            }

            let received = min(
                done_pages * PAGE_SIZE as u64 + pending.len() as u64,
                sfile.length,
            );
            if received > reported {
                reported = received;
                progress(reported, sfile.length);
            }

            while pending.len() >= PAGE_SIZE && done_pages < page_count {
                let absolute_page = first_page + done_pages;
                page.copy_from_slice(&pending[..PAGE_SIZE]);
                if self.verified
                    && let Err(err) = self.hashes.check(absolute_page, &page)
                {
                    // Throw away this page and whatever came after it on the
                    // same connection, and ask again from here.
                    let count = match bad_page {
                        Some((p, n)) if p == absolute_page => n + 1,
                        _ => 1,
                    };
                    if count >= policy.bad_page_limit {
                        return Err(Box::new(Error::new(
                            ErrorKind::InvalidData,
                            format!("{err}, {count} times over; giving up on this file"),
                        )));
                    }
                    bad_page = Some((absolute_page, count));
                    pending.clear();
                    stream = None;
                    failures += 1;
                    last_error = err.to_string();
                    break;
                }
                let _ = pending.split_to(PAGE_SIZE);

                let to_write_remaining = remaining.min(PAGE_SIZE as u64) as usize;
                let to_write = if let Some(crypto) = &crypto {
                    self.decrypt_page(&mut page, absolute_page, crypto)?;
                    to_write_remaining
                } else if sfile.keep_encrypted {
                    // Decryption needs full 4k blocks
                    PAGE_SIZE
                } else {
                    to_write_remaining
                };
                out.write_all(&page[..to_write]).await?;
                remaining -= to_write_remaining as u64;
                done_pages += 1;

                failures = 0;
                last_good = Instant::now();
            }
        }
        Ok(())
    }

    async fn extract_file_ex<Writer, Reader, Progress>(
        &self,
        i: &mut Reader,
        out: &mut Writer,
        sfile: &SegmentFile,
        full_key: [u8; 32],
        mut progress: Progress,
        decrypt_all: bool,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + Unpin,
        Writer: AsyncWrite + Unpin,
        Progress: FnMut(u64, u64),
    {
        if sfile.length == 0 {
            return Ok(());
        }

        let first_page = Self::first_page_of(sfile)?;
        let crypto = self.file_crypto(sfile, full_key, !sfile.keep_encrypted || decrypt_all);
        let page_count = sfile.length.div_ceil(PAGE_SIZE as u64);
        // Reading from a package's own pages, they are checked like downloaded
        // ones. Mounting reads a file already on disk, written raw, and is
        // left as it was.
        let verify = self.verified && !decrypt_all;

        let mut page = [0u8; PAGE_SIZE];

        for n in 0..page_count {
            progress(min(n * PAGE_SIZE as u64, sfile.length), sfile.length);
            i.read_exact(&mut page).await?;
            let absolute_page = first_page + n;
            if verify {
                self.hashes.check(absolute_page, &page)?;
            }
            let to_write = min(
                PAGE_SIZE as u64,
                sfile.length - min(n * PAGE_SIZE as u64, sfile.length),
            ) as usize;
            let to_write = if let Some(crypto) = &crypto {
                self.decrypt_page(&mut page, absolute_page, crypto)?;
                to_write
            } else if sfile.keep_encrypted {
                // Decryption needs full 4k blocks
                PAGE_SIZE
            } else {
                to_write
            };
            out.write_all(&page[..to_write]).await?;
        }
        Ok(())
    }

    // Reader is an full xvd file
    pub async fn extract_file<Writer, Reader, Progress>(
        &self,
        i: &mut Reader,
        out: &mut Writer,
        sfile: &SegmentFile,
        full_key: [u8; 32],
        progress: Progress,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
        Writer: AsyncWrite + Unpin,
        Progress: FnMut(u64, u64),
    {
        i.seek(std::io::SeekFrom::Start(sfile.offset)).await?;
        self.extract_file_ex(i, out, sfile, full_key, progress, false)
            .await
    }

    // Reader points to file content
    pub async fn mount_mem_fd<Writer, Reader, Progress>(
        &self,
        i: &mut Reader,
        out: &mut Writer,
        sfile: &SegmentFile,
        full_key: [u8; 32],
        progress: Progress,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + Unpin,
        Writer: AsyncWrite + Unpin,
        Progress: FnMut(u64, u64),
    {
        self.extract_file_ex(i, out, sfile, full_key, progress, true)
            .await
    }
}

/// A package built in memory, for tests here and in the crates that use this
/// one. Not part of the API.
#[doc(hidden)]
pub mod testing {
    use sha2::{Digest, Sha256};

    use super::PAGE_SIZE;
    use crate::models::xvd::{HASH_ENTRIES_IN_PAGE, HASH_ENTRY_LENGTH, XvdHeader};
    use msixvc_common::parse::BinaryTryParse;

    pub const DRIVE_PAGES: usize = 340;

    /// Small enough to build in a test and large enough to need a two-level
    /// hash tree: three header pages, the tree, one page of user data and
    /// `DRIVE_PAGES` pages of plain drive data, every hash real. Nothing in it
    /// is encrypted.
    pub struct Package {
        pub bytes: Vec<u8>,
        pub tree_start: usize,
        pub user_data_page: usize,
        pub drive_page: usize,
    }

    fn drive_page_bytes(n: usize) -> Vec<u8> {
        (0..PAGE_SIZE)
            .map(|i| ((i * 7 + n * 13) % 251) as u8)
            .collect()
    }

    fn header_bytes(top_hash: &[u8; 32]) -> Vec<u8> {
        let mut h = vec![0u8; 3 * PAGE_SIZE];
        h[0x200..0x208].copy_from_slice(b"msft-xvd");
        // Created in 2019, as a FILETIME.
        h[0x210..0x218].copy_from_slice(&132_000_000_000_000_000i64.to_le_bytes());
        h[0x218..0x220].copy_from_slice(&((DRIVE_PAGES * PAGE_SIZE) as u64).to_le_bytes());
        h[0x240..0x260].copy_from_slice(top_hash);
        h[0x28C..0x290].copy_from_slice(&(PAGE_SIZE as u32).to_le_bytes());
        h
    }

    fn entry(page: &[u8]) -> [u8; HASH_ENTRY_LENGTH] {
        let digest = Sha256::digest(page);
        let mut e = [0u8; HASH_ENTRY_LENGTH];
        e.copy_from_slice(&digest[..HASH_ENTRY_LENGTH]);
        e
    }

    /// Hash entries packed the way a level stores them: `HASH_ENTRIES_IN_PAGE`
    /// to a page, the rest of each page zero.
    fn level_pages(entries: &[[u8; HASH_ENTRY_LENGTH]]) -> Vec<Vec<u8>> {
        entries
            .chunks(HASH_ENTRIES_IN_PAGE)
            .map(|chunk| {
                let mut page = vec![0u8; PAGE_SIZE];
                for (i, e) in chunk.iter().enumerate() {
                    page[i * HASH_ENTRY_LENGTH..(i + 1) * HASH_ENTRY_LENGTH].copy_from_slice(e);
                }
                page
            })
            .collect()
    }

    pub fn package() -> Package {
        let mut buf = XvdHeader::buffer();
        let len = buf.len();
        buf.copy_from_slice(&header_bytes(&[0; 32])[..len]);
        let layout = XvdHeader::try_from_array(&buf).unwrap().layout();
        let tree = layout.hash_tree_layout;
        assert_eq!(
            tree.top_level(),
            1,
            "the fixture is meant to need two levels"
        );

        // User data: a header whose type says "no package file table".
        let mut user_data = vec![0u8; PAGE_SIZE];
        user_data[8..12].copy_from_slice(&1u32.to_le_bytes());
        let mut data_pages = vec![user_data];
        data_pages.extend((0..DRIVE_PAGES).map(drive_page_bytes));

        let level0 = level_pages(&data_pages.iter().map(|p| entry(p)).collect::<Vec<_>>());
        let level1 = level_pages(&level0.iter().map(|p| entry(p)).collect::<Vec<_>>());
        assert_eq!(level0.len(), tree.level0.num_pages().0 as usize);
        assert_eq!(level1.len(), 1);
        let top: [u8; 32] = Sha256::digest(&level1[0]).into();

        let mut bytes = header_bytes(&top);
        let tree_start = layout.hash_tree.start.0 as usize;
        assert_eq!(bytes.len(), tree_start * PAGE_SIZE);
        for page in level1.iter().chain(level0.iter()) {
            bytes.extend_from_slice(page);
        }
        let user_data_page = layout.user_data.start.0 as usize;
        assert_eq!(bytes.len(), user_data_page * PAGE_SIZE);
        for page in &data_pages {
            bytes.extend_from_slice(page);
        }
        Package {
            bytes,
            tree_start,
            user_data_page,
            drive_page: layout.drive_data.start.0 as usize,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::testing::{DRIVE_PAGES, Package, package};
    use super::{
        PAGE_SIZE, PageHashMismatch, RetryPolicy, SegmentFile, XvdFile, package_relative_path,
    };

    fn flip(bytes: &mut [u8], offset: usize) {
        bytes[offset] ^= 0x01;
    }

    /// Pages 5..8 of the drive and a little of page 8, as a file of the package.
    fn sample_file(p: &Package) -> (SegmentFile, Vec<u8>) {
        let first = p.drive_page + 5;
        let length = 3 * PAGE_SIZE + 100;
        let file = SegmentFile {
            offset: (first * PAGE_SIZE) as u64,
            length: length as u64,
            data_hashs: vec![],
            keep_encrypted: false,
        };
        let expected = p.bytes[first * PAGE_SIZE..first * PAGE_SIZE + length].to_vec();
        (file, expected)
    }

    async fn parse_verified(bytes: &[u8]) -> Result<XvdFile, Box<dyn std::error::Error>> {
        XvdFile::parse_verified(Cursor::new(bytes.to_vec())).await
    }

    #[test]
    fn package_names_cannot_leave_the_install_folder() {
        assert_eq!(
            package_relative_path(r"Content\Paks\data.pak").unwrap(),
            std::path::PathBuf::from("Content/Paks/data.pak")
        );
        assert_eq!(
            package_relative_path("Game.exe").unwrap(),
            std::path::PathBuf::from("Game.exe")
        );
        for bad in [
            "",
            r"..\..\.config\autostart\x.desktop",
            r"Content\..\..\x",
            "../x",
            r"\etc\passwd",
            "/etc/passwd",
            r"C:\Windows\x.dll",
            "C:x",
            r"a\\b",
            r"a\",
            r".\a",
            "a\0b",
            "file.txt:stream",
        ] {
            assert!(
                package_relative_path(bad).is_err(),
                "{bad:?} should have been refused"
            );
        }
    }

    #[test]
    fn retry_waits_double_up_to_the_cap() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.delay(1), Duration::from_secs(1));
        assert_eq!(policy.delay(2), Duration::from_secs(2));
        assert_eq!(policy.delay(5), Duration::from_secs(16));
        assert_eq!(policy.delay(6), Duration::from_secs(30));
        assert_eq!(policy.delay(1000), Duration::from_secs(30));
    }

    #[tokio::test]
    async fn an_intact_package_verifies() {
        let p = package();
        let xvd = parse_verified(&p.bytes).await.unwrap();
        assert!(xvd.verified);
        // Hashed page 0 is the first user data page.
        assert_eq!(xvd.hashes.first_page, p.user_data_page as u64);
        assert_eq!(xvd.hashes.hashes.len(), 1 + DRIVE_PAGES);
    }

    #[tokio::test]
    async fn a_damaged_hash_tree_is_refused() {
        let p = package();
        // A level-0 entry: its page no longer matches the level above.
        let mut bytes = p.bytes.clone();
        flip(&mut bytes, (p.tree_start + 1) * PAGE_SIZE + 30);
        let err = parse_verified(&bytes).await.err().unwrap();
        assert!(err.to_string().contains("hash tree is damaged"), "{err}");

        // The top page: it no longer matches the header.
        let mut bytes = p.bytes.clone();
        flip(&mut bytes, p.tree_start * PAGE_SIZE + 3);
        let err = parse_verified(&bytes).await.err().unwrap();
        assert!(err.to_string().contains("the package header"), "{err}");

        // Unchecked parsing is what the installed container gets, and it
        // takes the tree as it is.
        assert!(XvdFile::parse(Cursor::new(bytes)).await.is_ok());
    }

    #[tokio::test]
    async fn a_damaged_metadata_page_is_refused() {
        let p = package();
        let mut bytes = p.bytes.clone();
        flip(&mut bytes, p.user_data_page * PAGE_SIZE + 100);
        let err = parse_verified(&bytes).await.err().unwrap();
        assert!(
            err.to_string().contains("does not match its hash tree"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn extracting_checks_every_page() {
        let p = package();
        let xvd = parse_verified(&p.bytes).await.unwrap();
        let (file, expected) = sample_file(&p);

        let mut out = Vec::new();
        xvd.extract_file(
            &mut Cursor::new(p.bytes.clone()),
            &mut out,
            &file,
            [0; 32],
            |_, _| {},
        )
        .await
        .unwrap();
        assert_eq!(out, expected);

        let mut damaged = p.bytes.clone();
        flip(&mut damaged, file.offset as usize + 2 * PAGE_SIZE + 9);
        let mut out = Vec::new();
        let err = xvd
            .extract_file(
                &mut Cursor::new(damaged),
                &mut out,
                &file,
                [0; 32],
                |_, _| {},
            )
            .await
            .unwrap_err();
        let io = err.downcast_ref::<std::io::Error>().unwrap();
        let mismatch = io
            .get_ref()
            .and_then(|e| e.downcast_ref::<PageHashMismatch>())
            .unwrap();
        assert_eq!(mismatch.page, file.offset / PAGE_SIZE as u64 + 2);
        // Nothing from the damaged page or after it was written.
        assert_eq!(out.len(), 2 * PAGE_SIZE);
    }

    /// What the test server does with the request it is numbered.
    #[derive(Clone, Copy, Debug)]
    enum Answer {
        /// The range asked for.
        Serve,
        /// The range asked for, with one byte changed.
        Damaged,
        /// The first `n` bytes of the range, then the connection closes.
        Short(usize),
        /// Just this status.
        Status(u16),
        /// Accept the connection and close it without a word.
        Hang,
    }

    struct Server {
        url: String,
        ranges: Arc<Mutex<Vec<String>>>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    async fn serve(body: Vec<u8>, script: Vec<Answer>, then: Answer) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/package", listener.local_addr().unwrap());
        let ranges = Arc::new(Mutex::new(Vec::new()));
        let seen = ranges.clone();
        let count = Arc::new(AtomicUsize::new(0));
        let body = Arc::new(body);
        let handle = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let n = count.fetch_add(1, Ordering::SeqCst);
                let answer = script.get(n).copied().unwrap_or(then);
                let body = body.clone();
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                        }
                    }
                    let text = String::from_utf8_lossy(&request).to_string();
                    let range = text
                        .lines()
                        .find_map(|l| l.strip_prefix("range: ").or(l.strip_prefix("Range: ")))
                        .unwrap_or("")
                        .to_owned();
                    seen.lock().unwrap().push(range.clone());
                    let (start, end) = range
                        .strip_prefix("bytes=")
                        .and_then(|r| r.split_once('-'))
                        .map(|(a, b)| (a.parse::<usize>().unwrap(), b.parse::<usize>().unwrap()))
                        .unwrap_or((0, body.len() - 1));
                    let mut part = body[start..=end].to_vec();
                    let head = |status: &str, len: usize| {
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {len}\r\n\
                             Content-Range: bytes {start}-{end}/{}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                    };
                    let reply = match answer {
                        Answer::Serve => {
                            [head("206 Partial Content", part.len()).into_bytes(), part].concat()
                        }
                        Answer::Damaged => {
                            part[PAGE_SIZE / 2] ^= 0x40;
                            [head("206 Partial Content", part.len()).into_bytes(), part].concat()
                        }
                        Answer::Short(n) => {
                            let len = part.len();
                            part.truncate(n);
                            [head("206 Partial Content", len).into_bytes(), part].concat()
                        }
                        Answer::Status(code) => format!(
                            "HTTP/1.1 {code} Nope\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .into_bytes(),
                        Answer::Hang => Vec::new(),
                    };
                    let _ = stream.write_all(&reply).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Server {
            url,
            ranges,
            handle,
        }
    }

    fn quick() -> RetryPolicy {
        RetryPolicy {
            first_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(20),
            give_up_after: Duration::from_millis(500),
            stall: Duration::from_secs(2),
            bad_page_limit: 3,
        }
    }

    async fn download(
        xvd: &XvdFile,
        server: &Server,
        file: &SegmentFile,
        out: &mut (impl AsyncWrite + Unpin),
        policy: &RetryPolicy,
    ) -> Result<(), String> {
        let client = reqwest::Client::new();
        // Bounded, so a regression to retrying for ever fails the test instead
        // of hanging it.
        tokio::time::timeout(
            Duration::from_secs(20),
            xvd.download_file_http_with(
                &client,
                &server.url,
                out,
                file,
                [0; 32],
                |_, _| {},
                policy,
            ),
        )
        .await
        .map_err(|_| "still retrying after 20 s".to_owned())?
        .map_err(|e| e.to_string())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_download_resumes_where_the_connection_dropped() {
        let p = package();
        let xvd = parse_verified(&p.bytes).await.unwrap();
        let (file, expected) = sample_file(&p);
        let server = serve(
            p.bytes.clone(),
            vec![Answer::Short(PAGE_SIZE + 10)],
            Answer::Serve,
        )
        .await;

        let mut out = Vec::new();
        download(&xvd, &server, &file, &mut out, &quick())
            .await
            .unwrap();
        assert_eq!(out, expected);
        let ranges = server.ranges.lock().unwrap().clone();
        assert_eq!(ranges.len(), 2);
        assert_eq!(
            ranges[1],
            format!(
                "bytes={}-{}",
                file.offset + PAGE_SIZE as u64 + 10,
                file.offset + 4 * PAGE_SIZE as u64 - 1
            )
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_damaged_page_is_fetched_again_and_never_written() {
        let p = package();
        let xvd = parse_verified(&p.bytes).await.unwrap();
        let (file, expected) = sample_file(&p);
        let server = serve(p.bytes.clone(), vec![Answer::Damaged], Answer::Serve).await;

        let mut out = Vec::new();
        download(&xvd, &server, &file, &mut out, &quick())
            .await
            .unwrap();
        assert_eq!(out, expected);
        let ranges = server.ranges.lock().unwrap().clone();
        assert_eq!(ranges.len(), 2, "{ranges:?}");
        // The damage was in the first page, so it was asked for again whole.
        assert_eq!(ranges[0], ranges[1]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_page_that_stays_damaged_fails_the_file() {
        let p = package();
        let xvd = parse_verified(&p.bytes).await.unwrap();
        let (file, _) = sample_file(&p);
        let server = serve(p.bytes.clone(), vec![], Answer::Damaged).await;

        let mut out = Vec::new();
        let err = download(&xvd, &server, &file, &mut out, &quick())
            .await
            .unwrap_err();
        assert!(err.contains("does not match its hash tree"), "{err}");
        assert!(out.is_empty());
        assert_eq!(server.ranges.lock().unwrap().len(), 3);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_missing_object_fails_at_once() {
        let p = package();
        let xvd = parse_verified(&p.bytes).await.unwrap();
        let (file, _) = sample_file(&p);
        for code in [403, 404, 416, 200] {
            let server = serve(p.bytes.clone(), vec![], Answer::Status(code)).await;
            let err = download(
                &xvd,
                &server,
                &file,
                &mut Vec::new(),
                &RetryPolicy::default(),
            )
            .await
            .unwrap_err();
            assert!(err.contains(&code.to_string()), "{err}");
            assert_eq!(
                server.ranges.lock().unwrap().len(),
                1,
                "{code} was asked again"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_dead_connection_is_given_up_on() {
        let p = package();
        let xvd = parse_verified(&p.bytes).await.unwrap();
        let (file, _) = sample_file(&p);
        for answer in [Answer::Hang, Answer::Status(503)] {
            let server = serve(p.bytes.clone(), vec![], answer).await;
            let err = download(&xvd, &server, &file, &mut Vec::new(), &quick())
                .await
                .unwrap_err();
            assert!(err.contains("without progress"), "{err}");
            let asked = server.ranges.lock().unwrap().len();
            // Retried, but with a wait between attempts rather than flat out:
            // in half a second at 5 ms doubling to 20 ms, a few dozen at most.
            assert!((2..60).contains(&asked), "{answer:?} asked {asked} times");
        }
    }

    struct FullDisk;

    impl AsyncWrite for FullDisk {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(Err(std::io::Error::from_raw_os_error(28)))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_write_error_fails_the_file() {
        let p = package();
        let xvd = parse_verified(&p.bytes).await.unwrap();
        let (file, _) = sample_file(&p);
        let server = serve(p.bytes.clone(), vec![], Answer::Serve).await;

        let err = download(&xvd, &server, &file, &mut FullDisk, &quick())
            .await
            .unwrap_err();
        assert!(err.contains("No space left"), "{err}");
    }
}
