use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use msixvc::layout::PAGE_SIZE;
use msixvc::signature::XvdSigningKey;
use msixvc::streaming;
use msixvc::xvd::{
    HeaderChecks, HeaderRefused, PackageIdentity, SegmentFile, TopHashMismatch, XvdFile,
    package_relative_path,
};
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncSeek};
use tokio::sync::mpsc::{Receiver, Sender};
use uuid::Uuid;
use xodus::tokens::TokenManager;

use crate::license::get_license;
use crate::package::{
    HeaderCheck, get_content_id, get_packages, header_anchor, package_url, unanchored_note,
};

type Job = crate::download_plan::Entry;

/// What the package header is held to before anything in it is believed.
#[derive(Default)]
struct HeaderTrust {
    /// The package service's `HashOfHashes`, read as the header's top hash.
    anchor: Option<[u8; 32]>,
    /// The key the header's signature must verify with.
    key: Option<XvdSigningKey>,
    /// The package the package service named, which a signed header must be.
    identity: Option<PackageIdentity>,
}

impl HeaderTrust {
    fn checks(&self) -> HeaderChecks<'_> {
        HeaderChecks {
            top_hash: self.anchor.as_ref(),
            signed_by: self.key.as_ref(),
            identity: self.identity.as_ref(),
        }
    }
}

/// The key to check the package header's signature with, fetched once if it
/// is not stored yet; see `crate::xvd_key::for_install`. `Err` when there is
/// none and `XODUS_REQUIRE_SIGNED_PACKAGE=1`.
async fn signing_key(fetch: crate::xvd_key::Fetch) -> Result<Option<XvdSigningKey>, ExitCode> {
    crate::xvd_key::for_install(fetch).await.map_err(|err| {
        crate::download_session::diagnostic("metadata-invalid", 0);
        eprintln!("{err}");
        ExitCode::FAILURE
    })
}

enum ProgressEvent {
    Advanced { delta: u64 },
    UpdateRemaining { name: String, total: u64 },
    UpdateStatus { name: String },
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    source: String,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
) -> ExitCode {
    crate::download_session::metadata();
    let (tx, rx) = tokio::sync::mpsc::channel::<ProgressEvent>(256);
    let result = if source.starts_with("file://") {
        let fsrc = source.strip_prefix("file://").unwrap_or_default();
        let f = match File::open(fsrc).await {
            Ok(f) => f,
            Err(err) => {
                eprintln!("could not open {fsrc}: {err}");
                return ExitCode::FAILURE;
            }
        };
        let l = match f.metadata().await {
            Ok(metadata) => metadata.len(),
            Err(err) => {
                eprintln!("could not read metadata for {fsrc}: {err}");
                return ExitCode::FAILURE;
            }
        };
        // A file on disk: its signature is checked if a key is stored (never
        // fetched for it, so this stays offline), but nothing says which
        // package it should be.
        let key = match signing_key(crate::xvd_key::Fetch::Never).await {
            Ok(key) => key,
            Err(code) => return code,
        };
        let trust = HeaderTrust {
            key,
            ..HeaderTrust::default()
        };
        run_cli_reader(
            client,
            tokens,
            destination,
            try_skip_ntfs,
            parallel,
            market,
            f,
            l,
            &source,
            trust,
            tx,
            rx,
        )
        .await
    } else {
        // The top hash the package service vouches for, when the package came
        // from it and it gave one, and the package it named. A URL given
        // directly has nothing to go by but the header's signature.
        let (vurl, trust) = if source.starts_with("http://") || source.starts_with("https://") {
            let key = match signing_key(crate::xvd_key::Fetch::Allowed).await {
                Ok(key) => key,
                Err(code) => return code,
            };
            if source.starts_with("http://") {
                eprintln!(
                    "warning: {source} is plain http; {}",
                    HeaderCheck::new(key.is_some(), false).note()
                );
            }
            (
                source,
                HeaderTrust {
                    key,
                    ..HeaderTrust::default()
                },
            )
        } else {
            let content_id = if Uuid::try_parse(&source).is_err() {
                let content_id_task = get_content_id(client, source, market.clone()).await;
                let Ok(content_id) = content_id_task else {
                    let Err(err) = content_id_task else {
                        eprintln!("Unknown Error");
                        return ExitCode::FAILURE;
                    };
                    eprintln!("{}", err);
                    return ExitCode::FAILURE;
                };
                content_id
            } else {
                source
            };
            let package_result = get_packages(client, tokens, content_id.clone()).await;
            let Ok(package) = package_result else {
                let Err(err) = package_result else {
                    eprintln!("Unknown Error");
                    return ExitCode::FAILURE;
                };
                eprintln!("{}", err);
                return ExitCode::FAILURE;
            };
            let Some(file) = package
                .package_files
                .iter()
                .find(|p| p.file_name.ends_with(".msixvc"))
            else {
                // Name what was there instead. Every Store product resolves to
                // a package list; only some of those lists hold an XVD
                // container. The rest are Appx/Msix packages -- ordinary OPC
                // zips, or their encrypted E-prefixed variants -- which this
                // streaming path cannot open, and "No .msixvc file found" reads
                // as "the product is broken" rather than "it ships in another
                // format".
                eprintln!("No .msixvc file found. This product ships as:");
                for f in &package.package_files {
                    eprintln!("  {}", f.file_name);
                }
                if package.package_files.is_empty() {
                    eprintln!("  (nothing at all -- the package list came back empty)");
                }
                return ExitCode::FAILURE;
            };
            let anchor = match header_anchor(&package) {
                Ok(anchor) => anchor,
                Err(err) => {
                    eprintln!("{err}");
                    return ExitCode::FAILURE;
                }
            };
            let key = match signing_key(crate::xvd_key::Fetch::Allowed).await {
                Ok(key) => key,
                Err(code) => return code,
            };
            if anchor.is_none() && key.is_none() {
                eprintln!("{}", unanchored_note(file));
            }
            let checked = HeaderCheck::new(key.is_some(), anchor.is_some());
            // What a signed header must say it is.
            let identity = PackageIdentity {
                content_id: package.content_id.clone(),
                version_id: package.version_id.clone(),
                version: package.version.clone(),
            };
            match package_url(&file.cdn_root_paths, &file.relative_url, checked) {
                Ok(url) => (
                    url,
                    HeaderTrust {
                        anchor,
                        key,
                        identity: Some(identity),
                    },
                ),
                Err(err) => {
                    eprintln!("{err}");
                    return ExitCode::FAILURE;
                }
            }
        };
        let url = &vurl;
        // Its own sender, owned by the reader, so that the channel closes when
        // the download is over and the progress task can finish.
        let progress_tx = tx.clone();
        let mut pos = 0;
        let http_file = match streaming::HttpRead::open(
            client.clone(),
            url,
            Some(move |c: u64, _| {
                if progress_tx
                    .try_send(ProgressEvent::Advanced {
                        delta: c.saturating_sub(pos),
                    })
                    .is_ok()
                {
                    pos = c;
                }
            }),
        )
        .await
        {
            Ok(http_file) => http_file,
            Err(err) => {
                crate::download_session::diagnostic("metadata-network", 0);
                eprintln!("could not start the download from {url}: {err}");
                return ExitCode::FAILURE;
            }
        };
        let l = http_file.len();

        run_cli_reader(
            client,
            tokens,
            destination,
            try_skip_ntfs,
            parallel,
            market,
            http_file,
            l,
            url,
            trust,
            tx,
            rx,
        )
        .await
    };

    // Every way this can fail ends here, and none of them is a success. A
    // licence refused, a full disk or a file that would not extract all used
    // to return early from a function with nothing to return, and the process
    // exited 0 -- so an update that never happened was reported as finished.
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

/// Download progress another program can read.
///
/// `indicatif` draws to a terminal and hides itself when stderr is not one --
/// which is exactly how a launcher runs this. The front end is then left with a
/// child process, no output, and a multi-gigabyte wait to explain to somebody,
/// so it can only show a spinner and hope.
///
/// One JSON object per line on stdout, and only when `XODUS_PROGRESS=json` asks
/// for it, so a terminal run is byte-for-byte what it was. Deliberately just
/// the two numbers: rate and time remaining are the reader's to work out, and a
/// reader that draws a bar already needs its own smoothing to avoid a figure
/// that jitters between four seconds and nine minutes.
struct JsonProgress {
    enabled: bool,
    last: Instant,
}

/// Often enough to look live, rarely enough that a 45 GB download does not
/// spend its time writing JSON: the events behind this arrive per chunk.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(250);

impl JsonProgress {
    fn from_env() -> Self {
        JsonProgress {
            enabled: std::env::var("XODUS_PROGRESS").is_ok_and(|v| v == "json"),
            // So the first event is emitted rather than swallowed by the
            // throttle: a download that shows nothing for its first quarter
            // second is fine, one that shows nothing until the first 250 ms
            // *after* an event is not the same thing when events are sparse.
            last: Instant::now() - PROGRESS_INTERVAL,
        }
    }

    fn emit(&mut self, bar: &ProgressBar, force: bool) {
        if !self.enabled || (!force && self.last.elapsed() < PROGRESS_INTERVAL) {
            return;
        }
        self.last = Instant::now();
        // The length is not fixed -- `UpdateRemaining` extends it as the plan
        // is walked -- so it is sent every time rather than once at the start.
        let total = bar.length().unwrap_or(0);
        let mut out = std::io::stdout().lock();
        let _ = writeln!(
            out,
            r#"{{"progress":{{"done":{},"total":{}}}}}"#,
            bar.position(),
            total
        );
        let _ = out.flush();
    }
}

async fn run_cli_reader<Reader>(
    client: &reqwest::Client,
    tokens: &TokenManager,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
    reader: Reader,
    l: u64,
    url: &str,
    trust: HeaderTrust,
    tx: Sender<ProgressEvent>,
    mut rx: Receiver<ProgressEvent>,
) -> Result<(), String>
where
    Reader: AsyncRead + AsyncSeek + Unpin,
{
    let progress = tokio::spawn(async move {
        let multi_progress = MultiProgress::new();
        let total_progess = multi_progress.add(ProgressBar::new(l).with_style(
            ProgressStyle::with_template("{msg:30!} {bytes:>12}/{total_bytes:>12} {bytes_per_sec:>12} [{bar:40.cyan/blue}] {percent:>3}%").unwrap()
            .progress_chars("#>-")
        ));

        total_progess.set_message("Initializing");
        let mut json = JsonProgress::from_env();

        while let Some(event) = rx.recv().await {
            match event {
                ProgressEvent::Advanced { delta } => total_progess.inc(delta),
                ProgressEvent::UpdateRemaining { name, total } => {
                    total_progess.set_message(name);
                    total_progess.set_length(total_progess.position() + total);
                }
                ProgressEvent::UpdateStatus { name } => {
                    total_progess.set_message(name);
                }
            }
            json.emit(&total_progess, false);
        }

        // Forced, so the last line is the finished one. Without it a download
        // ends at whatever the throttle last let through -- 99% forever, which
        // reads as a hang at the worst possible moment.
        json.emit(&total_progess, true);
        total_progess.abandon();
    });
    let result = run_reader(
        client,
        tokens,
        destination,
        try_skip_ntfs,
        parallel,
        market,
        reader,
        l,
        url,
        &trust,
        &tx,
    )
    .await;
    // The task above ends when the last sender goes, and the forced final line
    // is the last thing it does. Without waiting for it here, `main` returned
    // and the runtime dropped the task first as often as not.
    drop(tx);
    let _ = progress.await;
    result
}

/// Describe a streaming failure, instead of panicking.
///
/// These parses read the package header through a cache that the HTTP response
/// fills. When the response ends early the cache is shorter than it recorded --
/// `cache ended before cached_len` -- and every read past that point fails. That
/// is an interrupted download, and it reached the user as a Rust panic and a
/// backtrace, which says nothing about what happened or what to do next.
fn stopped<E: std::fmt::Display>(what: &str) -> impl FnOnce(E) -> String + '_ {
    move |err| {
        format!(
            "failed to {what}: {err}\n\
             the download did not finish -- this is usually the connection dropping \
             partway through, so trying again is the first thing to do"
        )
    }
}

/// The progress label for a file: its last characters, if it is long.
///
/// Counted in characters, not bytes. Slicing at a byte offset panicked on a
/// name with anything but ASCII near its end -- deterministically, so a title
/// with such a file could never be installed.
#[cfg(test)]
fn shown_name(path: &str) -> String {
    const WIDTH: usize = 30;
    if path.chars().count() <= WIDTH {
        return path.to_owned();
    }
    let tail: Vec<char> = path.chars().rev().take(WIDTH - 3).collect();
    format!("...{}", tail.into_iter().rev().collect::<String>())
}

/// How long a file is on disk once it is fully written: what it holds, or
/// whole pages for one kept encrypted, which is written a page at a time.
fn written_len(file: &SegmentFile) -> u64 {
    if file.keep_encrypted {
        file.length.div_ceil(PAGE_SIZE as u64) * PAGE_SIZE as u64
    } else {
        file.length
    }
}

/// Whether a file has to be fetched, given what the last install recorded.
///
/// The record is the container the last install committed, and it says what
/// the package held, not what reached the disk. A file the record says is
/// current is therefore also checked for being there at its full length, so
/// one that was truncated or lost -- by a crash, a full disk, a hand -- is
/// fetched again instead of being skipped for ever.
fn needs_download(
    out: &Path,
    name: &str,
    remote: &SegmentFile,
    local: Option<&SegmentFile>,
) -> bool {
    let Some(local) = local else {
        return true;
    };
    if remote.data_hashs.is_empty() || remote.data_hashs != local.data_hashs {
        return true;
    }
    let Ok(relative) = package_relative_path(name) else {
        return true;
    };
    std::fs::metadata(out.join(relative)).map_or(true, |m| m.len() != written_len(remote))
}

/// Parse a package being downloaded, checked before anything in it is believed.
///
/// With a key, the header's signature must verify with it before any of the
/// header is read, a signed header may not turn data integrity off, and with
/// an identity it must name the package the package service named. With an
/// anchor, the header's top hash must be the one the package service gave.
/// A header that fails any of these is refused before the tree it names is
/// read: see `XvdFile::parse_checked`. With none of them, the package is
/// checked against itself only, as `XvdFile::parse_verified` does.
async fn read_header<Reader>(
    remote_file: &mut Reader,
    trust: &HeaderTrust,
) -> Result<XvdFile, String>
where
    Reader: AsyncRead + AsyncSeek + Unpin,
{
    let parsed = XvdFile::parse_checked(remote_file, trust.checks()).await;
    parsed.map_err(|err| {
        crate::download_session::diagnostic("metadata-invalid", 0);
        if let Some(mismatch) = err.downcast_ref::<TopHashMismatch>() {
            format!(
                "refusing this download: {mismatch}, which the package service gave as its \
                 HashOfHashes. The package was changed on its way here, or the CDN served \
                 another package; nothing from it was installed"
            )
        } else if let Some(refused) = err.downcast_ref::<HeaderRefused>() {
            format!(
                "refusing this download: {refused}. The header is checked against the key that \
                 signs retail game packages, so this package was changed on its way here, or \
                 is not the one the package service named; nothing from it was installed"
            )
        } else {
            stopped("read the package header")(err)
        }
    })
}

/// Read the container the last install committed, for what it says is there.
async fn read_installed(final_path: &Path) -> Result<HashMap<String, SegmentFile>, String> {
    let mut file = File::open(final_path).await.map_err(|e| e.to_string())?;
    let xvd = XvdFile::parse(&mut file).await.map_err(|e| e.to_string())?;
    let mut lfiles = HashMap::new();
    let files = xvd
        .parse_user_package_files(&mut file)
        .await
        .map_err(|e| e.to_string())?;
    for (k, v) in &files {
        if k == "SegmentMetadata.bin" {
            lfiles = xvd
                .parse_segment_metadata(&mut file, v)
                .await
                .map_err(|e| e.to_string())?;
        }
    }

    if let Ok(sfiles) = xvd
        .parse_ntfs_segment_metadata(&mut file, !lfiles.is_empty())
        .await
    {
        lfiles.extend(sfiles);
    }
    Ok(lfiles)
}

/// Make the new container the record of what is installed, durably.
///
/// The files go to disk first and the record after them, and the record
/// replaces the old one in a single rename. Before, the old record was deleted,
/// the new one renamed into its place and nothing synced at all: a power cut
/// soon after could leave an empty or partial record, which every later update
/// then failed to parse, or game files that never reached the disk under a
/// record saying they had.
fn commit(out: &Path, cache_path: &Path, final_path: &Path) -> Result<(), String> {
    let dir =
        std::fs::File::open(out).map_err(|e| format!("could not open {}: {e}", out.display()))?;
    #[cfg(target_os = "linux")]
    rustix::fs::syncfs(&dir)
        .map_err(|e| format!("could not flush {} to disk: {e}", out.display()))?;
    #[cfg(not(target_os = "linux"))]
    std::fs::File::open(cache_path)
        .and_then(|f| f.sync_all())
        .map_err(|e| format!("could not flush {} to disk: {e}", cache_path.display()))?;
    std::fs::rename(cache_path, final_path).map_err(|e| {
        format!(
            "could not record the install ({} -> {}): {e}",
            cache_path.display(),
            final_path.display()
        )
    })?;
    dir.sync_all()
        .map_err(|e| format!("could not flush {} to disk: {e}", out.display()))
}

async fn read_metadata<Reader: AsyncRead + AsyncSeek + Unpin>(
    remote_file: &mut Reader,
    trust: &HeaderTrust,
    try_skip_ntfs: bool,
    tx: &Sender<ProgressEvent>,
) -> Result<(XvdFile, HashMap<String, SegmentFile>), String> {
    let remote_xvd = read_header(&mut *remote_file, trust).await?;
    let mut rfiles: HashMap<String, SegmentFile> = HashMap::new();

    let files = remote_xvd
        .parse_user_package_files(&mut *remote_file)
        .await
        .map_err(stopped("read the package file table"))?;
    for (k, v) in &files {
        if k == "SegmentMetadata.bin" {
            rfiles = remote_xvd
                .parse_segment_metadata(&mut *remote_file, v)
                .await
                .map_err(stopped("read the package segment metadata"))?;
        }
    }

    if !try_skip_ntfs || rfiles.is_empty() {
        tx.send(ProgressEvent::UpdateStatus {
            name: "Downloading ntfs...".to_owned(),
        })
        .await
        .ok();
        let sfiles = remote_xvd
            .parse_ntfs_segment_metadata(&mut *remote_file, !rfiles.is_empty())
            .await
            .map_err(stopped("read the package filesystem"))?;
        rfiles.extend(sfiles);
    }
    Ok((remote_xvd, rfiles))
}

async fn run_reader<Reader>(
    client: &reqwest::Client,
    tokens: &TokenManager,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
    reader: Reader,
    l: u64,
    url: &str,
    trust: &HeaderTrust,
    tx: &Sender<ProgressEvent>,
) -> Result<(), String>
where
    Reader: AsyncRead + AsyncSeek + Unpin,
{
    let out: &Path = Path::new(&destination);

    std::fs::create_dir_all(out).map_err(|e| format!("could not create {}: {e}", out.display()))?;

    let _installation = crate::download_state::writer(out).map_err(|e| {
        crate::download_session::diagnostic("installation-busy", 0);
        e.to_string()
    })?;
    let recovering = crate::download_state::incomplete(out).map_err(|e| e.to_string())?;
    let cache_path = out.join(".xodus-streaming-tmp.msixvc");
    if std::fs::symlink_metadata(&cache_path)
        .is_ok_and(|m| !m.is_file() || m.file_type().is_symlink())
    {
        return Err("Refusing an unsafe package metadata cache".into());
    }
    let final_path = out.join(".xodus-streaming.msixvc");

    let mut remote_file = streaming::PrefixCacheFile::resumable(reader, l, cache_path.clone())
        .await
        .map_err(stopped("open the download cache"))?;
    let reused = remote_file.cached_len();
    if reused > 0 {
        eprintln!("Validating {reused} bytes of saved package metadata");
    }
    let parsed = read_metadata(&mut remote_file, trust, try_skip_ntfs, tx).await;
    let (remote_xvd, rfiles) = match parsed {
        Err(_) if reused > 0 => {
            eprintln!("Saved metadata failed validation; fetching a fresh copy");
            remote_file
                .restart()
                .await
                .map_err(stopped("reset the metadata cache"))?;
            read_metadata(&mut remote_file, trust, try_skip_ntfs, tx).await?
        }
        result => result?,
    };
    // The cache has everything it is going to get; the rest comes from the
    // files' own ranges.
    drop(remote_file);

    // Every name the package gives is checked before anything is fetched, so a
    // package that names a file outside the destination is refused whole, not
    // after it has written the files that came before.
    for name in rfiles.keys() {
        package_relative_path(name)
            .map_err(|e| format!("refusing to install this package: {e}"))?;
    }

    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();
    if final_path.exists() {
        // Only a record of what is there; if it cannot be read, everything is
        // fetched again, which is slow but right. It used to be a panic on
        // every later run.
        match read_installed(&final_path).await {
            Ok(files) => lfiles = files,
            Err(err) => eprintln!(
                "the record of the last install ({}) could not be read ({err}); \
                 every file will be downloaded again",
                final_path.display()
            ),
        }
    }

    let license = get_license(
        client,
        tokens,
        remote_xvd.content_id().to_string(),
        market.unwrap_or("neutral".to_string()),
    )
    .await;
    let (key, game_splicense) = license.map_err(|err| {
        crate::download_session::diagnostic("license", 0);
        err.to_string()
    })?;
    if game_splicense.content_keys.len() != 1 {
        return Err(format!(
            "unexpected number of content keys {}",
            game_splicense.content_keys.len()
        ));
    }
    let Some((_, content_key)) = game_splicense.content_keys.into_iter().next() else {
        return Err("the licence holds no content key".into());
    };

    let full_key = content_key
        .unpack(&key)
        .map_err(|e| format!("could not unpack the content key: {e}"))?;

    let jobs: Vec<Job> = rfiles
        .into_iter()
        .filter(|(name, content)| {
            recovering || needs_download(out, name, content, lfiles.get(name))
        })
        .map(|(name, content)| Job { name, content })
        .collect();
    let total_size: u64 = jobs.iter().map(|job| job.content.length).sum();

    tx.send(ProgressEvent::UpdateRemaining {
        name: "Downloading".to_owned(),
        total: total_size,
    })
    .await
    .ok();

    // Stops at the first file that fails, and that failure is the result. The
    // cache is not committed unless every file arrived, so the next run still
    // sees the old record and fetches whatever this one did not finish.
    let session = fetch_files_with_old(
        client,
        &remote_xvd,
        jobs,
        &lfiles,
        out,
        url,
        *full_key,
        parallel,
        tx,
    )
    .await?;
    let committed = commit(out, &cache_path, &final_path)
        .and_then(|()| crate::download_state::finish(out).map_err(|e| e.to_string()));
    session.finish(committed.is_ok());
    committed
}

/// Fetch every file in `jobs` into `out`, `parallel` at a time, from `url`
/// (a package over http(s), or a container on disk as `file://`).
///
/// The first file that fails stops the rest and is the result. Each file is
/// written under a temporary name and renamed into place only once all of it
/// is written, so neither the file that failed nor one stopped because of it
/// is left half written, and a file being replaced keeps its old contents.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn fetch_files(
    client: &reqwest::Client,
    xvd: &XvdFile,
    jobs: Vec<Job>,
    out: &Path,
    url: &str,
    full_key: [u8; 32],
    parallel: Option<usize>,
    tx: &Sender<ProgressEvent>,
) -> Result<(), String> {
    fetch_files_with_old(
        client,
        xvd,
        jobs,
        &HashMap::new(),
        out,
        url,
        full_key,
        parallel,
        tx,
    )
    .await
    .map(|_| ())
}

#[allow(clippy::too_many_arguments)]
async fn fetch_files_with_old(
    client: &reqwest::Client,
    xvd: &XvdFile,
    jobs: Vec<Job>,
    old: &HashMap<String, SegmentFile>,
    out: &Path,
    url: &str,
    key: [u8; 32],
    parallel: Option<usize>,
    tx: &Sender<ProgressEvent>,
) -> Result<crate::download_session::Session, String> {
    crate::download_plan::execute(
        client,
        xvd,
        jobs,
        old,
        out,
        url,
        key,
        parallel.unwrap_or(4),
        |delta| {
            let _ = tx.try_send(ProgressEvent::Advanced { delta });
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(length: u64, hashes: &[u8], keep_encrypted: bool) -> SegmentFile {
        SegmentFile {
            offset: 0,
            length,
            data_hashs: hashes.iter().map(|&b| [b; 20]).collect(),
            keep_encrypted,
        }
    }

    #[test]
    fn long_names_are_shortened_on_a_character_boundary() {
        assert_eq!(shown_name("Content/short.pak"), "Content/short.pak");
        // Each of these characters is three bytes, so byte `len - 27` falls
        // inside one: the old slice panicked here.
        let name = "Content/ローカライズ/テキストテキストテキストテキスト.pak";
        let shown = shown_name(name);
        assert!(shown.starts_with("..."));
        assert_eq!(shown.chars().count(), 30);
        assert!(name.ends_with(&shown[3..]));
    }

    #[test]
    fn a_file_the_record_lists_is_still_fetched_if_it_is_not_all_there() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path();
        std::fs::create_dir_all(out.join("Content")).unwrap();
        let name = r"Content\data.pak";
        let remote = file(5000, &[1, 2], false);
        let same = file(5000, &[1, 2], false);

        // Not on disk at all.
        assert!(needs_download(out, name, &remote, Some(&same)));
        // Cut short, as a crash before the data reached the disk leaves it.
        std::fs::write(out.join("Content/data.pak"), vec![0u8; 100]).unwrap();
        assert!(needs_download(out, name, &remote, Some(&same)));
        // Whole, and unchanged in the package: skipped.
        std::fs::write(out.join("Content/data.pak"), vec![0u8; 5000]).unwrap();
        assert!(!needs_download(out, name, &remote, Some(&same)));
        // Changed in the package, or not in the record: fetched.
        assert!(needs_download(
            out,
            name,
            &remote,
            Some(&file(5000, &[1, 3], false))
        ));
        assert!(needs_download(out, name, &remote, None));

        // A file kept encrypted is written in whole pages.
        let exe = file(5000, &[4, 5], true);
        std::fs::write(out.join("Game.exe"), vec![0u8; 5000]).unwrap();
        assert!(needs_download(
            out,
            "Game.exe",
            &exe,
            Some(&file(5000, &[4, 5], true))
        ));
        std::fs::write(out.join("Game.exe"), vec![0u8; 8192]).unwrap();
        assert!(!needs_download(
            out,
            "Game.exe",
            &exe,
            Some(&file(5000, &[4, 5], true))
        ));
    }

    #[test]
    fn the_commit_replaces_the_record_in_one_step() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path();
        let cache = out.join(".xodus-streaming-tmp.msixvc");
        let record = out.join(".xodus-streaming.msixvc");
        std::fs::write(&record, b"old").unwrap();
        std::fs::write(&cache, b"new").unwrap();
        commit(out, &cache, &record).unwrap();
        assert_eq!(std::fs::read(&record).unwrap(), b"new");
        assert!(!cache.exists());
    }

    /// The header is held to the package service's top hash when there is
    /// one: a match is read, a mismatch refused before the tree is read, and
    /// with no hash the package is checked against itself as before.
    #[tokio::test]
    async fn the_header_is_held_to_the_package_services_hash() {
        let p = msixvc::xvd::testing::package();
        let top: [u8; 32] = p.bytes[0x240..0x260].try_into().unwrap();
        let read = |bytes: Vec<u8>, anchor: Option<[u8; 32]>| async move {
            let trust = HeaderTrust {
                anchor,
                ..HeaderTrust::default()
            };
            read_header(&mut std::io::Cursor::new(bytes), &trust).await
        };

        // Match.
        assert!(read(p.bytes.clone(), Some(top)).await.is_ok());
        // Absent: the package is still checked against itself.
        assert!(read(p.bytes.clone(), None).await.is_ok());
        let mut damaged = p.bytes.clone();
        damaged[p.tree_start * PAGE_SIZE + 3] ^= 1;
        let err = read(damaged, None).await.err().unwrap();
        assert!(err.contains("hash tree is damaged"), "{err}");

        // Mismatch: a package rewritten whole, consistent with itself, under
        // the hash of the package the service named.
        let rewritten = msixvc::xvd::testing::package_with(|drive| drive[2][9] ^= 1);
        assert!(read(rewritten.bytes.clone(), None).await.is_ok());
        let err = read(rewritten.bytes, Some(top)).await.err().unwrap();
        assert!(err.starts_with("refusing this download"), "{err}");
        assert!(err.contains("HashOfHashes"), "{err}");
        assert!(!err.contains("trying again"), "{err}");
        // The header alone is enough to refuse.
        let err = read(p.bytes[..PAGE_SIZE].to_vec(), Some([0; 32]))
            .await
            .err()
            .unwrap();
        assert!(err.starts_with("refusing this download"), "{err}");
    }

    /// With the signing key, the header must carry a signature that verifies
    /// with it and name the package the package service named; anything else
    /// is refused before the tree is read, and said to be a refusal rather
    /// than a dropped connection.
    #[tokio::test]
    async fn the_header_is_held_to_its_signature_and_the_package_named() {
        use msixvc::signature::testing::{sign, test_verifying_key};

        let content_id = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
        let pduid = "11223344-5566-7788-99aa-bbccddeeff00";
        let mut p = msixvc::xvd::testing::package();
        let content = uuid::Uuid::parse_str(content_id).unwrap().to_bytes_le();
        p.bytes[0x220..0x230].copy_from_slice(&content);
        p.bytes[0x230..0x240].copy_from_slice(&content);
        p.bytes[0x3AC..0x3BC].copy_from_slice(&uuid::Uuid::parse_str(pduid).unwrap().to_bytes_le());
        p.bytes[0x3BC..0x3C4].copy_from_slice(&[0, 0, 109, 0, 0xB0, 2, 3, 0]);
        sign(&mut p.bytes);
        let top: [u8; 32] = p.bytes[0x240..0x260].try_into().unwrap();
        let trust = |version: &str| HeaderTrust {
            anchor: Some(top),
            key: Some(test_verifying_key()),
            identity: Some(PackageIdentity {
                content_id: content_id.into(),
                version_id: format!("aaaaaaaa-0000-4000-8000-000000000000.{pduid}"),
                version: version.into(),
            }),
        };
        let read = |bytes: Vec<u8>, trust: HeaderTrust| async move {
            read_header(&mut std::io::Cursor::new(bytes), &trust).await
        };

        assert!(read(p.bytes.clone(), trust("3.688.109.0")).await.is_ok());

        // Signed by the right key, for another version of the package.
        let err = read(p.bytes.clone(), trust("3.688.110.0"))
            .await
            .err()
            .unwrap();
        assert!(err.starts_with("refusing this download"), "{err}");
        assert!(err.contains("package_version"), "{err}");

        // One byte of the signed header changed: the signature fails before
        // the top hash or the tree are looked at.
        let mut changed = p.bytes[..PAGE_SIZE].to_vec();
        changed[0x288] ^= 1;
        let err = read(changed, trust("3.688.109.0")).await.err().unwrap();
        assert!(err.starts_with("refusing this download"), "{err}");
        assert!(err.contains("signature does not verify"), "{err}");
        assert!(!err.contains("trying again"), "{err}");

        // Not signed at all.
        let mut unsigned = p.bytes.clone();
        unsigned[..0x200].fill(0);
        let err = read(unsigned, trust("3.688.109.0")).await.err().unwrap();
        assert!(err.contains("not signed"), "{err}");

        // Signed, but with data integrity off.
        let mut no_integrity = p.bytes.clone();
        no_integrity[0x208] |= 1 << 2;
        sign(&mut no_integrity);
        let err = read(no_integrity, trust("3.688.109.0"))
            .await
            .err()
            .unwrap();
        assert!(err.contains("DATA_INTEGRITY_DISABLED"), "{err}");

        // Without a key, as before: the same unsigned header is read.
        let mut unsigned = p.bytes.clone();
        unsigned[..0x200].fill(0);
        let without_key = HeaderTrust {
            anchor: Some(top),
            ..HeaderTrust::default()
        };
        assert!(read(unsigned, without_key).await.is_ok());
    }

    /// A package on disk, the parsed package, and a job for pages 5..8 of its
    /// drive plus a little of page 8.
    async fn fixture(dir: &Path) -> (std::path::PathBuf, XvdFile, Job, Vec<u8>) {
        let p = msixvc::xvd::testing::package();
        let path = dir.join("package.msixvc");
        std::fs::write(&path, &p.bytes).unwrap();
        let xvd = XvdFile::parse_verified(std::io::Cursor::new(p.bytes.clone()))
            .await
            .unwrap();
        let first = (p.drive_page + 5) * PAGE_SIZE;
        let length = 3 * PAGE_SIZE + 100;
        let job = Job {
            name: r"Content\data.pak".into(),
            content: SegmentFile {
                offset: first as u64,
                length: length as u64,
                data_hashs: vec![],
                keep_encrypted: false,
            },
        };
        (path, xvd, job, p.bytes[first..first + length].to_vec())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn files_are_extracted_from_a_container() {
        let dir = tempfile::tempdir().unwrap();
        let (path, xvd, job, expected) = fixture(dir.path()).await;
        let out = dir.path().join("game");
        let (tx, _rx) = tokio::sync::mpsc::channel(256);
        let url = format!("file://{}", path.display());

        fetch_files(
            &reqwest::Client::new(),
            &xvd,
            vec![job],
            &out,
            &url,
            [0; 32],
            None,
            &tx,
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read(out.join("Content/data.pak")).unwrap(),
            expected
        );
    }

    /// Extracting from a container that stops short: the file that runs off
    /// the end is an error, the error is the result, and the half-written
    /// file is gone. Before, the worker printed a message and returned, the
    /// container was committed as if the extract were complete, and the
    /// process exited 0 -- so a later run skipped the truncated file for good.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_file_that_cannot_be_extracted_fails_the_run() {
        let dir = tempfile::tempdir().unwrap();
        let (path, xvd, job, _) = fixture(dir.path()).await;
        let cut = job.content.offset + PAGE_SIZE as u64 + 7;
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(cut)
            .unwrap();
        let out = dir.path().join("game");
        let (tx, _rx) = tokio::sync::mpsc::channel(256);
        let url = format!("file://{}", path.display());

        let err = fetch_files(
            &reqwest::Client::new(),
            &xvd,
            vec![job],
            &out,
            &url,
            [0; 32],
            None,
            &tx,
        )
        .await
        .unwrap_err();
        assert!(err.contains("does not contain this file"), "{err}");
        assert!(!out.join("Content/data.pak").exists());
    }

    /// A damaged page in the source is refused, not installed.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_damaged_page_fails_the_run() {
        let dir = tempfile::tempdir().unwrap();
        let (path, xvd, job, _) = fixture(dir.path()).await;
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[job.content.offset as usize + 2 * PAGE_SIZE + 1] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        let out = dir.path().join("game");
        let (tx, _rx) = tokio::sync::mpsc::channel(256);
        let url = format!("file://{}", path.display());

        let err = fetch_files(
            &reqwest::Client::new(),
            &xvd,
            vec![job],
            &out,
            &url,
            [0; 32],
            None,
            &tx,
        )
        .await
        .unwrap_err();
        assert!(err.contains("does not match its hash tree"), "{err}");
        assert!(!out.join("Content/data.pak").exists());
    }

    /// The first file that fails stops the others mid-write. None of them is
    /// left half written: a file being replaced keeps its old contents, and no
    /// temporary file is left behind.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_failure_leaves_the_other_files_as_they_were() {
        let dir = tempfile::tempdir().unwrap();
        let (path, xvd, job, _) = fixture(dir.path()).await;
        let out = dir.path().join("game");
        std::fs::create_dir_all(out.join("Content")).unwrap();
        std::fs::write(out.join("Content/data.pak"), b"the old, good copy").unwrap();
        let failing = Job {
            name: r"..\escaped.txt".into(),
            content: SegmentFile {
                offset: job.content.offset,
                length: job.content.length,
                data_hashs: vec![],
                keep_encrypted: false,
            },
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(256);
        let url = format!("file://{}", path.display());

        let err = fetch_files(
            &reqwest::Client::new(),
            &xvd,
            vec![job, failing],
            &out,
            &url,
            [0; 32],
            Some(2),
            &tx,
        )
        .await
        .unwrap_err();
        assert!(err.contains("refusing to install"), "{err}");
        // Anything a dropped job had left running on a blocking thread.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            std::fs::read(out.join("Content/data.pak")).unwrap(),
            b"the old, good copy"
        );
        let left: Vec<_> = std::fs::read_dir(out.join("Content"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, ["data.pak"]);
    }

    /// A name that climbs out of the destination is refused before anything is
    /// written anywhere.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_file_named_outside_the_destination_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (path, xvd, mut job, _) = fixture(dir.path()).await;
        job.name = r"..\escaped.txt".into();
        let out = dir.path().join("game");
        let (tx, _rx) = tokio::sync::mpsc::channel(256);
        let url = format!("file://{}", path.display());

        let err = fetch_files(
            &reqwest::Client::new(),
            &xvd,
            vec![job],
            &out,
            &url,
            [0; 32],
            None,
            &tx,
        )
        .await
        .unwrap_err();
        assert!(err.contains("refusing to install"), "{err}");
        assert!(!dir.path().join("escaped.txt").exists());
    }

    /// An unreadable record is not a reason to stop: it is read as "nothing
    /// installed" and everything is fetched. It used to panic on every run.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_damaged_record_reads_as_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let record = dir.path().join(".xodus-streaming.msixvc");
        std::fs::write(&record, b"").unwrap();
        assert!(read_installed(&record).await.is_err());
        std::fs::write(&record, vec![0x5au8; 3 * 4096]).unwrap();
        assert!(read_installed(&record).await.is_err());
    }
}
