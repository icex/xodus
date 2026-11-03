//! The key that signs retail PC game package headers, found on this machine.
//!
//! This client does not carry that key. It is a public key, but Microsoft's,
//! so it is fetched at run time from Microsoft's own Gaming Services package,
//! downloaded anonymously from the Store's delivery service (see `fe3`), and
//! kept only if the SHA-256 of its blob is the pinned
//! `msixvc::signature::GAME_PACKAGE_KEY_SHA256`. The blob is stored 0600 in a
//! 0700 directory and hashed again every time it is loaded; the downloaded
//! package is deleted as soon as it has been read.
//!
//! Where: `XODUS_XVD_KEY_DIR`, else `$XDG_DATA_HOME/xodus/xvd-key`, else
//! `~/.local/share/xodus/xvd-key`. The download goes to an unnamed temporary
//! file (`O_TMPFILE`, or unlinked as soon as it is made) in
//! `XODUS_XVD_KEY_DIR/.fetch`, else `$XDG_CACHE_HOME/xodus/xvd-key-fetch`, else
//! `~/.cache/xodus/xvd-key-fetch`, so the kernel frees it however the process
//! ends, a signal included.

pub mod fe3;
pub mod scan;
pub mod xml;
pub mod zip;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use msixvc::signature::{GAME_PACKAGE_KEY_SHA256, XvdSigningKey, hex};
use sha2::{Digest, Sha256};

/// Overrides where the key, and the download it comes from, are kept.
pub const KEY_DIR_ENV: &str = "XODUS_XVD_KEY_DIR";
/// `1`: refuse to install a package whose header signature cannot be checked
/// because no key is available.
pub const REQUIRE_SIGNED_ENV: &str = "XODUS_REQUIRE_SIGNED_PACKAGE";
/// `0`: never fetch the key on the way to an install; only `xvd-key fetch`
/// does.
pub const AUTO_FETCH_ENV: &str = "XODUS_XVD_KEY_AUTOFETCH";

const KEY_FILE: &str = "game-package-key.blob";
/// Its modification time is when an automatic fetch last failed.
const FAILED_FILE: &str = "last-fetch-failed";
/// An automatic fetch that failed is not tried again for this long; an
/// explicit `xvd-key fetch` always is.
const RETRY_AFTER: Duration = Duration::from_secs(24 * 3600);
/// How long an install waits for the key before going on without it.
pub const AUTO_FETCH_TIMEOUT: Duration = Duration::from_secs(180);
/// How long `xvd-key fetch` waits.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(900);
/// The bundle was about 200 MB when this was written.
const MAX_BUNDLE: u64 = 1 << 30;
/// A blob is 539 bytes; a file much larger is not one.
const MAX_KEY_FILE: u64 = 4096;

fn env_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

fn home() -> Result<PathBuf, String> {
    env_dir("HOME").ok_or_else(|| "HOME is not set".to_string())
}

/// Where the key is kept.
pub fn key_dir() -> Result<PathBuf, String> {
    if let Some(dir) = env_dir(KEY_DIR_ENV) {
        return Ok(dir);
    }
    let data = match env_dir("XDG_DATA_HOME") {
        Some(dir) => dir,
        None => home()?.join(".local/share"),
    };
    Ok(data.join("xodus/xvd-key"))
}

/// Where the download goes while it is read.
pub fn fetch_dir() -> Result<PathBuf, String> {
    if let Some(dir) = env_dir(KEY_DIR_ENV) {
        return Ok(dir.join(".fetch"));
    }
    let cache = match env_dir("XDG_CACHE_HOME") {
        Some(dir) => dir,
        None => home()?.join(".cache"),
    };
    Ok(cache.join("xodus/xvd-key-fetch"))
}

/// Make `dir` and its parents, `dir` itself 0700 and this user's.
fn private_dir(dir: &Path) -> Result<(), String> {
    let fail = |e: std::io::Error| format!("{}: {e}", dir.display());
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(fail)?;
        crate::commands::presence::private_dir(dir, true).map_err(fail)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir).map_err(fail)
    }
}

/// Whether the key is here, and usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Present {
        fingerprint: [u8; 32],
    },
    Absent,
    /// There is a file, and it is not the pinned key or not safe to use.
    Invalid(String),
}

/// Read the key from `dir`, checking the file is this user's alone and the
/// blob is the pinned one, every time.
pub fn load_from(dir: &Path, pin: &[u8; 32]) -> Result<Option<XvdSigningKey>, String> {
    let path = dir.join(KEY_FILE);
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    let file = match options.open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let meta = file
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // Safety: geteuid cannot fail and touches no memory.
        if meta.uid() != unsafe { nix::libc::geteuid() } {
            return Err(format!("{} belongs to another user", path.display()));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(format!("{} is open to other users", path.display()));
        }
    }
    let mut blob = Vec::new();
    file.take(MAX_KEY_FILE + 1)
        .read_to_end(&mut blob)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    XvdSigningKey::from_blob(&blob, pin)
        .map(Some)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// What `xvd-key status` reports for `dir`.
pub fn status_of(dir: &Path, pin: &[u8; 32]) -> Status {
    match load_from(dir, pin) {
        Ok(Some(key)) => Status::Present {
            fingerprint: *key.fingerprint(),
        },
        Ok(None) => Status::Absent,
        Err(e) => Status::Invalid(e),
    }
}

/// Write the blob to `dir`, 0600, replacing whatever was there in one rename.
pub fn store_in(dir: &Path, blob: &[u8]) -> Result<PathBuf, String> {
    private_dir(dir)?;
    let path = dir.join(KEY_FILE);
    let mut tmp = tempfile::Builder::new()
        .prefix(".key-")
        .tempfile_in(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    tmp.write_all(blob).map_err(|e| e.to_string())?;
    tmp.as_file().sync_all().map_err(|e| e.to_string())?;
    tmp.persist(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

/// Remove the key and the failure record from `dir`. Whether there was a key.
pub fn forget_in(dir: &Path) -> Result<bool, String> {
    let _ = std::fs::remove_file(dir.join(FAILED_FILE));
    match std::fs::remove_file(dir.join(KEY_FILE)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("{}: {e}", dir.join(KEY_FILE).display())),
    }
}

/// When an automatic fetch last failed, if one has.
pub fn last_failure(dir: &Path) -> Option<SystemTime> {
    std::fs::metadata(dir.join(FAILED_FILE))
        .and_then(|m| m.modified())
        .ok()
}

/// Until when automatic fetching is paused because an automatic fetch failed
/// less than `RETRY_AFTER` ago; `None` when it is not paused.
pub fn auto_fetch_paused_until(dir: &Path) -> Option<SystemTime> {
    let failed = last_failure(dir)?;
    let until = failed.checked_add(RETRY_AFTER)?;
    // A failure stamped in the future (clock moved back) still pauses, but
    // never for longer than `RETRY_AFTER` from now.
    let now = SystemTime::now();
    let until = until.min(now.checked_add(RETRY_AFTER)?);
    (until > now).then_some(until)
}

fn record_failure(dir: &Path) {
    if private_dir(dir).is_ok() {
        let _ = std::fs::write(dir.join(FAILED_FILE), b"");
    }
}

/// Where a fetched key came from, for the report.
#[derive(Debug, Clone)]
pub struct Fetched {
    pub key: XvdSigningKey,
    pub path: PathBuf,
    pub package: String,
    pub member: String,
    pub bundle: String,
    pub bytes: u64,
    pub seconds: f64,
}

/// Download `location` into a temporary file in `scratch`, checking its size
/// and SHA-256 as it comes.
async fn download(
    location: &fe3::BundleLocation,
    scratch: &Path,
    timeout: Duration,
) -> Result<std::fs::File, String> {
    if location.size == 0 || location.size > MAX_BUNDLE {
        return Err(format!(
            "the package is said to be {} bytes, outside what is expected",
            location.size
        ));
    }
    let client = fe3::download_client(timeout)?;
    let mut response = client
        .get(location.url.clone())
        .send()
        .await
        .map_err(|e| format!("could not download Gaming Services: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "the Gaming Services download answered {}",
            response.status()
        ));
    }
    if !fe3::download_url_allowed(response.url()) {
        return Err("the Gaming Services download ended on another host".into());
    }
    // Unnamed: nothing is left behind if the process is killed.
    let mut file =
        tempfile::tempfile_in(scratch).map_err(|e| format!("{}: {e}", scratch.display()))?;
    let mut hasher = Sha256::new();
    let mut written = 0u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("the Gaming Services download stopped: {e}"))?
    {
        written += chunk.len() as u64;
        if written > location.size {
            return Err(
                "the Gaming Services download is larger than the delivery service said".into(),
            );
        }
        hasher.update(&chunk);
        file.write_all(&chunk).map_err(|e| e.to_string())?;
    }
    if written != location.size {
        return Err(format!(
            "the Gaming Services download stopped at {written} of {} bytes",
            location.size
        ));
    }
    if let Some(expected) = location.sha256
        && <[u8; 32]>::from(hasher.finalize()) != expected
    {
        return Err(
            "the Gaming Services download does not match the SHA-256 the delivery service gave"
                .into(),
        );
    }
    file.flush().map_err(|e| e.to_string())?;
    Ok(file)
}

/// Fetch the key: find Gaming Services, download it, look for the pinned key
/// in it, store the key and delete the download.
pub async fn fetch(timeout: Duration) -> Result<Fetched, String> {
    let dir = key_dir()?;
    let scratch = fetch_dir()?;
    private_dir(&scratch)?;
    let started = Instant::now();
    let location = fe3::locate_bundle(timeout).await?;
    let bundle = download(&location, &scratch, timeout).await?;
    let scratch_for_scan = scratch.clone();
    let name = location.moniker.clone();
    // The bundle is unnamed; it is freed when the scan drops it.
    let (found, stats) = tokio::task::spawn_blocking(move || {
        let mut bundle = bundle;
        let mut stats = scan::ScanStats::default();
        scan::scan_bundle(
            &mut bundle,
            &name,
            &scratch_for_scan,
            &GAME_PACKAGE_KEY_SHA256,
            &mut stats,
        )
        .map(|found| (found, stats))
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format!("could not read the Gaming Services package: {e}"))?;
    let found = found.ok_or_else(|| {
        format!(
            "{} holds no key with the pinned fingerprint ({} candidate keys in {} files); \
             Microsoft may have changed the package",
            location.moniker, stats.candidates, stats.members
        )
    })?;
    let key = XvdSigningKey::from_blob(&found.blob, &GAME_PACKAGE_KEY_SHA256)
        .map_err(|e| e.to_string())?;
    let path = store_in(&dir, &found.blob)?;
    let _ = std::fs::remove_file(dir.join(FAILED_FILE));
    Ok(Fetched {
        key,
        path,
        package: found.package,
        member: found.member,
        bundle: location.moniker,
        bytes: location.size,
        seconds: started.elapsed().as_secs_f64(),
    })
}

fn env_is(name: &str, value: &str) -> bool {
    std::env::var(name).is_ok_and(|v| v == value)
}

pub fn signature_required() -> bool {
    env_is(REQUIRE_SIGNED_ENV, "1")
}

pub fn auto_fetch_enabled() -> bool {
    !env_is(AUTO_FETCH_ENV, "0")
}

/// Whether `for_key` may fetch the key when none is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fetch {
    /// A download from the package service: one bounded automatic attempt.
    Allowed,
    /// A package file on disk: only the stored key is used, so an install
    /// from a local file never reaches the network for it.
    Never,
}

/// The key for checking a package about to be installed.
///
/// The stored key if there is one. Otherwise, with `Fetch::Allowed`, one
/// attempt to fetch it, bounded by `AUTO_FETCH_TIMEOUT`, unless
/// `XODUS_XVD_KEY_AUTOFETCH=0` or an automatic attempt failed in the last day
/// (`auto_fetch_paused_until`). Without a key the install goes on, with a
/// warning on stderr, unless `XODUS_REQUIRE_SIGNED_PACKAGE=1`, in which case
/// this is an error.
pub async fn for_install(fetch_policy: Fetch) -> Result<Option<XvdSigningKey>, String> {
    let dir = key_dir();
    let mut why = String::new();
    if let Ok(dir) = &dir {
        match load_from(dir, &GAME_PACKAGE_KEY_SHA256) {
            Ok(Some(key)) => return Ok(Some(key)),
            Ok(None) => why = "no package signing key is stored".into(),
            Err(e) => {
                eprintln!("warning: ignoring the stored package signing key: {e}");
                why = format!("the stored key is unusable ({e})");
            }
        }
        if fetch_policy == Fetch::Never {
            why.push_str(" (a package file on disk does not fetch it)");
        } else if !auto_fetch_enabled() {
            why.push_str(&format!(" and {AUTO_FETCH_ENV}=0"));
        } else if auto_fetch_paused_until(dir).is_some() {
            why.push_str(" and fetching it failed less than a day ago");
        } else {
            eprintln!(
                "note: fetching the key that signs game packages from Microsoft Gaming Services \
                 (anonymous Store download, about 200 MB, once)"
            );
            match tokio::time::timeout(AUTO_FETCH_TIMEOUT, fetch(AUTO_FETCH_TIMEOUT)).await {
                Ok(Ok(fetched)) => {
                    eprintln!(
                        "note: package signing key {} stored in {}",
                        hex(fetched.key.fingerprint()),
                        fetched.path.display()
                    );
                    return Ok(Some(fetched.key));
                }
                Ok(Err(e)) => {
                    record_failure(dir);
                    why = format!("fetching it failed: {e}");
                }
                Err(_) => {
                    record_failure(dir);
                    why = format!(
                        "fetching it took longer than {} s",
                        AUTO_FETCH_TIMEOUT.as_secs()
                    );
                }
            }
        }
    } else if let Err(e) = &dir {
        why = e.clone();
    }
    if signature_required() {
        return Err(format!(
            "refusing this download: {REQUIRE_SIGNED_ENV}=1, and the package header's signature \
             cannot be checked: {why}. Run `xodus-cli xvd-key fetch` to fetch the key"
        ));
    }
    eprintln!(
        "warning: the package header's signature is not checked: {why}. Run `xodus-cli xvd-key \
         fetch` to fetch the key, or set {REQUIRE_SIGNED_ENV}=1 to refuse such installs"
    );
    Ok(None)
}

#[cfg(test)]
mod tests {
    use msixvc::signature::testing::{blob_sha256, other_key, public_blob, test_key};

    use super::*;

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_stored_key_is_private_and_hashed_again_when_loaded() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("xvd-key");
        let blob = public_blob(&test_key().to_public_key());
        let pin = blob_sha256(&blob);
        assert_eq!(status_of(&dir, &pin), Status::Absent);

        let path = store_in(&dir, &blob).unwrap();
        #[cfg(unix)]
        {
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(&dir), 0o700);
        }
        assert_eq!(status_of(&dir, &pin), Status::Present { fingerprint: pin });
        assert!(load_from(&dir, &pin).unwrap().is_some());
        // The real pin does not accept the test key.
        assert!(matches!(
            status_of(&dir, &GAME_PACKAGE_KEY_SHA256),
            Status::Invalid(e) if e.contains("not the pinned")
        ));

        // Changed on disk: refused on the next load.
        let other = public_blob(&other_key().to_public_key());
        std::fs::write(&path, &other).unwrap();
        assert!(matches!(status_of(&dir, &pin), Status::Invalid(_)));

        assert!(forget_in(&dir).unwrap());
        assert!(!forget_in(&dir).unwrap());
        assert_eq!(status_of(&dir, &pin), Status::Absent);
    }

    #[test]
    fn a_failed_automatic_fetch_pauses_automatic_fetching_for_a_day() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("xvd-key");
        assert_eq!(auto_fetch_paused_until(&dir), None);
        record_failure(&dir);
        let until = auto_fetch_paused_until(&dir).expect("paused after a failure");
        let left = until.duration_since(SystemTime::now()).unwrap();
        assert!(left > RETRY_AFTER - Duration::from_secs(60) && left <= RETRY_AFTER);

        // A failure older than a day no longer pauses.
        let old = SystemTime::now() - RETRY_AFTER - Duration::from_secs(1);
        std::fs::File::options()
            .write(true)
            .open(dir.join(FAILED_FILE))
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert_eq!(auto_fetch_paused_until(&dir), None);

        // Forgetting the key clears the pause.
        record_failure(&dir);
        forget_in(&dir).unwrap();
        assert_eq!(auto_fetch_paused_until(&dir), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_key_file_others_can_read_or_a_link_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("xvd-key");
        let blob = public_blob(&test_key().to_public_key());
        let pin = blob_sha256(&blob);
        let path = store_in(&dir, &blob).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(status_of(&dir, &pin), Status::Invalid(e) if e.contains("open to other")));

        std::fs::remove_file(&path).unwrap();
        let elsewhere = root.path().join("elsewhere.blob");
        std::fs::write(&elsewhere, &blob).unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        assert!(matches!(status_of(&dir, &pin), Status::Invalid(_)));
    }

    /// Checks the key verifies real package headers: the files named by
    /// `XODUS_LIVE_XVD_HEADERS` (separated by `:`; each at least the first
    /// 4096 bytes of a retail package, such as an installed
    /// `.xodus-streaming.msixvc`). Uses the key stored in `XODUS_XVD_KEY_DIR`
    /// if there is one; otherwise fetches Microsoft Gaming Services
    /// anonymously from the Store (about 200 MB, into that directory's
    /// `.fetch`, deleted after). Nothing signs in. Run with `--ignored`.
    #[tokio::test]
    #[ignore = "may download Microsoft Gaming Services from the Store"]
    async fn live_the_key_verifies_retail_headers() {
        let headers = std::env::var("XODUS_LIVE_XVD_HEADERS")
            .expect("set XODUS_LIVE_XVD_HEADERS to retail package headers, separated by ':'");
        let dir = key_dir().unwrap();
        let key = match load_from(&dir, &GAME_PACKAGE_KEY_SHA256).unwrap() {
            Some(key) => key,
            None => {
                let fetched = fetch(FETCH_TIMEOUT).await.unwrap();
                assert_eq!(
                    std::fs::read_dir(fetch_dir().unwrap()).unwrap().count(),
                    0,
                    "the download is deleted"
                );
                fetched.key
            }
        };
        assert_eq!(key.fingerprint(), &GAME_PACKAGE_KEY_SHA256);
        for path in headers.split(':') {
            let mut header = vec![0u8; 4096];
            std::fs::File::open(path)
                .and_then(|mut f| f.read_exact(&mut header))
                .unwrap();
            msixvc::signature::verify_header(&header, &key)
                .unwrap_or_else(|e| panic!("{path}: {e}"));
            // And one changed signed byte does not.
            header[0x240] ^= 1;
            assert!(msixvc::signature::verify_header(&header, &key).is_err());
        }
    }
}
