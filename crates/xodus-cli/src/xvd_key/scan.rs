//! Finding the pinned key among the bytes of a Microsoft Gaming Services
//! package.
//!
//! The key is a `BCRYPT_RSAPUBLIC_BLOB` held as data in some of the package's
//! binaries. Every place an RSA-4096 public blob could start is a candidate,
//! and a candidate is kept only if its SHA-256 is the pin: nothing else about
//! where it was found is trusted, so a package that holds other keys, or was
//! changed on its way here, can at worst hold no key this accepts.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use msixvc::signature::{BLOB_HEADER_LEN, BLOB_MAGIC, rsa4096_public_blob_len};
use sha2::{Digest, Sha256};

use super::zip::{Archive, Entry, STORED};

/// The longest blob this looks for: an eight-byte exponent.
const MAX_BLOB: usize = BLOB_HEADER_LEN + 8 + 512;
const CHUNK: usize = 1 << 20;
/// No binary in the package is near this; a member that claims to be is
/// read no further.
pub const MAX_MEMBER: u64 = 512 << 20;
/// Nor is a package inside the bundle.
pub const MAX_NESTED_PACKAGE: u64 = 1 << 30;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScanStats {
    /// Members read.
    pub members: usize,
    /// Bytes read, after inflating.
    pub bytes: u64,
    /// Well-formed RSA-4096 public blobs seen, the pinned one included.
    pub candidates: usize,
}

/// The pinned blob, if `reader` holds one.
pub fn scan_reader(
    mut reader: impl Read,
    pin: &[u8; 32],
    stats: &mut ScanStats,
) -> io::Result<Option<Vec<u8>>> {
    let mut buf: Vec<u8> = Vec::with_capacity(CHUNK + MAX_BLOB);
    let mut chunk = vec![0u8; CHUNK];
    loop {
        let n = reader.read(&mut chunk)?;
        let eof = n == 0;
        buf.extend_from_slice(&chunk[..n]);
        stats.bytes += n as u64;
        // Positions before `done` need nothing past the end of `buf`.
        let done = if eof {
            buf.len()
        } else {
            buf.len().saturating_sub(MAX_BLOB - 1)
        };
        // The magic may straddle `done`; only a start before it is taken now.
        let window = (done + BLOB_MAGIC.len() - 1).min(buf.len());
        let mut i = 0;
        while let Some(found) = memfind(&buf[i..window], BLOB_MAGIC) {
            let at = i + found;
            if at >= done {
                break;
            }
            if let Some(len) = rsa4096_public_blob_len(&buf[at..])
                && at + len <= buf.len()
            {
                stats.candidates += 1;
                let blob = &buf[at..at + len];
                if Sha256::digest(blob).as_slice() == pin {
                    return Ok(Some(blob.to_vec()));
                }
            }
            i = at + 1;
        }
        if eof {
            return Ok(None);
        }
        buf.drain(..done);
    }
}

fn memfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Whether a member of a package is worth reading: the two binaries the key
/// has been found in first, then any other binary.
fn priority(path: &str) -> Option<u8> {
    let lower = path.to_ascii_lowercase();
    let file = lower.rsplit('/').next().unwrap_or(&lower);
    match file {
        "xsapi.dll" | "xvdd.sys" => Some(0),
        _ if [".dll", ".sys", ".exe"]
            .iter()
            .any(|ext| file.ends_with(ext)) =>
        {
            Some(1)
        }
        _ => None,
    }
}

/// Whether a member of the bundle is a package worth opening: the x64 one
/// first, then any other that is not for ARM.
fn package_priority(path: &str) -> Option<u8> {
    let lower = path.to_ascii_lowercase();
    if !(lower.ends_with(".appx") || lower.ends_with(".msix")) {
        return None;
    }
    if lower.contains("arm") {
        return None;
    }
    Some(if lower.contains("x64") { 0 } else { 1 })
}

fn by_priority(entries: &[Entry], rank: fn(&str) -> Option<u8>) -> Vec<Entry> {
    let mut ranked: Vec<(u8, Entry)> = entries
        .iter()
        .filter_map(|e| rank(&e.path()).map(|r| (r, e.clone())))
        .collect();
    ranked.sort_by_key(|(r, _)| *r);
    ranked.into_iter().map(|(_, e)| e).collect()
}

/// Where the pinned key was found, and the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub blob: Vec<u8>,
    pub package: String,
    pub member: String,
}

/// Look for the pinned key in the binaries of a package (an Appx or Msix
/// archive) at `start..start + len` of `file`.
fn scan_package(
    file: &mut File,
    start: u64,
    len: u64,
    pin: &[u8; 32],
    stats: &mut ScanStats,
) -> io::Result<Option<(Vec<u8>, String)>> {
    let mut archive = Archive::open(&mut *file, start, len)?;
    for entry in by_priority(&archive.entries, priority) {
        stats.members += 1;
        let reader = archive.reader(&entry, MAX_MEMBER)?;
        if let Some(blob) = scan_reader(reader, pin, stats)? {
            return Ok(Some((blob, entry.path())));
        }
    }
    Ok(None)
}

/// Look for the pinned key in an Appx bundle in `file`, called `name`.
///
/// Each package in the bundle is read where it lies when it is stored, as
/// bundles store them. One that is deflated is inflated into an unnamed
/// temporary file in `scratch` (freed by the kernel however the process
/// ends), at most `MAX_NESTED_PACKAGE` bytes. A package given directly,
/// rather than a bundle, is read the same way.
pub fn scan_bundle(
    file: &mut File,
    name: &str,
    scratch: &Path,
    pin: &[u8; 32],
    stats: &mut ScanStats,
) -> io::Result<Option<Found>> {
    let len = file.seek(SeekFrom::End(0))?;
    let entries = Archive::open(&mut *file, 0, len)?.entries;
    let packages = by_priority(&entries, package_priority);
    if packages.is_empty() {
        return Ok(
            scan_package(file, 0, len, pin, stats)?.map(|(blob, member)| Found {
                blob,
                package: name.to_string(),
                member,
            }),
        );
    }
    for package in packages {
        let found = if package.method == STORED {
            let (start, len) = Archive::open(&mut *file, 0, len)?.data_range(&package)?;
            scan_package(file, start, len, pin, stats)?
        } else {
            let mut inner = tempfile::tempfile_in(scratch)?;
            {
                let mut archive = Archive::open(&mut *file, 0, len)?;
                let mut reader = archive.reader(&package, MAX_NESTED_PACKAGE)?;
                io::copy(&mut reader, &mut inner)?;
            }
            inner.flush()?;
            let inner_len = inner.seek(SeekFrom::End(0))?;
            scan_package(&mut inner, 0, inner_len, pin, stats)?
        };
        if let Some((blob, member)) = found {
            return Ok(Some(Found {
                blob,
                package: package.path(),
                member,
            }));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use msixvc::signature::testing::{blob_sha256, other_key, public_blob, test_key};

    use super::super::zip::testing::zip;
    use super::*;

    fn blob() -> Vec<u8> {
        public_blob(&test_key().to_public_key())
    }

    /// A binary with the blob at `at`, among noise and decoys.
    fn binary(at: usize, len: usize, key: Option<&[u8]>) -> Vec<u8> {
        let mut data: Vec<u8> = (0..len).map(|i| (i * 131 % 253) as u8).collect();
        // Decoys: the magic alone, and a 2048-bit header.
        data[10..14].copy_from_slice(b"RSA1");
        data[100..104].copy_from_slice(b"RSA1");
        data[104..108].copy_from_slice(&2048u32.to_le_bytes());
        if let Some(key) = key {
            data[at..at + key.len()].copy_from_slice(key);
        }
        data
    }

    #[test]
    fn the_pinned_blob_is_found_anywhere_in_a_stream() {
        let key = blob();
        let pin = blob_sha256(&key);
        // At the start, across a chunk boundary, and at the very end.
        for at in [
            0,
            CHUNK - 7,
            CHUNK - MAX_BLOB - 1,
            CHUNK - MAX_BLOB,
            CHUNK - MAX_BLOB + 1,
            CHUNK - MAX_BLOB + 3,
            3 * CHUNK - key.len(),
        ] {
            let data = binary(at, 3 * CHUNK, Some(&key));
            let mut stats = ScanStats::default();
            let found = scan_reader(Cursor::new(data), &pin, &mut stats).unwrap();
            assert_eq!(found.as_deref(), Some(&key[..]), "at {at}");
            assert_eq!(stats.candidates, 1, "at {at}");
        }
        // Not there.
        let mut stats = ScanStats::default();
        let data = binary(0, CHUNK + 5, None);
        assert_eq!(
            scan_reader(Cursor::new(data), &pin, &mut stats).unwrap(),
            None
        );
        assert_eq!(stats.candidates, 0);
    }

    #[test]
    fn a_blob_that_is_not_the_pinned_one_is_not_taken() {
        let other = public_blob(&other_key().to_public_key());
        let pin = blob_sha256(&blob());
        let data = binary(5000, 20_000, Some(&other));
        let mut stats = ScanStats::default();
        assert_eq!(
            scan_reader(Cursor::new(data), &pin, &mut stats).unwrap(),
            None
        );
        assert_eq!(stats.candidates, 1);
        // The same blob one byte off.
        let mut changed = blob();
        changed[300] ^= 1;
        let data = binary(5000, 20_000, Some(&changed));
        let mut stats = ScanStats::default();
        assert_eq!(
            scan_reader(Cursor::new(data), &pin, &mut stats).unwrap(),
            None
        );
        assert_eq!(stats.candidates, 1);
    }

    fn bundle(stored_package: bool, key_member: &str, zip64: bool) -> Vec<u8> {
        let key = blob();
        let other = public_blob(&other_key().to_public_key());
        let with_key = binary(777, 50_000, Some(&key));
        let with_other = binary(10, 9_000, Some(&other));
        let x64 = zip(
            &[
                ("AppxManifest.xml", b"<Package/>", true),
                ("other.dll", &with_other, true),
                (key_member, &with_key, true),
            ],
            zip64,
        );
        let arm = zip(&[("xsapi.dll", &with_other, true)], zip64);
        zip(
            &[
                ("AppxMetadata/AppxBundleManifest.xml", b"<Bundle/>", true),
                ("Microsoft.Thing_1.0.0.0_arm64.msix", &arm, false),
                ("Microsoft.Thing_1.0.0.0_x64.msix", &x64, !stored_package),
            ],
            zip64,
        )
    }

    #[test]
    fn the_key_is_found_in_a_package_inside_a_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let pin = blob_sha256(&blob());
        for (stored, member, zip64) in [
            (true, "xsapi.dll", true),
            (true, "drivers%2Fxvdd.sys", false),
            (false, "drivers/xvdd.sys", true),
            (true, "bin/SomethingElse.exe", true),
        ] {
            let path = dir.path().join("bundle.appxbundle");
            std::fs::write(&path, bundle(stored, member, zip64)).unwrap();
            let mut stats = ScanStats::default();
            let mut file = File::open(&path).unwrap();
            let found = scan_bundle(&mut file, "bundle", dir.path(), &pin, &mut stats)
                .unwrap()
                .unwrap_or_else(|| panic!("{member}: not found"));
            assert_eq!(found.blob, blob());
            assert_eq!(found.package, "Microsoft.Thing_1.0.0.0_x64.msix");
            assert_eq!(found.member, member.replace("%2F", "/"));
            assert!(stats.candidates >= 1);
        }
        // Nothing left behind in the scratch directory but the bundle.
        let left: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(left.len(), 1);
    }

    #[test]
    fn a_bundle_without_the_pinned_key_yields_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.appxbundle");
        std::fs::write(&path, bundle(true, "xsapi.dll", true)).unwrap();
        let mut stats = ScanStats::default();
        let wrong_pin = [7u8; 32];
        assert_eq!(
            scan_bundle(
                &mut File::open(&path).unwrap(),
                "bundle",
                dir.path(),
                &wrong_pin,
                &mut stats
            )
            .unwrap(),
            None
        );
        // The ARM package is never opened; both x64 binaries holding a key are.
        assert_eq!(stats.candidates, 2);
        // Not a zip at all.
        std::fs::write(&path, b"not a bundle").unwrap();
        assert!(
            scan_bundle(
                &mut File::open(&path).unwrap(),
                "bundle",
                dir.path(),
                &wrong_pin,
                &mut stats
            )
            .is_err()
        );
    }
}
