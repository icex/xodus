//! Just enough of the zip format to read members out of an Appx bundle and the
//! packages inside it, without extracting the rest.
//!
//! Appx packages and bundles are zip64 archives whose members are stored or
//! deflated. Members are found through the central directory, every size and
//! offset is checked against the bounds of the archive they belong to, and an
//! archive inside another is read where it lies when it is stored, so a 200 MB
//! bundle is never unpacked to read two files.

use std::io::{self, Read, Seek, SeekFrom, Take};

use flate2::read::DeflateDecoder;

/// More members than any package this reads has, by a wide margin.
const MAX_ENTRIES: u64 = 200_000;
/// More central directory than that many members need.
const MAX_CENTRAL_DIRECTORY: u64 = 64 << 20;
const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const ZIP64_EOCD_SIGNATURE: u32 = 0x0606_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;

pub const STORED: u16 = 0;
pub const DEFLATED: u16 = 8;

fn invalid(what: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.into())
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// A member of an archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub method: u16,
    pub compressed_size: u64,
    pub size: u64,
    /// Where the member's local header is, from the start of the archive.
    local_header: u64,
}

impl Entry {
    /// The member's name as the package means it: Appx packages
    /// percent-encode names, and both separators are seen.
    pub fn path(&self) -> String {
        let mut out = Vec::with_capacity(self.name.len());
        let bytes = self.name.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%'
                && i + 2 < bytes.len()
                && let Ok(byte) = u8::from_str_radix(
                    std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("zz"),
                    16,
                )
            {
                out.push(byte);
                i += 3;
                continue;
            }
            out.push(if bytes[i] == b'\\' { b'/' } else { bytes[i] });
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }
}

/// An archive occupying `start..start + len` of `file`.
pub struct Archive<R> {
    file: R,
    start: u64,
    len: u64,
    pub entries: Vec<Entry>,
}

impl<R: Read + Seek> Archive<R> {
    /// Read the central directory of the archive at `start..start + len`.
    pub fn open(mut file: R, start: u64, len: u64) -> io::Result<Self> {
        let entries = read_central_directory(&mut file, start, len)?;
        Ok(Archive {
            file,
            start,
            len,
            entries,
        })
    }

    /// Where a member's data lies, from the start of `file`, and how long it is.
    pub fn data_range(&mut self, entry: &Entry) -> io::Result<(u64, u64)> {
        let mut local = [0u8; 30];
        if entry
            .local_header
            .checked_add(30)
            .is_none_or(|end| end > self.len)
        {
            return Err(invalid(format!(
                "{}: local header out of bounds",
                entry.name
            )));
        }
        self.file
            .seek(SeekFrom::Start(self.start + entry.local_header))?;
        self.file.read_exact(&mut local)?;
        if u32_at(&local, 0) != LOCAL_SIGNATURE {
            return Err(invalid(format!("{}: no local header", entry.name)));
        }
        let skip = 30 + u16_at(&local, 26) as u64 + u16_at(&local, 28) as u64;
        let data = entry.local_header + skip;
        match data.checked_add(entry.compressed_size) {
            Some(end) if end <= self.len => Ok((self.start + data, entry.compressed_size)),
            _ => Err(invalid(format!("{}: data out of bounds", entry.name))),
        }
    }

    /// A reader of a member's contents, inflated if need be, that stops at
    /// the size the directory gives and at `cap` bytes, whichever is less.
    pub fn reader(&mut self, entry: &Entry, cap: u64) -> io::Result<Box<dyn Read + '_>> {
        let (data, len) = self.data_range(entry)?;
        self.file.seek(SeekFrom::Start(data))?;
        let raw: Take<&mut R> = (&mut self.file).take(len);
        let limit = entry.size.min(cap);
        match entry.method {
            STORED => Ok(Box::new(raw.take(limit))),
            DEFLATED => Ok(Box::new(DeflateDecoder::new(raw).take(limit))),
            other => Err(invalid(format!(
                "{}: compression method {other} is not supported",
                entry.name
            ))),
        }
    }

    #[cfg(test)]
    pub fn into_inner(self) -> R {
        self.file
    }
}

fn read_central_directory<R: Read + Seek>(
    file: &mut R,
    start: u64,
    len: u64,
) -> io::Result<Vec<Entry>> {
    // The end of central directory record is in the last 64 KiB + 22 bytes.
    let tail_len = len.min(0xFFFF + 22);
    if tail_len < 22 {
        return Err(invalid("not a zip archive: too short"));
    }
    let tail_start = len - tail_len;
    let mut tail = vec![0u8; tail_len as usize];
    file.seek(SeekFrom::Start(start + tail_start))?;
    file.read_exact(&mut tail)?;
    let eocd = (0..=tail.len() - 22)
        .rev()
        .find(|&i| u32_at(&tail, i) == EOCD_SIGNATURE)
        .ok_or_else(|| invalid("not a zip archive: no end of central directory"))?;
    let mut count = u16_at(&tail, eocd + 10) as u64;
    let mut cd_size = u32_at(&tail, eocd + 12) as u64;
    let mut cd_offset = u32_at(&tail, eocd + 16) as u64;

    // Zip64: the locator sits just before the record above.
    if eocd >= 20 && u32_at(&tail, eocd - 20) == ZIP64_LOCATOR_SIGNATURE {
        let record = u64_at(&tail, eocd - 20 + 8);
        if record.checked_add(56).is_none_or(|end| end > len) {
            return Err(invalid("zip64 end of central directory out of bounds"));
        }
        let mut z = [0u8; 56];
        file.seek(SeekFrom::Start(start + record))?;
        file.read_exact(&mut z)?;
        if u32_at(&z, 0) != ZIP64_EOCD_SIGNATURE {
            return Err(invalid("no zip64 end of central directory"));
        }
        count = u64_at(&z, 32);
        cd_size = u64_at(&z, 40);
        cd_offset = u64_at(&z, 48);
    }
    if count > MAX_ENTRIES || cd_size > MAX_CENTRAL_DIRECTORY {
        return Err(invalid("zip central directory is implausibly large"));
    }
    if cd_offset.checked_add(cd_size).is_none_or(|end| end > len) {
        return Err(invalid("zip central directory out of bounds"));
    }
    let mut cd = vec![0u8; cd_size as usize];
    file.seek(SeekFrom::Start(start + cd_offset))?;
    file.read_exact(&mut cd)?;

    let mut entries = Vec::with_capacity(count as usize);
    let mut at = 0usize;
    for _ in 0..count {
        if at + 46 > cd.len() || u32_at(&cd, at) != CENTRAL_SIGNATURE {
            return Err(invalid("zip central directory entry is damaged"));
        }
        let method = u16_at(&cd, at + 10);
        let mut compressed_size = u32_at(&cd, at + 20) as u64;
        let mut size = u32_at(&cd, at + 24) as u64;
        let name_len = u16_at(&cd, at + 28) as usize;
        let extra_len = u16_at(&cd, at + 30) as usize;
        let comment_len = u16_at(&cd, at + 32) as usize;
        let mut local_header = u32_at(&cd, at + 42) as u64;
        let name_at = at + 46;
        let extra_at = name_at + name_len;
        let next = extra_at + extra_len + comment_len;
        if next > cd.len() {
            return Err(invalid("zip central directory entry is damaged"));
        }
        let name = String::from_utf8_lossy(&cd[name_at..extra_at]).into_owned();

        // The zip64 extra field holds, in order, whichever of these is
        // 0xFFFFFFFF in the fixed part.
        let mut extra = &cd[extra_at..extra_at + extra_len];
        while extra.len() >= 4 {
            let id = u16_at(extra, 0);
            let field_len = u16_at(extra, 2) as usize;
            if 4 + field_len > extra.len() {
                break;
            }
            if id == 0x0001 {
                let mut field = &extra[4..4 + field_len];
                for value in [&mut size, &mut compressed_size, &mut local_header] {
                    if *value == 0xFFFF_FFFF {
                        if field.len() < 8 {
                            return Err(invalid(format!("{name}: zip64 field too short")));
                        }
                        *value = u64_at(field, 0);
                        field = &field[8..];
                    }
                }
            }
            extra = &extra[4 + field_len..];
        }
        entries.push(Entry {
            name,
            method,
            compressed_size,
            size,
            local_header,
        });
        at = next;
    }
    Ok(entries)
}

/// Writing archives, for tests: stored or deflated members, optionally with
/// zip64 records, the way Appx packages are written.
#[cfg(test)]
pub mod testing {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::DeflateEncoder;

    pub fn zip(members: &[(&str, &[u8], bool)], zip64: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for (name, data, deflate) in members {
            let (method, body) = if *deflate {
                let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
                e.write_all(data).unwrap();
                (8u16, e.finish().unwrap())
            } else {
                (0u16, data.to_vec())
            };
            let offset = out.len() as u64;
            let crc = 0u32; // not checked by the reader
            let (c32, s32, o32) = if zip64 {
                (0xFFFF_FFFFu32, 0xFFFF_FFFFu32, 0xFFFF_FFFFu32)
            } else {
                (body.len() as u32, data.len() as u32, offset as u32)
            };
            // Local header, with an extra field of its own length to make
            // sure the reader takes the local lengths for the data offset.
            let local_extra = [0xAAu8, 0xAA, 3, 0, 1, 2, 3];
            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            out.extend_from_slice(&[45, 0, 0, 0]);
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0, 0, 0, 0]);
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&(local_extra.len() as u16).to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&local_extra);
            out.extend_from_slice(&body);

            let mut extra = Vec::new();
            if zip64 {
                extra.extend_from_slice(&1u16.to_le_bytes());
                extra.extend_from_slice(&24u16.to_le_bytes());
                extra.extend_from_slice(&(data.len() as u64).to_le_bytes());
                extra.extend_from_slice(&(body.len() as u64).to_le_bytes());
                extra.extend_from_slice(&offset.to_le_bytes());
            }
            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central.extend_from_slice(&[45, 0, 45, 0, 0, 0]);
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&[0, 0, 0, 0]);
            central.extend_from_slice(&crc.to_le_bytes());
            central.extend_from_slice(&c32.to_le_bytes());
            central.extend_from_slice(&s32.to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&(extra.len() as u16).to_le_bytes());
            // Comment length, disk, internal and external attributes.
            central.extend_from_slice(&[0; 10]);
            central.extend_from_slice(&o32.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
            central.extend_from_slice(&extra);
        }
        let cd_offset = out.len() as u64;
        out.extend_from_slice(&central);
        let count = members.len() as u64;
        if zip64 {
            let record = out.len() as u64;
            out.extend_from_slice(&0x0606_4b50u32.to_le_bytes());
            out.extend_from_slice(&44u64.to_le_bytes());
            out.extend_from_slice(&[45, 0, 45, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            out.extend_from_slice(&count.to_le_bytes());
            out.extend_from_slice(&count.to_le_bytes());
            out.extend_from_slice(&(central.len() as u64).to_le_bytes());
            out.extend_from_slice(&cd_offset.to_le_bytes());
            out.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&record.to_le_bytes());
            out.extend_from_slice(&1u32.to_le_bytes());
        }
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        let (n16, cds, cdo) = if zip64 {
            (0xFFFFu16, 0xFFFF_FFFFu32, 0xFFFF_FFFFu32)
        } else {
            (count as u16, central.len() as u32, cd_offset as u32)
        };
        out.extend_from_slice(&n16.to_le_bytes());
        out.extend_from_slice(&n16.to_le_bytes());
        out.extend_from_slice(&cds.to_le_bytes());
        out.extend_from_slice(&cdo.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use super::testing::zip;
    use super::*;

    fn read_all(archive: &mut Archive<Cursor<Vec<u8>>>, name: &str, cap: u64) -> Vec<u8> {
        let entry = archive
            .entries
            .iter()
            .find(|e| e.name == name)
            .unwrap()
            .clone();
        let mut out = Vec::new();
        archive
            .reader(&entry, cap)
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    #[test]
    fn members_are_read_stored_or_deflated_with_and_without_zip64() {
        let big: Vec<u8> = (0..100_000u32).map(|i| (i % 7) as u8).collect();
        for zip64 in [false, true] {
            let bytes = zip(
                &[("a.txt", b"hello", false), ("dir%2Fb.bin", &big, true)],
                zip64,
            );
            let len = bytes.len() as u64;
            let mut archive = Archive::open(Cursor::new(bytes), 0, len).unwrap();
            assert_eq!(archive.entries.len(), 2);
            assert_eq!(archive.entries[1].path(), "dir/b.bin");
            assert_eq!(read_all(&mut archive, "a.txt", u64::MAX), b"hello");
            assert_eq!(read_all(&mut archive, "dir%2Fb.bin", u64::MAX), big);
            // The cap holds.
            assert_eq!(read_all(&mut archive, "dir%2Fb.bin", 10).len(), 10);
        }
    }

    #[test]
    fn an_archive_inside_another_is_read_where_it_lies() {
        let inner = zip(&[("drivers/x.sys", b"inner data", true)], true);
        let mut outer_bytes = vec![0xEEu8; 100]; // something before the archive
        let outer = zip(&[("pkg.appx", &inner, false)], true);
        outer_bytes.extend_from_slice(&outer);
        let len = outer.len() as u64;
        let mut archive = Archive::open(Cursor::new(outer_bytes), 100, len).unwrap();
        let entry = archive.entries[0].clone();
        let (start, len) = archive.data_range(&entry).unwrap();
        let mut nested = Archive::open(archive.into_inner(), start, len).unwrap();
        assert_eq!(nested.entries[0].name, "drivers/x.sys");
        let e = nested.entries[0].clone();
        let mut out = Vec::new();
        nested
            .reader(&e, u64::MAX)
            .unwrap()
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, b"inner data");
    }

    #[test]
    fn damaged_archives_are_refused() {
        assert!(Archive::open(Cursor::new(vec![0u8; 10]), 0, 10).is_err());
        assert!(Archive::open(Cursor::new(vec![0u8; 1000]), 0, 1000).is_err());
        // A directory that points past the end.
        let mut bytes = zip(&[("a", b"x", false)], false);
        let n = bytes.len();
        bytes[n - 6..n - 2].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
        assert!(Archive::open(Cursor::new(bytes), 0, n as u64).is_err());
        // A member whose data runs past the end of the archive it is in.
        let bytes = zip(&[("a", b"xyz", false)], false);
        let n = bytes.len() as u64;
        let mut archive = Archive::open(Cursor::new(bytes), 0, n).unwrap();
        let mut entry = archive.entries[0].clone();
        entry.compressed_size = n;
        assert!(archive.data_range(&entry).is_err());
    }
}
