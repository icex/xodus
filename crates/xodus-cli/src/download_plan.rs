// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Ferestre contributors.
//! Rebuild files in bounded windows, committing only complete verified output.
use crate::{
    download_session::{Session, diagnostic},
    download_state,
};
use futures_util::{StreamExt, stream};
use msixvc::{
    layout::PAGE_SIZE,
    xvd::{SegmentFile, XvdFile},
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io,
    ops::Range,
    os::unix::fs::{FileExt, OpenOptionsExt},
    path::Path,
};

const WINDOW: usize = 8 * 1024 * 1024;
const REQUEST_PAGES: usize = 512;
const INDEX_LIMIT: usize = 262144;
pub struct Entry {
    pub name: String,
    pub content: SegmentFile,
}

pub fn stored_size(file: &SegmentFile) -> io::Result<u64> {
    if file.keep_encrypted {
        file.length
            .checked_add(PAGE_SIZE as u64 - 1)
            .map(|n| n / PAGE_SIZE as u64 * PAGE_SIZE as u64)
            .ok_or_else(|| io::Error::other("File size exceeds the supported range"))
    } else {
        Ok(file.length)
    }
}
fn fingerprint(package: [u8; 32], file: &SegmentFile) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(package);
    hash.update(file.offset.to_le_bytes());
    hash.update(file.length.to_le_bytes());
    hash.update([u8::from(file.keep_encrypted)]);
    for value in &file.data_hashs {
        hash.update(value);
    }
    hash.finalize().to_vec()
}
fn read_only(path: &Path) -> io::Result<Option<File>> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) if file.metadata()?.is_file() => Ok(Some(file)),
        Ok(_) => Err(io::Error::other("Local reuse source is not a regular file")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
/// Recheck every complete stored page; a checkpoint is never an assertion that
/// bytes are authentic. A partial final plaintext page is fetched again.
fn verified_prefix(
    file: &File,
    limit: u64,
    mut accepts: impl FnMut(u64, &[u8]) -> bool,
) -> io::Result<u64> {
    let limit = limit / PAGE_SIZE as u64 * PAGE_SIZE as u64;
    let mut offset = 0;
    let mut buffer = vec![0u8; WINDOW];
    while offset < limit {
        let bytes = (limit - offset).min(WINDOW as u64) as usize;
        file.read_exact_at(&mut buffer[..bytes], offset)?;
        for page in buffer[..bytes].chunks_exact(PAGE_SIZE) {
            if !accepts(offset / PAGE_SIZE as u64, page) {
                return Ok(offset);
            }
            offset += PAGE_SIZE as u64;
        }
    }
    Ok(offset)
}
/// Short unchanged islands are cheaper to fetch inside one request. Long
/// unchanged spans stay local; every range remains within a fixed window.
fn gaps(valid: &[bool]) -> Vec<Range<usize>> {
    let mut spans: Vec<Range<usize>> = vec![];
    let mut page = 0;
    while page < valid.len() {
        if valid[page] {
            page += 1;
            continue;
        }
        let start = page;
        while page < valid.len() && !valid[page] {
            page += 1;
        }
        if let Some(previous) = spans.last_mut().filter(|r| start - r.end <= 8) {
            previous.end = page;
        } else {
            spans.push(start..page);
        }
    }
    spans
        .into_iter()
        .flat_map(|r| {
            (r.start..r.end)
                .step_by(REQUEST_PAGES)
                .map(move |start| start..(start + REQUEST_PAGES).min(r.end))
        })
        .collect()
}
fn old_positions(old: Option<&SegmentFile>) -> HashMap<[u8; 20], u64> {
    let Some(old) = old.filter(|old| old.data_hashs.len() <= INDEX_LIMIT) else {
        return HashMap::new();
    };
    let mut positions = HashMap::new();
    for (index, digest) in old.data_hashs.iter().enumerate() {
        positions
            .entry(*digest)
            .or_insert(index as u64 * PAGE_SIZE as u64);
    }
    positions
}
fn fill_local(
    buffer: &mut [u8],
    offset: u64,
    source: Option<&File>,
    current: &SegmentFile,
    positions: &HashMap<[u8; 20], u64>,
    mut accepts: impl FnMut(u64, &[u8]) -> bool,
) -> Vec<bool> {
    let mut valid = vec![false; buffer.len().div_ceil(PAGE_SIZE)];
    let Some(source) = source else { return valid };
    for (local, page) in buffer.chunks_exact_mut(PAGE_SIZE).enumerate() {
        let absolute = offset / PAGE_SIZE as u64 + local as u64;
        let at_same_position = absolute * PAGE_SIZE as u64;
        let relocated = current
            .data_hashs
            .get(absolute as usize)
            .and_then(|digest| positions.get(digest))
            .copied();
        for position in [Some(at_same_position), relocated].into_iter().flatten() {
            if source.read_exact_at(page, position).is_ok() && accepts(absolute, page) {
                valid[local] = true;
                break;
            }
        }
    }
    valid
}

#[allow(clippy::too_many_arguments)]
pub async fn execute(
    client: &reqwest::Client,
    xvd: &XvdFile,
    jobs: Vec<Entry>,
    old: &HashMap<String, SegmentFile>,
    root: &Path,
    url: &str,
    key: [u8; 32],
    parallel: usize,
    mut advanced: impl FnMut(u64),
) -> Result<Session, String> {
    fs::create_dir_all(root).map_err(|e| e.to_string())?;
    // Validate the entire plan before replacing the first file.
    for entry in &jobs {
        download_state::destination(root, &entry.name)
            .map_err(|e| format!("refusing to install this package: {e}"))?;
    }
    let total = jobs
        .iter()
        .try_fold(0u64, |sum, e| -> Result<u64, String> {
            let size = stored_size(&e.content).map_err(|e| e.to_string())?;
            e.content
                .offset
                .checked_add(size)
                .ok_or("Package file range overflows")?;
            sum.checked_add(size)
                .ok_or_else(|| "Download plan is too large".into())
        })?;
    let session = Session::new(total);
    if !jobs.is_empty() {
        download_state::begin(root).map_err(|e| e.to_string())?;
    }
    for entry in jobs {
        let result = one_file(
            client,
            xvd,
            &entry,
            old.get(&entry.name),
            root,
            url,
            key,
            parallel.clamp(1, 8),
            &session,
            &mut advanced,
        )
        .await;
        if let Err(error) = result {
            session.finish(false);
            diagnostic("transfer-io", 0);
            return Err(error);
        }
    }
    session.finalizing();
    Ok(session)
}

#[allow(clippy::too_many_arguments)]
async fn one_file(
    client: &reqwest::Client,
    xvd: &XvdFile,
    entry: &Entry,
    old: Option<&SegmentFile>,
    root: &Path,
    url: &str,
    key: [u8; 32],
    parallel: usize,
    session: &Session,
    advanced: &mut impl FnMut(u64),
) -> Result<(), String> {
    let content = &entry.content;
    let target = download_state::destination(root, &entry.name).map_err(|e| e.to_string())?;
    let (temporary, output) = download_state::partial(
        root,
        &entry.name,
        &fingerprint(xvd.transfer_stamp(), content),
    )
    .map_err(|e| e.to_string())?;
    let length = stored_size(content).map_err(|e| e.to_string())?;
    let saved = output
        .metadata()
        .map_err(|e| e.to_string())?
        .len()
        .min(length);
    let mut offset = tokio::task::block_in_place(|| {
        verified_prefix(&output, saved, |index, page| {
            xvd.accepts_installed_page(content, index, key, page)
        })
    })
    .map_err(|e| e.to_string())?;
    output.set_len(offset).map_err(|e| e.to_string())?;
    output.sync_data().map_err(|e| e.to_string())?;
    let free = fs2::available_space(root).map_err(|e| e.to_string())?;
    if free < length - offset {
        diagnostic("disk-space", 0);
        return Err(format!(
            "Not enough free space to rebuild {}: need {} bytes, have {free}",
            entry.name,
            length - offset
        ));
    }
    session.advance(offset, 0, offset);
    advanced(offset);
    let source = read_only(&target).map_err(|e| e.to_string())?;
    let positions = old_positions(old);
    while offset < length {
        session.ready().await?;
        let end = offset.saturating_add(WINDOW as u64).min(length);
        let mut data = vec![0u8; (end - offset) as usize];
        let valid = tokio::task::block_in_place(|| {
            fill_local(
                &mut data,
                offset,
                source.as_ref(),
                content,
                &positions,
                |index, page| xvd.accepts_installed_page(content, index, key, page),
            )
        });
        let fetched = stream::iter(gaps(&valid))
            .map(|range| {
                let start = offset + range.start as u64 * PAGE_SIZE as u64;
                let request_end = (offset + range.end as u64 * PAGE_SIZE as u64).min(length);
                let file = SegmentFile {
                    offset: content.offset + start,
                    length: (request_end - start).min(content.length - start.min(content.length)),
                    data_hashs: vec![],
                    keep_encrypted: content.keep_encrypted,
                };
                async move {
                    let downloaded = session
                        .request(|| async {
                            let mut bytes = vec![];
                            if let Some(local) = url.strip_prefix("file://") {
                                let mut source = tokio::fs::File::open(local)
                                    .await
                                    .map_err(|e| e.to_string())?;
                                xvd.extract_file(&mut source, &mut bytes, &file, key, |_, _| {})
                                    .await
                                    .map_err(|e| {
                                        format!(
                                            "{}: {e}; this container does not contain this file",
                                            entry.name
                                        )
                                    })?;
                            } else {
                                xvd.download_file_http(
                                    client,
                                    url,
                                    &mut bytes,
                                    &file,
                                    key,
                                    |_, _| {},
                                )
                                .await
                                .map_err(|e| format!("{}: {e}", entry.name))?;
                            }
                            Ok(bytes)
                        })
                        .await?;
                    if downloaded.len() as u64 != request_end - start {
                        return Err("Package returned an unexpected amount of output".to_string());
                    }
                    Ok((range.start * PAGE_SIZE, downloaded))
                }
            })
            .buffer_unordered(parallel)
            .collect::<Vec<Result<(usize, Vec<u8>), String>>>()
            .await;
        // Settle all HTTP buffers before exposing an error. No background task
        // retains an installation writer after this function releases it.
        let mut network = 0u64;
        for result in fetched {
            let (start, bytes) = result?;
            network += bytes.len() as u64;
            data[start..start + bytes.len()].copy_from_slice(&bytes);
        }
        session.ready().await?;
        tokio::task::block_in_place(|| {
            output.write_all_at(&data, offset)?;
            output.sync_data()
        })
        .map_err(|e: io::Error| e.to_string())?;
        let durable = data.len() as u64;
        session.advance(durable, network, durable - network);
        advanced(durable);
        offset = end;
    }
    output.sync_all().map_err(|e| e.to_string())?;
    drop(output);
    drop(source);
    fs::rename(&temporary, &target).map_err(|e| e.to_string())?;
    File::open(target.parent().unwrap())
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    File::open(temporary.parent().unwrap())
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn resume_verifies_all_pages_and_discards_a_corrupt_suffix() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("saved");
        fs::write(&path, vec![7; 3 * PAGE_SIZE + 13]).unwrap();
        let f = File::open(path).unwrap();
        let mut checked = vec![];
        assert_eq!(
            verified_prefix(&f, 3 * PAGE_SIZE as u64 + 13, |index, bytes| {
                checked.push(index);
                bytes[0] == 7 && index < 1
            })
            .unwrap(),
            PAGE_SIZE as u64
        );
        assert_eq!(checked, vec![0, 1]);
        assert_eq!(
            verified_prefix(&f, 3 * PAGE_SIZE as u64 + 13, |_, _| true).unwrap(),
            3 * PAGE_SIZE as u64
        );
    }
    #[test]
    fn missing_ranges_are_coalesced_and_capped_without_leaving_the_window() {
        let mut valid = vec![true; 3000];
        valid[2] = false;
        valid[8] = false;
        valid[1000..2999].fill(false);
        let missing = gaps(&valid);
        assert_eq!(missing[0], 2..9);
        assert!(
            missing
                .iter()
                .all(|r| r.len() <= REQUEST_PAGES && r.end <= valid.len())
        );
        for (index, present) in valid.iter().enumerate() {
            if !present {
                assert!(missing.iter().any(|r| r.contains(&index)));
            }
        }
    }
    #[test]
    fn local_reuse_checks_candidates_in_the_new_target_position() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("old");
        let mut bytes = vec![1; PAGE_SIZE];
        bytes.extend(vec![2; PAGE_SIZE]);
        fs::write(&path, bytes).unwrap();
        let current = SegmentFile {
            offset: 0,
            length: PAGE_SIZE as u64,
            data_hashs: vec![[9; 20]],
            keep_encrypted: true,
        };
        let mut map = HashMap::new();
        map.insert([9; 20], PAGE_SIZE as u64);
        let mut output = vec![0; PAGE_SIZE];
        let source = File::open(path).unwrap();
        assert_eq!(
            fill_local(
                &mut output,
                0,
                Some(&source),
                &current,
                &map,
                |index, p| index == 0 && p[0] == 2
            ),
            vec![true]
        );
        assert!(output.iter().all(|b| *b == 2));
        assert_eq!(
            fill_local(&mut output, 0, Some(&source), &current, &map, |_, _| false),
            vec![false]
        );
    }
    #[test]
    fn stage_fingerprints_change_with_package_layout_and_ciphertext() {
        let mut f = SegmentFile {
            offset: 0,
            length: 5000,
            data_hashs: vec![[1; 20]],
            keep_encrypted: false,
        };
        let original = fingerprint([0; 32], &f);
        f.offset = 4096;
        assert_ne!(original, fingerprint([0; 32], &f));
        f.offset = 0;
        f.keep_encrypted = true;
        assert_ne!(original, fingerprint([0; 32], &f));
        assert_eq!(stored_size(&f).unwrap(), 8192);
        f.keep_encrypted = false;
        f.data_hashs[0] = [2; 20];
        assert_ne!(original, fingerprint([0; 32], &f));
        assert_ne!(original, fingerprint([1; 32], &f));
    }
}

#[cfg(test)]
#[path = "download_plan_tests.rs"]
mod transfer_tests;
