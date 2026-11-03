// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Ferestre contributors.
//! Credential-free tests of real package hashes, HTTP ranges and durable output.
use super::*;
use std::{
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
struct Server {
    url: String,
    ranges: Arc<Mutex<Vec<(usize, usize)>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn new(bytes: Vec<u8>, status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let ranges = Arc::new(Mutex::new(vec![]));
        let stop = Arc::new(AtomicBool::new(false));
        let (worker_ranges, worker_stop) = (ranges.clone(), stop.clone());
        let worker = thread::spawn(move || {
            for stream in listener.incoming() {
                if worker_stop.load(Ordering::SeqCst) {
                    break;
                }
                let mut stream = stream.unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut range = None;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("range: bytes=") {
                        if let Some((a, b)) = value.trim().split_once('-') {
                            range =
                                Some((a.parse::<usize>().unwrap(), b.parse::<usize>().unwrap()));
                        }
                    }
                }
                if status != 206 {
                    write!(stream,"HTTP/1.1 {status} Refused\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").ok();
                    continue;
                }
                let Some((a, b)) = range else { continue };
                worker_ranges.lock().unwrap().push((a, b));
                if b >= bytes.len() {
                    write!(
                        stream,
                        "HTTP/1.1 416 Range\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .ok();
                    continue;
                }
                write!(stream,"HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {a}-{b}/{}\r\nConnection: close\r\n\r\n",b-a+1,bytes.len()).unwrap();
                stream.write_all(&bytes[a..=b]).ok();
            }
        });
        Self {
            url: format!("http://{address}/package"),
            ranges,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        TcpStream::connect(
            self.url
                .strip_prefix("http://")
                .unwrap()
                .split('/')
                .next()
                .unwrap(),
        )
        .ok();
        self.worker.take().unwrap().join().unwrap();
    }
}
async fn fixture(changed: bool) -> (Vec<u8>, XvdFile, Entry, Vec<u8>) {
    let package = msixvc::xvd::testing::package_with(|pages| {
        if changed {
            pages[32][30] ^= 1;
        }
    });
    let start = package.drive_page * PAGE_SIZE;
    let length = 64 * PAGE_SIZE;
    let expected = package.bytes[start..start + length].to_vec();
    let hashes = expected
        .chunks_exact(PAGE_SIZE)
        .map(|p| {
            let digest = Sha256::digest(p);
            let mut out = [0; 20];
            out.copy_from_slice(&digest[..20]);
            out
        })
        .collect();
    let xvd = XvdFile::parse_verified(&mut std::io::Cursor::new(&package.bytes))
        .await
        .unwrap();
    let entry = Entry {
        name: "Content/payload.dat".into(),
        content: SegmentFile {
            offset: start as u64,
            length: length as u64,
            data_hashs: hashes,
            keep_encrypted: false,
        },
    };
    (package.bytes, xvd, entry, expected)
}
fn client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn authentic_local_content_needs_no_network_request() {
    let (_, xvd, entry, expected) = fixture(false).await;
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("Content")).unwrap();
    fs::write(root.path().join(&entry.name), &expected).unwrap();
    let mut durable = 0;
    execute(
        &client(),
        &xvd,
        vec![entry],
        &HashMap::new(),
        root.path(),
        "http://127.0.0.1:9/unavailable",
        [0; 32],
        4,
        |n| durable += n,
    )
    .await
    .unwrap();
    assert_eq!(durable, expected.len() as u64);
    assert_eq!(
        fs::read(root.path().join("Content/payload.dat")).unwrap(),
        expected
    );
    assert!(
        download_state::incomplete(root.path()).unwrap(),
        "Only metadata commit may clear the barrier"
    );
}
#[tokio::test(flavor = "multi_thread")]
async fn failed_updates_keep_the_old_file_and_resume_only_verified_staged_pages() {
    let (bytes, xvd, entry, expected) = fixture(false).await;
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("Content")).unwrap();
    let target = root.path().join(&entry.name);
    fs::write(&target, b"previous installed version").unwrap();
    let (_, stage) = download_state::partial(
        root.path(),
        &entry.name,
        &fingerprint(xvd.transfer_stamp(), &entry.content),
    )
    .unwrap();
    stage.write_all_at(&expected[..2 * PAGE_SIZE], 0).unwrap();
    stage.sync_all().unwrap();
    drop(stage);
    let refused = Server::new(bytes.clone(), 403);
    assert!(
        execute(
            &client(),
            &xvd,
            vec![entry],
            &HashMap::new(),
            root.path(),
            &refused.url,
            [0; 32],
            4,
            |_| {}
        )
        .await
        .is_err()
    );
    assert_eq!(fs::read(&target).unwrap(), b"previous installed version");
    assert!(download_state::incomplete(root.path()).unwrap());
    let (_, _, entry, _) = fixture(false).await;
    let server = Server::new(bytes, 206);
    let first = entry.content.offset as usize;
    execute(
        &client(),
        &xvd,
        vec![entry],
        &HashMap::new(),
        root.path(),
        &server.url,
        [0; 32],
        4,
        |_| {},
    )
    .await
    .unwrap();
    assert_eq!(fs::read(target).unwrap(), expected);
    assert!(
        server
            .ranges
            .lock()
            .unwrap()
            .iter()
            .all(|(start, _)| *start >= first + 2 * PAGE_SIZE)
    );
}
#[tokio::test(flavor = "multi_thread")]
async fn a_corrupt_saved_page_is_replaced_instead_of_trusting_its_length() {
    let (bytes, xvd, entry, expected) = fixture(false).await;
    let root = tempfile::tempdir().unwrap();
    let (_, stage) = download_state::partial(
        root.path(),
        &entry.name,
        &fingerprint(xvd.transfer_stamp(), &entry.content),
    )
    .unwrap();
    let mut saved = expected[..5 * PAGE_SIZE].to_vec();
    saved[PAGE_SIZE + 100] ^= 1;
    stage.write_all_at(&saved, 0).unwrap();
    stage.sync_all().unwrap();
    drop(stage);
    let server = Server::new(bytes, 206);
    let first = entry.content.offset as usize;
    execute(
        &client(),
        &xvd,
        vec![entry],
        &HashMap::new(),
        root.path(),
        &server.url,
        [0; 32],
        4,
        |_| {},
    )
    .await
    .unwrap();
    assert_eq!(
        fs::read(root.path().join("Content/payload.dat")).unwrap(),
        expected
    );
    assert_eq!(
        server.ranges.lock().unwrap().iter().map(|(a, _)| *a).min(),
        Some(first + PAGE_SIZE)
    );
}
#[tokio::test(flavor = "multi_thread")]
async fn an_incremental_update_fetches_only_changed_authenticated_pages() {
    let (_, _, old_entry, old_bytes) = fixture(false).await;
    let (bytes, xvd, entry, expected) = fixture(true).await;
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("Content")).unwrap();
    fs::write(root.path().join(&entry.name), old_bytes).unwrap();
    let mut old = HashMap::new();
    old.insert(old_entry.name, old_entry.content);
    let server = Server::new(bytes, 206);
    execute(
        &client(),
        &xvd,
        vec![entry],
        &old,
        root.path(),
        &server.url,
        [0; 32],
        4,
        |_| {},
    )
    .await
    .unwrap();
    assert_eq!(
        fs::read(root.path().join("Content/payload.dat")).unwrap(),
        expected
    );
    let transferred: usize = server
        .ranges
        .lock()
        .unwrap()
        .iter()
        .map(|(a, b)| b - a + 1)
        .sum();
    assert_eq!(
        transferred, PAGE_SIZE,
        "The other 63 pages must be authenticated and reused locally"
    );
}
