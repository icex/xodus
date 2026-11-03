// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Ferestre contributors.
//! A process-local control channel and versioned, credential-free progress.
use std::{
    future::Future,
    io::{BufRead, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;

/// The preparation phase has no game-download total yet. Sequence zero lets
/// the first planned-transfer event (sequence one) take over the same stream.
pub fn metadata() {
    if std::env::var("XODUS_PROGRESS").is_ok_and(|value| value == "json") {
        println!(
            "FERESTRE_PROGRESS {}",
            serde_json::json!({"schema":1,"event":"progress","sequence":0,"phase":"metadata","completedBytes":0,"totalBytes":null,"paused":false,"canPause":false})
        );
    }
}

#[derive(Clone)]
pub struct Session(Arc<Shared>);
struct Shared {
    paused: AtomicBool,
    stopped: AtomicBool,
    wake: Notify,
    json: bool,
    controlled: bool,
    progress: Mutex<Progress>,
}
struct Progress {
    done: u64,
    total: u64,
    network: u64,
    reused: u64,
    sequence: u64,
    phase: &'static str,
    last: Instant,
}
impl Session {
    pub fn new(total: u64) -> Self {
        let controlled = std::env::var_os("FERESTRE_STREAMING_CONTROL").is_some();
        let session = Self::with_options(
            total,
            std::env::var("XODUS_PROGRESS").is_ok_and(|s| s == "json"),
            controlled,
        );
        if controlled {
            let controls = session.clone();
            std::thread::spawn(move || {
                let input = std::io::stdin();
                let mut reader = input.lock();
                let mut command = Vec::new();
                loop {
                    command.clear();
                    let received =
                        std::io::Read::take(&mut reader, 513).read_until(b'\n', &mut command);
                    match received {
                        Ok(0) | Err(_) => break,
                        Ok(_) if command.len() > 512 => {
                            if command.last() != Some(&b'\n') {
                                reader.skip_until(b'\n').ok();
                            }
                        }
                        Ok(_) => {
                            controls.command(&command);
                        }
                    }
                }
                controls.stop();
            });
        }
        session.emit(true);
        session
    }
    fn with_options(total: u64, json: bool, controlled: bool) -> Self {
        Self(Arc::new(Shared {
            paused: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            wake: Notify::new(),
            json,
            controlled,
            progress: Mutex::new(Progress {
                done: 0,
                total,
                network: 0,
                reused: 0,
                sequence: 0,
                phase: "downloading",
                last: Instant::now(),
            }),
        }))
    }
    fn command(&self, bytes: &[u8]) -> bool {
        if bytes.len() > 512 {
            return false;
        }
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return false;
        };
        let Some(command) = value.as_object() else {
            return false;
        };
        if command.len() != 2 || command.get("schema") != Some(&serde_json::json!(1)) {
            return false;
        }
        match command.get("command").and_then(|v| v.as_str()) {
            Some("pause") => self.set_paused(true),
            Some("resume") => self.set_paused(false),
            Some("stop") => self.stop(),
            _ => return false,
        }
        true
    }
    fn set_paused(&self, value: bool) {
        self.0.paused.store(value, Ordering::SeqCst);
        self.0.wake.notify_waiters();
        self.emit(true);
    }
    fn stop(&self) {
        self.0.stopped.store(true, Ordering::SeqCst);
        self.0.wake.notify_waiters();
        diagnostic("transfer-cancelled", 0);
    }
    pub async fn ready(&self) -> Result<(), String> {
        loop {
            let wake = self.0.wake.notified();
            if self.0.stopped.load(Ordering::SeqCst) {
                return Err("Download stopped; verified staging data was retained".into());
            }
            if !self.0.paused.load(Ordering::SeqCst) {
                return Ok(());
            }
            wake.await;
        }
    }
    /// Cancelling only the in-memory HTTP buffer closes the connection on
    /// pause. The durable staging file is never owned by a cancelled future.
    pub async fn request<T, F, M>(&self, mut start: M) -> Result<T, String>
    where
        F: Future<Output = Result<T, String>>,
        M: FnMut() -> F,
    {
        loop {
            self.ready().await?;
            let changed = self.0.wake.notified();
            if self.0.paused.load(Ordering::SeqCst) || self.0.stopped.load(Ordering::SeqCst) {
                continue;
            }
            tokio::select! { result=start()=>return result, _=changed=>() }
        }
    }
    pub fn advance(&self, bytes: u64, downloaded: u64, reused: u64) {
        {
            let mut p = self.0.progress.lock().unwrap();
            p.done = p.done.saturating_add(bytes);
            p.network = p.network.saturating_add(downloaded);
            p.reused = p.reused.saturating_add(reused);
        }
        self.emit(false);
    }
    pub fn finalizing(&self) {
        self.0.progress.lock().unwrap().phase = "finalizing";
        self.emit(true);
    }
    pub fn finish(&self, success: bool) {
        self.0.progress.lock().unwrap().phase = if success { "complete" } else { "failed" };
        self.emit(true);
    }
    fn snapshot(&self, force: bool) -> Option<serde_json::Value> {
        let mut p = self.0.progress.lock().unwrap();
        if !force && p.last.elapsed() < Duration::from_millis(100) {
            return None;
        }
        p.sequence = p.sequence.saturating_add(1);
        p.last = Instant::now();
        Some(
            serde_json::json!({"schema":1,"event":"progress","sequence":p.sequence,"phase":p.phase,
            "completedBytes":p.done,"totalBytes":p.total,"networkBytes":p.network,"reusedBytes":p.reused,
            "paused":self.0.paused.load(Ordering::SeqCst),"canPause":self.0.controlled&&p.phase=="downloading"}),
        )
    }
    fn emit(&self, force: bool) {
        if self.0.json {
            if let Some(value) = self.snapshot(force) {
                let mut out = std::io::stdout().lock();
                writeln!(out, "FERESTRE_PROGRESS {value}").ok();
                out.flush().ok();
            }
        }
    }
}
pub fn diagnostic(stage: &str, status: u16) {
    eprintln!("FERESTRE_TRANSFER_DIAGNOSTIC_V1 {stage} {status}");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn pause_closes_an_inflight_request_and_resume_restarts_it() {
        let s = Session::with_options(100, false, true);
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let task = {
            let s = s.clone();
            let attempts = attempts.clone();
            tokio::spawn(async move {
                s.request(|| {
                    let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if attempt == 0 {
                            std::future::pending::<()>().await;
                        }
                        Ok(42)
                    }
                })
                .await
            })
        };
        while attempts.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        assert!(s.command(br#"{"schema":1,"command":"pause"}"#));
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!task.is_finished());
        assert!(s.command(br#"{"schema":1,"command":"resume"}"#));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            42
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }
    #[tokio::test]
    async fn stop_or_controller_loss_wakes_a_paused_transfer_without_restarting_it() {
        let session = Session::with_options(100, false, true);
        assert!(session.command(br#"{"schema":1,"command":"pause"}"#));
        let task = {
            let session = session.clone();
            tokio::spawn(async move {
                session
                    .request(|| async {
                        panic!("Stopped work must not start");
                        #[allow(unreachable_code)]
                        Ok::<(), String>(())
                    })
                    .await
            })
        };
        tokio::task::yield_now().await;
        session.stop();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
    }
    #[test]
    fn controls_are_bounded_and_do_not_accept_other_fields() {
        let s = Session::with_options(100, false, true);
        for bytes in [
            br#"{"schema":2,"command":"pause"}"#.as_slice(),
            br#"{"schema":1,"command":"pause","token":"secret"}"#.as_slice(),
            br#"{"schema":1,"command":"execute"}"#.as_slice(),
        ] {
            assert!(!s.command(bytes));
        }
        assert!(!s.command(&vec![b'x'; 513]));
        assert!(!s.0.paused.load(Ordering::SeqCst));
    }
    #[test]
    fn progress_counts_durable_data_and_monotonically_sequences_snapshots() {
        let s = Session::with_options(100, false, true);
        s.advance(80, 20, 60);
        let first = s.snapshot(true).unwrap();
        assert_eq!(first["completedBytes"], 80);
        assert_eq!(first["networkBytes"], 20);
        assert_eq!(first["reusedBytes"], 60);
        assert!(
            s.snapshot(true).unwrap()["sequence"].as_u64().unwrap()
                > first["sequence"].as_u64().unwrap()
        );
        s.finish(false);
        assert_eq!(s.snapshot(true).unwrap()["phase"], "failed");
    }
}
