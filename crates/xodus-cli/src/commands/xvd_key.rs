//! `xodus-cli xvd-key status|fetch|forget`: the key that package header
//! signatures are checked with. See `crate::xvd_key`.
//!
//! None of these signs in, reads the keychain or prints key bytes; the JSON
//! carries the key's SHA-256 fingerprint and where it is kept.

use std::process::ExitCode;

use msixvc::signature::{GAME_PACKAGE_KEY_SHA256, hex};
use serde_json::json;

use crate::xvd_key::{
    self, AUTO_FETCH_ENV, FETCH_TIMEOUT, REQUIRE_SIGNED_ENV, Status, auto_fetch_paused_until,
    forget_in, key_dir, last_failure, status_of,
};

fn rfc3339(t: std::time::SystemTime) -> String {
    chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339()
}

fn settings() -> serde_json::Value {
    json!({
        "pinned": hex(&GAME_PACKAGE_KEY_SHA256),
        "required": xvd_key::signature_required(),
        "auto_fetch": xvd_key::auto_fetch_enabled(),
    })
}

fn merge(mut a: serde_json::Value, b: serde_json::Value) -> serde_json::Value {
    if let (Some(a), serde_json::Value::Object(b)) = (a.as_object_mut(), b) {
        a.extend(b);
    }
    a
}

fn status_json() -> Result<serde_json::Value, String> {
    let dir = key_dir()?;
    let last_failed = last_failure(&dir).map(rfc3339);
    // When set, an install does not fetch the key before this time.
    let paused_until = auto_fetch_paused_until(&dir).map(rfc3339);
    let mut value = match status_of(&dir, &GAME_PACKAGE_KEY_SHA256) {
        Status::Present { fingerprint } => json!({
            "status": "present",
            "fingerprint": hex(&fingerprint),
        }),
        Status::Absent => json!({ "status": "absent" }),
        Status::Invalid(detail) => json!({ "status": "invalid", "detail": detail }),
    };
    value = merge(value, settings());
    value = merge(
        value,
        json!({
            "dir": dir.display().to_string(),
            "last_failed_fetch": last_failed,
            "auto_fetch_paused_until": paused_until,
        }),
    );
    Ok(value)
}

fn fail(json_out: bool, error: &str) -> ExitCode {
    if json_out {
        println!("{}", json!({ "status": "error", "error": error }));
    } else {
        eprintln!("{error}");
    }
    ExitCode::FAILURE
}

pub fn status(json_out: bool) -> ExitCode {
    let value = match status_json() {
        Ok(value) => value,
        Err(e) => return fail(json_out, &e),
    };
    if json_out {
        println!("{value}");
    } else {
        match value["status"].as_str() {
            Some("present") => println!(
                "Package signing key present ({}); package headers are checked.",
                value["fingerprint"].as_str().unwrap_or_default()
            ),
            Some("absent") => {
                let when = if !xvd_key::auto_fetch_enabled() {
                    "with `xodus-cli xvd-key fetch` (automatic fetching is off)".to_string()
                } else if let Some(until) = value["auto_fetch_paused_until"].as_str() {
                    format!(
                        "by the first install after {until} (an automatic fetch failed), or now \
                         with `xodus-cli xvd-key fetch`"
                    )
                } else {
                    "on the next install, or now with `xodus-cli xvd-key fetch`".to_string()
                };
                println!(
                    "No package signing key. It is fetched from Microsoft Gaming Services {when}."
                )
            }
            _ => println!(
                "The stored package signing key is unusable: {}",
                value["detail"].as_str().unwrap_or_default()
            ),
        }
        println!("Kept in {}", value["dir"].as_str().unwrap_or_default());
        if xvd_key::signature_required() {
            println!("{REQUIRE_SIGNED_ENV}=1: installs without a checked signature are refused.");
        }
        if !xvd_key::auto_fetch_enabled() {
            println!("{AUTO_FETCH_ENV}=0: installs do not fetch the key.");
        }
    }
    ExitCode::SUCCESS
}

pub async fn fetch(json_out: bool) -> ExitCode {
    match tokio::time::timeout(FETCH_TIMEOUT, xvd_key::fetch(FETCH_TIMEOUT)).await {
        Ok(Ok(fetched)) => {
            if json_out {
                let value = merge(
                    json!({
                        "status": "present",
                        "fingerprint": hex(fetched.key.fingerprint()),
                        "path": fetched.path.display().to_string(),
                        "source": {
                            "bundle": fetched.bundle,
                            "package": fetched.package,
                            "file": fetched.member,
                            "bytes": fetched.bytes,
                        },
                        "seconds": (fetched.seconds * 10.0).round() / 10.0,
                    }),
                    settings(),
                );
                println!("{value}");
            } else {
                println!(
                    "Package signing key {} found in {} ({}, {}), stored in {} ({:.1} s; the \
                     download is deleted)",
                    hex(fetched.key.fingerprint()),
                    fetched.bundle,
                    fetched.package,
                    fetched.member,
                    fetched.path.display(),
                    fetched.seconds
                );
            }
            ExitCode::SUCCESS
        }
        Ok(Err(e)) => fail(json_out, &e),
        Err(_) => fail(
            json_out,
            &format!(
                "fetching the key took longer than {} s",
                FETCH_TIMEOUT.as_secs()
            ),
        ),
    }
}

pub fn forget(json_out: bool) -> ExitCode {
    let removed = match key_dir().and_then(|dir| forget_in(&dir)) {
        Ok(removed) => removed,
        Err(e) => return fail(json_out, &e),
    };
    if json_out {
        println!(
            "{}",
            merge(
                json!({ "status": "absent", "removed": removed }),
                settings()
            )
        );
    } else if removed {
        println!("Package signing key removed.");
    } else {
        println!("There was no package signing key.");
    }
    ExitCode::SUCCESS
}
