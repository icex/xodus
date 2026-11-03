//! The heartbeat loop against a local server, with credentials from a fake
//! provider. Nothing here signs in or reaches the network: the server is a
//! listener on 127.0.0.1 that answers from a script and records what it saw.

use super::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One protocol second in a test.
const SECOND: Duration = Duration::from_millis(1);
const SECRET: &str = "eyJTESTSECRETTOKENaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const XUID: &str = "2535400000000001";

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: String,
    at: Instant,
}

#[derive(Clone)]
enum Reply {
    Status(u16, Vec<(&'static str, String)>, String),
    /// Read the request, then hang up without answering.
    HangUp,
    /// Read the request and never answer it.
    Stall,
}

fn ok(heartbeat: Option<&str>) -> Reply {
    let headers = heartbeat
        .map(|value| vec![("X-Heartbeat-After", value.to_string())])
        .unwrap_or_default();
    Reply::Status(200, headers, String::new())
}

fn status(code: u16) -> Reply {
    Reply::Status(code, Vec::new(), String::new())
}

type Script = Arc<dyn Fn(&Seen, usize) -> Reply + Send + Sync>;

struct Server {
    base: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    /// POSTs are answered from `posts` in order, the last one repeating.
    /// DELETEs and GETs get 204 unless `script` says otherwise.
    async fn start(posts: Vec<Reply>) -> Server {
        let posts = Arc::new(posts);
        Server::with_script(Arc::new(move |seen: &Seen, n: usize| {
            if seen.method == "POST" {
                posts[n.min(posts.len() - 1)].clone()
            } else {
                status(204)
            }
        }))
        .await
    }

    async fn with_script(script: Script) -> Server {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let posts = Arc::new(AtomicUsize::new(0));
        let recorded = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let (script, recorded, posts) = (script.clone(), recorded.clone(), posts.clone());
                tokio::spawn(async move {
                    let _ = serve(socket, script, recorded, posts).await;
                });
            }
        });
        Server { base, seen }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn posts(&self) -> Vec<Seen> {
        self.seen()
            .into_iter()
            .filter(|s| s.method == "POST")
            .collect()
    }

    /// Resolves once the server has seen `n` requests matching `method`.
    ///
    /// A request is recorded before it is answered, so a test that needs the
    /// loop to have acted on the answer to POST n waits for POST n + 1, which
    /// the loop only sends after it has.
    fn after(&self, method: &'static str, n: usize) -> impl Future<Output = ()> + use<> {
        let seen = self.seen.clone();
        async move {
            loop {
                if seen
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|s| s.method == method)
                    .count()
                    >= n
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }
}

async fn serve(
    mut socket: tokio::net::TcpStream,
    script: Script,
    recorded: Arc<Mutex<Vec<Seen>>>,
    posts: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    let mut buffer = Vec::new();
    loop {
        let end = loop {
            if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            let mut chunk = [0u8; 4096];
            let n = socket.read(&mut chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..n]);
        };
        let head = String::from_utf8_lossy(&buffer[..end]).to_string();
        let mut lines = head.split("\r\n");
        let mut request = lines.next().unwrap_or_default().split(' ');
        let method = request.next().unwrap_or_default().to_string();
        let path = request.next().unwrap_or_default().to_string();
        let headers: HashMap<String, String> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        let length: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        while buffer.len() < end + length {
            let mut chunk = [0u8; 4096];
            let n = socket.read(&mut chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&chunk[..n]);
        }
        let body = String::from_utf8_lossy(&buffer[end..end + length]).to_string();
        buffer.drain(..end + length);

        let seen = Seen {
            method,
            path,
            headers,
            body,
            at: Instant::now(),
        };
        let n = if seen.method == "POST" {
            posts.fetch_add(1, Ordering::SeqCst)
        } else {
            0
        };
        let reply = script(&seen, n);
        recorded.lock().unwrap().push(seen);
        match reply {
            Reply::HangUp => return Ok(()),
            Reply::Stall => std::future::pending::<()>().await,
            Reply::Status(code, headers, body) => {
                let mut response = format!("HTTP/1.1 {code} Scripted\r\n");
                for (name, value) in headers {
                    response.push_str(&format!("{name}: {value}\r\n"));
                }
                response.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
                socket.write_all(response.as_bytes()).await?;
            }
        }
    }
}

/// Hands out credentials whose token names the mint, so a test can tell a
/// re-mint from a reuse.
struct Fake {
    mints: Arc<AtomicUsize>,
    /// Seconds from now the credentials expire.
    lifetime: i64,
    /// The store's sign-in. A test can flip it while the loop runs.
    signed_out: Arc<AtomicBool>,
    /// Mints after this many find the account signed out, though the
    /// sign-in check before them did not: a sign-out landing in between.
    signed_out_after: Option<usize>,
    /// Mints that fail before one succeeds.
    failing: usize,
    /// Never finish minting.
    hang: bool,
    /// Every signer handed out, in mint order, so a test can check a
    /// signature against the key that should have made it.
    signers: Arc<Mutex<Vec<RequestSigner>>>,
}

impl Fake {
    fn new() -> (Fake, Arc<AtomicUsize>) {
        let mints = Arc::new(AtomicUsize::new(0));
        (
            Fake {
                mints: mints.clone(),
                lifetime: 3600 * 16,
                signed_out: Arc::default(),
                signed_out_after: None,
                failing: 0,
                hang: false,
                signers: Arc::default(),
            },
            mints,
        )
    }
}

#[async_trait]
impl TokenProvider for Fake {
    async fn mint(&mut self) -> Result<Credentials, MintError> {
        if self.hang {
            std::future::pending::<()>().await;
        }
        if self.signed_out.load(Ordering::SeqCst) {
            return Err(MintError::SignedOut);
        }
        if self
            .signed_out_after
            .is_some_and(|limit| self.mints.load(Ordering::SeqCst) >= limit)
        {
            return Err(MintError::SignedOut);
        }
        let n = self.mints.fetch_add(1, Ordering::SeqCst) + 1;
        if n <= self.failing {
            return Err(MintError::Failed(format!("refused {SECRET}")));
        }
        let signer = RequestSigner::generate();
        self.signers.lock().unwrap().push(signer.clone());
        Ok(Credentials {
            authorization: format!("XBL3.0 x=1234;{SECRET}-{n}"),
            signer,
            policy: Some((1, 8192)),
            xuid: XUID.to_string(),
            expires_at: chrono::Utc::now().timestamp() + self.lifetime,
        })
    }

    fn signed_in(&mut self) -> bool {
        !self.signed_out.load(Ordering::SeqCst)
    }
}

/// Check a request's `Signature` header the way the service does: rebuild
/// the message from the request as received and verify it against the
/// public half of `signer`. The version and timestamp come from the header
/// itself, which is what lets a server rebuild the message at all.
fn verify_signature(seen: &Seen, signer: &RequestSigner) -> Result<(), String> {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use p256::ecdsa::signature::Verifier;

    let header = STANDARD
        .decode(seen.headers.get("signature").ok_or("no Signature header")?)
        .map_err(|e| format!("Signature is not base64: {e}"))?;
    if header.len() != 4 + 8 + 64 {
        return Err(format!("Signature is {} bytes", header.len()));
    }
    let mut message = Vec::new();
    for part in [
        &header[..4],
        &header[4..12],
        seen.method.as_bytes(),
        seen.path.as_bytes(),
        seen.headers["authorization"].as_bytes(),
        seen.body.as_bytes(),
    ] {
        message.extend_from_slice(part);
        message.push(0);
    }
    let proof = signer.proof_key();
    let coordinate = |text: &str| URL_SAFE_NO_PAD.decode(text).expect("proof key coordinate");
    let (x, y) = (coordinate(&proof.x), coordinate(&proof.y));
    let point = p256::EncodedPoint::from_affine_coordinates(
        p256::FieldBytes::from_slice(&x),
        p256::FieldBytes::from_slice(&y),
        false,
    );
    let key = p256::ecdsa::VerifyingKey::from_encoded_point(&point).expect("a P-256 key");
    let signature =
        p256::ecdsa::Signature::from_slice(&header[12..]).map_err(|e| format!("r||s: {e}"))?;
    key.verify(&message, &signature)
        .map_err(|_| "the signature does not cover this request".to_string())
}

/// Run the loop until `stop`, returning its exit status and stdout lines.
async fn drive(
    server: &Server,
    provider: Fake,
    stop: impl Future<Output = ()>,
) -> (u8, Vec<serde_json::Value>, String) {
    let client = reqwest::Client::new();
    let heartbeat = Heartbeat {
        client: &client,
        provider,
        base: server.base.clone(),
        title: "Fixture Game".into(),
        timing: Timing { second: SECOND },
        json: true,
    };
    let mut out = Vec::new();
    let code = tokio::time::timeout(Duration::from_secs(20), heartbeat.run(&mut out, stop))
        .await
        .expect("the loop finished");
    let text = String::from_utf8(out).expect("utf-8");
    let events = text
        .lines()
        .map(|line| serde_json::from_str(line).expect("every line is JSON"))
        .collect();
    (code, events, text)
}

fn names(events: &[serde_json::Value]) -> Vec<&str> {
    events
        .iter()
        .map(|e| e["event"].as_str().unwrap_or("?"))
        .collect()
}

fn post_path() -> String {
    format!("/users/xuid({XUID})/devices/current/titles/current")
}

#[test]
fn the_heartbeat_is_held_to_its_bounds_and_defaults_to_five_minutes() {
    let headers = |value: Option<&str>| {
        let mut map = reqwest::header::HeaderMap::new();
        if let Some(value) = value {
            map.insert("x-heartbeat-after", value.parse().unwrap());
        }
        map
    };
    assert_eq!(heartbeat_after(&headers(None)), 300);
    assert_eq!(heartbeat_after(&headers(Some("120"))), 120);
    assert_eq!(heartbeat_after(&headers(Some("30"))), 60);
    assert_eq!(heartbeat_after(&headers(Some("2000"))), 900);
    assert_eq!(heartbeat_after(&headers(Some("soon"))), 300);
    assert_eq!(heartbeat_after(&headers(Some("-5"))), 300);
}

#[test]
fn retry_after_reads_seconds_and_dates_and_backoff_doubles_to_five_minutes() {
    let mut map = reqwest::header::HeaderMap::new();
    assert_eq!(retry_after(&map), None);
    map.insert("retry-after", "7".parse().unwrap());
    assert_eq!(retry_after(&map), Some(7));
    map.insert("retry-after", "0".parse().unwrap());
    assert_eq!(retry_after(&map), Some(1));
    map.insert("retry-after", "999999".parse().unwrap());
    assert_eq!(retry_after(&map), Some(3600));
    let soon = chrono::Utc::now() + chrono::Duration::seconds(120);
    map.insert("retry-after", soon.to_rfc2822().parse().unwrap());
    let seconds = retry_after(&map).expect("an HTTP date");
    assert!((110..=120).contains(&seconds), "{seconds}");

    let steps: Vec<u64> = (0..8).map(backoff).collect();
    assert_eq!(steps, [15, 30, 60, 120, 240, 300, 300, 300]);
    assert_eq!(backoff(u32::MAX), 300);
}

#[test]
fn events_keep_the_documented_shape_and_key_order() {
    assert_eq!(
        Event::Online {
            title: "Halo \"Infinite\"".into(),
            heartbeat_after: 300
        }
        .to_json(),
        r#"{"schema":1,"event":"online","title":"Halo \"Infinite\"","heartbeat_after":300}"#
    );
    assert_eq!(
        Event::Retrying {
            reason: "throttled".into(),
            after: 7
        }
        .to_json(),
        r#"{"event":"retrying","reason":"throttled","in":7}"#
    );
    assert_eq!(
        Event::Error {
            fatal: true,
            code: SIGNED_OUT
        }
        .to_json(),
        r#"{"event":"error","fatal":true,"code":"signed-out"}"#
    );
    assert_eq!(Event::Offline.to_json(), r#"{"event":"offline"}"#);
    assert_eq!(Event::Busy.to_json(), r#"{"event":"busy"}"#);
}

#[tokio::test]
async fn the_post_is_signed_and_carries_no_title_id() {
    let server = Server::start(vec![ok(Some("120"))]).await;
    let (fake, _) = Fake::new();
    let (code, events, _) = drive(&server, fake, server.after("POST", 2)).await;
    assert_eq!(code, 0);
    assert_eq!(names(&events), ["online", "offline"]);
    assert_eq!(events[0]["schema"], 1);
    assert_eq!(events[0]["title"], "Fixture Game");
    assert_eq!(events[0]["heartbeat_after"], 120);

    let post = &server.posts()[0];
    assert_eq!(post.path, post_path());
    let body: serde_json::Value = serde_json::from_str(&post.body).expect("JSON body");
    assert_eq!(body, serde_json::json!({"state": "active"}));
    assert!(body.get("id").is_none(), "the title comes from the claim");
    assert_eq!(post.headers["x-xbl-contract-version"], "3");
    assert_eq!(post.headers["content-type"], "application/json");
    assert!(post.headers["authorization"].starts_with("XBL3.0 x=1234;"));
    let signature = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &post.headers["signature"],
    )
    .expect("base64 signature");
    assert_eq!(signature.len(), 4 + 8 + 64, "version, filetime, r||s");
    assert_eq!(&signature[..4], &1u32.to_be_bytes(), "policy version 1");
}

#[tokio::test]
async fn the_signature_covers_the_method_path_authorization_and_body() {
    let server = Server::start(vec![ok(Some("60"))]).await;
    let (fake, _) = Fake::new();
    let signers = fake.signers.clone();
    let (code, _, _) = drive(&server, fake, server.after("POST", 2)).await;
    assert_eq!(code, 0);
    let signer = signers.lock().unwrap()[0].clone();
    let seen = server.seen();
    let post = seen.iter().find(|s| s.method == "POST").expect("a POST");
    let delete = seen
        .iter()
        .find(|s| s.method == "DELETE")
        .expect("a DELETE");
    assert_eq!(post.body, ACTIVE_BODY);
    assert!(delete.body.is_empty());
    verify_signature(post, &signer).expect("the POST verifies");
    verify_signature(delete, &signer).expect("the DELETE verifies");

    // The check itself has to tell a wrong input from a right one, or the
    // two lines above prove nothing.
    let other = RequestSigner::generate();
    assert!(verify_signature(post, &other).is_err(), "another key");
    let mut changed = post.clone();
    changed.path = format!("{}{}", server.base, post.path);
    assert!(verify_signature(&changed, &signer).is_err(), "the full URL");
    let mut changed = post.clone();
    changed.method = "PUT".into();
    assert!(verify_signature(&changed, &signer).is_err(), "the method");
    let mut changed = post.clone();
    changed.body = r#"{"state":"active","id":"1"}"#.into();
    assert!(verify_signature(&changed, &signer).is_err(), "the body");
    let mut changed = post.clone();
    changed
        .headers
        .insert("authorization".into(), "XBL3.0 x=1234;other".into());
    assert!(verify_signature(&changed, &signer).is_err(), "the token");
}

#[tokio::test]
async fn a_route_without_a_signature_policy_is_sent_unsigned() {
    struct Unsigned(Fake);
    #[async_trait]
    impl TokenProvider for Unsigned {
        async fn mint(&mut self) -> Result<Credentials, MintError> {
            let mut credentials = self.0.mint().await?;
            credentials.policy = None;
            Ok(credentials)
        }

        fn signed_in(&mut self) -> bool {
            self.0.signed_in()
        }
    }
    let server = Server::start(vec![ok(None)]).await;
    let (fake, _) = Fake::new();
    let client = reqwest::Client::new();
    let heartbeat = Heartbeat {
        client: &client,
        provider: Unsigned(fake),
        base: server.base.clone(),
        title: "Fixture Game".into(),
        timing: Timing { second: SECOND },
        json: true,
    };
    let mut out = Vec::new();
    assert_eq!(heartbeat.run(&mut out, server.after("POST", 1)).await, 0);
    assert!(!server.posts()[0].headers.contains_key("signature"));
}

#[tokio::test]
async fn the_next_heartbeat_waits_as_long_as_the_server_asked_held_to_the_minimum() {
    // 30 is below the floor, so the loop must wait 60, not 30.
    let server = Server::start(vec![ok(Some("30"))]).await;
    let (fake, mints) = Fake::new();
    let (code, events, _) = drive(&server, fake, server.after("POST", 3)).await;
    assert_eq!(code, 0);
    assert_eq!(
        names(&events),
        ["online", "offline"],
        "online once, not per heartbeat"
    );
    assert_eq!(events[0]["heartbeat_after"], 60);
    let posts = server.posts();
    for pair in posts.windows(2) {
        let gap = pair[1].at - pair[0].at;
        assert!(gap >= SECOND * 60, "heartbeat came after {gap:?}");
    }
    assert_eq!(
        mints.load(Ordering::SeqCst),
        1,
        "one identity, so one device, for the whole run"
    );
    let authorizations: Vec<_> = posts.iter().map(|p| &p.headers["authorization"]).collect();
    assert!(authorizations.windows(2).all(|w| w[0] == w[1]));
}

#[tokio::test]
async fn a_missing_heartbeat_header_means_five_minutes_and_a_huge_one_fifteen() {
    for (header, expected) in [(None, 300), (Some("2000"), 900)] {
        let server = Server::start(vec![ok(header)]).await;
        let (fake, _) = Fake::new();
        let (_, events, _) = drive(&server, fake, server.after("POST", 2)).await;
        assert_eq!(events[0]["heartbeat_after"], expected, "{header:?}");
    }
}

#[tokio::test]
async fn throttling_follows_retry_after_then_announces_online_again() {
    let server = Server::start(vec![
        ok(Some("60")),
        Reply::Status(429, vec![("Retry-After", "50".into())], String::new()),
        ok(Some("60")),
    ])
    .await;
    let (fake, _) = Fake::new();
    let (code, events, _) = drive(&server, fake, server.after("POST", 4)).await;
    assert_eq!(code, 0);
    assert_eq!(names(&events), ["online", "retrying", "online", "offline"]);
    assert_eq!(events[1]["reason"], "throttled");
    assert_eq!(events[1]["in"], 50);
    let posts = server.posts();
    assert!(posts[2].at - posts[1].at >= SECOND * 50);
}

#[tokio::test]
async fn unavailable_without_retry_after_backs_off() {
    let server = Server::start(vec![status(503), status(500), ok(None)]).await;
    let (fake, _) = Fake::new();
    let (_, events, _) = drive(&server, fake, server.after("POST", 4)).await;
    assert_eq!(
        names(&events),
        ["retrying", "retrying", "online", "offline"]
    );
    assert_eq!(events[0]["reason"], "unavailable");
    assert_eq!(events[0]["in"], 15);
    assert_eq!(events[1]["reason"], "server error 500");
    assert_eq!(events[1]["in"], 30);
}

#[tokio::test]
async fn a_401_mints_again_once_and_carries_on() {
    let server = Server::start(vec![status(401), ok(Some("60"))]).await;
    let (fake, mints) = Fake::new();
    let (code, events, _) = drive(&server, fake, server.after("POST", 3)).await;
    assert_eq!(code, 0);
    assert_eq!(names(&events), ["online", "offline"]);
    assert_eq!(mints.load(Ordering::SeqCst), 2);
    let posts = server.posts();
    assert!(posts[0].headers["authorization"].ends_with("-1"));
    assert!(posts[1].headers["authorization"].ends_with("-2"));
}

#[tokio::test]
async fn a_second_401_in_a_row_is_fatal() {
    let server = Server::start(vec![status(401)]).await;
    let (fake, mints) = Fake::new();
    let (code, events, _) = drive(&server, fake, std::future::pending()).await;
    assert_eq!(code, 1);
    assert_eq!(names(&events), ["error"]);
    assert_eq!(events[0]["fatal"], true);
    assert_eq!(events[0]["code"], "unauthorized");
    assert_eq!(mints.load(Ordering::SeqCst), 2, "re-minted exactly once");
    assert_eq!(server.posts().len(), 2);
}

#[tokio::test]
async fn the_re_mint_allowance_comes_back_after_a_good_heartbeat() {
    let server = Server::start(vec![
        status(401),
        ok(Some("60")),
        status(401),
        ok(Some("60")),
    ])
    .await;
    let (fake, mints) = Fake::new();
    let (code, events, _) = drive(&server, fake, server.after("POST", 5)).await;
    assert_eq!(code, 0);
    assert_eq!(names(&events), ["online", "offline"]);
    assert_eq!(mints.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn forbidden_and_signed_out_are_fatal() {
    let server = Server::start(vec![status(403)]).await;
    let (fake, _) = Fake::new();
    let (code, events, _) = drive(&server, fake, std::future::pending()).await;
    assert_eq!((code, events[0]["code"].as_str()), (1, Some("forbidden")));

    let server = Server::start(vec![ok(None)]).await;
    let (fake, _) = Fake::new();
    fake.signed_out.store(true, Ordering::SeqCst);
    let (code, events, _) = drive(&server, fake, std::future::pending()).await;
    assert_eq!(code, 1);
    assert_eq!(
        events,
        [serde_json::json!({"event":"error","fatal":true,"code":"signed-out"})]
    );
    assert!(
        server.seen().is_empty(),
        "nothing is sent without a sign-in"
    );
}

#[tokio::test]
async fn network_failures_back_off_and_recover() {
    let server = Server::start(vec![Reply::HangUp, Reply::HangUp, ok(None)]).await;
    let (fake, mints) = Fake::new();
    let (code, events, _) = drive(&server, fake, server.after("POST", 4)).await;
    assert_eq!(code, 0);
    assert_eq!(
        names(&events),
        ["retrying", "retrying", "online", "offline"]
    );
    assert_eq!(events[0]["reason"], "network");
    assert_eq!(events[0]["in"], 15);
    assert_eq!(events[1]["in"], 30);
    assert_eq!(
        mints.load(Ordering::SeqCst),
        1,
        "the network is not the token"
    );

    // Nothing listening at all.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let gone = Server {
        base,
        seen: Arc::default(),
    };
    let (fake, _) = Fake::new();
    let stop = async {
        tokio::time::sleep(SECOND * 100).await;
    };
    let (code, events, _) = drive(&gone, fake, stop).await;
    assert_eq!(code, 0);
    assert_eq!(events[0]["event"], "retrying");
    assert_eq!(events[0]["reason"], "network");
    assert_eq!(events.last().unwrap()["event"], "offline");
}

#[tokio::test]
async fn a_failed_mint_retries_without_giving_up() {
    let server = Server::start(vec![ok(None)]).await;
    let (mut fake, mints) = Fake::new();
    fake.failing = 2;
    let (code, events, text) = drive(&server, fake, server.after("POST", 2)).await;
    assert_eq!(code, 0);
    assert_eq!(
        names(&events),
        ["retrying", "retrying", "online", "offline"]
    );
    assert_eq!(events[0]["reason"], "sign-in");
    assert_eq!(mints.load(Ordering::SeqCst), 3);
    assert!(!text.contains(SECRET));
}

#[tokio::test]
async fn credentials_near_expiry_are_minted_again_before_the_next_post() {
    let server = Server::start(vec![ok(Some("60"))]).await;
    let (mut fake, mints) = Fake::new();
    fake.lifetime = 60; // inside the ten-minute margin
    let (code, _, _) = drive(&server, fake, server.after("POST", 3)).await;
    assert_eq!(code, 0);
    assert!(mints.load(Ordering::SeqCst) >= 3);
}

#[tokio::test]
async fn a_sign_out_mid_run_takes_the_record_down_within_a_minute() {
    // A long heartbeat, so a sign-out noticed only at the next one would
    // come fifteen minutes late.
    let server = Server::start(vec![ok(Some("900"))]).await;
    let (fake, mints) = Fake::new();
    let signed_out = fake.signed_out.clone();
    let posted = server.after("POST", 1);
    tokio::spawn(async move {
        posted.await;
        signed_out.store(true, Ordering::SeqCst);
    });
    let (code, events, _) = drive(&server, fake, std::future::pending()).await;
    assert_eq!(code, 1);
    assert_eq!(names(&events), ["online", "error"]);
    assert_eq!(
        events[1],
        serde_json::json!({"event":"error","fatal":true,"code":"signed-out"})
    );
    assert_eq!(mints.load(Ordering::SeqCst), 1);
    let seen = server.seen();
    let methods: Vec<&str> = seen.iter().map(|s| s.method.as_str()).collect();
    assert_eq!(
        methods,
        ["POST", "DELETE"],
        "deleted, and nothing posted after"
    );
    let delete = &seen[1];
    assert_eq!(delete.path, post_path());
    assert!(delete.headers["authorization"].ends_with("-1"));
    let gap = delete.at - seen[0].at;
    assert!(gap < SECOND * 600, "noticed after {gap:?}");
}

#[tokio::test]
async fn a_sign_out_found_by_a_re_mint_still_deletes_with_the_old_credentials() {
    let server = Server::start(vec![ok(Some("60"))]).await;
    let (mut fake, mints) = Fake::new();
    fake.lifetime = 300; // inside the margin, so the next round mints again
    fake.signed_out_after = Some(1);
    let (code, events, _) = drive(&server, fake, std::future::pending()).await;
    assert_eq!(code, 1);
    assert_eq!(names(&events), ["online", "error"]);
    assert_eq!(events[1]["code"], "signed-out");
    assert_eq!(mints.load(Ordering::SeqCst), 1);
    let seen = server.seen();
    let methods: Vec<&str> = seen.iter().map(|s| s.method.as_str()).collect();
    assert_eq!(methods, ["POST", "DELETE"]);
    assert!(seen[1].headers["authorization"].ends_with("-1"));
}

#[tokio::test]
async fn a_re_mint_before_expiry_deletes_the_old_devices_record_first() {
    let server = Server::start(vec![ok(Some("60"))]).await;
    let (mut fake, _) = Fake::new();
    fake.lifetime = 300; // inside the margin: every round is a new device
    let (code, _, _) = drive(&server, fake, server.after("POST", 3)).await;
    assert_eq!(code, 0);
    let seen = server.seen();
    let by = |method: &str, n: usize| -> Vec<usize> {
        let suffix = format!("-{n}");
        seen.iter()
            .enumerate()
            .filter(|(_, s)| s.method == method && s.headers["authorization"].ends_with(&suffix))
            .map(|(at, _)| at)
            .collect()
    };
    for n in 1..=2 {
        let deletes = by("DELETE", n);
        assert_eq!(deletes.len(), 1, "one delete for device {n}");
        let next_post = by("POST", n + 1)[0];
        assert!(
            deletes[0] < next_post,
            "device {n}'s record goes before device {} posts",
            n + 1
        );
        assert_eq!(seen[deletes[0]].path, post_path());
    }
    // The last device's record goes when the run stops.
    assert_eq!(by("DELETE", 3).len(), 1);
    assert_eq!(seen.last().unwrap().method, "DELETE");
}

#[tokio::test]
async fn a_401_leaves_nothing_to_delete_before_the_re_mint() {
    let server = Server::start(vec![status(401), ok(Some("60"))]).await;
    let (fake, _) = Fake::new();
    let (code, _, _) = drive(&server, fake, server.after("POST", 3)).await;
    assert_eq!(code, 0);
    let methods: Vec<String> = server.seen().into_iter().map(|s| s.method).collect();
    assert_eq!(methods, ["POST", "POST", "POST", "DELETE"]);
}

#[tokio::test]
async fn stopping_deletes_the_same_record_then_says_offline() {
    let server = Server::start(vec![ok(Some("60"))]).await;
    let (fake, _) = Fake::new();
    let (code, events, _) = drive(&server, fake, server.after("POST", 2)).await;
    assert_eq!(code, 0);
    assert_eq!(names(&events), ["online", "offline"]);
    let seen = server.seen();
    let delete = seen
        .iter()
        .find(|s| s.method == "DELETE")
        .expect("a DELETE");
    assert_eq!(delete.path, post_path());
    assert_eq!(delete.headers["x-xbl-contract-version"], "3");
    assert!(delete.headers.contains_key("signature"));
    assert!(delete.body.is_empty());
    assert_eq!(seen.last().unwrap().method, "DELETE", "nothing after it");
}

#[tokio::test]
async fn a_delete_that_hangs_is_abandoned_after_five_seconds() {
    let server = Server::with_script(Arc::new(|seen: &Seen, _| {
        if seen.method == "DELETE" {
            Reply::Stall
        } else {
            ok(None)
        }
    }))
    .await;
    let (fake, _) = Fake::new();
    // Five protocol seconds is 5 ms here; a delete waited on for good would
    // run into drive's own 20 s limit instead.
    let started = Instant::now();
    let (code, events, _) = drive(&server, fake, server.after("POST", 2)).await;
    assert_eq!(code, 0);
    assert_eq!(names(&events), ["online", "offline"]);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    assert!(server.seen().iter().any(|s| s.method == "DELETE"));
}

#[tokio::test]
async fn stopping_while_minting_says_offline_and_deletes_nothing() {
    let server = Server::start(vec![ok(None)]).await;
    let (mut fake, _) = Fake::new();
    fake.hang = true;
    let stop = async {
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let (code, events, _) = drive(&server, fake, stop).await;
    assert_eq!(code, 0);
    assert_eq!(names(&events), ["offline"]);
    assert!(server.seen().is_empty());
}

#[tokio::test]
async fn end_of_stdin_stops_the_run() {
    use std::os::unix::net::UnixStream;
    let server = Server::start(vec![ok(Some("60"))]).await;
    let (fake, _) = Fake::new();
    let (mut launcher, child) = UnixStream::pair().expect("pipe");
    let eof = end_of_input(child);
    let posted = server.after("POST", 2);
    tokio::spawn(async move {
        posted.await;
        // Input before the close is ignored, not taken as a command.
        launcher.write_all(b"anything\n").expect("write");
        drop(launcher);
    });
    let (code, events, _) = drive(&server, fake, eof).await;
    assert_eq!(code, 0);
    assert_eq!(names(&events), ["online", "offline"]);
    assert_eq!(server.seen().last().unwrap().method, "DELETE");
}

#[tokio::test]
async fn sigterm_stops_the_run() {
    let server = Server::start(vec![ok(Some("60"))]).await;
    let (fake, _) = Fake::new();
    // The handlers are in place once this returns, so the signal below is
    // caught rather than killing the test binary.
    let terminated = termination().expect("signal handlers");
    let posted = server.after("POST", 2);
    tokio::spawn(async move {
        posted.await;
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGTERM).expect("raise");
    });
    let (code, events, _) = drive(&server, fake, terminated).await;
    assert_eq!(code, 0);
    assert_eq!(names(&events), ["online", "offline"]);
    assert_eq!(server.seen().last().unwrap().method, "DELETE");
}

#[test]
fn a_second_runner_for_the_same_profile_is_busy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let first = match lock(dir.path(), "0123456789abcdef0123456789abcdef") {
        Ok(file) => file,
        Err(_) => panic!("the first runner takes the lock"),
    };
    assert!(matches!(
        lock(dir.path(), "0123456789abcdef0123456789abcdef"),
        Err(LockError::Busy)
    ));
    assert!(
        lock(dir.path(), "default").is_ok(),
        "another profile has its own lock"
    );
    drop(first);
    assert!(
        lock(dir.path(), "0123456789abcdef0123456789abcdef").is_ok(),
        "released when the runner goes"
    );
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(dir.path().join("presence-default.lock"))
            .unwrap()
            .permissions(),
    );
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn the_lock_does_not_follow_a_planted_symlink() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("elsewhere");
    std::fs::write(&target, b"keep").unwrap();
    let profile = "0123456789abcdef0123456789abcdef";
    std::os::unix::fs::symlink(&target, dir.path().join(format!("presence-{profile}.lock")))
        .unwrap();
    assert!(matches!(lock(dir.path(), profile), Err(LockError::Io(_))));
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");
}

#[test]
fn the_lock_is_refused_when_it_is_not_a_regular_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("presence-default.lock")).unwrap();
    assert!(matches!(lock(dir.path(), "default"), Err(LockError::Io(_))));
}

#[test]
fn a_profile_id_cannot_name_a_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    for profile in ["../x", "a/b", "", "0123456789ABCDEF0123456789ABCDEF"] {
        assert!(
            matches!(lock(dir.path(), profile), Err(LockError::Io(_))),
            "{profile:?}"
        );
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

fn mode_of(path: &Path) -> u32 {
    std::os::unix::fs::PermissionsExt::mode(&std::fs::symlink_metadata(path).unwrap().permissions())
        & 0o777
}

#[test]
fn the_runtime_dir_is_a_private_candidate_or_one_under_the_profile_root() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = tempfile::tempdir().expect("tempdir");
    let root = scratch.path().join("state/xodus/accounts");

    // A private candidate is used as it is.
    let private = scratch.path().join("private");
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        choose_runtime_dir(std::slice::from_ref(&private), &root).unwrap(),
        private
    );
    assert!(!root.exists(), "nothing created when a candidate will do");

    // Missing, relative or symlinked candidates are passed over, and the
    // fallback is made private under the profile root.
    let link = scratch.path().join("link");
    std::os::unix::fs::symlink(&private, &link).unwrap();
    let candidates = [
        scratch.path().join("missing"),
        PathBuf::from("relative"),
        link,
    ];
    let chosen = choose_runtime_dir(&candidates, &root).unwrap();
    assert_eq!(chosen, root.join(".run"));
    assert_eq!(mode_of(&chosen), 0o700);
    assert_eq!(mode_of(&root), 0o700);

    // A candidate open to others is passed over and left as it is; the
    // fallback, which is this client's own, is tightened if it was opened.
    let open = scratch.path().join("open");
    std::fs::create_dir(&open).unwrap();
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
    std::fs::set_permissions(root.join(".run"), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        choose_runtime_dir(std::slice::from_ref(&open), &root).unwrap(),
        root.join(".run")
    );
    assert_eq!(mode_of(&open), 0o777);
    assert_eq!(mode_of(&root.join(".run")), 0o700);

    // A fallback that was tampered into a symlink is refused, not followed.
    std::fs::remove_dir(root.join(".run")).unwrap();
    std::os::unix::fs::symlink(&private, root.join(".run")).unwrap();
    assert!(choose_runtime_dir(&[], &root).is_err());
}

#[test]
fn the_runtime_dir_never_falls_back_to_the_shared_temp_dir() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let root = scratch.path().join("accounts");
    // Named outright, the shared temp dir is still passed over: it is open
    // to everyone, and nobody else's is private to this user.
    let chosen = choose_runtime_dir(&[PathBuf::from("/tmp")], &root).unwrap();
    assert_eq!(chosen, root.join(".run"));
}

#[tokio::test]
async fn no_token_reaches_stdout_whatever_happens() {
    let scripts = vec![
        vec![ok(None)],
        vec![status(401)],
        vec![status(403)],
        vec![Reply::HangUp, status(429), ok(None)],
    ];
    for posts in scripts {
        let server = Server::start(posts).await;
        let (mut fake, _) = Fake::new();
        fake.failing = 1;
        let (_, _, text) = drive(&server, fake, server.after("POST", 3)).await;
        assert!(!text.contains(SECRET), "{text}");
        assert!(!text.contains("XBL3.0"), "{text}");
        assert!(
            server
                .seen()
                .iter()
                .all(|s| s.headers["authorization"].contains(SECRET)),
            "the token goes to the server and nowhere else"
        );
    }
    let (mut fake, _) = Fake::new();
    let credentials = fake.mint().await.unwrap();
    assert!(!format!("{credentials:?}").contains(SECRET));
}

#[test]
fn diagnostics_are_scrubbed_of_anything_token_shaped() {
    let line = format!("xsts said no for XBL3.0 x=1234;{SECRET} (HTTP 401)");
    let scrubbed = scrub(&line);
    assert!(!scrubbed.contains(SECRET), "{scrubbed}");
    assert!(scrubbed.contains("HTTP 401"));
    let kept = "heartbeat answered HTTP 503 (MS-CV 0123456789abcdef0123456789abcdef.0) for \
                url (https://userpresence.xboxlive.com/users/xuid(2535400000000001)/devices)";
    assert_eq!(scrub(kept), kept, "what a failure is chased with survives");
    let ticket = "t=EwB4A+l3BAAU2kNaBZ0w/8lMxkSUAgAAAX+example+ticket/AAA=";
    assert!(!scrub(ticket).contains("EwB4A"), "{}", scrub(ticket));
}

#[test]
fn the_url_override_is_honoured_and_trimmed() {
    assert_eq!(
        base_url_from(Some("http://127.0.0.1:9/".into())),
        "http://127.0.0.1:9"
    );
    assert_eq!(base_url_from(Some("  ".into())), PRESENCE_URL);
    assert_eq!(base_url_from(None), PRESENCE_URL);
    assert_eq!(
        title_url(PRESENCE_URL, "42"),
        "https://userpresence.xboxlive.com/users/xuid(42)/devices/current/titles/current"
    );
}

fn write_config(dir: &Path, xml: &str) {
    std::fs::write(dir.join("MicrosoftGame.config"), xml).expect("write config");
}

#[test]
fn the_title_and_its_name_come_from_the_game_config() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_config(
        dir.path(),
        r#"<Game configVersion="1"><TitleId>69C7AA31</TitleId>
<MSAAppId>cb41e2e1-503c-48ac-98b6-55b194b4ab66</MSAAppId>
<ShellVisuals DefaultDisplayName="Fixture &amp; Friends" PublisherDisplayName="Studio"/></Game>"#,
    );
    let (identity, name) = resolve_identity(Some(dir.path()), None, None).expect("identity");
    assert_eq!(identity.title_id, 0x69C7_AA31);
    assert_eq!(identity.client_id, "cb41e2e1-503c-48ac-98b6-55b194b4ab66");
    assert_eq!(name, "Fixture & Friends");

    // Explicit ids win, but the directory still names the game.
    let (identity, name) =
        resolve_identity(Some(dir.path()), Some(42), Some("explicit".into())).expect("explicit");
    assert_eq!(
        (identity.title_id, identity.client_id.as_str()),
        (42, "explicit")
    );
    assert_eq!(name, "Fixture & Friends");

    let (_, name) = resolve_identity(None, Some(42), Some("explicit".into())).expect("ids only");
    assert_eq!(name, "42");

    // Half a pair is not mixed with the directory's other half; the
    // directory supplies the whole identity, as in xbl-check.
    let (identity, _) =
        resolve_identity(Some(dir.path()), Some(42), None).expect("the directory's identity");
    assert_eq!(identity.title_id, 0x69C7_AA31);
    assert_eq!(identity.client_id, "cb41e2e1-503c-48ac-98b6-55b194b4ab66");
    let (identity, _) = resolve_identity(Some(dir.path()), None, Some("explicit".into()))
        .expect("the directory's identity");
    assert_eq!(identity.client_id, "cb41e2e1-503c-48ac-98b6-55b194b4ab66");
}

#[test]
fn a_localised_name_falls_back_to_the_title_id() {
    assert_eq!(
        display_name(
            Some(r#"<ShellVisuals DefaultDisplayName="ms-resource:AppName"/>"#),
            1774692913
        ),
        "1774692913"
    );
    assert_eq!(display_name(None, 7), "7");
}

#[test]
fn no_msa_app_id_means_no_title_identity_rather_than_a_borrowed_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_config(dir.path(), "<Game><TitleId>10203040</TitleId></Game>");
    let error = resolve_identity(Some(dir.path()), None, None).expect_err("no MSAAppId");
    assert!(error.contains("MSAAppId"), "{error}");
    assert!(resolve_identity(None, Some(42), None).is_err());
    assert!(resolve_identity(None, Some(42), Some(" ".into())).is_err());
    let missing = dir.path().join("nowhere");
    assert!(resolve_identity(Some(&missing), None, None).is_err());
}

#[test]
fn the_server_status_is_reduced_to_what_a_badge_shows() {
    let presence = serde_json::json!({
        "xuid": XUID,
        "state": "Online",
        "devices": [
            {"type": "Scarlett", "titles": [
                {"id": "750323071", "name": "Home", "placement": "Background", "state": "Active"},
                {"id": 1774692913u64, "name": "Fixture Game", "placement": "Full"}
            ]},
            {"type": "WindowsOneCore"}
        ],
        "lastSeen": {"titleName": "ignored"}
    });
    assert_eq!(
        summarize(&presence),
        serde_json::json!({"schema": 1, "state": "Online", "devices": [
            {"type": "Scarlett", "titles": [
                {"id": "750323071", "name": "Home"},
                {"id": "1774692913", "name": "Fixture Game"}
            ]},
            {"type": "WindowsOneCore", "titles": []}
        ]})
    );
    for (state, expected) in [
        ("away", "Away"),
        ("Offline", "Offline"),
        ("Cloaked", "Offline"),
        ("", "Offline"),
    ] {
        assert_eq!(
            summarize(&serde_json::json!({ "state": state }))["state"],
            expected
        );
    }
    assert_eq!(
        summarize(&serde_json::json!({}))["devices"],
        serde_json::json!([])
    );
}

#[tokio::test]
async fn get_reads_the_accounts_own_presence_in_contract_3() {
    let server = Server::with_script(Arc::new(|seen: &Seen, _| {
        if seen.method == "GET" {
            Reply::Status(
                200,
                vec![("Content-Type", "application/json".into())],
                r#"{"xuid":"1","state":"Away","devices":[{"type":"Android","titles":[{"id":"328178078","name":"Xbox App"}]}]}"#.into(),
            )
        } else {
            status(405)
        }
    }))
    .await;
    let client = reqwest::Client::new();
    let summary = fetch(&client, &server.base, &format!("XBL3.0 x=1;{SECRET}"))
        .await
        .expect("summary");
    assert_eq!(summary["state"], "Away");
    assert_eq!(summary["devices"][0]["titles"][0]["name"], "Xbox App");
    let seen = &server.seen()[0];
    assert_eq!(seen.path, "/users/me?level=all");
    assert_eq!(seen.headers["x-xbl-contract-version"], "3");

    let refused = Server::with_script(Arc::new(|_: &Seen, _| status(401))).await;
    let error = fetch(&client, &refused.base, "XBL3.0 x=1;t")
        .await
        .unwrap_err();
    assert!(error.starts_with("unauthorized"), "{error}");
}

#[test]
fn the_capability_list_advertises_presence() {
    assert!(super::super::profiles::CAPABILITIES.contains(&"presence-v1"));
    assert!(super::super::profiles::CAPABILITIES.contains(&"store-player-accounts"));
}

#[tokio::test]
async fn a_stalled_heartbeat_does_not_hold_up_a_stop() {
    let server = Server::with_script(Arc::new(|seen: &Seen, _| {
        if seen.method == "POST" {
            Reply::Stall
        } else {
            status(204)
        }
    }))
    .await;
    let (fake, _) = Fake::new();
    // Real seconds: the 30-second request timeout must not be what ends the
    // POST here, only the stop.
    let timing = Timing {
        second: Duration::from_secs(1),
    };
    let client = reqwest::Client::new();
    let heartbeat = Heartbeat {
        client: &client,
        provider: fake,
        base: server.base.clone(),
        title: "Fixture Game".into(),
        timing,
        json: true,
    };
    let mut out = Vec::new();
    let started = Instant::now();
    let code = heartbeat.run(&mut out, server.after("POST", 1)).await;
    assert_eq!(code, 0);
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(String::from_utf8(out).unwrap(), "{\"event\":\"offline\"}\n");
    assert_eq!(server.seen().last().unwrap().method, "DELETE");
}
