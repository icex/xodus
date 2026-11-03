//! Show the player as playing the game a launcher started, and read back what
//! friends see.
//!
//! On Windows the Game Bar keeps a title's presence alive: while the game runs
//! it re-posts `{"state":"active"}` to `titles/current` under the game's own
//! identity, as often as the service asks. Under Proton nothing does that, so a
//! game started from a launcher never shows up on anyone's friends list.
//!
//! `presence run` is that writer. It is a long-running child: the launcher
//! starts it next to the game and closes its stdin when the game exits. It
//! mints one SISU identity for the game's own TitleId and MSAAppId and keeps it
//! in memory for the whole run. A command per heartbeat would mint a new key,
//! and so a new device, every few minutes.
//!
//! It never borrows another title's identity. A game whose config carries no
//! MSAAppId gets `no-title-identity`, not a stand-in claim, because a wrong
//! claim shows friends the wrong game.
//!
//! The protocol on stdout is one JSON object per line:
//!
//!   {"schema":1,"event":"online","title":"<name>","heartbeat_after":N}
//!   {"event":"retrying","reason":"<why>","in":N}
//!   {"event":"error","fatal":true,"code":"unauthorized|forbidden|signed-out|network|no-title-identity"}
//!   {"event":"offline"}
//!   {"event":"busy"}
//!
//! `online` is written when the service first accepts the title, and again
//! after any `retrying`. `offline` is the last line of a run that was asked to
//! stop: the record has been deleted, or the delete was tried and the record
//! will expire on its own. A fatal `error` is the last line of a run that could
//! not go on, and its exit status is 1. `busy` means another runner already
//! holds this profile's lock, and its exit status is 3.
//!
//! The `reason` of a `retrying` is `network`, `throttled` (429), `unavailable`
//! (503), `server error <code>`, `refused with <code>` or `sign-in` (the
//! title's token could not be minted). None of them ends the run, which is why
//! the `network` error code is in the protocol but this runner never sends it.
//!
//! Nothing here prints a token, on stdout or on stderr. Diagnostics go to
//! stderr and are scrubbed of anything token-shaped first.
//!
//! `presence get` is the one-shot read for a status badge: the account's own
//! presence, mapped to the few fields a launcher shows.

use std::fmt;
use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use async_trait::async_trait;
use uuid::Uuid;
use xodus::api::xbox::RequestSigner;
use xodus::models::secrets::Token;
use xodus::tokens::{TokenManager, store::TokenStoreError};

use super::xblcheck::TitleIdentity;

/// Where presence lives. `XODUS_PRESENCE_URL` replaces it, so tests can point
/// both commands at a local server.
pub const PRESENCE_URL: &str = "https://userpresence.xboxlive.com";
const PRESENCE_URL_ENV: &str = "XODUS_PRESENCE_URL";
/// Every presence route answers in contract version 3.
const CONTRACT_VERSION: &str = "3";
const XBOXLIVE_RELYING_PARTY: &str = "http://xboxlive.com";

/// The heartbeat bounds. The service says how long it will keep the record in
/// `X-Heartbeat-After`; this keeps a missing or absurd value from either
/// hammering it or letting the record lapse.
const HEARTBEAT_MIN: u64 = 60;
const HEARTBEAT_MAX: u64 = 900;
const HEARTBEAT_FALLBACK: u64 = 300;
/// Network failures back off from here, doubling up to five minutes.
const BACKOFF_FIRST: u64 = 15;
const BACKOFF_MAX: u64 = 300;
/// A `Retry-After` longer than this is treated as this.
const RETRY_AFTER_MAX: u64 = 3600;
/// Mint again once the credentials have less than this left.
const REMINT_MARGIN: i64 = 600;
/// A wait between heartbeats looks at the sign-in this often, so a sign-out
/// from anywhere takes the record down within a minute rather than a whole
/// heartbeat later.
const SIGN_IN_POLL: u64 = 60;
/// The final delete gets this long before the run gives up on it.
const DELETE_TIMEOUT: u64 = 5;
const REQUEST_TIMEOUT: u64 = 30;

/// Exit status when another runner holds the profile's lock.
pub const EXIT_BUSY: u8 = 3;

pub fn base_url() -> String {
    base_url_from(std::env::var(PRESENCE_URL_ENV).ok())
}

fn base_url_from(setting: Option<String>) -> String {
    setting
        .map(|url| url.trim().trim_end_matches('/').to_string())
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| PRESENCE_URL.to_string())
}

/// The route a title's own presence is written to.
fn title_url(base: &str, xuid: &str) -> String {
    format!("{base}/users/xuid({xuid})/devices/current/titles/current")
}

/// What one run authenticates with. The authorization header is the whole
/// secret, so Debug leaves it out.
pub struct Credentials {
    /// `XBL3.0 x=<uhs>;<token>`.
    pub authorization: String,
    /// The key the token was minted under. Signatures from any other key are
    /// rejected.
    pub signer: RequestSigner,
    /// Signature policy version and body limit, or `None` when the endpoint
    /// table says the route is not signed.
    pub policy: Option<(u32, usize)>,
    pub xuid: String,
    /// Unix time the earliest token in the chain expires.
    pub expires_at: i64,
}

impl Credentials {
    /// Whether the service still takes these. A record they wrote can be
    /// deleted with them until then.
    fn usable(&self) -> bool {
        self.expires_at > chrono::Utc::now().timestamp()
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("authorization", &"<redacted>")
            .field("policy", &self.policy)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum MintError {
    /// No signed-in user for this profile. Retrying cannot fix that.
    SignedOut,
    /// Anything else. The message is for stderr, after scrubbing.
    Failed(String),
}

/// Where credentials come from. The real one runs SISU for the game; tests
/// hand out fixed ones so the heartbeat loop can run against a local server.
#[async_trait]
pub trait TokenProvider: Send {
    async fn mint(&mut self) -> Result<Credentials, MintError>;

    /// Whether the account is still signed in. Credentials already minted
    /// keep working after a sign-out, so the loop asks this before every
    /// heartbeat and during the waits between them. Only a sign-in that is
    /// gone answers false; a store that cannot be read right now does not end
    /// a game's presence.
    fn signed_in(&mut self) -> bool;
}

/// The game's own identity: SISU with its MSAAppId and TitleId, then an XSTS
/// token for xboxlive.com carrying that title claim and the SISU device claim.
/// `titles/current` resolves both, and refuses a token missing either.
pub struct TitleMinter<'a> {
    client: &'a reqwest::Client,
    tokens: &'a TokenManager,
    identity: TitleIdentity,
    /// Looked up once per run; the endpoint table does not change under it.
    policy: Option<Option<(u32, usize)>>,
}

impl<'a> TitleMinter<'a> {
    pub fn new(
        client: &'a reqwest::Client,
        tokens: &'a TokenManager,
        identity: TitleIdentity,
    ) -> Self {
        Self {
            client,
            tokens,
            identity,
            policy: None,
        }
    }

    /// The signature policy the endpoint table gives presence. The same
    /// lookup the service does for a title's own calls, against the default
    /// table. If the table cannot be fetched or does not list presence, sign
    /// with policy version 1 and an 8192-byte body limit, the policy the
    /// client already signs authentication with: a signature a service does
    /// not check costs nothing, and a missing one it does check is a 401.
    async fn signature_policy(&mut self) -> Option<(u32, usize)> {
        if let Some(policy) = self.policy {
            return policy;
        }
        let url = title_url(PRESENCE_URL, "0");
        let policy = match xodus::api::xbox::title::get_title_management(self.client).await {
            Ok(table) => xodus::api::xbox::title::get_endpoint(&url, &table).map(|endpoint| {
                endpoint
                    .signature_policy_index
                    .and_then(|index| table.signature_policies.get(index as usize))
                    .map(|policy| (policy.version as u32, policy.max_body_bytes as usize))
            }),
            Err(error) => {
                diag(&format!(
                    "endpoint discovery failed ({error}); signing anyway"
                ));
                None
            }
        };
        let policy = policy.unwrap_or(Some((1, 8192)));
        self.policy = Some(policy);
        policy
    }
}

#[async_trait]
impl TokenProvider for TitleMinter<'_> {
    async fn mint(&mut self) -> Result<Credentials, MintError> {
        match self.tokens.get_user_sts_token() {
            Ok(Token::Legacy(_)) => {}
            Ok(_) => return Err(MintError::Failed("unsupported user token form".into())),
            Err(TokenStoreError::NotFound) => return Err(MintError::SignedOut),
            Err(error) => {
                return Err(MintError::Failed(format!(
                    "could not read the sign-in: {error}"
                )));
            }
        }
        let identity = xodus::auth::sisu_identity_for(
            self.client,
            self.tokens,
            &self.identity.client_id,
            self.identity.title_id,
        )
        .await
        .map_err(MintError::Failed)?;
        let signer = RequestSigner::from_pkcs8(&identity.key_pkcs8)
            .ok_or_else(|| MintError::Failed("invalid title signing key".into()))?;
        let xsts = xodus::api::xbox::request_xsts_token(
            self.client,
            identity.user_token,
            Some(identity.device_token),
            Some(identity.title_token),
            XBOXLIVE_RELYING_PARTY,
            Some(&signer),
        )
        .await
        .map_err(|e| MintError::Failed(format!("xsts/authorize refused the title claim: {e}")))?;
        let xuid = xsts
            .xuid()
            .filter(|xuid| !xuid.is_empty())
            .ok_or_else(|| MintError::Failed("the token carries no xuid".into()))?
            .to_string();
        if xsts.user_hash().is_none() {
            return Err(MintError::Failed("the token carries no user hash".into()));
        }
        let expires_at = identity.expires_at.min(xsts.not_after.timestamp());
        let policy = self.signature_policy().await;
        Ok(Credentials {
            authorization: xodus::api::xbox::get_xsts_auth_header(xsts),
            signer,
            policy,
            xuid,
            expires_at,
        })
    }

    /// The same read `mint` starts with. It goes to the store every time, so
    /// `logout` run anywhere else, or the launcher signing the Player out,
    /// shows up here.
    fn signed_in(&mut self) -> bool {
        match self.tokens.get_user_sts_token() {
            Err(TokenStoreError::NotFound) => false,
            Err(error) => {
                diag(&format!("could not read the sign-in: {error}"));
                true
            }
            Ok(_) => true,
        }
    }
}

/// One line of the protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Online { title: String, heartbeat_after: u64 },
    Retrying { reason: String, after: u64 },
    Error { fatal: bool, code: &'static str },
    Offline,
    Busy,
}

impl Event {
    /// Written by hand rather than through a map, so the keys keep the order
    /// the protocol documents.
    pub fn to_json(&self) -> String {
        let quote = |s: &str| serde_json::Value::from(s).to_string();
        match self {
            Event::Online {
                title,
                heartbeat_after,
            } => format!(
                r#"{{"schema":1,"event":"online","title":{},"heartbeat_after":{heartbeat_after}}}"#,
                quote(title)
            ),
            Event::Retrying { reason, after } => format!(
                r#"{{"event":"retrying","reason":{},"in":{after}}}"#,
                quote(reason)
            ),
            Event::Error { fatal, code } => format!(
                r#"{{"event":"error","fatal":{fatal},"code":{}}}"#,
                quote(code)
            ),
            Event::Offline => r#"{"event":"offline"}"#.to_string(),
            Event::Busy => r#"{"event":"busy"}"#.to_string(),
        }
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Online {
                title,
                heartbeat_after,
            } => write!(
                f,
                "online: playing {title} (next heartbeat in {heartbeat_after} s)"
            ),
            Event::Retrying { reason, after } => write!(f, "retrying in {after} s: {reason}"),
            Event::Error { fatal: true, code } => write!(f, "stopped: {code}"),
            Event::Error { fatal: false, code } => write!(f, "error: {code}"),
            Event::Offline => write!(f, "offline"),
            Event::Busy => write!(f, "another presence runner is active for this account"),
        }
    }
}

pub const UNAUTHORIZED: &str = "unauthorized";
pub const FORBIDDEN: &str = "forbidden";
pub const SIGNED_OUT: &str = "signed-out";
pub const NETWORK: &str = "network";
pub const NO_TITLE_IDENTITY: &str = "no-title-identity";

fn emit(out: &mut dyn Write, json: bool, event: &Event) {
    // A launcher that has gone away closes stdin too, and that is what ends
    // the run. A failed write here has nothing better to do.
    let line = if json {
        event.to_json()
    } else {
        event.to_string()
    };
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// Anything long enough to be a token, replaced. Error text from the sign-in
/// chain is ours and carries none, but stderr is often captured into logs a
/// user pastes into an issue, and this costs nothing.
///
/// Two long shapes are kept, because they are what a failure is chased with
/// and neither can be a token: a correlation vector or other id that is only
/// hexadecimal, and the host and path of a URL, which follow a `//`.
pub fn scrub(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        let identifier = run
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '.' || c == '-');
        if run.len() >= 32 && !identifier && !run.starts_with("//") {
            out.push_str("[redacted]");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | '/' | '=' | '%') {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

fn diag(message: &str) {
    eprintln!("presence: {}", scrub(message));
}

/// How long one second of the protocol takes. Always one real second outside
/// tests, which shrink it so a heartbeat of 300 does not take five minutes.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    pub second: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            second: Duration::from_secs(1),
        }
    }
}

impl Timing {
    fn of(&self, seconds: u64) -> Duration {
        self.second
            .saturating_mul(seconds.min(u32::MAX as u64) as u32)
    }
}

/// `X-Heartbeat-After`, held to 60..=900, or 300 when missing or unreadable.
pub fn heartbeat_after(headers: &reqwest::header::HeaderMap) -> u64 {
    headers
        .get("x-heartbeat-after")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map_or(HEARTBEAT_FALLBACK, |seconds| {
            seconds.clamp(HEARTBEAT_MIN, HEARTBEAT_MAX)
        })
}

/// `Retry-After` in seconds, from either form the header takes.
pub fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let value = headers.get("retry-after")?.to_str().ok()?.trim();
    let seconds = match value.parse::<u64>() {
        Ok(seconds) => seconds,
        Err(_) => {
            let at = chrono::DateTime::parse_from_rfc2822(value).ok()?;
            (at.timestamp() - chrono::Utc::now().timestamp()).max(0) as u64
        }
    };
    Some(seconds.clamp(1, RETRY_AFTER_MAX))
}

/// 15, 30, 60, 120, 240, then 300 for every failure after.
pub fn backoff(failures: u32) -> u64 {
    BACKOFF_FIRST
        .saturating_mul(1u64 << failures.min(10))
        .min(BACKOFF_MAX)
}

fn correlation_vector() -> String {
    format!("{}.0", Uuid::new_v4().simple())
}

/// One signed request to the title route.
async fn send(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    credentials: &Credentials,
    body: &[u8],
    timeout: Duration,
) -> reqwest::Result<reqwest::Response> {
    let mut request = client
        .request(method.clone(), url)
        .timeout(timeout)
        .header("Authorization", &credentials.authorization)
        .header("x-xbl-contract-version", CONTRACT_VERSION)
        .header("Accept", "application/json")
        .header("MS-CV", correlation_vector());
    if let Some((version, max_body)) = credentials.policy {
        request = request.header(
            "Signature",
            credentials.signer.sign(
                version,
                method.as_str(),
                &xodus::api::xbox::path_and_query(url),
                &credentials.authorization,
                body,
                max_body,
            ),
        );
    }
    if !body.is_empty() {
        request = request
            .header("Content-Type", "application/json")
            .body(body.to_vec());
    }
    request.send().await
}

/// The body Windows sends. No `id`: the title comes from the token's claim,
/// and a body naming a title the token does not claim is refused.
pub const ACTIVE_BODY: &str = r#"{"state":"active"}"#;

/// The heartbeat loop, apart from where its tokens and its stop come from.
pub struct Heartbeat<'a, P> {
    pub client: &'a reqwest::Client,
    pub provider: P,
    pub base: String,
    pub title: String,
    pub timing: Timing,
    pub json: bool,
}

enum Wait {
    Elapsed,
    Stopped,
}

impl<P: TokenProvider> Heartbeat<'_, P> {
    /// Keep the title's presence alive until `stop` resolves, then delete it.
    /// Returns the exit status: 0 after a requested stop, 1 after a fatal
    /// error.
    pub async fn run(mut self, out: &mut dyn Write, stop: impl Future<Output = ()>) -> u8 {
        tokio::pin!(stop);
        let mut credentials: Option<Credentials> = None;
        // Whether the launcher has been told the title is up since the last
        // trouble it was told about.
        let mut announced = false;
        let mut failures: u32 = 0;
        // A 401 earns one fresh mint. Reset by any accepted heartbeat.
        let mut reminted = false;

        loop {
            if !self.provider.signed_in() {
                return self.signed_out(out, credentials.as_ref()).await;
            }
            let stale = credentials
                .as_ref()
                .is_none_or(|c| c.expires_at - chrono::Utc::now().timestamp() < REMINT_MARGIN);
            if stale {
                let minted = tokio::select! {
                    minted = self.provider.mint() => minted,
                    _ = &mut stop => return self.finish(out, credentials.as_ref()).await,
                };
                match minted {
                    Ok(fresh) => {
                        // Every mint is a new SISU device. The record the
                        // old one wrote would otherwise stay up next to the
                        // new one until it expired, so friends would see the
                        // game twice. A 401 leaves nothing to delete with.
                        if let Some(old) = credentials.take().filter(Credentials::usable) {
                            self.withdraw(&old).await;
                        }
                        credentials = Some(fresh);
                    }
                    Err(MintError::SignedOut) => {
                        return self.signed_out(out, credentials.as_ref()).await;
                    }
                    Err(MintError::Failed(message)) => {
                        diag(&format!("could not mint the title's token: {message}"));
                        // Credentials that are only close to expiry still
                        // work. Keep the title up with them and try the mint
                        // again after the next heartbeat; the launcher has
                        // nothing to be told yet.
                        if !credentials.as_ref().is_some_and(Credentials::usable) {
                            credentials = None;
                            let after = backoff(failures);
                            failures += 1;
                            announced = false;
                            self.say(
                                out,
                                &Event::Retrying {
                                    reason: "sign-in".into(),
                                    after,
                                },
                            );
                            if let Wait::Stopped = self.wait(after, &mut stop).await {
                                return self.finish(out, None).await;
                            }
                            continue;
                        }
                    }
                }
            }
            let Some(current) = credentials.as_ref() else {
                continue;
            };

            let url = title_url(&self.base, &current.xuid);
            // The body is read inside the select too, so a server that stalls
            // halfway through an answer cannot hold up a stop.
            let exchange = async {
                let response = send(
                    self.client,
                    reqwest::Method::POST,
                    &url,
                    current,
                    ACTIVE_BODY.as_bytes(),
                    self.timing.of(REQUEST_TIMEOUT),
                )
                .await?;
                let status = response.status();
                let headers = response.headers().clone();
                let body = response.text().await.unwrap_or_default();
                Ok::<_, reqwest::Error>((status, headers, body))
            };
            let sent = tokio::select! {
                sent = exchange => sent,
                _ = &mut stop => return self.finish(out, credentials.as_ref()).await,
            };
            let (status, headers, body) = match sent {
                Ok(answer) => answer,
                Err(error) => {
                    diag(&format!("heartbeat failed: {error}"));
                    let after = backoff(failures);
                    failures += 1;
                    announced = false;
                    self.say(
                        out,
                        &Event::Retrying {
                            reason: NETWORK.into(),
                            after,
                        },
                    );
                    if let Wait::Stopped = self.wait(after, &mut stop).await {
                        return self.finish(out, credentials.as_ref()).await;
                    }
                    continue;
                }
            };
            let cv = headers
                .get("ms-cv")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();

            if status.is_success() {
                failures = 0;
                reminted = false;
                let after = heartbeat_after(&headers);
                if !announced {
                    announced = true;
                    self.say(
                        out,
                        &Event::Online {
                            title: self.title.clone(),
                            heartbeat_after: after,
                        },
                    );
                }
                if let Wait::Stopped = self.wait(after, &mut stop).await {
                    return self.finish(out, credentials.as_ref()).await;
                }
                continue;
            }

            diag(&format!(
                "heartbeat answered HTTP {status} (MS-CV {cv}) {}",
                first_line(&body)
            ));
            match status.as_u16() {
                401 if !reminted => {
                    reminted = true;
                    credentials = None;
                }
                401 => return self.fatal(out, UNAUTHORIZED),
                403 => return self.fatal(out, FORBIDDEN),
                code => {
                    let reason = match code {
                        429 => "throttled".to_string(),
                        503 => "unavailable".to_string(),
                        500..=599 => format!("server error {code}"),
                        _ => format!("refused with {code}"),
                    };
                    let after = match (code, retry_after(&headers)) {
                        (429 | 503, Some(after)) => after,
                        _ => {
                            failures += 1;
                            backoff(failures - 1)
                        }
                    };
                    announced = false;
                    self.say(out, &Event::Retrying { reason, after });
                    if let Wait::Stopped = self.wait(after, &mut stop).await {
                        return self.finish(out, credentials.as_ref()).await;
                    }
                }
            }
        }
    }

    fn say(&self, out: &mut dyn Write, event: &Event) {
        emit(out, self.json, event);
    }

    fn fatal(&self, out: &mut dyn Write, code: &'static str) -> u8 {
        self.say(out, &Event::Error { fatal: true, code });
        1
    }

    /// Sleep for `seconds`, unless a stop comes first. The sign-in is looked
    /// at every minute on the way; once it is gone the wait ends early, and
    /// the top of the loop takes the record down.
    async fn wait(&mut self, seconds: u64, stop: &mut std::pin::Pin<&mut impl Future>) -> Wait {
        let mut left = seconds;
        loop {
            let step = left.min(SIGN_IN_POLL);
            tokio::select! {
                _ = tokio::time::sleep(self.timing.of(step)) => {}
                _ = stop.as_mut() => return Wait::Stopped,
            }
            left -= step;
            if left == 0 || !self.provider.signed_in() {
                return Wait::Elapsed;
            }
        }
    }

    /// Delete the record these credentials wrote. Bounded: a launcher waiting
    /// on this before signing out must not wait on a dead network, and a
    /// record that is not deleted expires on its own.
    async fn withdraw(&self, credentials: &Credentials) {
        let url = title_url(&self.base, &credentials.xuid);
        match send(
            self.client,
            reqwest::Method::DELETE,
            &url,
            credentials,
            &[],
            self.timing.of(DELETE_TIMEOUT),
        )
        .await
        {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => diag(&format!(
                "delete answered HTTP {}; the record will expire on its own",
                response.status()
            )),
            Err(error) => diag(&format!(
                "delete failed ({error}); the record will expire on its own"
            )),
        }
    }

    /// Take the record down, then say so.
    async fn finish(&self, out: &mut dyn Write, credentials: Option<&Credentials>) -> u8 {
        if let Some(credentials) = credentials {
            self.withdraw(credentials).await;
        }
        self.say(out, &Event::Offline);
        0
    }

    /// The account was signed out under a running game. Its credentials still
    /// work until they expire, so the record goes now rather than when the
    /// service gives up on it, and then the run ends.
    async fn signed_out(&self, out: &mut dyn Write, credentials: Option<&Credentials>) -> u8 {
        if let Some(credentials) = credentials.filter(|c| c.usable()) {
            self.withdraw(credentials).await;
        }
        self.fatal(out, SIGNED_OUT)
    }
}

fn first_line(body: &str) -> String {
    let line = body.lines().next().unwrap_or_default().trim();
    line.chars().take(160).collect()
}

/// Resolves when the reader reaches end of file.
///
/// The read happens on a plain thread rather than tokio's stdin, because a
/// blocking read tokio owns would hold up runtime shutdown after a SIGTERM
/// until the launcher closed the pipe.
pub fn end_of_input<R: Read + Send + 'static>(mut reader: R) -> impl Future<Output = ()> {
    let (done, finished) = tokio::sync::oneshot::channel::<()>();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 256];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
        let _ = done.send(());
    });
    async move {
        let _ = finished.await;
    }
}

/// Resolves on SIGTERM, SIGINT or SIGHUP. The handlers are installed before
/// this returns, so a signal sent right after it cannot kill the process.
pub fn termination() -> std::io::Result<impl Future<Output = ()>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let mut hup = signal(SignalKind::hangup())?;
    Ok(async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
            _ = hup.recv() => {}
        }
    })
}

pub enum LockError {
    Busy,
    Io(std::io::Error),
}

/// `presence-<profile>.lock` in [`runtime_dir`], held for the whole run.
///
/// One runner per account: two would post from two devices and fight over
/// which is current. The lock is the backstop for a second launcher process;
/// the file descriptor is released however the process ends.
///
/// `dir` should be private to this user (see [`runtime_dir`]). The file is
/// opened without following a symlink, and refused unless it is a regular
/// file this user owns, so nobody else can choose what it is.
pub fn lock(dir: &Path, profile: &str) -> Result<std::fs::File, LockError> {
    use fs2::FileExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if profile != "default" && !xodus::profiles::valid_id(profile) {
        return Err(LockError::Io(std::io::Error::other(
            "invalid account profile ID",
        )));
    }
    let path = dir.join(format!("presence-{profile}.lock"));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&path)
        .map_err(LockError::Io)?;
    let meta = file.metadata().map_err(LockError::Io)?;
    if !meta.file_type().is_file() {
        return Err(LockError::Io(std::io::Error::other(format!(
            "{} is not a regular file",
            path.display()
        ))));
    }
    if meta.uid() != current_uid() {
        return Err(LockError::Io(std::io::Error::other(format!(
            "{} belongs to another user",
            path.display()
        ))));
    }
    match file.try_lock_exclusive() {
        Ok(()) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Err(LockError::Busy),
        Err(error) => match error.raw_os_error() {
            Some(code) if code == nix::libc::EWOULDBLOCK => Err(LockError::Busy),
            _ => Err(LockError::Io(error)),
        },
    }
}

fn current_uid() -> u32 {
    // Safety: geteuid cannot fail and touches no memory.
    unsafe { nix::libc::geteuid() }
}

/// Whether `dir` is a directory, not a symlink, that only this user can
/// enter: owned by them, with no group or other permissions. With `tighten`,
/// an owned directory that is too open is set to 0700 rather than refused;
/// only for the directory this client makes for itself.
pub fn private_dir(dir: &Path, tighten: bool) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.file_type().is_dir() {
        return Err(std::io::Error::other(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    if meta.uid() != current_uid() {
        return Err(std::io::Error::other(format!(
            "{} belongs to another user",
            dir.display()
        )));
    }
    if meta.mode() & 0o077 != 0 {
        if !tighten {
            return Err(std::io::Error::other(format!(
                "{} is open to other users",
                dir.display()
            )));
        }
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Where the lock lives: `XODUS_RUNTIME_DIR`, else `XDG_RUNTIME_DIR`, else
/// `.run` under the account profile root, created 0700. Each must be private
/// to this user; one that is not is skipped. Never the shared temporary
/// directory, where another user could plant the file first.
pub fn runtime_dir() -> std::io::Result<PathBuf> {
    let candidates: Vec<PathBuf> = ["XODUS_RUNTIME_DIR", "XDG_RUNTIME_DIR"]
        .iter()
        .filter_map(|name| std::env::var_os(name).filter(|value| !value.is_empty()))
        .map(PathBuf::from)
        .collect();
    let root = xodus::profiles::root().map_err(|e| std::io::Error::other(e.to_string()))?;
    choose_runtime_dir(&candidates, &root)
}

/// [`runtime_dir`] with its inputs given: the first private candidate, else
/// `.run` under `profile_root`.
pub fn choose_runtime_dir(candidates: &[PathBuf], profile_root: &Path) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    for candidate in candidates {
        // Only an absolute path: a relative one depends on where this runs.
        if candidate.is_absolute() && private_dir(candidate, false).is_ok() {
            return Ok(candidate.clone());
        }
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(profile_root)?;
    let dir = profile_root.join(".run");
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    private_dir(&dir, true)?;
    Ok(dir)
}

/// The name friends see is the one the service holds, which the client cannot
/// read without a token. The config's display name is the same string for
/// every title that does not localise it, and the TitleId stands in for the
/// rest.
pub fn display_name(config: Option<&str>, title_id: i64) -> String {
    config
        .and_then(|xml| {
            let start = xml.find("DefaultDisplayName=\"")? + "DefaultDisplayName=\"".len();
            let len = xml[start..].find('"')?;
            Some(unescape(xml[start..start + len].trim()))
        })
        .filter(|name| !name.is_empty() && !name.starts_with("ms-resource:"))
        .unwrap_or_else(|| title_id.to_string())
}

fn unescape(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Which title to report, from the command line.
///
/// As in `xbl-check`, the ids are used only as a pair. Half of one is not
/// mixed with half of the game directory's, which could name two different
/// titles; the directory supplies the whole identity instead.
pub fn resolve_identity(
    game_dir: Option<&Path>,
    title_id: Option<i64>,
    title_client_id: Option<String>,
) -> Result<(TitleIdentity, String), String> {
    let config = game_dir
        .and_then(|dir| std::fs::read_to_string(super::xblcheck::game_config_path(dir)).ok());
    let identity = match (title_id.zip(title_client_id), game_dir) {
        (Some((title_id, client_id)), _) => TitleIdentity {
            title_id,
            client_id,
        },
        (None, Some(dir)) => super::xblcheck::identity_from_game_dir(dir)?,
        (None, None) => {
            return Err("give --game-dir, or --title-id with --title-client-id".to_string());
        }
    };
    if identity.client_id.trim().is_empty() {
        return Err(format!(
            "title {} has no MSAAppId, so it has no SISU identity to report presence with",
            identity.title_id
        ));
    }
    let name = display_name(config.as_deref(), identity.title_id);
    Ok((identity, name))
}

/// `presence run`.
pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    json: bool,
    game_dir: Option<PathBuf>,
    title_id: Option<i64>,
    title_client_id: Option<String>,
) -> ExitCode {
    let mut stdout = std::io::stdout();
    // Signals first: a launcher stopping the runner while it is still minting
    // must get a clean `offline`, not a killed process.
    let terminated = match termination() {
        Ok(terminated) => terminated,
        Err(error) => {
            diag(&format!("cannot watch for SIGTERM: {error}"));
            return ExitCode::FAILURE;
        }
    };
    if game_dir.is_none() && title_id.is_none() {
        eprintln!("presence run: give --game-dir, or --title-id with --title-client-id");
        return ExitCode::from(2);
    }
    let (identity, title) = match resolve_identity(game_dir.as_deref(), title_id, title_client_id) {
        Ok(resolved) => resolved,
        Err(message) => {
            diag(&message);
            emit(
                &mut stdout,
                json,
                &Event::Error {
                    fatal: true,
                    code: NO_TITLE_IDENTITY,
                },
            );
            return ExitCode::FAILURE;
        }
    };

    let profile = tokens.profile_id().unwrap_or("default").to_string();
    let _lock = match runtime_dir()
        .map_err(LockError::Io)
        .and_then(|dir| lock(&dir, &profile))
    {
        Ok(file) => Some(file),
        Err(LockError::Busy) => {
            emit(&mut stdout, json, &Event::Busy);
            return ExitCode::from(EXIT_BUSY);
        }
        // The lock only guards against a second runner. Not being able to
        // take it is worth a warning, not a missing presence.
        Err(LockError::Io(error)) => {
            diag(&format!("cannot take the presence lock: {error}"));
            None
        }
    };

    let stop = {
        let eof = end_of_input(std::io::stdin());
        async move {
            tokio::select! {
                _ = eof => {}
                _ = terminated => {}
            }
        }
    };
    let heartbeat = Heartbeat {
        client,
        provider: TitleMinter::new(client, tokens, identity),
        base: base_url(),
        title,
        timing: Timing::default(),
        json,
    };
    ExitCode::from(heartbeat.run(&mut stdout, stop).await)
}

/// The account's presence, reduced to what a badge shows.
pub fn summarize(presence: &serde_json::Value) -> serde_json::Value {
    let text = |value: &serde_json::Value| match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        _ => String::new(),
    };
    let state = match presence["state"]
        .as_str()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "online" => "Online",
        "away" => "Away",
        _ => "Offline",
    };
    let devices: Vec<serde_json::Value> = presence["devices"]
        .as_array()
        .map(|devices| {
            devices
                .iter()
                .map(|device| {
                    let titles: Vec<serde_json::Value> = device["titles"]
                        .as_array()
                        .map(|titles| {
                            titles
                                .iter()
                                .map(|title| {
                                    serde_json::json!({
                                        "id": text(&title["id"]),
                                        "name": text(&title["name"]),
                                    })
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    serde_json::json!({"type": text(&device["type"]), "titles": titles})
                })
                .collect()
        })
        .unwrap_or_default();
    serde_json::json!({"schema": 1, "state": state, "devices": devices})
}

/// GET the signed-in account's own presence with a plain user token.
pub async fn fetch(
    client: &reqwest::Client,
    base: &str,
    authorization: &str,
) -> Result<serde_json::Value, String> {
    let url = format!("{base}/users/me?level=all");
    let response = client
        .get(&url)
        .timeout(Duration::from_secs(REQUEST_TIMEOUT))
        .header("Authorization", authorization)
        .header("x-xbl-contract-version", CONTRACT_VERSION)
        .header("Accept", "application/json")
        .header("MS-CV", correlation_vector())
        .send()
        .await
        .map_err(|e| format!("{NETWORK}: {e}"))?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    match status.as_u16() {
        200..=299 => serde_json::from_str::<serde_json::Value>(&body)
            .map(|value| summarize(&value))
            .map_err(|e| format!("presence answered with something other than JSON: {e}")),
        401 => Err(format!("{UNAUTHORIZED}: HTTP {status}")),
        403 => Err(format!("{FORBIDDEN}: HTTP {status}")),
        _ => Err(format!("HTTP {status} {}", first_line(&body))),
    }
}

/// `presence get`.
pub async fn get(client: &reqwest::Client, tokens: &TokenManager, json: bool) -> ExitCode {
    let Ok(Token::Legacy(device)) = tokens.get_device_sts_token() else {
        eprintln!("presence: no usable device token; sign in first");
        return ExitCode::FAILURE;
    };
    let user = match tokens.get_user_sts_token() {
        Ok(Token::Legacy(user)) => user,
        _ => {
            eprintln!("presence: {SIGNED_OUT}");
            return ExitCode::FAILURE;
        }
    };
    let xsts = match xodus::api::xbox::try_run_with_signer(
        client,
        device,
        user,
        XBOXLIVE_RELYING_PARTY,
        None,
    )
    .await
    {
        Ok(xsts) if xsts.user_hash().is_some() => xsts,
        Ok(_) => {
            eprintln!("presence: the token carries no user hash");
            return ExitCode::FAILURE;
        }
        Err(message) => {
            diag(&message);
            return ExitCode::FAILURE;
        }
    };
    let authorization = xodus::api::xbox::get_xsts_auth_header(xsts);
    match fetch(client, &base_url(), &authorization).await {
        Ok(summary) => {
            if json {
                println!("{summary}");
            } else {
                println!("{}", summary["state"].as_str().unwrap_or("Offline"));
                for device in summary["devices"].as_array().into_iter().flatten() {
                    for title in device["titles"].as_array().into_iter().flatten() {
                        println!(
                            "  {}: {}",
                            device["type"].as_str().unwrap_or_default(),
                            title["name"].as_str().unwrap_or_default()
                        );
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            diag(&message);
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
