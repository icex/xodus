use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xodus::models::live::ExchangeUserTokenOutcome;
use xodus::models::secrets::Token;
use xodus::models::soap;
use xodus::models::xgameruntime::xuser::{
    MSATokenRequest, MSATokenResponse, XSTSTokenRequest, XSTSTokenResponse,
};
use xodus::proto::xodus::XodusMessageType;

use crate::XML_MAGIC;
use crate::simple_context::SimpleContext;

const AUTH_TIMEOUT: Duration = Duration::from_secs(30);

enum CachedValue<V> {
    Ready(V),
    Failed {
        message: String,
        retry_after: tokio::time::Instant,
    },
}

/// Each key has its own in-flight fetch. Network work never holds the map
/// lock, so an unavailable title cannot stall another title's cached requests.
struct AsyncCache<K, V> {
    entries: Mutex<HashMap<K, Arc<tokio::sync::Mutex<Option<CachedValue<V>>>>>>,
    fetch_timeout: Duration,
    retry_delay: Duration,
}

impl<K: Eq + Hash, V: Clone> AsyncCache<K, V> {
    fn new(fetch_timeout: Duration, retry_delay: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            fetch_timeout,
            retry_delay,
        }
    }

    async fn get_or_try_init<F, Fut>(
        &self,
        key: K,
        valid: impl Fn(&V) -> bool,
        fetch: F,
    ) -> Result<V, String>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, String>>,
    {
        let entry = self
            .entries
            .lock()
            .map_err(|_| "authentication cache poisoned")?
            .entry(key)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None)))
            .clone();
        let mut entry = entry.lock().await;
        match entry.as_ref() {
            Some(CachedValue::Ready(value)) if valid(value) => return Ok(value.clone()),
            Some(CachedValue::Failed {
                message,
                retry_after,
            }) if *retry_after > tokio::time::Instant::now() => return Err(message.clone()),
            _ => {}
        }
        let result = tokio::time::timeout(self.fetch_timeout, fetch())
            .await
            .unwrap_or_else(|_| Err("authentication or endpoint discovery timed out".to_string()));
        *entry = Some(match &result {
            Ok(value) => CachedValue::Ready(value.clone()),
            Err(message) => CachedValue::Failed {
                message: message.clone(),
                retry_after: tokio::time::Instant::now() + self.retry_delay,
            },
        });
        result
    }
}

/// Tokens cached per relying party until shortly before they expire.
///
/// Minting one runs the whole MSA -> user token -> XSTS chain, several network
/// round trips and a second or more. A title asks per request, so without this
/// every marketplace page and profile fetch pays that cost again; the token is
/// valid for a day, so there is nothing to gain by re-minting it.
static XSTS_CACHE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, CachedToken>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// The title-management endpoint list: which relying party each host
/// authenticates against. It is static configuration, but fetching it is a
/// network round trip -- and doing that per request cost more than minting the
/// token did.
static ENDPOINTS: std::sync::LazyLock<AsyncCache<(), xodus::models::xbox::TitleMgtResponse>> =
    std::sync::LazyLock::new(|| AsyncCache::new(Duration::from_secs(15), Duration::from_secs(5)));

/// One user/device/title identity and its proof key per title and auth client.
/// Legacy Windows titles authenticate by TitleId; newer configs supply a
/// client ID for SISU. Failed attempts are retried after a short backoff.
static IDENTITIES: std::sync::LazyLock<
    AsyncCache<([u8; 32], i64, String), std::sync::Arc<xodus::auth::SisuIdentity>>,
> = std::sync::LazyLock::new(|| AsyncCache::new(AUTH_TIMEOUT, Duration::from_secs(60)));

/// Relying parties xsts/authorize refused a title token for.
///
/// Rather than carry a list of which audiences accept a title claim -- which
/// would be wrong the moment Xbox changes one -- try it and remember the
/// answer. The retry without the claim happens on the same request, so a
/// refusal costs one extra round trip, once.
static NO_TITLE_CLAIM: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

/// Mint (or reuse) the identity for one title.
///
/// The SOAP exchange behind it fails intermittently -- an empty or truncated
/// response deserialises as a missing `wst:TokenType` -- and a failure here
/// costs the title its multiplayer, so a second attempt is worth more than the
/// second or so it takes.
async fn identity_for(
    client: &reqwest::Client,
    tokens: &xodus::tokens::TokenManager,
    title_id: i64,
    client_id: &str,
    session: [u8; 32],
) -> Option<std::sync::Arc<xodus::auth::SisuIdentity>> {
    let result = IDENTITIES.get_or_try_init(
        (session, title_id, client_id.to_string()),
        |id| id.expires_at > chrono::Utc::now().timestamp() + 60,
        || async {
            let mut last = String::new();
            for attempt in 1..=2 {
                let result = if client_id.is_empty() {
                    xodus::auth::win32_identity_for(client, tokens, title_id).await
                } else {
                    xodus::auth::sisu_identity_for(client, tokens, client_id, title_id).await
                };
                match result {
                    Ok(id) => {
                        tracing::info!("issued a token set claiming title {title_id}");
                        return Ok(std::sync::Arc::new(id));
                    }
                    Err(e) => {
                        tracing::warn!(
                            "title authentication attempt {attempt} for title {title_id} failed: {e}"
                        );
                        last = e;
                    }
                }
            }
            Err(last)
        },
    ).await;
    result
        .map_err(|error| {
            tracing::error!(
                "no title claim for title {title_id} (client id {client_id}): {error}. \
             Requests needing this title identity may be refused until authentication succeeds."
            );
        })
        .ok()
}

/// The key that signs requests. It has to be the key the token was minted
/// under; cached tokens retain their own issuer key.
static SIGNER: std::sync::LazyLock<xodus::api::xbox::RequestSigner> =
    std::sync::LazyLock::new(xodus::api::xbox::RequestSigner::generate);

/// Default and title-specific NSAL keep their own signature-policy tables.
struct EndpointConfig {
    default: xodus::models::xbox::TitleMgtResponse,
    title: Option<xodus::models::xbox::TitleMgtResponse>,
}

impl EndpointConfig {
    fn endpoint(
        &self,
        url: &str,
    ) -> Option<(
        &xodus::models::xbox::TitleMgtEndPoint,
        &xodus::models::xbox::TitleMgtResponse,
    )> {
        xodus::api::xbox::title::get_endpoint_with_title(url, &self.default, self.title.as_ref())
    }

    fn relying_party(&self, url: &str) -> String {
        self.endpoint(url)
            .and_then(|(e, _)| e.relying_party.clone())
            .unwrap_or_else(|| {
                reqwest::Url::parse(url)
                    .ok()
                    .and_then(|u| u.host_str().map(|h| format!("https://{h}/")))
                    .unwrap_or_else(|| "http://xboxlive.com".to_string())
            })
    }
}

fn signature_policy(url: &str, endpoints: &EndpointConfig) -> Option<(u32, usize)> {
    let (endpoint, source) = endpoints.endpoint(url)?;
    let index = endpoint.signature_policy_index? as usize;
    let policy = source.signature_policies.get(index)?;
    Some((policy.version as u32, policy.max_body_bytes as usize))
}

static TITLE_ENDPOINTS: std::sync::LazyLock<
    AsyncCache<i64, xodus::models::xbox::TitleMgtResponse>,
> = std::sync::LazyLock::new(|| AsyncCache::new(Duration::from_secs(15), Duration::from_secs(5)));

async fn title_endpoints_for(
    client: &reqwest::Client,
    title_id: i64,
    identity: &xodus::auth::SisuIdentity,
) -> Result<xodus::models::xbox::TitleMgtResponse, String> {
    TITLE_ENDPOINTS
        .get_or_try_init(
            title_id,
            |_| true,
            || async {
                let signer = xodus::api::xbox::RequestSigner::from_pkcs8(&identity.key_pkcs8)
                    .ok_or_else(|| "invalid title signing key".to_string())?;
                let xsts = xodus::api::xbox::request_xsts_token(
                    client,
                    identity.user_token.clone(),
                    Some(identity.device_token.clone()),
                    Some(identity.title_token.clone()),
                    "http://xboxlive.com",
                    Some(&signer),
                )
                .await
                .map_err(|e| format!("title discovery authorization failed: {e}"))?;
                let authorization = xodus::api::xbox::get_xsts_auth_header(xsts);
                let endpoints =
                    xodus::api::xbox::title::get_title_endpoints(client, &authorization, &signer)
                        .await
                        .map_err(|e| format!("title endpoint discovery failed: {e}"))?;
                tracing::info!(
                    "discovered {} service endpoints for title {title_id}",
                    endpoints.end_points.len()
                );
                Ok(endpoints)
            },
        )
        .await
}

fn token_cache_key(
    session: &[u8; 32],
    title: Option<&(i64, String)>,
    relying_party: &str,
    signer: &xodus::api::xbox::RequestSigner,
) -> String {
    let proof = signer.proof_key();
    format!(
        "{session:?}|{}|{}|{relying_party}|{}|{}",
        title.map(|(id, _)| *id).unwrap_or(0),
        title.map(|(_, client)| client.as_str()).unwrap_or(""),
        proof.x,
        proof.y
    )
}

#[derive(Clone)]
struct CachedToken {
    signer: xodus::api::xbox::RequestSigner,
    token: String,
    xuid: String,
    gamertag: String,
    expiry: i64,
}

pub async fn handle(
    socket: &mut tokio::net::UnixStream,
    context: &mut SimpleContext,
) -> tokio::io::Result<()> {
    tracing::debug!("Parsing XML");
    let message_type = socket.read_u16_le().await?;
    let message_size = socket.read_u16_le().await?;
    let mut buffer = vec![0; message_size as usize];
    tracing::debug!("Reading buffer {message_size}");
    socket.read_exact(&mut buffer).await?;
    tracing::debug!("Read buffer");
    let message_type = XodusMessageType::try_from(message_type as i32).unwrap_or_default();

    let out_buf = match parse_message(context, message_type, buffer).await {
        Ok(buf) => buf,
        Err(err) => {
            tracing::error!("Failed parsing message: {err}");
            vec![]
        }
    };

    let data = super::encode_message(XML_MAGIC, message_type as u16 + 1, out_buf);
    socket.write_all(&data).await
}

async fn endpoints_for(client: &reqwest::Client) -> Option<xodus::models::xbox::TitleMgtResponse> {
    ENDPOINTS
        .get_or_try_init(
            (),
            |_| true,
            || async {
                xodus::api::xbox::title::get_title_management(client)
                    .await
                    .map_err(|error| format!("default endpoint discovery failed: {error}"))
            },
        )
        .await
        .map_err(|error| tracing::warn!("{error}"))
        .ok()
}

/// Sign with the key the token was actually minted under: a
/// signature made with any other key is rejected.
fn sign_for_with(
    req: &XSTSTokenRequest,
    authorization: &str,
    endpoints: &EndpointConfig,
    signer: &xodus::api::xbox::RequestSigner,
) -> String {
    let Some((version, max_body)) = signature_policy(&req.url, endpoints) else {
        return String::new();
    };
    let body = if req.body_base64.is_empty() {
        Vec::new()
    } else {
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &req.body_base64)
            .unwrap_or_default()
    };
    let method = if req.method.is_empty() {
        "GET"
    } else {
        &req.method
    };
    signer.sign(
        version,
        method,
        &xodus::api::xbox::path_and_query(&req.url),
        authorization,
        &body,
        max_body,
    )
}

pub(super) async fn xsts_token(
    context: &mut SimpleContext,
    req: XSTSTokenRequest,
) -> Result<XSTSTokenResponse, Box<dyn std::error::Error + Send + Sync>> {
    tracing::debug!("XSTS token request for {}", req.url);

    // Read the persisted credential before any cache lookup: a logout
    // invalidates access and a different login must never reuse an old identity.
    let Token::Legacy(current_user) = context.tokens().get_user_sts_token()? else {
        return Err("no signed-in credentials".into());
    };
    // STS refresh rotates credential bytes during ordinary SISU calls.
    // Scope caches to the signed-in account, while requiring both its
    // persisted identity and credentials to still exist after logout.
    let account = context.tokens().get_user()?;
    if account.puid.is_empty() {
        return Err("signed-in account has no identity".into());
    }
    let session: [u8; 32] = Sha256::digest(account.puid.as_bytes()).into();
    let title = req.title().map(|(id, client)| (id, client.to_string()));
    let identity = match &title {
        Some((id, client)) => {
            identity_for(&context.client, context.tokens(), *id, client, session).await
        }
        None => None,
    };
    if title.is_some() && identity.is_none() {
        return Err("the requested title identity could not be authenticated; retry later".into());
    }
    let issuer = match &identity {
        Some(id) => xodus::api::xbox::RequestSigner::from_pkcs8(&id.key_pkcs8)
            .ok_or("invalid title signing key")?,
        None => SIGNER.clone(),
    };
    let mut endpoints = EndpointConfig {
        default: endpoints_for(&context.client).await.unwrap_or(
            xodus::models::xbox::TitleMgtResponse {
                end_points: vec![],
                signature_policies: vec![],
            },
        ),
        title: None,
    };
    if let (Some((id, _)), Some(identity)) = (&title, &identity) {
        match title_endpoints_for(&context.client, *id, identity).await {
            Ok(list) => endpoints.title = Some(list),
            Err(e) => tracing::warn!("title {id}: {e}"),
        }
    }
    let relying_party = if req.relying_party.is_empty() {
        endpoints.relying_party(&req.url)
    } else {
        req.relying_party.clone()
    };
    let cache_key = token_cache_key(&session, title.as_ref(), &relying_party, &issuer);
    let now = chrono::Utc::now().timestamp();
    if let Some(hit) = XSTS_CACHE
        .lock()
        .ok()
        .and_then(|c| c.get(&cache_key).cloned())
        .filter(|c| c.expiry > now + 60)
    {
        let signature = sign_for_with(&req, &hit.token, &endpoints, &hit.signer);
        let payload = XSTSTokenResponse {
            token: hit.token,
            xuid: hit.xuid,
            gamertag: hit.gamertag,
            expiry: hit.expiry,
            signature,
        };
        return Ok(payload);
    }

    let (xsts, signer) = if let Some(identity) = identity {
        let signer = xodus::api::xbox::RequestSigner::from_pkcs8(&identity.key_pkcs8)
            .ok_or("invalid title signing key")?;
        let refused = NO_TITLE_CLAIM
            .lock()
            .map(|s| s.contains(&cache_key))
            .unwrap_or(false);
        let result = tokio::time::timeout(
            AUTH_TIMEOUT,
            xodus::api::xbox::request_xsts_token(
                &context.client,
                identity.user_token.clone(),
                Some(identity.device_token.clone()),
                if refused {
                    None
                } else {
                    Some(identity.title_token.clone())
                },
                &relying_party,
                Some(&signer),
            ),
        )
        .await
        .map_err(|_| "XSTS authorization timed out")?;
        let xsts = match result {
            Ok(token) => token,
            Err(e)
                if !refused
                    && matches!(
                        e.status(),
                        Some(reqwest::StatusCode::BAD_REQUEST | reqwest::StatusCode::FORBIDDEN)
                    ) =>
            {
                // Some audiences accept the user/device chain only. Retry
                // under the same key, scoped to this title and audience.
                let token = tokio::time::timeout(
                    AUTH_TIMEOUT,
                    xodus::api::xbox::request_xsts_token(
                        &context.client,
                        identity.user_token.clone(),
                        Some(identity.device_token.clone()),
                        None,
                        &relying_party,
                        Some(&signer),
                    ),
                )
                .await
                .map_err(|_| "XSTS authorization without title claim timed out")?
                .map_err(|e| {
                    std::io::Error::other(format!(
                        "XSTS authorization without title claim for {relying_party} failed: {e}"
                    ))
                })?;
                tracing::warn!(
                    "{relying_party} accepts this title's user/device token without a title claim"
                );
                if let Ok(mut set) = NO_TITLE_CLAIM.lock() {
                    set.insert(cache_key.clone());
                }
                token
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "XSTS authorization for {relying_party} failed: {e}"
                ))
                .into());
            }
        };
        (xsts, signer)
    } else {
        let user_token = current_user;
        let device_token = context
            .device_token
            .as_ref()
            .ok_or("no device credentials")?
            .clone();
        let token = tokio::time::timeout(
            AUTH_TIMEOUT,
            xodus::api::xbox::try_run_with_signer(
                &context.client,
                device_token,
                user_token,
                &relying_party,
                Some(&SIGNER),
            ),
        )
        .await
        .map_err(|_| "unclaimed Xbox authentication timed out")?
        .map_err(std::io::Error::other)?;
        (token, SIGNER.clone())
    };
    let token = xodus::api::xbox::get_xsts_auth_header(xsts.clone());
    let signature = sign_for_with(&req, &token, &endpoints, &signer);
    let payload = XSTSTokenResponse {
        xuid: xsts.xuid().unwrap_or_default().to_string(),
        gamertag: xsts.gamertag().unwrap_or_default().to_string(),
        expiry: xsts.not_after.timestamp(),
        token,
        signature,
    };
    if let Ok(mut cache) = XSTS_CACHE.lock() {
        cache.insert(
            cache_key,
            CachedToken {
                signer,
                token: payload.token.clone(),
                xuid: payload.xuid.clone(),
                gamertag: payload.gamertag.clone(),
                expiry: payload.expiry,
            },
        );
    }
    Ok(payload)
}

pub async fn parse_message(
    context: &mut SimpleContext,
    message_type: XodusMessageType,
    buffer: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    match message_type {
        XodusMessageType::Ping => Ok(buffer),
        XodusMessageType::MsaTokenRequest => {
            tracing::debug!("Raw buffer: {buffer:?}");
            let string_buf = std::str::from_utf8(&buffer)?;
            tracing::debug!("String buffer: {string_buf:?}");
            let req = quick_xml::de::from_str::<MSATokenRequest>(string_buf)?;
            let Token::Legacy(token) = context.tokens().get_user_sts_token()? else {
                return Ok(vec![]);
            };
            let scope = if req.msa_full_trust {
                "service::user.auth.xboxlive.com::MBI_SSL"
            } else {
                "xboxlive.signin"
            };
            let device_token = context.device_token.as_ref().unwrap();
            let device_token_resp = xodus::api::live::exchange_device_token(
                &context.client,
                device_token.clone(),
                "{28C08266-F973-4AE6-FFE4-409B249F138F}".to_string(),
                "scope=service::user.auth.xboxlive.com::MBI_SSL".to_owned(),
                Some(soap::PolicyReference::token_broker()),
            )
            .await;

            let ms_device_rps_token = if let Some((Token::Compact(ms_device_token), Ok(lifetime))) =
                device_token_resp.ok().map(|t| {
                    let expiry = chrono::DateTime::parse_from_rfc3339(&t.lifetime.expires);
                    (t.into(), expiry)
                }) {
                Some((ms_device_token, lifetime.timestamp()))
            } else {
                None
            };

            let user_token = xodus::api::live::exchange_user_token(
                &context.client,
                token,
                "USERNAME".to_string(),
                device_token.clone(),
                None,
                Some("Silent".to_string()),
                req.client_id.clone(),
                &[
                    (
                        format!("scope={scope}&api-version=2.0&clientid={}", req.client_id),
                        Some(soap::PolicyReference::token_broker()),
                    ),
                    ("http://Passport.NET/tb".to_string(), None),
                ],
            )
            .await?;

            match user_token {
                ExchangeUserTokenOutcome::Issued(
                    soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
                ) => {
                    if let Some(sts) = collection.security_tokens.pop() {
                        let address = sts.applies_to.endpoint_reference.address.clone();
                        let sts: Token = sts.into();
                        let address = if let Token::Legacy(legacy) = &sts {
                            legacy.key_name.clone().unwrap_or(address)
                        } else {
                            address
                        };
                        if let Err(err) = context.tokens().save_user_token(address, sts) {
                            tracing::warn!("Failed to persist refreshed STS token: {err}");
                        }
                    }
                    let token = collection.security_tokens.remove(0);
                    let expiry = chrono::DateTime::parse_from_rfc3339(&token.lifetime.expires)?;
                    let token: Token = token.into();
                    let Token::Compact(user_token) = token else {
                        return Ok(vec![]);
                    };
                    let payload = MSATokenResponse {
                        token: user_token,
                        expiry: expiry.timestamp(),
                        device_expiry: ms_device_rps_token.as_ref().map(|(_, r)| *r).unwrap_or(0),
                        device_rps: ms_device_rps_token
                            .map(|(t, _)| t)
                            .unwrap_or_else(String::new),
                    };
                    let payload = quick_xml::se::to_string(&payload)?;
                    Ok(payload.as_bytes().to_vec())
                }
                _ => todo!("Error handling sill sucks"),
            }
        }
        XodusMessageType::XstsTokenRequest => {
            let req = quick_xml::de::from_str::<XSTSTokenRequest>(std::str::from_utf8(&buffer)?)?;
            let payload = xsts_token(context, req).await?;
            Ok(quick_xml::se::to_string(&payload)?.into_bytes())
        }
        XodusMessageType::LicenseTokenRequest => {
            // This response is the raw, validated JWT; an empty frame is failure.
            // Do not expose authorization headers or response bodies in diagnostics.
            match tokio::time::timeout(
                Duration::from_secs(45),
                super::license::fetch(context, &buffer),
            )
            .await
            {
                Ok(Ok(token)) => Ok(token.into_bytes()),
                _ => {
                    tracing::warn!("license-token request failed");
                    Ok(Vec::new())
                }
            }
        }

        _ => Err("Unimplemented".into()),
    }
}

#[cfg(test)]
#[path = "xml_tests.rs"]
mod tests;
