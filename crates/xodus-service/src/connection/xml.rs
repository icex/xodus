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

/// Tokens cached per relying party until shortly before they expire.
///
/// Minting one runs the whole MSA -> user token -> XSTS chain, several network
/// round trips and a second or more. A title asks per request, so without this
/// every marketplace page and profile fetch pays that cost again; the token is
/// valid for a day, so there is nothing to gain by re-minting it.
static XSTS_CACHE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, CachedToken>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Whether the one-off SISU run that yields a title token has been attempted.
static TITLE_TOKEN: tokio::sync::OnceCell<bool> = tokio::sync::OnceCell::const_new();

/// The title-management endpoint list: which relying party each host
/// authenticates against. It is static configuration, but fetching it is a
/// network round trip -- and doing that per request cost more than minting the
/// token did.
static ENDPOINTS: tokio::sync::OnceCell<Option<xodus::models::xbox::TitleMgtResponse>> =
    tokio::sync::OnceCell::const_new();

/// The identity SISU issued for a title: device, title and user tokens plus the
/// key they are all bound to. Xbox will not let us mix keys, so when this is
/// present it replaces the whole locally-built chain -- signing key included.
///
/// Keyed by title, because the claim it carries *names* a title. A token
/// claiming the wrong one is not a weaker token, it is a refused one: the
/// session directory answers "The requested service config cannot be accessed."
/// and presence's titles/current answers 403, while the same request with no
/// claim at all goes through. Handing every title the Xbox app's identity --
/// which is what this used to do -- therefore broke exactly the two services a
/// title needs it for.
///
/// The mutex is held across the mint so a title asking for several relying
/// parties at once runs SISU once rather than once per ask.
static SISU: std::sync::LazyLock<
    tokio::sync::Mutex<
        std::collections::HashMap<i64, Option<std::sync::Arc<xodus::auth::SisuIdentity>>>,
    >,
> = std::sync::LazyLock::new(|| tokio::sync::Mutex::new(std::collections::HashMap::new()));

/// Relying parties xsts/authorize refused a title token for.
///
/// Rather than carry a list of which audiences accept a title claim -- which
/// would be wrong the moment Xbox changes one -- try it and remember the
/// answer. The retry without the claim happens on the same request, so a
/// refusal costs one extra round trip, once.
static NO_TITLE_CLAIM: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

/// Mint (or reuse) the SISU identity for one title.
///
/// The SOAP exchange behind it fails intermittently -- an empty or truncated
/// response deserialises as a missing `wst:TokenType` -- and a failure here
/// costs the title its multiplayer, so a second attempt is worth more than the
/// second or so it takes.
async fn sisu_for(
    client: &reqwest::Client,
    tokens: &xodus::tokens::TokenManager,
    title_id: i64,
    client_id: &str,
) -> Option<std::sync::Arc<xodus::auth::SisuIdentity>> {
    let mut cache = SISU.lock().await;
    if let Some(hit) = cache.get(&title_id) {
        return hit.clone();
    }
    let mut last = String::new();
    for attempt in 1..=2 {
        match xodus::auth::sisu_identity_for(client, tokens, client_id, title_id).await {
            Ok(id) => {
                tracing::info!("SISU issued a token set claiming title {title_id}");
                let id = std::sync::Arc::new(id);
                cache.insert(title_id, Some(id.clone()));
                return Some(id);
            }
            Err(e) => {
                tracing::warn!("SISU attempt {attempt} for title {title_id} failed: {e}");
                last = e;
            }
        }
    }
    tracing::error!(
        "no title claim for title {title_id} (client id {client_id}): {last}. \
         Presence and multiplayer will answer 403 until this succeeds."
    );
    cache.insert(title_id, None);
    None
}

/// The key that signs requests. It has to be the key the token was minted
/// under, so it follows SISU when SISU supplied the tokens.
static SIGNER: std::sync::LazyLock<xodus::api::xbox::RequestSigner> =
    std::sync::LazyLock::new(xodus::api::xbox::RequestSigner::generate);

/// The signature policy for a host, if it has one: the policy version and how
/// much of the body is covered.
fn signature_policy(
    url: &str,
    endpoints: &Option<xodus::models::xbox::TitleMgtResponse>,
) -> Option<(u32, usize)> {
    let list = endpoints.as_ref()?;
    let endpoint = xodus::api::xbox::title::get_endpoint(url, list).or_else(|| {
        let host = reqwest::Url::parse(url).ok()?.host_str()?.to_string();
        list.end_points
            .iter()
            .filter(|e| !e.host.contains('*') && host.ends_with(&format!(".{}", e.host)))
            .max_by_key(|e| e.host.len())
    })?;
    let index = endpoint.signature_policy_index? as usize;
    let policy = list.signature_policies.get(index)?;
    Some((policy.version as u32, policy.max_body_bytes as usize))
}

#[derive(Clone)]
struct CachedToken {
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
        .get_or_init(|| async {
            xodus::api::xbox::title::get_title_management(client)
                .await
                .ok()
        })
        .await
        .clone()
}

/// Sign the caller's request, if its endpoint demands one.
fn sign_for(
    req: &XSTSTokenRequest,
    authorization: &str,
    endpoints: &Option<xodus::models::xbox::TitleMgtResponse>,
) -> String {
    sign_for_with(req, authorization, endpoints, &SIGNER)
}

/// As `sign_for`, but with the key the token was actually minted under: a
/// signature made with any other key is rejected.
fn sign_for_with(
    req: &XSTSTokenRequest,
    authorization: &str,
    endpoints: &Option<xodus::models::xbox::TitleMgtResponse>,
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
            tracing::debug!("XSTS token request for {}", req.url);

            // Which relying party this URL authenticates against. The
            // title-management endpoint list is authoritative; its PlayFab entry
            // is the bare domain, so fall back to a suffix match for the
            // per-title hosts (b980a380.minecraft.playfabapi.com and friends).
            let relying_party = if !req.relying_party.is_empty() {
                req.relying_party.clone()
            } else {
                let endpoints = ENDPOINTS
                    .get_or_init(|| async {
                        xodus::api::xbox::title::get_title_management(&context.client)
                            .await
                            .ok()
                    })
                    .await;
                let from_list = endpoints.as_ref().and_then(|list| {
                    xodus::api::xbox::title::get_endpoint(&req.url, list)
                        .and_then(|e| e.relying_party.clone())
                });
                match from_list {
                    Some(rp) => rp,
                    None => {
                        let host = reqwest::Url::parse(&req.url)
                            .ok()
                            .and_then(|u| u.host_str().map(str::to_owned))
                            .unwrap_or_default();
                        let fallback = endpoints.as_ref().and_then(|list| {
                            list.end_points
                                .iter()
                                .filter(|e| {
                                    e.relying_party.is_some()
                                        && !e.host.contains('*')
                                        && host.ends_with(&format!(".{}", e.host))
                                })
                                .max_by_key(|e| e.host.len())
                                .and_then(|e| e.relying_party.clone())
                        });
                        // A service Xbox does not list still has a relying
                        // party: its own origin. Minecraft Realms is the case
                        // in point -- the title asks for a token for
                        // pocket.realms.minecraft.net, which is not an
                        // xboxlive.com host, and handing it an xboxlive.com
                        // token made every Realms endpoint answer 401.
                        fallback.unwrap_or_else(|| {
                            reqwest::Url::parse(&req.url)
                                .ok()
                                .and_then(|u| u.host_str().map(|h| format!("https://{h}/")))
                                .unwrap_or_else(|| "http://xboxlive.com".to_string())
                        })
                    }
                }
            };
            // Which title is asking, when the runtime told us. Everything
            // below keys off it: two titles running at once must not be handed
            // each other's claim, and neither must a title be handed the
            // claimless token minted before its own arrived.
            let title = req.title().map(|(id, client)| (id, client.to_string()));
            match &title {
                Some((id, client)) => {
                    tracing::debug!("Relying party: {relying_party} (title {id}, client {client})")
                }
                None => {
                    tracing::debug!("Relying party: {relying_party} (no title claim asked for)")
                }
            }
            let cache_key = format!(
                "{}|{relying_party}",
                title.as_ref().map(|(id, _)| *id).unwrap_or(0)
            );

            // Re-use a still-valid token rather than paying for the whole
            // chain again; keep a minute of headroom so one never expires in
            // flight.
            let now = chrono::Utc::now().timestamp();
            if let Some(hit) = XSTS_CACHE
                .lock()
                .ok()
                .and_then(|c| c.get(&cache_key).cloned())
                .filter(|c| c.expiry > now + 60)
            {
                tracing::debug!("Re-using cached token for {relying_party}");
                let signature = sign_for(&req, &hit.token, &endpoints_for(&context.client).await);
                let payload = XSTSTokenResponse {
                    token: hit.token,
                    xuid: hit.xuid,
                    gamertag: hit.gamertag,
                    expiry: hit.expiry,
                    signature,
                };
                return Ok(quick_xml::se::to_string(&payload)?.as_bytes().to_vec());
            }

            let Token::Legacy(user_token) = context.tokens().get_user_sts_token()? else {
                return Ok(vec![]);
            };

            // Xbox will only issue a title token against an RPS ticket obtained
            // under the title's own client id, which is why title/authenticate
            // answers 403 for the generic ticket the token path holds. SISU does
            // hold one, so run it once and hand the title token over: presence
            // resolves `titles/current` from that claim and fails without it.
            // Off unless asked for: the token SISU returns is bound to its own
            // proof key, while the user and device tokens here are bound to
            // ours, and xsts/authorize answers 400 to that mixture. Presence
            // needs the whole chain minted under one key, which is a rebuild of
            // this path rather than an addition to it.
            if std::env::var("XODUS_TITLE_TOKEN").is_ok_and(|v| v == "1") {
                TITLE_TOKEN
                    .get_or_init(|| async {
                        match xodus::auth::do_sisu(
                            &context.client,
                            context.tokens(),
                            "0000000040159362",
                            896928775,
                        )
                        .await
                        {
                            Ok((_, resp, _)) => {
                                tracing::info!("SISU supplied a title token");
                                xodus::api::xbox::set_title_token(resp.title_token.token.clone());
                                true
                            }
                            Err(e) => {
                                tracing::warn!("SISU title token unavailable: {e}");
                                false
                            }
                        }
                    })
                    .await;
            }
            let device_token = context.device_token.as_ref().unwrap().clone();

            // A claim for the title that is actually running, or none.
            //
            // Never a stand-in: a token claiming some other title is refused by
            // the very services the claim exists for, so where the title is
            // unknown the claimless chain below is the better answer.
            let refused = NO_TITLE_CLAIM
                .lock()
                .map(|s| s.contains(&relying_party))
                .unwrap_or(false);
            let sisu = match (&title, refused) {
                (Some((id, client)), false) => {
                    sisu_for(&context.client, context.tokens(), *id, client).await
                }
                _ => None,
            };

            // Say so when this request is one of the ones that will come back
            // 403 without a claim. It is the only chance to name the cause:
            // the title makes the call itself, sees a bare 403, and reports it
            // as "failed to create party" or a broken sign-in.
            if sisu.is_none() {
                if let Some(what) = xodus::api::xbox::claims::needs_title_claim(&req.url) {
                    let why = match (&title, refused) {
                        (None, _) => "the runtime sent no TitleId/MSAAppId (is the title's \
                                      MicrosoftGame.config readable?)"
                            .to_string(),
                        (Some(_), true) => {
                            format!("{relying_party} would not issue a token carrying one")
                        }
                        (Some((id, _)), false) => format!("SISU could not mint one for title {id}"),
                    };
                    tracing::error!("{} will fail: no title claim -- {why}", what);
                }
            }

            if let Some(id) = sisu.as_ref() {
                let signer = xodus::api::xbox::RequestSigner::from_pkcs8(&id.key_pkcs8);
                let xsts = xodus::api::xbox::request_xsts_token(
                    &context.client,
                    id.user_token.clone(),
                    Some(id.device_token.clone()),
                    Some(id.title_token.clone()),
                    &relying_party,
                )
                .await;
                match xsts {
                    Ok(xsts) => {
                        let token = xodus::api::xbox::get_xsts_auth_header(xsts.clone());
                        let signature = match signer.as_ref() {
                            Some(s) => sign_for_with(
                                &req,
                                &token,
                                &endpoints_for(&context.client).await,
                                s,
                            ),
                            None => String::new(),
                        };
                        let payload = XSTSTokenResponse {
                            xuid: xsts.xuid().unwrap_or_default().to_string(),
                            gamertag: xsts.gamertag().unwrap_or_default().to_string(),
                            expiry: xsts.not_after.timestamp(),
                            token,
                            signature,
                        };
                        if let Ok(mut cache) = XSTS_CACHE.lock() {
                            cache.insert(
                                cache_key.clone(),
                                CachedToken {
                                    token: payload.token.clone(),
                                    xuid: payload.xuid.clone(),
                                    gamertag: payload.gamertag.clone(),
                                    expiry: payload.expiry,
                                },
                            );
                        }
                        return Ok(quick_xml::se::to_string(&payload)?.as_bytes().to_vec());
                    }
                    Err(e) => {
                        // The audience would not take a title claim. Remember
                        // it so the next request for it skips straight to the
                        // claimless chain instead of paying for the refusal.
                        tracing::warn!(
                            "{relying_party} refused a title claim ({e}); \
                             falling back to a token without one"
                        );
                        if let Ok(mut set) = NO_TITLE_CLAIM.lock() {
                            set.insert(relying_party.clone());
                        }
                    }
                }
            }

            // A refused relying party used to panic the task serving this
            // request, leaving the title waiting for a token for ever. Report
            // it instead, and try the generic Xbox audience before giving up.
            let xsts = match xodus::api::xbox::try_run_with_signer(
                &context.client,
                device_token.clone(),
                user_token.clone(),
                &relying_party,
                Some(&SIGNER),
            )
            .await
            {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!("{e}; retrying with the generic Xbox audience");
                    match xodus::api::xbox::try_run_with_signer(
                        &context.client,
                        device_token,
                        user_token,
                        "http://xboxlive.com",
                        Some(&SIGNER),
                    )
                    .await
                    {
                        Ok(t) => t,
                        Err(e) => {
                            tracing::error!("no token for {}: {e}", req.url);
                            return Ok(vec![]);
                        }
                    }
                }
            };

            let token = xodus::api::xbox::get_xsts_auth_header(xsts.clone());
            let signature = sign_for(&req, &token, &endpoints_for(&context.client).await);
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
                        token: payload.token.clone(),
                        xuid: payload.xuid.clone(),
                        gamertag: payload.gamertag.clone(),
                        expiry: payload.expiry,
                    },
                );
            }
            Ok(quick_xml::se::to_string(&payload)?.as_bytes().to_vec())
        }
        _ => Err("Unimplemented".into()),
    }
}
