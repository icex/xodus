//! Microsoft Store ID keys for a title's own service (XStoreGetUserCollectionsId).
//!
//! A title's service hands the game a service ticket (an Entra token for
//! `https://onestore.microsoft.com`) and the game asks the Store to turn it
//! into a Collections ID key for the signed-in Store account. The title then
//! sends that key to its own service, which uses it to query what the player
//! owns. On Windows the Gaming Runtime posts the ticket to
//! `collections.mp.microsoft.com/v7.0/beneficiaries/me/keys` with the Store
//! account's Microsoft account ticket as `WLID1.0` authorization; this does
//! the same from the service, which owns the Store account's credentials.
//!
//! Wire (little-endian u32s), magic "KSDX":
//!   request:  magic, version 1, kind (1 = Collections), ticket length,
//!             publisher user ID length, ticket bytes, publisher user ID bytes
//!   response: version 1, status (0 = key follows, 1 = failed,
//!             2 = unsupported kind), key length, key bytes
//! Neither the ticket nor the key is logged: both are bearer credentials.
use crate::simple_context::SimpleContext;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xodus::models::live::ExchangeUserTokenOutcome;
use xodus::models::secrets::Token;
use xodus::models::soap;

pub const MAGIC: u32 = 0x5844534B; // KSDX
const COLLECTIONS_KEYS: &str = "https://collections.mp.microsoft.com/v7.0/beneficiaries/me/keys";
const MAX_TICKET: usize = 16 * 1024;
const MAX_PUBLISHER_USER_ID: usize = 1024;
const MAX_RESPONSE: usize = 65536;
const MAX_KEY: usize = 60000;
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(45);
type Error = &'static str;

/// The Store account's Microsoft account ticket, in the `t=...&p=` form the
/// Store services take.
async fn user_ticket(context: &SimpleContext) -> Result<String, Error> {
    let store = context.store_context();
    let tokens = store.tokens();
    let user = tokens.get_user().map_err(|_| "Store account is signed out")?;
    let Ok(Token::Legacy(legacy)) = tokens.get_user_sts_token() else {
        return Err("Store account credentials are unavailable");
    };
    let (_, dev_token) = xodus::api::live::exchange_device_token_managed(
        &context.client,
        tokens,
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        "www.microsoft.com".to_owned(),
        Some(soap::PolicyReference::mbi_ssl()),
    )
    .await
    .map_err(|_| "Store device authentication failed")?;
    let outcome = xodus::api::live::exchange_user_token(
        &context.client,
        legacy,
        user.username,
        dev_token,
        None,
        Some("Silent".to_string()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        &[(
            "www.microsoft.com".to_owned(),
            Some(soap::PolicyReference::mbi_ssl()),
        )],
    )
    .await
    .map_err(|_| "Store account authentication failed")?;
    let token: Token = match outcome {
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(collection),
        ) => collection
            .security_tokens
            .into_iter()
            .next()
            .ok_or("Store account supplied no ticket")?
            .into(),
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(t)) => {
            (*t).into()
        }
        _ => return Err("Store account ticket exchange was refused"),
    };
    let Token::Compact(ticket) = token else {
        return Err("Store account ticket has an unsupported form");
    };
    Ok(xodus::licensing::store_ticket::user_ticket(ticket))
}

fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_KEY
        && key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
}

/// The error code a Store service names in a refusal, never anything else
/// from the body.
fn refusal_code(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("code")
                .or_else(|| v.get("errorCode"))
                .and_then(|c| c.as_str().map(str::to_owned))
        })
        .filter(|c| c.len() <= 64 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        .unwrap_or_else(|| "-".into())
}

async fn collections_key(
    context: &SimpleContext,
    service_ticket: &str,
    publisher_user_id: &str,
) -> Result<String, Error> {
    let ticket = user_ticket(context).await?;
    let body = serde_json::to_vec(&serde_json::json!({
        "serviceTicket": service_ticket,
        "publisherUserId": publisher_user_id,
    }))
    .map_err(|_| "cannot serialize request")?;
    let client = reqwest::Client::builder()
        .user_agent("XboxGameRuntime")
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|_| "cannot create Store client")?;
    let cv = xodus::xal::cvlib::CorrelationVector::new();
    let mut response = client
        .post(COLLECTIONS_KEYS)
        .header("Authorization", format!("WLID1.0={ticket}"))
        .header("MS-CV", cv.to_string())
        .header("Content-Type", "application/json; charset=UTF-8")
        .header("Cache-Control", "no-cache")
        .body(body)
        .send()
        .await
        .map_err(|_| "Collections transport failed")?;
    let status = response.status();
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Collections response failed")?
    {
        if chunk.len() > MAX_RESPONSE - bytes.len() {
            return Err("Collections response too large");
        }
        bytes.extend_from_slice(&chunk);
    }
    if !status.is_success() {
        tracing::warn!(
            "Collections ID key request refused: HTTP {} (code {}, MS-CV {cv})",
            status.as_u16(),
            refusal_code(&bytes)
        );
        return Err("Collections ID key request refused");
    }
    let key = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get("key").and_then(|k| k.as_str().map(str::to_owned)))
        .ok_or("Collections ID key response has no key")?;
    if !valid_key(&key) {
        return Err("Collections ID key response has an invalid key");
    }
    tracing::info!("issued a Collections ID key ({} characters)", key.len());
    Ok(key)
}

async fn read_u32(socket: &mut tokio::net::UnixStream) -> Option<u32> {
    let mut b = [0; 4];
    match tokio::time::timeout(READ_TIMEOUT, socket.read_exact(&mut b)).await {
        Ok(Ok(_)) => Some(u32::from_le_bytes(b)),
        _ => None,
    }
}

async fn read_text(socket: &mut tokio::net::UnixStream, n: usize) -> Option<String> {
    let mut b = vec![0; n];
    match tokio::time::timeout(READ_TIMEOUT, socket.read_exact(&mut b)).await {
        Ok(Ok(_)) => String::from_utf8(b).ok(),
        _ => None,
    }
}

fn reply(status: u32, key: &str) -> Vec<u8> {
    let mut out: Vec<u8> = [1u32, status, key.len() as u32]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    out.extend_from_slice(key.as_bytes());
    out
}

/// Answer one request. `Ok(false)` means the framing was broken and the
/// connection should be dropped.
pub async fn handle(
    socket: &mut tokio::net::UnixStream,
    context: &SimpleContext,
) -> tokio::io::Result<bool> {
    let (Some(1), Some(kind), Some(ticket_len), Some(id_len)) = (
        read_u32(socket).await,
        read_u32(socket).await,
        read_u32(socket).await,
        read_u32(socket).await,
    ) else {
        return Ok(false);
    };
    let (ticket_len, id_len) = (ticket_len as usize, id_len as usize);
    if ticket_len == 0 || ticket_len > MAX_TICKET || id_len > MAX_PUBLISHER_USER_ID {
        return Ok(false);
    }
    let (Some(ticket), Some(publisher_user_id)) = (
        read_text(socket, ticket_len).await,
        read_text(socket, id_len).await,
    ) else {
        return Ok(false);
    };
    let out = if kind != 1 {
        reply(2, "")
    } else {
        match tokio::time::timeout(
            TOTAL_TIMEOUT,
            collections_key(context, &ticket, &publisher_user_id),
        )
        .await
        {
            Ok(Ok(key)) => reply(0, &key),
            Ok(Err(cause)) => {
                tracing::warn!("Collections ID key request failed: {cause}");
                reply(1, "")
            }
            Err(_) => {
                tracing::warn!("Collections ID key request timed out");
                reply(1, "")
            }
        }
    };
    socket.write_all(&out).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_jwt_shaped_keys_are_passed_on() {
        assert!(valid_key("aGVhZGVy.cGF5bG9hZA.c2ln-_"));
        assert!(!valid_key(""));
        assert!(!valid_key("a b"));
        assert!(!valid_key("<xml/>"));
        assert!(!valid_key(&"a".repeat(MAX_KEY + 1)));
    }

    #[test]
    fn a_refusal_reports_only_its_code() {
        assert_eq!(
            refusal_code(br#"{"code":"InvalidServiceTicket","message":"secret detail"}"#),
            "InvalidServiceTicket"
        );
        assert_eq!(refusal_code(b"not json"), "-");
        assert_eq!(refusal_code(br#"{"code":"has spaces <x>"}"#), "-");
    }

    #[tokio::test]
    async fn broken_framing_drops_the_connection_and_unknown_kinds_are_refused() {
        let context = crate::simple_context::tests::context("owner-key", "player-key");
        let (mut client, mut server) = tokio::net::UnixStream::pair().unwrap();
        let mut request: Vec<u8> = [1u32, 2, 3, 0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        request.extend(b"abc");
        client.write_all(&request).await.unwrap();
        assert!(handle(&mut server, &context).await.unwrap());
        let mut answer = [0; 12];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(
            answer.as_slice(),
            [1u32, 2, 0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>()
        );
        client
            .write_all(
                &[2u32, 1, 3, 0]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect::<Vec<_>>(),
            )
            .await
            .unwrap();
        assert!(!handle(&mut server, &context).await.unwrap());
    }
}
