use crate::models::live::ExchangeUserTokenOutcome;
use crate::models::secrets::{LegacyToken, Token};
use crate::models::soap;
use crate::models::xbox::XstsResponse;

pub mod auth;
pub mod signing;
pub mod title;
pub use auth::{
    authenticate_xbox_device, authenticate_xbox_title, authenticate_xbox_user, get_xsts_auth_header, request_xsts_token,
};
pub use signing::{ProofKey, RequestSigner, path_and_query};

pub async fn run(
    client: &reqwest::Client,
    dev_token: LegacyToken,
    legacy: LegacyToken,
    relying_party: &str,
) -> XstsResponse {
    run_with_signer(client, dev_token, legacy, relying_party, None).await
}

/// As `run`, but binds the issued token to a signing key so the caller can sign
/// requests to endpoints that require it.
/// As `run_with_signer`, but reports failure instead of panicking.
///
/// The panicking version kills the task serving a token request, so the title
/// waits for an answer that never arrives -- one bad relying party or one
/// hiccup from the Xbox token service and that account looks signed out for
/// the rest of the session.
/// An RPS ticket issued under Minecraft's own client id.
///
/// Xbox will not issue a title token against the generic user ticket the rest
/// of this path uses -- title/authenticate answers 403 -- so the title call
/// needs its own ticket, obtained the way the SISU flow obtains one. Doing it
/// here rather than through SISU keeps the whole chain bound to our signing
/// key, which is what xsts/authorize insists on: a title token bound to a
/// different key makes it answer 400.
async fn title_scoped_rps(
    client: &reqwest::Client,
    dev_token: LegacyToken,
    legacy: LegacyToken,
) -> Result<String, String> {
    const CLIENT_ID: &str = "0000000040159362"; /* Minecraft */

    let dev_for_title = dev_token.clone();
    let legacy_for_title = legacy.clone();
    let outcome = crate::api::live::exchange_user_token(
        client,
        legacy,
        "USERNAME".to_string(),
        dev_token,
        None,
        Some("Silent".to_string()),
        CLIENT_ID.to_string(),
        &[
            (
                format!("scope=xboxlive.signin&api-version=2.0&clientid={CLIENT_ID}"),
                Some(soap::PolicyReference::token_broker()),
            ),
            ("http://Passport.NET/tb".to_string(), None),
        ],
    )
    .await
    .map_err(|e| format!("title-scoped RPS exchange failed: {e}"))?;

    let ExchangeUserTokenOutcome::Issued(
        soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
    ) = outcome
    else {
        return Err("title-scoped RPS exchange returned no collection".to_string());
    };
    if collection.security_tokens.is_empty() {
        return Err("title-scoped RPS exchange returned no tokens".to_string());
    }
    let token: Token = collection.security_tokens.remove(0).into();
    match token {
        Token::Compact(t) => {
            eprintln!(
                "[xodus] title-scoped ticket: {} chars, prefix {:?}",
                t.len(),
                &t[..t.len().min(2)]
            );
            Ok(t)
        }
        _ => Err("title-scoped RPS ticket is not compact".to_string()),
    }
}

/// A title token supplied from outside, for when title/authenticate refuses us.
///
/// Xbox only issues a title token to an RPS ticket obtained under the title's
/// own client id, and the ticket this path holds is a generic user one, so
/// title/authenticate answers 403. The SISU flow does hold such a ticket, so
/// the service runs it once and hands the result here.
static SISU_TITLE_TOKEN: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub fn set_title_token(token: String) {
    let _ = SISU_TITLE_TOKEN.set(token);
}

/// Whether to attach device and title claims. On by default; set
/// XODUS_DEVICE_TOKEN=0 to mint plain user-only tokens.
fn claims_wanted() -> bool {
    !std::env::var("XODUS_DEVICE_TOKEN").is_ok_and(|v| v == "0")
}

pub async fn try_run_with_signer(
    client: &reqwest::Client,
    dev_token: LegacyToken,
    legacy: LegacyToken,
    relying_party: &str,
    signer: Option<&signing::RequestSigner>,
) -> Result<XstsResponse, String> {
    let dev_for_title = dev_token.clone();
    let legacy_for_title = legacy.clone();
    let outcome = crate::api::live::exchange_user_token(
        client,
        legacy,
        "USERNAME".to_string(),
        dev_token,
        None,
        Some("Silent".to_string()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        &[(
            "user.auth.xboxlive.com".to_owned(),
            Some(soap::PolicyReference::mbi_ssl()),
        )],
    )
    .await
    .map_err(|e| format!("MSA user token exchange failed: {e}"))?;

    let user_token: Token = match outcome {
        ExchangeUserTokenOutcome::Fault(_) => return Err("MSA returned a fault".to_string()),
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
        ) => {
            if collection.security_tokens.is_empty() {
                return Err("MSA returned no tokens".to_string());
            }
            collection.security_tokens.remove(0).into()
        }
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(t)) => {
            (*t).into()
        }
        _ => return Err("unexpected MSA response".to_string()),
    };
    let Token::Compact(user_token) = user_token else {
        return Err("unsupported MSA token form".to_string());
    };

    let resp = authenticate_xbox_user(client, user_token, signer.map(|s| s.proof_key()))
        .await
        .map_err(|e| format!("Xbox user authentication failed: {e}"))?;

    // Device and title claims travel together. `devices/current` resolves from
    // one and `titles/current` from the other, so presence needs both; sending
    // only the device claim still leaves the service answering 400. Either
    // failing is not fatal -- everything that does not need them keeps working.
    let (device_token, title_token) = match signer.filter(|_| claims_wanted()) {
        Some(s) => {
            let dev = match authenticate_xbox_device(client, s).await {
                Ok(d) => Some(d.token),
                Err(e) => {
                    eprintln!("[xodus] device authenticate failed: {e}");
                    None
                }
            };
            let title = match dev.as_ref() {
                Some(d) => {
                    let ticket = match title_scoped_rps( client, dev_for_title.clone(), legacy_for_title.clone() ).await {
                        Ok(t) => Some(t),
                        Err(e) => {
                            eprintln!("[xodus] {e}");
                            None
                        }
                    };
                    match ticket {
                        Some(ticket) => match authenticate_xbox_title(client, ticket, d.clone(), s).await {
                            Ok(t) => Some(t.token),
                            Err(e) => {
                                eprintln!("[xodus] title authenticate failed: {e}");
                                SISU_TITLE_TOKEN.get().cloned()
                            }
                        },
                        None => SISU_TITLE_TOKEN.get().cloned(),
                    }
                }
                None => None,
            };
            eprintln!(
                "[xodus] claims: device={} title={}",
                dev.is_some(),
                title.is_some()
            );
            (dev, title)
        }
        None => (None, None),
    };

    request_xsts_token(client, resp.token, device_token, title_token, relying_party)
        .await
        .map_err(|e| format!("XSTS authorize failed for {relying_party}: {e}"))
}

pub async fn run_with_signer(
    client: &reqwest::Client,
    dev_token: LegacyToken,
    legacy: LegacyToken,
    relying_party: &str,
    signer: Option<&signing::RequestSigner>,
) -> XstsResponse {
    let dev_for_title = dev_token.clone();
    let legacy_for_title = legacy.clone();
    let user_token = crate::api::live::exchange_user_token(
        client,
        legacy,
        "USERNAME".to_string(),
        dev_token,
        None,
        Some("Silent".to_string()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        &[(
            "user.auth.xboxlive.com".to_owned(),
            Some(soap::PolicyReference::mbi_ssl()),
        )],
    )
    .await
    .expect("Failed to get ms user token");

    let user_token: Token = match user_token {
        ExchangeUserTokenOutcome::Fault(_) => {
            eprintln!("Failed to get exchange MS token");
            panic!("TODO");
        }
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
        ) => {
            let token = collection.security_tokens.remove(0);
            token.into()
        }
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
            token,
        )) => (*token).into(),
        _ => unreachable!("Only responses are handled"),
    };
    let Token::Compact(user_token) = user_token else {
        eprintln!("Unsupported token");
        panic!("TODO");
    };
    let resp = authenticate_xbox_user(client, user_token, signer.map(|s| s.proof_key()))
        .await
        .expect("Failed to authenticate Xbox user");

    // A device claim is what lets services address `devices/current`; without
    // one, setting presence is rejected and the account never shows as online.
    // A failure here is not fatal -- everything that does not need a device
    // still works -- so fall back to a user-only token.
    let (device_token, title_token) = match signer.filter(|_| claims_wanted()) {
        Some(s) => {
            let dev = match authenticate_xbox_device(client, s).await {
                Ok(d) => Some(d.token),
                Err(e) => {
                    eprintln!("[xodus] device authenticate failed: {e}");
                    None
                }
            };
            let title = match dev.as_ref() {
                Some(d) => {
                    let ticket = match title_scoped_rps( client, dev_for_title.clone(), legacy_for_title.clone() ).await {
                        Ok(t) => Some(t),
                        Err(e) => {
                            eprintln!("[xodus] {e}");
                            None
                        }
                    };
                    match ticket {
                        Some(ticket) => match authenticate_xbox_title(client, ticket, d.clone(), s).await {
                            Ok(t) => Some(t.token),
                            Err(e) => {
                                eprintln!("[xodus] title authenticate failed: {e}");
                                SISU_TITLE_TOKEN.get().cloned()
                            }
                        },
                        None => SISU_TITLE_TOKEN.get().cloned(),
                    }
                }
                None => None,
            };
            eprintln!(
                "[xodus] claims: device={} title={}",
                dev.is_some(),
                title.is_some()
            );
            (dev, title)
        }
        None => (None, None),
    };

    request_xsts_token(client, resp.token, device_token, title_token, relying_party)
        .await
        .expect("Failed to authenticate Xbox user")
}
