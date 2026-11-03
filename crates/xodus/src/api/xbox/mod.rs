use crate::models::live::ExchangeUserTokenOutcome;
use crate::models::secrets::{LegacyToken, Token};
use crate::models::soap;
use crate::models::xbox::XstsResponse;

pub mod auth;
pub mod claims;
pub mod signing;
pub mod title;
pub use auth::{
    authenticate_xbox_device, authenticate_xbox_title, authenticate_xbox_title_win,
    authenticate_xbox_user, get_xsts_auth_header, request_xsts_token,
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

/// Whether to attach a device claim. On by default; set
/// XODUS_DEVICE_TOKEN=0 to mint plain user-only tokens.
fn claims_wanted() -> bool {
    !std::env::var("XODUS_DEVICE_TOKEN").is_ok_and(|v| v == "0")
}

/// Authenticate the signed-in user and optional device without a title claim.
/// Reports authentication failures instead of panicking.
pub async fn try_run_with_signer(
    client: &reqwest::Client,
    dev_token: LegacyToken,
    legacy: LegacyToken,
    relying_party: &str,
    signer: Option<&signing::RequestSigner>,
) -> Result<XstsResponse, String> {
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

    let resp = authenticate_xbox_user(client, user_token, signer)
        .await
        .map_err(|e| format!("Xbox user authentication failed: {e}"))?;

    // This generic flow has no title metadata, so it can only attach the
    // user's own device claim. Title-specific callers authenticate separately.
    let device_token = match signer.filter(|_| claims_wanted()) {
        Some(s) => match authenticate_xbox_device(client, s).await {
            Ok(device) => Some(device.token),
            Err(e) => {
                tracing::warn!("Xbox device authentication failed: {e}");
                None
            }
        },
        None => None,
    };

    request_xsts_token(
        client,
        resp.token,
        device_token,
        None,
        relying_party,
        signer,
    )
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
    try_run_with_signer(client, dev_token, legacy, relying_party, signer)
        .await
        .expect("Failed to authenticate Xbox user")
}
