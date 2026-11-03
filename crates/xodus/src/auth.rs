use reqwest::Client;
use xal::client_params::CLIENT_WINDOWS;
use xal::oauth2::basic::BasicTokenType;
use xal::oauth2::{EmptyExtraTokenFields, RedirectUrl, Scope, StandardTokenResponse};
use xal::response::{
    XADDisplayClaims, XATDisplayClaims, XAUDisplayClaims, XSTSDisplayClaims, XTokenResponse,
};
use xal::{
    AuthPromptCallback, Constants, DeviceType, Flows, TokenStore, XalAppParameters,
    XalAuthenticator,
};

use crate::models::live::ExchangeUserTokenOutcome;
use crate::models::secrets::Token;
use crate::models::soap;
use crate::tokens::TokenManager;

fn get_app_params() -> XalAppParameters {
    XalAppParameters {
        client_id: "000000004424da1f".to_string(),
        title_id: Some("704208617".into()),
        auth_scopes: vec![Scope::new(
            xal::Constants::SCOPE_SERVICE_USER_AUTH.to_owned(),
        )],
        redirect_uri: Some(
            RedirectUrl::new(xal::Constants::OAUTH20_DESKTOP_REDIRECT_URL.into()).unwrap(),
        ),
        client_secret: None,
    }
}

pub async fn start_new_session(
    cb: impl AuthPromptCallback,
) -> Result<TokenStore, Box<dyn std::error::Error>> {
    let app_params = get_app_params();
    let mut authenticator = XalAuthenticator::new(app_params, CLIENT_WINDOWS(), "RETAIL".into());
    let ts = Flows::ms_authorization_flow(&mut authenticator, cb, true).await?;
    let ts = Flows::xbox_live_authorization_traditional_flow(
        &mut authenticator,
        ts.live_token,
        Constants::RELYING_PARTY_XBOXLIVE.to_string(),
        xal::AccessTokenPrefix::None,
        false,
    )
    .await?;
    Ok(ts)
}

pub async fn get_xsts_token(
    device_token: Option<&XTokenResponse<XADDisplayClaims>>,
    title_token: Option<&XTokenResponse<XATDisplayClaims>>,
    user_token: Option<&XTokenResponse<XAUDisplayClaims>>,
    relying_party: &str,
) -> Result<XTokenResponse<XSTSDisplayClaims>, xal::Error> {
    let app_params = get_app_params();
    let mut authenticator = XalAuthenticator::new(app_params, CLIENT_WINDOWS(), "RETAIL".into());
    authenticator
        .get_xsts_token(device_token, title_token, user_token, relying_party)
        .await
}

pub async fn refresh_tokens(
    authenticator: &mut XalAuthenticator,
    live_token: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
) -> Result<TokenStore, Box<dyn std::error::Error>> {
    let ts = Flows::xbox_live_sisu_authorization_flow(authenticator, live_token).await?;
    Ok(ts)
}

pub async fn do_sisu(
    client: &Client,
    manager: &TokenManager,
    client_id: &str,
    title_id: i64,
) -> Result<
    (
        XalAuthenticator,
        xal::response::SisuRPSAuthorizationResponse,
        xal::response::DeviceToken,
    ),
    Box<dyn std::error::Error>,
> {
    let Token::Legacy(token) = manager.get_user_sts_token()? else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "error",
        )));
    };
    let scope = "xboxlive.signin";
    let (device_token_resp, device_token) = crate::api::live::exchange_device_token_managed(
        client,
        manager,
        "{28C08266-F973-4AE6-FFE4-409B249F138F}".to_string(),
        "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0".to_owned(),
        Some(soap::PolicyReference::token_broker()),
    )
    .await?;

    let Token::Compact(ms_device_token) = device_token_resp.into() else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "error",
        )));
    };

    let user_token = crate::api::live::exchange_user_token(
        client,
        token,
        "USERNAME".to_string(),
        device_token,
        None,
        Some("Silent".to_string()),
        client_id.to_string(),
        &[
            (
                format!("scope={scope}&api-version=2.0&clientid={client_id}"),
                Some(soap::PolicyReference::token_broker()),
            ),
            ("http://Passport.NET/tb".to_string(), None),
        ],
    )
    .await?;

    let ExchangeUserTokenOutcome::Issued(
        soap::BodyContent::RequestSecurityTokenResponseCollection(mut collection),
    ) = user_token
    else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "error",
        )));
    };

    if let Some(sts) = collection.security_tokens.pop() {
        let address = sts.applies_to.endpoint_reference.address.clone();
        let sts: Token = sts.into();
        let address = if let Token::Legacy(legacy) = &sts {
            legacy.key_name.clone().unwrap_or(address)
        } else {
            address
        };
        if let Err(err) = manager.save_user_token(address, sts) {
            tracing::warn!("Failed to persist refreshed STS token: {err}");
        }
    }
    let token = collection
        .security_tokens
        .into_iter()
        .next()
        .ok_or_else(|| std::io::Error::other("MSA returned no user token for SISU"))?;
    let token: Token = token.into();
    let Token::Compact(user_token) = token else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "error",
        )));
    };

    let mut auth = XalAuthenticator::new(
        XalAppParameters {
            client_id: client_id.to_owned(),
            title_id: Some(title_id.to_string()),
            auth_scopes: vec![],
            redirect_uri: None,
            client_secret: None,
        },
        xal::XalClientParameters {
            user_agent: "XAL GRTS 2025.11.20251105.000".to_string(),
            device_type: DeviceType::WIN32,
            client_version: "10.0.22621".to_string(),
            query_display: String::new(),
        },
        "RETAIL".to_owned(),
    );

    let data = auth
        .get_device_token_rps(ms_device_token.to_owned())
        .await?;
    let resp = auth
        .sisu_authorize_rps(&user_token, &data.token, None)
        .await?;
    Ok((auth, resp, data))
}

#[ignore]
#[tokio::test]
async fn test_minecraft_win_auth() {
    let client = reqwest::Client::new();
    crate::secrets::init_secrets().expect("Unable to initialize credentials");
    let tokens = TokenManager::with_keychain_and_memory();

    let (_, resp, _) = do_sisu(
        &client,
        &tokens,
        MINECRAFT_WIN_CLIENT_ID,
        MINECRAFT_WIN_TITLE_ID,
    )
    .await
    .expect("ok");

    println!("title {}", resp.title_token.token);
    println!("user {}", resp.user_token.token);
    println!("webpage {}", resp.web_page);
}

/// Everything a title needs to authenticate, all bound to one signing key.
///
/// Xbox refuses to mix keys: a title token minted under one key and a user
/// token minted under another makes xsts/authorize answer 400. Both SISU and
/// the Windows title authentication flow return this complete set, including
/// the key that must also sign subsequent service requests.
pub struct SisuIdentity {
    pub key_pkcs8: Vec<u8>,
    pub device_token: String,
    pub title_token: String,
    pub user_token: String,
    /// Earliest token expiry, expressed as a Unix timestamp.
    pub expires_at: i64,
}

/// Authenticate a Windows title whose metadata provides a TitleId.
///
/// Uses the signed-in account's legacy credentials for the user exchange and
/// binds the user, device and title tokens to one newly generated signing key.
/// Unlike SISU, the Windows title exchange does not require an MSAAppId.
pub async fn win32_identity_for(
    client: &Client,
    manager: &TokenManager,
    title_id: i64,
) -> Result<SisuIdentity, String> {
    use crate::api::xbox::{
        RequestSigner, authenticate_xbox_device, authenticate_xbox_title_win,
        authenticate_xbox_user,
    };

    if !(1..=u32::MAX as i64).contains(&title_id) {
        return Err(
            "Windows title authentication requires a TitleId in 1..=4294967295".to_string(),
        );
    }
    let Token::Legacy(user_sts) = manager
        .get_user_sts_token()
        .map_err(|e| format!("could not load the signed-in user's STS token: {e}"))?
    else {
        return Err("Windows title authentication requires a legacy user STS token".to_string());
    };
    let Token::Legacy(device_sts) = manager
        .get_device_sts_token()
        .map_err(|e| format!("could not load the device STS token: {e}"))?
    else {
        return Err("Windows title authentication requires a legacy device STS token".to_string());
    };

    let outcome = crate::api::live::exchange_user_token(
        client,
        user_sts,
        "USERNAME".to_string(),
        device_sts,
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

    let user_ticket: Token = match outcome {
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
    let Token::Compact(user_ticket) = user_ticket else {
        return Err("unsupported MSA token form".to_string());
    };

    let signer = RequestSigner::generate();
    let key_pkcs8 = signer
        .to_pkcs8()
        .ok_or_else(|| "could not export the Windows signing key".to_string())?;
    let user = authenticate_xbox_user(client, user_ticket, Some(&signer))
        .await
        .map_err(|e| format!("Xbox user authentication failed: {e}"))?;
    let device = authenticate_xbox_device(client, &signer)
        .await
        .map_err(|e| format!("Xbox device authentication failed: {e}"))?;
    let title =
        authenticate_xbox_title_win(client, device.token.clone(), title_id, &signer).await?;

    Ok(SisuIdentity {
        key_pkcs8,
        expires_at: user
            .not_after
            .timestamp()
            .min(device.not_after.timestamp())
            .min(title.not_after.timestamp()),
        device_token: device.token,
        title_token: title.token,
        user_token: user.token,
    })
}

#[cfg(test)]
mod win32_identity_tests {
    use super::*;

    #[tokio::test]
    async fn win32_identity_rejects_invalid_title_id_before_loading_credentials() {
        let client = Client::new();
        let manager = TokenManager::with_memory();
        for title_id in [4294967296, 0, -1, i64::MIN, i64::MAX] {
            let error = win32_identity_for(&client, &manager, title_id)
                .await
                .err()
                .expect("invalid title ID must fail");
            assert_eq!(
                error,
                "Windows title authentication requires a TitleId in 1..=4294967295"
            );
        }
    }
}

/// Minecraft for Windows' identity, not the Xbox app's: this MSA client id and
/// TitleId are the pair `test_minecraft_win_auth` above signs in with. A token
/// minted from it claims Minecraft, so a service that shows the title, such as
/// presence, shows Minecraft. Only services that ask "is there a title claim
/// at all" are satisfied by it; services that check *which* title are not.
pub const MINECRAFT_WIN_CLIENT_ID: &str = "0000000040159362";
pub const MINECRAFT_WIN_TITLE_ID: i64 = 896928775;

/// A title-claimed identity for a caller that has no title of its own. It
/// claims Minecraft for Windows; never use it for anything a friend can see.
pub async fn sisu_identity(
    client: &Client,
    manager: &TokenManager,
) -> Result<SisuIdentity, String> {
    sisu_identity_for(
        client,
        manager,
        MINECRAFT_WIN_CLIENT_ID,
        MINECRAFT_WIN_TITLE_ID,
    )
    .await
}

/// The same set, but claiming a particular title.
///
/// `client_id` is the title's `MSAAppId` and `title_id` its `TitleId`, both
/// out of its `MicrosoftGame.config`. Xbox mints the title claim from the pair,
/// and a service that scopes what it returns by title -- presence's
/// `titles/current`, the session directory -- answers 403 to a claim naming a
/// different title just as it does to no claim at all.
pub async fn sisu_identity_for(
    client: &Client,
    manager: &TokenManager,
    client_id: &str,
    title_id: i64,
) -> Result<SisuIdentity, String> {
    use p256::pkcs8::EncodePrivateKey;

    let (auth, resp, device) = do_sisu(client, manager, client_id, title_id)
        .await
        .map_err(|e| format!("SISU failed: {e}"))?;

    let key = auth.request_signer().keypair;
    let key_pkcs8 = key
        .to_pkcs8_der()
        .map_err(|e| format!("could not export the SISU signing key: {e}"))?
        .as_bytes()
        .to_vec();

    Ok(SisuIdentity {
        key_pkcs8,
        expires_at: resp
            .user_token
            .not_after
            .timestamp()
            .min(device.not_after.timestamp())
            .min(resp.title_token.not_after.timestamp()),
        device_token: device.token,
        title_token: resp.title_token.token,
        user_token: resp.user_token.token,
    })
}
