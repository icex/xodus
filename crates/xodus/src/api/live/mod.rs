use base64::prelude::*;
use zerocopy::transmute;

use crate::licensing::splicense::ClepHmacState;
use crate::models::devicecredential::{DeviceAddRequest, DeviceAddResponse};
use crate::models::live::ExchangeUserTokenOutcome;
use crate::models::secrets::{LegacyToken, Token};
use crate::models::soap;

mod rst;
mod utils;

pub const XML_HEADER: &str = r#"<?xml version="1.0" encoding="UTF-8"?>"#;

pub async fn login_device_credential(
    client: &reqwest::Client,
    data: DeviceAddRequest,
) -> Result<DeviceAddResponse, rst::RSTError> {
    let data = quick_xml::se::to_string(&data)?;

    let response = client
        .post("https://login.live.com/ppsecure/deviceaddcredential.srf")
        .header("User-Agent", "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)")
        .header("Content-Type", "application/soap+xml")
        .header("Host", "login.live.com")
        .body(data)
        .send()
        .await?;
    let text = response.text().await?;
    let resp: DeviceAddResponse = quick_xml::de::from_str(&text)?;
    Ok(resp)
}

pub async fn authenticate_device(
    client: &reqwest::Client,
    username: String,
    private_key: rsa::RsaPrivateKey,
) -> Result<soap::Envelope, rst::RSTError> {
    let request = rst::RSTRequestBuilder::new()
        .username(soap::UsernameToken::devicetoken(username))
        .signature(rst::RSTSignature::Rsa(Box::new(private_key)))
        .scope_policy("http://Passport.NET/tb", None)
        .build()?;

    request.request(client).await
}

pub async fn exchange_device_token(
    client: &reqwest::Client,
    token: LegacyToken,
    hosting_app: String,
    scope: String,
    policy: Option<soap::PolicyReference>,
) -> Result<soap::RequestSecurityTokenResponse, rst::RSTError> {
    let secret = BASE64_STANDARD.decode(
        token
            .binary_secret
            .as_ref()
            .ok_or(rst::RSTError::InvalidDeviceCredential)?,
    )?;
    let secret: [u8; 4096] = secret
        .try_into()
        .map_err(|_| rst::RSTError::InvalidDeviceCredential)?;
    let secret: ClepHmacState = transmute!(secret);
    let hmac_secret = secret.get_hmac_state();

    let request = rst::RSTRequestBuilder::new()
        .sso_flags("SsoRestr")
        .hosting_app(&hosting_app)
        .device_token(token)
        .signature(rst::RSTSignature::Hmac {
            clep_secret: &*hmac_secret,
            tpm_secret: &[],
        })
        .scope_policy(&scope, policy)
        .build()?;

    let envelope = request.request(client).await?;

    device_response(envelope)
}

fn device_response(
    envelope: soap::Envelope,
) -> Result<soap::RequestSecurityTokenResponse, rst::RSTError> {
    match envelope.body.body {
        soap::BodyContent::RequestSecurityTokenResponse(res) => Ok(*res),
        soap::BodyContent::RequestSecurityTokenResponseCollection(collection) => collection
            .security_tokens
            .into_iter()
            .next()
            .ok_or(rst::RSTError::EmptyDeviceTokenResponse),
        soap::BodyContent::Fault(_) => {
            // Status is a number, never a response body, credential or inline URL.
            let status = envelope
                .header
                .pp
                .and_then(|pp| pp.req_status)
                .and_then(|code| {
                    if let Some(hex) = code.strip_prefix("0x").or_else(|| code.strip_prefix("0X")) {
                        u32::from_str_radix(hex, 16).ok()
                    } else {
                        code.parse::<u32>().ok()
                    }
                });
            Err(rst::RSTError::DeviceCredentialRejected { status })
        }
        _ => Err(rst::RSTError::UnexpectedDeviceTokenResponse),
    }
}

/// Exchange the current shared device credential. A server rejection can precede
/// its recorded expiry; renew with the existing device key and retry only once.
pub async fn exchange_device_token_managed(
    client: &reqwest::Client,
    tokens: &crate::tokens::TokenManager,
    hosting_app: String,
    scope: String,
    policy: Option<soap::PolicyReference>,
) -> Result<(soap::RequestSecurityTokenResponse, LegacyToken), rst::RSTError> {
    with_device_renewal(
        || async {
            let Token::Legacy(device) = tokens
                .get_device_sts_token()
                .map_err(|_| rst::RSTError::DeviceCredentialUnavailable)?
            else {
                return Err(rst::RSTError::InvalidDeviceCredential);
            };
            let issued = exchange_device_token(
                client,
                device.clone(),
                hosting_app.clone(),
                scope.clone(),
                policy.clone(),
            )
            .await?;
            Ok((issued, device))
        },
        || async {
            crate::tokens::device::refresh_device_credentials(client, tokens)
                .await
                .map_err(|_| rst::RSTError::DeviceCredentialRefreshFailed)
        },
    )
    .await
}

async fn with_device_renewal<T, E, EF, R, RF>(exchange: E, refresh: R) -> Result<T, rst::RSTError>
where
    E: Fn() -> EF,
    EF: std::future::Future<Output = Result<T, rst::RSTError>>,
    R: Fn() -> RF,
    RF: std::future::Future<Output = Result<(), rst::RSTError>>,
{
    match exchange().await {
        Err(rst::RSTError::DeviceCredentialRejected { .. }) => {
            refresh().await?;
            exchange().await
        }
        result => result,
    }
}

// Each parameter maps directly to a distinct SOAP request field; grouping them
// into a params struct would just move the sprawl rather than reduce it.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_user_token(
    client: &reqwest::Client,
    user_token: LegacyToken,
    username: String,
    device_token: LegacyToken,
    inline_token: Option<String>,
    inline_ux: Option<String>,
    hosting_app: String,
    scope_policies: &[(String, Option<soap::PolicyReference>)],
) -> Result<ExchangeUserTokenOutcome, rst::RSTError> {
    let secret = BASE64_STANDARD.decode(device_token.binary_secret.as_ref().unwrap())?;
    let secret: [u8; 4096] = secret.try_into().unwrap();
    let secret: ClepHmacState = transmute!(secret);
    let hmac_secret = secret.get_hmac_state();

    let mut builder = rst::RSTRequestBuilder::new()
        .username(soap::UsernameToken::user_hint(username))
        .device_token(device_token)
        .user_token(Token::Legacy(user_token))
        .hosting_app(&hosting_app)
        .sso_flags("SsoRestr")
        .license_signature_key_version(None)
        .signature(rst::RSTSignature::Hmac {
            clep_secret: &*hmac_secret,
            tpm_secret: &[],
        });

    if let Some(ux) = inline_ux.as_deref() {
        builder = builder.inline_ux(ux);
    }
    if let Some(ft) = inline_token.as_deref() {
        builder = builder.inline_ft(ft);
    }
    for (scope, policy) in scope_policies {
        builder = builder.scope_policy(scope, policy.clone());
    }

    let request = builder.build()?;
    let envelope = request.request(client).await?;

    Ok(match envelope.body.body {
        soap::BodyContent::Fault(_) => ExchangeUserTokenOutcome::Fault(envelope.header.pp),
        body => ExchangeUserTokenOutcome::Issued(body),
    })
}

#[cfg(test)]
mod test {
    use crate::api::live::exchange_device_token;
    use crate::models::secrets::Token;
    use crate::models::soap;
    use crate::tokens::TokenManager;
    use crate::tokens::device::ensure_device_credentials;

    #[test]
    fn device_response_fault_and_empty_collection_are_errors_without_token_data() {
        use super::{device_response, rst};
        let mut header = soap::Header::new();
        header.pp = Some(
            serde_json::from_value(
                serde_json::json!({"reqstatus":"0x800488e5","UserSessionKey":"must-not-leak"}),
            )
            .unwrap(),
        );
        let fault = soap::Envelope::new(
            header,
            soap::Body {
                body: soap::BodyContent::Fault(soap::base::Fault {}),
            },
        );
        let err = device_response(fault).unwrap_err();
        assert!(matches!(
            err,
            rst::RSTError::DeviceCredentialRejected {
                status: Some(0x800488e5)
            }
        ));
        assert!(!format!("{err:?}").contains("must-not-leak"));
        let empty = soap::Envelope::new(
            soap::Header::new(),
            soap::Body {
                body: soap::BodyContent::RequestSecurityTokenResponseCollection(
                    soap::RequestSecurityTokenResponseCollection {
                        security_tokens: vec![],
                    },
                ),
            },
        );
        assert!(matches!(
            device_response(empty),
            Err(rst::RSTError::EmptyDeviceTokenResponse)
        ));
    }
    #[tokio::test]
    async fn device_response_retry_uses_renewed_state_once() {
        use std::cell::Cell;
        let renewed = Cell::new(false);
        let attempts = Cell::new(0);
        let refreshes = Cell::new(0);
        let result = super::with_device_renewal(
            || async {
                attempts.set(attempts.get() + 1);
                if renewed.get() {
                    Ok("fresh-device")
                } else {
                    Err(super::rst::RSTError::DeviceCredentialRejected {
                        status: Some(0x800488e5),
                    })
                }
            },
            || async {
                refreshes.set(refreshes.get() + 1);
                renewed.set(true);
                Ok(())
            },
        )
        .await
        .unwrap();
        assert_eq!(result, "fresh-device");
        assert_eq!(attempts.get(), 2);
        assert_eq!(refreshes.get(), 1);
    }
    #[tokio::test]
    async fn device_response_rejection_retry_is_bounded() {
        use std::cell::Cell;
        let attempts = Cell::new(0);
        let refreshes = Cell::new(0);
        let result = super::with_device_renewal(
            || async {
                attempts.set(attempts.get() + 1);
                Err::<(), _>(super::rst::RSTError::DeviceCredentialRejected { status: None })
            },
            || async {
                refreshes.set(refreshes.get() + 1);
                Ok(())
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(attempts.get(), 2);
        assert_eq!(refreshes.get(), 1);
    }
    #[tokio::test]
    async fn device_response_other_failures_do_not_renew_credentials() {
        let result = super::with_device_renewal(
            || async { Err::<(), _>(super::rst::RSTError::EmptyDeviceTokenResponse) },
            || async { panic!("must not renew unrelated failures") },
        )
        .await;
        assert!(matches!(
            result,
            Err(super::rst::RSTError::EmptyDeviceTokenResponse)
        ));
    }
    #[tokio::test]
    async fn device_response_failed_renewal_never_retries_old_credentials() {
        use std::cell::Cell;
        let attempts = Cell::new(0);
        let result = super::with_device_renewal(
            || async {
                attempts.set(attempts.get() + 1);
                Err::<(), _>(super::rst::RSTError::DeviceCredentialRejected { status: None })
            },
            || async { Err(super::rst::RSTError::DeviceCredentialRefreshFailed) },
        )
        .await;
        assert!(matches!(
            result,
            Err(super::rst::RSTError::DeviceCredentialRefreshFailed)
        ));
        assert_eq!(attempts.get(), 1);
    }

    #[tokio::test]
    async fn test_get_xbox_live_dev_token() {
        let client = reqwest::Client::new();

        let mgr = TokenManager::with_memory();
        ensure_device_credentials(&client, &mgr).await.unwrap();

        let token: Token = mgr.get_device_sts_token().unwrap();
        let Token::Legacy(token) = token else {
            todo!("no a LegacyToken");
        };
        let resp = exchange_device_token(
            &client,
            token,
            "{28C08266-F973-4AE6-FFE4-409B249F138F}".to_string(),
            "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0".to_owned(),
            Some(soap::PolicyReference::token_broker()),
        )
        .await
        .unwrap();

        let ms_device_token: Token = resp.into();
        let Token::Compact(ms_device_token) = ms_device_token else {
            todo!("Unsupported token");
        };

        println!("{}", ms_device_token);
    }
}
