use crate::hardware;
use crate::licensing::splicense::SPLicense;
use crate::licensing::utils::{generate_string, parse_bcrypt_rsa_private};
use crate::models::devicecredential::{Authentication, ClientInfo, DeviceAddRequest, DeviceInfo};
use crate::models::secrets::Device;
use crate::models::soap::BodyContent;
use crate::tokens::manager::TokenManager;

/// Provisions a device (if none is stored yet) or re-authenticates an existing one
/// (if its STS token is missing/expired), persisting the result through `tokens`.
pub async fn ensure_device_credentials(
    client: &reqwest::Client,
    tokens: &TokenManager,
) -> Result<(), String> {
    match tokens.get_device_license() {
        Err(crate::tokens::store::TokenStoreError::NotFound) => {
            provision_device(client, tokens).await
        }
        Err(_) => Err("Stored device credentials could not be read".into()),
        Ok(license) if tokens.get_device_sts_token().is_err() => {
            reauthenticate_device(client, tokens, license).await
        }
        Ok(_) => Ok(()),
    }
}

/// Renew only the shared device token using the existing device license/key.
/// User accounts, save namespaces and the device license are never replaced.
pub async fn refresh_device_credentials(
    client: &reqwest::Client,
    tokens: &TokenManager,
) -> Result<(), String> {
    let license = tokens
        .get_device_license()
        .map_err(|_| "Stored device credentials are unavailable")?;
    reauthenticate_device(client, tokens, license).await
}

async fn provision_device(client: &reqwest::Client, tokens: &TokenManager) -> Result<(), String> {
    let username = format!("02{}", generate_string(14));
    let password = generate_string(20);
    let provision = DeviceAddRequest {
        client_info: ClientInfo::default(),
        authentication: Authentication::new(username.clone(), password.clone()),
        device_info: Some(DeviceInfo {
            id: "DeviceInfo".to_string(),
            components: hardware::probe_provision_components(),
            tpm_info: None,
        }),
    };
    let dev = crate::api::live::login_device_credential(client, provision)
        .await
        .map_err(|_| "Microsoft device registration failed")?;
    let device = Device {
        username: username.clone(),
        password,
        puid: dev.puid,
        hwid: dev.hw_device_id,
        device_id: dev.license.binding.device_id.unwrap_or_default(),
        splicense: dev.license.splicense_block,
    };
    tokens
        .save_device_license(&device)
        .map_err(|_| "Could not save device credentials")?;
    reauthenticate_device(client, tokens, device).await
}

async fn reauthenticate_device(
    client: &reqwest::Client,
    tokens: &TokenManager,
    license: Device,
) -> Result<(), String> {
    let sp_license = SPLicense::parse_base64(&license.splicense)
        .map_err(|_| "Stored device license is invalid")?;
    let state = sp_license
        .clep_sign_state
        .ok_or("Stored device license has no signing key")?;
    let private_key = parse_bcrypt_rsa_private(&state.get_rsa_key())
        .map_err(|_| "Stored device signing key is invalid")?;
    let resp = crate::api::live::authenticate_device(client, license.username, private_key)
        .await
        .map_err(|_| "Microsoft device authentication failed")?;
    match resp.body.body {
        BodyContent::RequestSecurityTokenResponse(resp) => save_device_sts_token(tokens, resp),
        _ => Err("Microsoft did not issue a refreshed device credential".into()),
    }
}

fn save_device_sts_token(
    tokens: &TokenManager,
    resp: Box<crate::models::soap::RequestSecurityTokenResponse>,
) -> Result<(), String> {
    let key_name = resp
        .requested_security_token
        .encrypted_data
        .as_ref()
        .and_then(|data| data.key_info.key_name.clone())
        .ok_or("Device response has no token key")?;
    if resp.token_type != "urn:passport:legacy" || resp.requested_proof_token.is_none() {
        return Err("Device response has no usable signing secret".into());
    }
    tokens
        .save_device_token(key_name, (*resp).into())
        .map_err(|_| "Could not save refreshed device credentials".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::secrets::{Token, User};
    #[tokio::test]
    async fn device_response_failed_refresh_preserves_license_user_and_token() {
        let manager = TokenManager::with_memory();
        let license = Device {
            puid: "fixture-device".into(),
            hwid: "fixture-hardware".into(),
            device_id: "fixture-id".into(),
            splicense: "%%%".into(),
            username: "fixture-device".into(),
            password: "fixture-secret".into(),
        };
        manager.save_device_license(&license).unwrap();
        manager
            .save_user(&User {
                puid: "fixture-user".into(),
                username: "fixture-user".into(),
            })
            .unwrap();
        manager
            .save_device_token(
                crate::tokens::manager::PASSPORT_STS.into(),
                Token::Compact("old-token".into()),
            )
            .unwrap();
        let before = serde_json::to_value(manager.get_device_license().unwrap()).unwrap();
        assert!(
            refresh_device_credentials(&reqwest::Client::new(), &manager)
                .await
                .is_err()
        );
        assert_eq!(
            serde_json::to_value(manager.get_device_license().unwrap()).unwrap(),
            before
        );
        assert_eq!(manager.get_user().unwrap().puid, "fixture-user");
        assert!(
            matches!(manager.get_device_sts_token().unwrap(),Token::Compact(value) if value=="old-token")
        );
    }
}
