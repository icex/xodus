use crate::models::xbox::{
    DeviceAuthProperties, DeviceAuthRequest, TitleAuthProperties, TitleAuthRequest,
    UserAuthProperties, UserAuthRequest, XstsPropertyBag, XstsRequest, XstsResponse,
};

pub async fn authenticate_xbox_user(
    client: &reqwest::Client,
    rps_ticket: String,
    proof_key: Option<crate::api::xbox::signing::ProofKey>,
) -> reqwest::Result<XstsResponse> {
    let body = UserAuthRequest {
        relying_party: "http://auth.xboxlive.com".to_string(),
        token_type: "JWT".to_string(),
        properties: UserAuthProperties {
            auth_method: "RPS".to_string(),
            site_name: "user.auth.xboxlive.com".to_string(),
            rps_ticket,
            proof_key,
        },
    };

    let resp = client
        .post("https://user.auth.xboxlive.com/user/authenticate")
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1")
        .json(&body)
        .send()
        .await?
        .error_for_status()?;

    resp.json().await
}

/// Authenticate this machine as a device.
///
/// Without a device token the XSTS token carries no device claim, and any
/// service that addresses `devices/current` cannot tell which device is
/// calling: setting presence fails with 400 ArgumentError, so the account
/// never appears online. The device identity is derived from the signing key
/// so it is stable for as long as that key is.
pub async fn authenticate_xbox_device(
    client: &reqwest::Client,
    signer: &crate::api::xbox::signing::RequestSigner,
) -> reqwest::Result<XstsResponse> {
    // A stable id for this device, derived from the signing key rather than
    // random so the same machine keeps the same identity across runs.
    let id = signer.device_id();
    let body = DeviceAuthRequest {
        relying_party: "http://auth.xboxlive.com".to_string(),
        token_type: "JWT".to_string(),
        properties: DeviceAuthProperties {
            auth_method: "ProofOfPossession".to_string(),
            device_type: "Win32".to_string(),
            id: format!("{{{id}}}"),
            serial_number: format!("{{{id}}}"),
            version: "10.0.22631".to_string(),
            proof_key: Some(signer.proof_key()),
        },
    };

    let payload = serde_json::to_vec(&body).expect("device auth request serialises");
    let signature = signer.sign(
        1,
        "POST",
        "/device/authenticate",
        "",
        &payload,
        8192,
    );

    let resp = client
        .post("https://device.auth.xboxlive.com/device/authenticate")
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1")
        .header("Signature", signature)
        .body(payload)
        .send()
        .await?
        .error_for_status()?;

    resp.json().await
}

/// Authenticate the title itself.
///
/// `titles/current` resolves from this claim the way `devices/current`
/// resolves from the device one, so setting presence needs both: supplying
/// only the device token still leaves the service answering 400.
pub async fn authenticate_xbox_title(
    client: &reqwest::Client,
    rps_ticket: String,
    device_token: String,
    signer: &crate::api::xbox::signing::RequestSigner,
) -> reqwest::Result<XstsResponse> {
    let body = TitleAuthRequest {
        relying_party: "http://auth.xboxlive.com".to_string(),
        token_type: "JWT".to_string(),
        properties: TitleAuthProperties {
            auth_method: "RPS".to_string(),
            device_token,
            site_name: "user.auth.xboxlive.com".to_string(),
            rps_ticket,
            proof_key: Some(signer.proof_key()),
        },
    };

    let payload = serde_json::to_vec(&body).expect("title auth request serialises");
    let signature = signer.sign(1, "POST", "/title/authenticate", "", &payload, 8192);

    let resp = client
        .post("https://title.auth.xboxlive.com/title/authenticate")
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1")
        .header("Signature", signature)
        .body(payload)
        .send()
        .await?
        .error_for_status()?;

    resp.json().await
}

pub async fn request_xsts_token(
    client: &reqwest::Client,
    token: String,
    device_token: Option<String>,
    title_token: Option<String>,
    relying_party: &str,
) -> reqwest::Result<XstsResponse> {
    let body = XstsRequest {
        relying_party: Some(relying_party.to_string()),
        token_type: Some("JWT".to_string()),
        properties: XstsPropertyBag {
            user_tokens: Some(vec![token]),
            device_token,
            title_token,
            sandbox_id: Some("RETAIL".to_string()),
            delegation_token: None,
            service_token: None,
        },
    };

    let resp = client
        .post("https://xsts.auth.xboxlive.com/xsts/authorize")
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1")
        .json(&body)
        .send()
        .await?
        .error_for_status()?;

    resp.json().await
}

pub fn get_xsts_auth_header(xsts: XstsResponse) -> String {
    let uhs = xsts.user_hash().expect("XSTS response missing xui claim");
    format!("XBL3.0 x={uhs};{}", xsts.token)
}
