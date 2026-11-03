//! The fixed Store endpoint stays inside the credential-owning service. Build
//! once, sign those bytes, send those bytes; never follow a signed redirect.
use crate::simple_context::SimpleContext;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::time::Duration;
use xodus::models::licensing::LicenseTokenResponse;
use xodus::models::xgameruntime::xuser::{LicenseTokenIpcRequest, XSTSTokenRequest};

const URL: &str = "https://licensing.mp.microsoft.com/v8.0/licenseToken";
const MAX_RESPONSE: usize = 65536;
const MAX_TOKEN: usize = 60000; // fits the IPC frame and the DLL result buffer
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);
type Error = &'static str;

fn body(req: &LicenseTokenIpcRequest) -> Result<Vec<u8>, Error> {
    let valid_id =
        |s: &str| !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_alphanumeric());
    if !valid_id(&req.parent_product_id)
        || req.product_ids.ids.len() > 256
        || req.product_ids.ids.iter().any(|id| !valid_id(id))
    {
        return Err("invalid product IDs");
    }
    let custom = STANDARD
        .decode(&req.custom_base64)
        .map_err(|_| "invalid custom string")?;
    let custom = std::str::from_utf8(&custom).map_err(|_| "invalid custom string")?;
    if custom.is_empty() {
        return Err("empty custom string");
    }
    // The Store expects a string containing an array, not an array value.
    let ids = serde_json::to_string(&req.product_ids.ids).map_err(|_| "invalid product IDs")?;
    serde_json::to_vec(&serde_json::json!({
        "parentProductId": req.parent_product_id,
        "enforceSellableBy": true,
        "relatedProductIds": ids,
        "customDeveloperString": custom,
    }))
    .map_err(|_| "cannot serialize request")
}

fn client_builder(timeout: Duration) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .user_agent("XboxGameRuntime")
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(timeout)
}

fn client(timeout: Duration) -> Result<reqwest::Client, Error> {
    client_builder(timeout)
        .build()
        .map_err(|_| "cannot create licensing client")
}

fn parse_response(bytes: &[u8]) -> Result<String, Error> {
    let response: LicenseTokenResponse =
        serde_json::from_slice(bytes).map_err(|_| "invalid token response")?;
    let token = response.license_token;
    // A JWT is nonempty ASCII base64url segments separated by dots. In
    // particular it contains no XML, NUL or control bytes on our raw IPC path.
    if token.is_empty()
        || token.len() > MAX_TOKEN
        || !token
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
    {
        return Err("invalid license token");
    }
    Ok(token)
}

async fn post(
    client: &reqwest::Client,
    url: &str,
    body: Vec<u8>,
    authorization: &str,
    signature: &str,
) -> Result<String, Error> {
    if authorization.is_empty() || signature.is_empty() {
        return Err("missing signed authorization");
    }
    let mut response = client
        .post(url)
        .header("Authorization", authorization)
        .header("Signature", signature)
        .header("Content-Type", "application/json; charset=UTF-8")
        .header("Cache-Control", "no-cache")
        .body(body)
        .send()
        .await
        .map_err(|_| "licensing transport failed")?;
    if response.status() != reqwest::StatusCode::OK {
        return Err("licensing HTTP failure");
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE as u64)
    {
        return Err("token response too large");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "licensing response failed")?
    {
        if chunk.len() > MAX_RESPONSE - bytes.len() {
            return Err("token response too large");
        }
        bytes.extend_from_slice(&chunk);
    }
    parse_response(&bytes)
}

async fn fetch_with<F, Fut>(
    xml: &[u8],
    url: &str,
    client: &reqwest::Client,
    authorize: F,
) -> Result<String, Error>
where
    F: FnOnce(XSTSTokenRequest) -> Fut,
    Fut: std::future::Future<
            Output = Result<xodus::models::xgameruntime::xuser::XSTSTokenResponse, Error>,
        >,
{
    let req: LicenseTokenIpcRequest =
        quick_xml::de::from_str(std::str::from_utf8(xml).map_err(|_| "invalid IPC request")?)
            .map_err(|_| "invalid IPC request")?;
    let bytes = body(&req)?;
    let auth = authorize(XSTSTokenRequest {
        url: url.into(),
        relying_party: String::new(),
        method: "POST".into(),
        body_base64: STANDARD.encode(&bytes),
        title_id: req.title_id,
        title_client_id: req.title_client_id,
    })
    .await?;
    post(client, url, bytes, &auth.token, &auth.signature).await
}

pub(super) async fn fetch(context: &mut SimpleContext, xml: &[u8]) -> Result<String, Error> {
    fetch_with(xml, URL, &client(HTTP_TIMEOUT)?, |req| async move {
        super::xml::xsts_token(context, req)
            .await
            .map_err(|_| "licensing authorization failed")
    })
    .await
}

#[cfg(test)]
mod tests;
