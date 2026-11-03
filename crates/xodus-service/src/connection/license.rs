//! The fixed Store endpoint stays inside the credential-owning service. Build
//! once, sign those bytes, send those bytes; never follow a signed redirect.
use crate::simple_context::SimpleContext;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::time::Duration;
use xodus::models::licensing::LicenseTokenResponse;
use xodus::models::xgameruntime::xuser::{LicenseTokenIpcRequest, XSTSTokenRequest};

pub(super) const URL: &str = "https://licensing.mp.microsoft.com/v8.0/licenseToken";
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

fn parse(xml: &[u8]) -> Result<LicenseTokenIpcRequest, Error> {
    quick_xml::de::from_str(std::str::from_utf8(xml).map_err(|_| "invalid IPC request")?)
        .map_err(|_| "invalid IPC request")
}

async fn fetch_with<F, Fut>(
    req: LicenseTokenIpcRequest,
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

/// Hold a licence request to the title the service is bound to.
///
/// A service bound to one title signs licence requests for that title only:
/// the Store account's token is not the running game's to spend on another
/// product it happens to own. The parent must be the bound product, every
/// product ID must be one the Store catalog ties to it (see
/// `Entitlement::admit_products`), and the request is signed under the bound
/// title's identity whatever TitleId and TitleClientId it carried. An unbound
/// service changes nothing.
async fn scope<L, Fut>(
    context: &SimpleContext,
    req: &mut LicenseTokenIpcRequest,
    lookup: L,
) -> Result<(), Error>
where
    L: FnOnce(Vec<String>) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<serde_json::Value>, Error>>,
{
    let Some(bound) = &context.entitlement else {
        // A service bound to a title is bound to its product too; one
        // without the product could not hold the request to it.
        if context.title.is_some() {
            tracing::warn!(
                "refused a licence token: this service has a title binding but no product"
            );
            return Err("licence token request without a bound product");
        }
        return Ok(());
    };
    if !req.parent_product_id.eq_ignore_ascii_case(bound.product()) {
        tracing::warn!(
            "refused a licence token with parent {:?}; this service is bound to {}",
            req.parent_product_id,
            bound.product()
        );
        return Err("licence token request is for another title");
    }
    // Bound to the product but to no title identity, which no released
    // launcher does: a title on the request could not be held to anything,
    // and the XSTS request would refuse it anyway. Say so here.
    if context.title.is_none() && req.title_id.parse::<u32>().is_ok_and(|id| id > 0) {
        tracing::warn!(
            "refused a licence token for title {:?}; this service is bound to {} without a title identity",
            req.title_id,
            bound.product()
        );
        return Err(
            "licence token request names a title, and this service has a product binding but no title",
        );
    }
    if let Err(refusal) = bound.admit_products(&req.product_ids.ids, lookup).await {
        tracing::warn!("{refusal}");
        return Err("licence token request names products outside the bound title");
    }
    if let Some(title) = &context.title {
        if req.title_id != title.title_id() || req.title_client_id != title.client_id() {
            tracing::info!(
                "licence token request claimed title {:?} (client {:?}); signing it as the bound title {:?} (client {:?})",
                req.title_id,
                req.title_client_id,
                title.title_id(),
                title.client_id()
            );
        }
        req.title_id = title.title_id();
        req.title_client_id = title.client_id().into();
    }
    Ok(())
}

pub(super) async fn fetch(context: &mut SimpleContext, xml: &[u8]) -> Result<String, Error> {
    let mut req = parse(xml)?;
    scope(context, &mut req, super::catalog::relationships).await?;
    let mut store = context.store_context();
    fetch_with(req, URL, &client(HTTP_TIMEOUT)?, |req| async move {
        super::xml::xsts_token_for(&mut store, req, super::xml::Caller::Licensing)
            .await
            .map_err(|_| "licensing authorization failed")
    })
    .await
}

#[cfg(test)]
mod tests;
