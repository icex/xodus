pub mod subscriptions;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserAuthRequest {
    pub relying_party: String,
    pub token_type: String,
    pub properties: UserAuthProperties,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserAuthProperties {
    pub auth_method: String,
    pub site_name: String,
    pub rps_ticket: String,
    /// Binds the issued token to a signing key, so requests to endpoints with
    /// a signature policy can be proven to come from its holder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_key: Option<crate::api::xbox::signing::ProofKey>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct XstsResponse {
    pub not_after: chrono::DateTime<chrono::Utc>,
    pub token: String,
    display_claims: DisplayClaims,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct DisplayClaims {
    #[serde(default)]
    xui: Vec<XuiClaim>,
    #[serde(default)]
    xti: Vec<XtiClaim>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct XuiClaim {
    uhs: String,
    gtg: Option<String>,
    xid: Option<String>,
    mgt: Option<String>,
    agg: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct XtiClaim {
    tid: Option<String>,
}

impl XstsResponse {
    pub fn user_hash(&self) -> Option<&str> {
        self.display_claims
            .xui
            .first()
            .map(|claim| claim.uhs.as_str())
    }

    pub fn xuid(&self) -> Option<&str> {
        self.display_claims
            .xui
            .first()
            .and_then(|claim| claim.xid.as_deref())
    }

    pub fn gamertag(&self) -> Option<&str> {
        self.display_claims
            .xui
            .first()
            .and_then(|claim| claim.gtg.as_deref())
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct XstsPropertyBag {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_token: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_tokens: Option<Vec<String>>,

    /// The device this session is running on. Services that address
    /// `devices/current` -- setting presence among them -- resolve the device
    /// from this claim, and reject the request outright when it is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_token: Option<String>,

    /// The title doing the calling. `titles/current` resolves from this, so
    /// setting presence needs it as well as the device claim: with only one of
    /// the two the service still answers 400.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title_token: Option<String>,

    #[serde(rename = "SandboxId", skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_token: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct XstsRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relying_party: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    pub properties: XstsPropertyBag,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct TitleMgtResponse {
    pub end_points: Vec<TitleMgtEndPoint>,
    pub signature_policies: Vec<TitleMgtSignaturePolicy>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct TitleMgtEndPoint {
    pub protocol: String,
    pub host: String,
    #[serde(default)]
    pub host_type: Option<String>,
    #[serde(default)]
    pub relying_party: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub signature_policy_index: Option<u8>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct TitleMgtSignaturePolicy {
    pub version: u16,
    pub supported_algorithms: Vec<String>,
    pub max_body_bytes: u64,
    pub supported_signature_types: Vec<String>,
}

/// A device authentication request. Unlike the user call this is proof of
/// possession: the request is signed with the same key advertised as ProofKey,
/// so the service can tie the device token to it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct DeviceAuthRequest {
    pub relying_party: String,
    pub token_type: String,
    pub properties: DeviceAuthProperties,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct DeviceAuthProperties {
    pub auth_method: String,
    pub device_type: String,
    pub id: String,
    pub serial_number: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_key: Option<crate::api::xbox::signing::ProofKey>,
}

/// A title authentication request: proves which game is calling, using the
/// device token and the same RPS ticket the user call uses.
#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TitleAuthRequest {
    pub relying_party: String,
    pub token_type: String,
    pub properties: TitleAuthProperties,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct TitleAuthProperties {
    pub auth_method: String,
    pub device_token: String,
    pub site_name: String,
    pub rps_ticket: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_key: Option<crate::api::xbox::signing::ProofKey>,
}
