use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MSATokenRequest {
    pub client_id: String,
    #[serde(default)]
    pub allow_ui: bool,
    #[serde(default, alias = "MSAFullTrust")]
    pub msa_full_trust: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct MSATokenResponse {
    pub token: String,
    pub expiry: i64,
    pub device_rps: String,
    pub device_expiry: i64,
}

/// Ask for an Xbox Live XSTS token suitable for authenticating to `url`.
/// The relying party is resolved from the title-management endpoint list.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct XSTSTokenRequest {
    pub url: String,
    /// Optional override; when absent the endpoint list decides.
    #[serde(default)]
    pub relying_party: String,
    /// The request being made. A signature covers the method, path,
    /// authorization header and body, so it cannot be replayed onto another
    /// request -- which means these have to travel with the ask.
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub body_base64: String,
    /// The running title, out of its `MicrosoftGame.config`: `TitleId` in
    /// decimal and optional `MSAAppId`. Xbox mints the token's *title claim* from the
    /// Windows title ID (or the pair for SISU), and services that scope by title -- presence's `titles/current`,
    /// the session directory -- refuse a claim naming a different title exactly
    /// as they refuse none. Empty when an older runtime is on the other end.
    #[serde(default)]
    pub title_id: String,
    #[serde(default)]
    pub title_client_id: String,
}

impl XSTSTokenRequest {
    /// The title this request is on behalf of, when it named one.
    pub fn title(&self) -> Option<(i64, &str)> {
        let id = self.title_id.parse::<u32>().ok().filter(|id| *id > 0)? as i64;
        Some((id, self.title_client_id.as_str()))
    }
}

/// The `XBL3.0 x=<uhs>;<token>` header a title puts on its request, plus the
/// identity that came back with it.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct XSTSTokenResponse {
    pub token: String,
    pub xuid: String,
    pub gamertag: String,
    pub expiry: i64,
    /// The `Signature` header value, empty when the endpoint needs none.
    #[serde(default)]
    pub signature: String,
}

#[cfg(test)]
mod title_tests {
    use super::*;

    fn request(title: &str, client: &str) -> XSTSTokenRequest {
        XSTSTokenRequest {
            url: "https://service.example.test/".into(),
            relying_party: String::new(),
            method: String::new(),
            body_base64: String::new(),
            title_id: title.into(),
            title_client_id: client.into(),
        }
    }

    #[test]
    fn legacy_title_identity_does_not_require_an_msa_client() {
        let req = request("12345", "");
        assert_eq!(req.title(), Some((12345, "")));
    }

    #[test]
    fn msa_identity_keeps_its_own_client_and_title() {
        let req = request("67890", "example-client");
        assert_eq!(req.title(), Some((67890, "example-client")));
    }

    #[test]
    fn invalid_title_ids_never_become_title_claims() {
        for id in ["", "0", "-1", "not-a-number", "4294967296"] {
            assert_eq!(request(id, "client").title(), None);
        }
    }
}

/// XML IPC envelope. Custom data is base64 so XML cannot normalize or reject
/// caller strings containing controls; JSON escaping belongs to the service.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LicenseTokenIpcRequest {
    pub parent_product_id: String,
    pub product_ids: LicenseProductIds,
    pub custom_base64: String,
    #[serde(default)]
    pub title_id: String,
    #[serde(default)]
    pub title_client_id: String,
}

#[derive(Deserialize)]
pub struct LicenseProductIds {
    #[serde(rename = "ProductId", default)]
    pub ids: Vec<String>,
}
