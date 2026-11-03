use crate::models::xbox::{
    DeviceAuthProperties, DeviceAuthRequest, TitleAuthProperties, TitleAuthRequest,
    UserAuthProperties, UserAuthRequest, XstsPropertyBag, XstsRequest, XstsResponse,
};

pub async fn authenticate_xbox_user(
    client: &reqwest::Client,
    rps_ticket: String,
    signer: Option<&crate::api::xbox::signing::RequestSigner>,
) -> reqwest::Result<XstsResponse> {
    authenticate_xbox_user_at(
        client,
        rps_ticket,
        signer,
        "https://user.auth.xboxlive.com/user/authenticate",
    )
    .await
}

async fn authenticate_xbox_user_at(
    client: &reqwest::Client,
    rps_ticket: String,
    signer: Option<&crate::api::xbox::signing::RequestSigner>,
    endpoint: &str,
) -> reqwest::Result<XstsResponse> {
    // Some delegation tickets are now rejected as d= but accepted as t=.
    // Keep the original exchange first and retry only that specific rejection.
    // The stored ticket and other MSA consumers must keep their original form.
    let fallback = rps_ticket
        .strip_prefix("d=")
        .filter(|t| !t.is_empty())
        .map(|t| format!("t={t}"));
    let response = xbox_user_request(client, &rps_ticket, signer, endpoint)
        .send()
        .await?;
    let response = match fallback {
        Some(ticket) if response.status() == reqwest::StatusCode::BAD_REQUEST => {
            // Rebuild the request: a proof-bound exchange must sign its new body.
            xbox_user_request(client, &ticket, signer, endpoint)
                .send()
                .await?
        }
        _ => response,
    };
    if !response.status().is_success() {
        eprintln!(
            "FERESTRE_TRANSFER_DIAGNOSTIC_V1 authentication {}",
            response.status().as_u16()
        );
    }
    response.error_for_status()?.json().await
}

fn xbox_user_request(
    client: &reqwest::Client,
    rps_ticket: &str,
    signer: Option<&crate::api::xbox::signing::RequestSigner>,
    endpoint: &str,
) -> reqwest::RequestBuilder {
    let body = UserAuthRequest {
        relying_party: "http://auth.xboxlive.com".to_string(),
        token_type: "JWT".to_string(),
        properties: UserAuthProperties {
            auth_method: "RPS".to_string(),
            site_name: "user.auth.xboxlive.com".to_string(),
            rps_ticket: rps_ticket.to_string(),
            proof_key: signer.map(|s| s.proof_key()),
        },
    };
    let payload = serde_json::to_vec(&body).expect("user auth request serialises");
    let mut request = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1");
    if let Some(signer) = signer {
        request = request.header(
            "Signature",
            signer.sign(1, "POST", "/user/authenticate", "", &payload, 8192),
        );
    }
    request.body(payload)
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
    let signature = signer.sign(1, "POST", "/device/authenticate", "", &payload, 8192);

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

fn win32_title_auth_payload(
    device_token: &str,
    title_id: i64,
    proof_key: crate::api::xbox::signing::ProofKey,
) -> Result<Vec<u8>, String> {
    if !(1..=u32::MAX as i64).contains(&title_id) {
        return Err(
            "Windows title authentication requires a TitleId in 1..=4294967295".to_string(),
        );
    }

    serde_json::to_vec(&serde_json::json!({
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT",
        "Properties": {
            "DeviceToken": device_token,
            "TitleId": title_id,
            "ProofKey": proof_key,
        },
    }))
    .map_err(|e| format!("could not serialize Windows title authentication request: {e}"))
}

/// Authenticate a Windows title using its configured numeric TitleId.
///
/// This is the Windows client-attested flow: it uses the device token and its
/// proof key, without requiring an MSAAppId or a title-scoped RPS ticket. The
/// device token must have been issued under `signer` as well.
pub async fn authenticate_xbox_title_win(
    client: &reqwest::Client,
    device_token: String,
    title_id: i64,
    signer: &crate::api::xbox::signing::RequestSigner,
) -> Result<XstsResponse, String> {
    let payload = win32_title_auth_payload(&device_token, title_id, signer.proof_key())?;
    let signature = signer.sign(1, "POST", "/title/authenticate", "", &payload, 8192);

    let resp = client
        .post("https://title.auth.xboxlive.com/title/authenticate")
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1")
        .header("Signature", signature)
        .body(payload)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| format!("Windows title authentication failed: {e}"))?;

    resp.json()
        .await
        .map_err(|e| format!("could not parse Windows title authentication response: {e}"))
}

/// Mint a token under the supplied proof key, or leave a user-only chain unbound.
/// A proof-bound identity must sign authorization with the same key that created it.
/// The existing XAL implementation signs this exchange as well as service calls.
pub async fn request_xsts_token(
    client: &reqwest::Client,
    token: String,
    device_token: Option<String>,
    title_token: Option<String>,
    relying_party: &str,
    signer: Option<&crate::api::xbox::signing::RequestSigner>,
) -> reqwest::Result<XstsResponse> {
    let request = xsts_request(
        client,
        token,
        device_token,
        title_token,
        relying_party,
        signer,
    )?;
    let resp = client.execute(request).await?;
    if let Err(error) = resp.error_for_status_ref() {
        let status = resp.status();
        let detail = resp.json::<serde_json::Value>().await.ok();
        let code = detail
            .as_ref()
            .and_then(|v| v.get("XErr"))
            .and_then(|v| v.as_u64());
        tracing::warn!(%status, ?code, "XSTS authorization refused for {relying_party}");
        return Err(error);
    }
    resp.json().await
}

fn xsts_request(
    client: &reqwest::Client,
    token: String,
    device_token: Option<String>,
    title_token: Option<String>,
    relying_party: &str,
    signer: Option<&crate::api::xbox::signing::RequestSigner>,
) -> reqwest::Result<reqwest::Request> {
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

    let payload = serde_json::to_vec(&body).expect("XSTS request serialises");
    let mut request = client
        .post("https://xsts.auth.xboxlive.com/xsts/authorize")
        .header("Content-Type", "application/json")
        .header("x-xbl-contract-version", "1");
    if let Some(signer) = signer {
        request = request.header(
            "Signature",
            signer.sign(1, "POST", "/xsts/authorize", "", &payload, 8192),
        );
    }
    request.body(payload).build()
}

pub fn get_xsts_auth_header(xsts: XstsResponse) -> String {
    let uhs = xsts.user_hash().expect("XSTS response missing xui claim");
    format!("XBL3.0 x={uhs};{}", xsts.token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::xbox::signing::ProofKey;

    fn synthetic_proof_key() -> ProofKey {
        ProofKey {
            crv: "P-256".to_string(),
            alg: "ES256".to_string(),
            use_: "sig".to_string(),
            kty: "EC".to_string(),
            x: "synthetic-x".to_string(),
            y: "synthetic-y".to_string(),
        }
    }

    #[test]
    fn proof_bound_xsts_request_signs_its_exact_wire_body() {
        use base64::Engine;
        use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        use p256::pkcs8::DecodePrivateKey;

        let signer = crate::api::xbox::RequestSigner::generate();
        let request = xsts_request(
            &reqwest::Client::new(),
            "synthetic-user".into(),
            Some("synthetic-device".into()),
            Some("synthetic-title".into()),
            "https://audience.example.test/",
            Some(&signer),
        )
        .unwrap();
        let encoded = request
            .headers()
            .get("Signature")
            .expect("proof-bound XSTS must be signed");
        let signature = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(signature.len(), 76);
        let body = request.body().unwrap().as_bytes().unwrap();
        let value: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(value["RelyingParty"], "https://audience.example.test/");
        assert_eq!(value["Properties"]["TitleToken"], "synthetic-title");
        let mut message = Vec::new();
        for part in [
            &signature[..4],
            &signature[4..12],
            b"POST",
            b"/xsts/authorize",
            b"",
            &body[..body.len().min(8192)],
        ] {
            message.extend_from_slice(part);
            message.push(0);
        }
        let key = p256::SecretKey::from_pkcs8_der(&signer.to_pkcs8().unwrap()).unwrap();
        let verifier = VerifyingKey::from(key.public_key());
        let signed = Signature::from_slice(&signature[12..]).unwrap();
        verifier
            .verify(&message, &signed)
            .expect("signature must use this identity's key and transmitted body");
        message[13] ^= 1;
        assert!(
            verifier.verify(&message, &signed).is_err(),
            "changed request must not authenticate"
        );
    }

    #[test]
    fn unbound_xsts_request_remains_unsigned() {
        let request = xsts_request(
            &reqwest::Client::new(),
            "synthetic-user".into(),
            None,
            None,
            "https://audience.example.test/",
            None,
        )
        .unwrap();
        assert!(!request.headers().contains_key("Signature"));
    }

    #[test]
    fn win32_title_request_uses_numeric_title_id_and_device_proof_only() {
        let payload =
            win32_title_auth_payload("synthetic-device-token", 0x12345678, synthetic_proof_key())
                .expect("valid title ID");
        let body: serde_json::Value = serde_json::from_slice(&payload).unwrap();

        assert_eq!(
            body,
            serde_json::json!({
                "RelyingParty": "http://auth.xboxlive.com",
                "TokenType": "JWT",
                "Properties": {
                    "DeviceToken": "synthetic-device-token",
                    "TitleId": 305419896,
                    "ProofKey": {
                        "crv": "P-256", "alg": "ES256", "use": "sig",
                        "kty": "EC", "x": "synthetic-x", "y": "synthetic-y"
                    }
                }
            })
        );
    }

    #[test]
    fn win32_title_request_rejects_ids_outside_nonzero_u32_range() {
        for title_id in [4294967296, 0, -1, i64::MIN, i64::MAX] {
            assert_eq!(
                win32_title_auth_payload("synthetic-device-token", title_id, synthetic_proof_key())
                    .unwrap_err(),
                "Windows title authentication requires a TitleId in 1..=4294967295"
            );
        }
    }

    #[test]
    fn win32_title_request_accepts_nonzero_u32_boundaries() {
        for title_id in [1, u32::MAX as i64] {
            let payload =
                win32_title_auth_payload("synthetic-device-token", title_id, synthetic_proof_key())
                    .expect("valid title ID boundary");
            let body: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            assert_eq!(body["Properties"]["TitleId"], title_id);
        }
    }
}

#[cfg(test)]
mod ticket_retry_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn server(
        statuses: Vec<u16>,
    ) -> (String, tokio::task::JoinHandle<Vec<(String, Vec<u8>)>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/user/authenticate",
            listener.local_addr().unwrap()
        );
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for status in statuses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let header_end = loop {
                    let mut buf = [0; 2048];
                    let n = socket.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buf[..n]);
                    if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                };
                let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                while bytes.len() < header_end + length {
                    let mut buf = [0; 2048];
                    let n = socket.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buf[..n]);
                }
                requests.push((headers, bytes[header_end..header_end + length].to_vec()));
                let body = if status == 200 {
                    r#"{"NotAfter":"2030-01-01T00:00:00Z","Token":"synthetic","DisplayClaims":{"xui":[]}}"#
                } else {
                    ""
                };
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
            requests
        });
        (url, task)
    }

    async fn exchange(
        ticket: &str,
        statuses: Vec<u16>,
        signed: bool,
    ) -> (
        reqwest::Result<XstsResponse>,
        Vec<(String, Vec<u8>)>,
        crate::api::xbox::RequestSigner,
    ) {
        let (url, task) = server(statuses).await;
        let signer = crate::api::xbox::RequestSigner::generate();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            authenticate_xbox_user_at(
                &reqwest::Client::new(),
                ticket.into(),
                signed.then_some(&signer),
                &url,
            ),
        )
        .await
        .unwrap();
        (result, task.await.unwrap(), signer)
    }

    #[tokio::test]
    async fn successful_original_ticket_is_never_rewritten() {
        let (result, requests, _) = exchange("d=synthetic-ticket", vec![200], false).await;
        assert_eq!(result.unwrap().token, "synthetic");
        assert_eq!(requests.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&requests[0].1).unwrap();
        assert_eq!(body["Properties"]["RpsTicket"], "d=synthetic-ticket");
        assert!(!requests[0].0.to_lowercase().contains("signature:"));
    }

    #[tokio::test]
    async fn rejected_delegation_ticket_retries_once_and_resigns_both_bodies() {
        use base64::Engine;
        use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
        use p256::pkcs8::DecodePrivateKey;
        let (result, requests, signer) = exchange("d=synthetic-ticket", vec![400, 200], true).await;
        assert!(result.is_ok());
        assert_eq!(requests.len(), 2);
        let key = p256::SecretKey::from_pkcs8_der(&signer.to_pkcs8().unwrap()).unwrap();
        let verifier = VerifyingKey::from(key.public_key());
        for ((headers, body), ticket) in requests
            .iter()
            .zip(["d=synthetic-ticket", "t=synthetic-ticket"])
        {
            let value: serde_json::Value = serde_json::from_slice(body).unwrap();
            assert_eq!(value["Properties"]["RpsTicket"], ticket);
            assert!(value["Properties"]["ProofKey"].is_object());
            let encoded = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("signature")
                        .then_some(value.trim())
                })
                .unwrap();
            let signature = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap();
            let mut message = Vec::new();
            for part in [
                &signature[..4],
                &signature[4..12],
                b"POST",
                b"/user/authenticate",
                b"",
                body.as_slice(),
            ] {
                message.extend_from_slice(part);
                message.push(0);
            }
            verifier
                .verify(&message, &Signature::from_slice(&signature[12..]).unwrap())
                .unwrap();
        }
    }

    #[tokio::test]
    async fn other_errors_and_ticket_forms_do_not_retry() {
        for (ticket, status) in [
            ("d=synthetic", 401),
            ("d=synthetic", 403),
            ("d=synthetic", 500),
            ("t=synthetic", 400),
            ("synthetic", 400),
            ("d=", 400),
        ] {
            let (result, requests, _) = exchange(ticket, vec![status], false).await;
            assert_eq!(result.unwrap_err().status().unwrap().as_u16(), status);
            assert_eq!(requests.len(), 1);
        }
        let (result, requests, _) = exchange("d=synthetic", vec![400, 400], false).await;
        assert_eq!(
            result.unwrap_err().status(),
            Some(reqwest::StatusCode::BAD_REQUEST)
        );
        assert_eq!(requests.len(), 2);
    }
}
