use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn request(custom: &str) -> LicenseTokenIpcRequest {
    quick_xml::de::from_str(&format!("<LicenseTokenRequest><ParentProductId>9TESTSTORE0ID</ParentProductId><ProductIds><ProductId>9TESTADDON00</ProductId></ProductIds><CustomBase64>{}</CustomBase64><TitleId>123</TitleId></LicenseTokenRequest>", STANDARD.encode(custom))).unwrap()
}

#[test]
fn custom_strings_round_trip_without_xml_or_json_damage() {
    for custom in [
        "plain",
        "{\"nonce\":\"a\\b\"}",
        "line\n\t\r\u{1}",
        "română 🪟",
    ] {
        let bytes = body(&request(custom)).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["customDeveloperString"], custom);
        assert_eq!(value["relatedProductIds"], "[\"9TESTADDON00\"]");
        assert_eq!(value["parentProductId"], "9TESTSTORE0ID");
        assert_eq!(value["enforceSellableBy"], true);
    }
    assert!(body(&request("")).is_err());
}

#[test]
fn response_requires_a_nonempty_top_level_string_and_valid_json() {
    for bytes in [
        br#"{"licenseToken":""}"#.as_slice(),
        br#"{"licenseToken":null,"error":"secret"}"#,
        br#"{"licenseToken":42,"other":"value"}"#,
        br#"{"error":{"licenseToken":"a.b.c"}}"#,
        br#"not-json "licenseToken":"a.b.c""#,
        br#"{"licenseToken":"secret"#,
        br#"{"licenseToken":"a.b.c","licenseToken":"d.e.f"}"#,
        br#"{"licenseToken":"a\u0000b"}"#,
    ] {
        assert!(parse_response(bytes).is_err());
    }
    assert_eq!(
        parse_response(br#"{"licenseToken":"\u0061.b.c","extra":true}"#).unwrap(),
        "a.b.c"
    );
}

async fn endpoint(
    status: u16,
    payload: Vec<u8>,
    extra: &str,
    delay: Duration,
) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/v8.0/licenseToken",
        listener.local_addr().unwrap()
    );
    let extra = extra.to_string();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0; 1024];
        loop {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&buf[..n]);
            if let Some(end) = bytes.windows(4).position(|x| x == b"\r\n\r\n") {
                let header = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                let length: usize = header
                    .lines()
                    .find_map(|x| x.strip_prefix("content-length: "))
                    .unwrap()
                    .parse()
                    .unwrap();
                if bytes.len() >= end + 4 + length {
                    break;
                }
            }
        }
        tokio::time::sleep(delay).await;
        let length = if extra.contains("Transfer-Encoding: chunked") {
            String::new()
        } else {
            format!("Content-Length: {}\r\n", payload.len())
        };
        let header = format!("HTTP/1.1 {status} Test\r\n{length}Connection: close\r\n{extra}\r\n");
        let _ = stream.write_all(header.as_bytes()).await;
        let _ = stream.write_all(&payload).await;
        bytes
    });
    (url, task)
}

#[tokio::test]
async fn posts_exact_signed_bytes_and_returns_token() {
    let (url, server) = endpoint(
        200,
        br#"{"licenseToken":"a.b.c"}"#.to_vec(),
        "",
        Duration::ZERO,
    )
    .await;
    let bytes = body(&request("{\"nonce\":\"a\\b\"}")).unwrap();
    assert_eq!(
        post(
            &client(HTTP_TIMEOUT).unwrap(),
            &url,
            bytes.clone(),
            "fixture-auth",
            "fixture-signature"
        )
        .await
        .unwrap(),
        "a.b.c"
    );
    let received = server.await.unwrap();
    let split = received.windows(4).position(|x| x == b"\r\n\r\n").unwrap();
    assert_eq!(&received[split + 4..], &bytes);
    let headers = String::from_utf8_lossy(&received[..split]).to_ascii_lowercase();
    assert!(headers.contains("authorization: fixture-auth\r\n"));
    assert!(headers.contains("signature: fixture-signature\r\n"));
}

#[tokio::test]
async fn redirects_never_reach_the_other_server() {
    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    for status in [301, 302, 303, 307, 308] {
        let (url, server) = endpoint(
            status,
            Vec::new(),
            &format!("Location: http://{}/sink\r\n", sink.local_addr().unwrap()),
            Duration::ZERO,
        )
        .await;
        assert!(
            post(
                &client(HTTP_TIMEOUT).unwrap(),
                &url,
                b"{}".to_vec(),
                "fixture-auth",
                "fixture-signature"
            )
            .await
            .is_err()
        );
        server.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), sink.accept())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn refuses_errors_oversize_and_stalls_without_response_contents() {
    for (status, payload, delay) in [
        (401, b"SECRET".to_vec(), Duration::ZERO),
        (503, b"SECRET".to_vec(), Duration::ZERO),
        (200, vec![b'a'; MAX_RESPONSE + 1], Duration::ZERO),
        (200, b"SECRET".to_vec(), Duration::from_millis(150)),
    ] {
        let (url, server) = endpoint(status, payload, "", delay).await;
        let result = post(
            &client(Duration::from_millis(50)).unwrap(),
            &url,
            b"{}".to_vec(),
            "fixture-auth",
            "fixture-signature",
        )
        .await;
        assert!(result.is_err());
        assert!(!result.unwrap_err().contains("SECRET"));
        server.await.unwrap();
    }
}

// Only compiled into the test executable. The normal service has no endpoint
// override or synthetic credential mode. The Wine harness drives this fixture
// over the real IPC framing and the production fetch/serialization/HTTP path.
#[tokio::test]
#[ignore = "launched by the Wine license-token regression harness"]
async fn offline_service_fixture() {
    use xodus::models::xgameruntime::xuser::XSTSTokenResponse;
    let dir = std::env::var("XODUS_LICENSE_FIXTURE_DIR").expect("fixture directory");
    let url = std::env::var("XODUS_LICENSE_FIXTURE_URL").expect("fixture endpoint");
    let listener = tokio::net::UnixListener::bind(format!("{dir}/xodus.sock")).unwrap();
    let mut builder = client_builder(Duration::from_millis(750));
    if let Ok(path) = std::env::var("XODUS_LICENSE_FIXTURE_CA") {
        // The same local endpoint must fail before the fixture CA is trusted.
        let mut req = request("untrusted-cert-probe");
        req.product_ids.ids.insert(0, "9TESTSTORE0ID".into());
        let bytes = body(&req).unwrap();
        assert!(
            post(
                &client(Duration::from_millis(750)).unwrap(),
                &url,
                bytes.clone(),
                "fixture-auth",
                &STANDARD.encode(&bytes)
            )
            .await
            .is_err()
        );
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(path).unwrap()).unwrap(),
        );
    }
    let client = builder.build().unwrap();
    std::fs::write(format!("{dir}/ready"), "ready").unwrap();
    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        let url = url.clone();
        let client = client.clone();
        tokio::spawn(async move {
            let mut header = [0; 8];
            if socket.read_exact(&mut header).await.is_err() {
                return;
            }
            assert_eq!(&header[..4], b"XSDX");
            let message = u16::from_le_bytes([header[4], header[5]]);
            let mut bytes = vec![0; u16::from_le_bytes([header[6], header[7]]) as usize];
            socket.read_exact(&mut bytes).await.unwrap();
            let payload = if message == 5 {
                b"<XSTSTokenResponse><Token>fixture-auth</Token><Signature>fixture-signature</Signature><Xuid>1</Xuid><Gamertag>Fixture</Gamertag><Expiry>4102444800</Expiry></XSTSTokenResponse>".to_vec()
            } else {
                assert_eq!(message, 7);
                let req: LicenseTokenIpcRequest =
                    quick_xml::de::from_str(std::str::from_utf8(&bytes).unwrap()).unwrap();
                let custom =
                    String::from_utf8(STANDARD.decode(&req.custom_base64).unwrap()).unwrap();
                match custom.as_str() {
                    "ipc-old-service" => {
                        let _ = socket
                            .write_all(&crate::connection::encode_message(
                                crate::XML_MAGIC,
                                1,
                                Vec::new(),
                            ))
                            .await;
                        return;
                    }
                    "ipc-disconnect" => return,
                    "ipc-truncated" | "ipc-oversize" => {
                        let size: u16 = if custom == "ipc-oversize" { 60001 } else { 10 };
                        let mut header = b"XSDX\x08\x00".to_vec();
                        header.extend_from_slice(&size.to_le_bytes());
                        header.extend_from_slice(b"abc");
                        let _ = socket.write_all(&header).await;
                        return;
                    }
                    "ipc-stall" => {
                        tokio::time::sleep(Duration::from_secs(55)).await;
                        return;
                    }
                    _ => {}
                }
                let outcome = fetch_with(&bytes, &url, &client, |request| async move {
                    assert_eq!(request.method, "POST");
                    assert_eq!(request.title_id, "1298034544");
                    assert_eq!(
                        request.title_client_id,
                        "00000000-0000-0000-0000-000000000000"
                    );
                    let bytes = STANDARD.decode(&request.body_base64).unwrap();
                    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(body["parentProductId"], "9TESTSTORE0ID");
                    assert_eq!(
                        body["relatedProductIds"],
                        "[\"9TESTSTORE0ID\",\"9TESTADDON00\"]"
                    );
                    // Bind the fixture Signature to the exact signed bytes.
                    Ok(XSTSTokenResponse {
                        token: "fixture-auth".into(),
                        signature: STANDARD.encode(bytes),
                        xuid: "1".into(),
                        gamertag: "Fixture".into(),
                        expiry: 4102444800,
                    })
                })
                .await;
                outcome.unwrap_or_default().into_bytes()
            };
            let frame = crate::connection::encode_message(crate::XML_MAGIC, message + 1, payload);
            let _ = socket.write_all(&frame).await;
        });
    }
}

#[tokio::test]
async fn chunked_bodies_are_parsed_and_bounded_without_content_length() {
    for (body, succeeds) in [
        (br#"{"licenseToken":"a.b.c"}"#.to_vec(), true),
        (vec![b'a'; MAX_RESPONSE + 1], false),
    ] {
        let mut wire = format!("{:x}\r\n", body.len()).into_bytes();
        wire.extend(body);
        wire.extend_from_slice(b"\r\n0\r\n\r\n");
        let (url, server) =
            endpoint(200, wire, "Transfer-Encoding: chunked\r\n", Duration::ZERO).await;
        let result = post(
            &client(HTTP_TIMEOUT).unwrap(),
            &url,
            b"{}".to_vec(),
            "fixture-auth",
            "fixture-signature",
        )
        .await;
        assert_eq!(result.is_ok(), succeeds);
        server.await.unwrap();
    }
}
