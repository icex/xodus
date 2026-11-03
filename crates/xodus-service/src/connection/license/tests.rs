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
            let mut magic = [0; 4];
            if socket.read_exact(&mut magic).await.is_err() {
                return;
            }
            assert_eq!(&magic, b"XSDX");
            let (message, bytes) = super::super::xml::read_request(&mut socket).await.unwrap();
            let message = message as u16;
            let payload = if message == 5 {
                let req: xodus::models::xgameruntime::xuser::XSTSTokenRequest =
                    quick_xml::de::from_str(std::str::from_utf8(&bytes).unwrap()).unwrap();
                if req.url == "https://fixture.invalid/large" {
                    let body = STANDARD.decode(req.body_base64).unwrap();
                    assert_eq!(body.len(), 100000);
                    assert!(body.iter().enumerate().all(|(n, b)| *b == (n % 251) as u8));
                }
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
                let req = parse(&bytes).unwrap();
                let outcome = fetch_with(req, &url, &client, |request| async move {
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

#[tokio::test]
async fn a_title_bound_service_signs_licence_requests_for_that_title_only() {
    let mut context = crate::simple_context::tests::context("owner-bound", "player-bound");
    context.entitlement = Some(crate::entitlement::Entitlement::fixture("9OTHERSTORE0"));
    let xml = format!(
        "<LicenseTokenRequest><ParentProductId>9TESTSTORE0ID</ParentProductId><ProductIds><ProductId>9TESTADDON00</ProductId></ProductIds><CustomBase64>{}</CustomBase64><TitleId>123</TitleId></LicenseTokenRequest>",
        STANDARD.encode("fixture")
    );
    assert_eq!(
        super::fetch(&mut context, xml.as_bytes()).await,
        Err("licence token request is for another title")
    );
}

fn catalog_entry(id: &str, related: &[(&str, &str)]) -> serde_json::Value {
    let related: Vec<_> = related
        .iter()
        .map(|(id, kind)| serde_json::json!({"RelatedProductId": id, "RelationshipType": kind}))
        .collect();
    serde_json::json!({"ProductId": id, "MarketProperties": [{"RelatedProducts": related}]})
}

/// The bound game, which names a bundle containing it and the storefront
/// that sells it; an add-on and an edition that name the game; and an
/// unrelated product only recommended alongside it.
fn catalog() -> Vec<serde_json::Value> {
    vec![
        catalog_entry(
            "9TESTSTORE0I",
            &[("9TESTBUNDLE0", "Bundle"), ("9TESTLAUNCH0", "SellableBy")],
        ),
        catalog_entry(
            "9TESTADDON00",
            &[
                ("9TESTSTORE0I", "addOnParent"),
                ("9TESTSTORE0I", "SellableBy"),
            ],
        ),
        catalog_entry("9TESTDELUXE0", &[("9TESTSTORE0I", "Parent")]),
        catalog_entry("9TESTBUNDLE0", &[]),
        catalog_entry("9TESTLAUNCH0", &[]),
        catalog_entry("9OTHERGAME00", &[("9TESTSTORE0I", "Recommendation")]),
        catalog_entry("9SOLDBYGAME0", &[("9TESTSTORE0I", "SellableBy")]),
    ]
}

fn bound_request(products: &[&str], title: &str, client: &str) -> LicenseTokenIpcRequest {
    let products: String = products
        .iter()
        .map(|id| format!("<ProductId>{id}</ProductId>"))
        .collect();
    parse(format!(
        "<LicenseTokenRequest><ParentProductId>9TESTSTORE0I</ParentProductId><ProductIds>{products}</ProductIds><CustomBase64>{}</CustomBase64><TitleId>{title}</TitleId><TitleClientId>{client}</TitleClientId></LicenseTokenRequest>",
        STANDARD.encode("fixture")
    ).as_bytes())
    .unwrap()
}

fn bound_context() -> SimpleContext {
    let mut context = crate::simple_context::tests::context("owner-scope", "player-scope");
    context.entitlement = Some(crate::entitlement::Entitlement::fixture("9TESTSTORE0I"));
    context.title = Some(crate::title::TitleIdentity::fixture(
        1805509784,
        "00000000-0000-0000-0000-00004C26E6C9",
    ));
    context
}

/// A catalog lookup that serves `catalog()` and counts how often it was asked.
fn lookup(
    calls: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> impl FnOnce(Vec<String>) -> std::future::Ready<Result<Vec<serde_json::Value>, Error>> {
    let calls = calls.clone();
    move |ids: Vec<String>| {
        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            ids[0], "9TESTSTORE0I",
            "the bound product is always looked up"
        );
        std::future::ready(Ok(catalog()
            .into_iter()
            .filter(|entry| {
                ids.iter()
                    .any(|id| id == entry["ProductId"].as_str().unwrap())
            })
            .collect()))
    }
}

#[tokio::test]
async fn a_bound_service_refuses_licence_tokens_for_products_outside_the_title() {
    let context = bound_context();
    let calls = Default::default();
    for products in [
        &["9TESTSTORE0I", "9OTHERGAME00"][..],
        &["9TESTADDON00", "9NOTINCATALG"],
        &["9TESTSTORE0I", "../../escape"],
        &["9TESTSTORE0I", "9TESTADDON00X"],
        // Listed by the game, not naming it: a bundle and a storefront can
        // grant other titles.
        &["9TESTSTORE0I", "9TESTBUNDLE0"],
        &["9TESTSTORE0I", "9TESTLAUNCH0"],
        // Sold through the game, but not one of its add-ons or editions.
        &["9TESTSTORE0I", "9SOLDBYGAME0"],
    ] {
        let mut req = bound_request(products, "1805509784", "");
        assert_eq!(
            scope(&context, &mut req, lookup(&calls)).await,
            Err("licence token request names products outside the bound title"),
            "{products:?}"
        );
    }
    // A catalog that cannot be reached confirms nothing.
    let mut req = bound_request(&["9TESTSTORE0I", "9TESTBUNDLE0"], "1805509784", "");
    let unreachable = |_| std::future::ready(Err("product catalog transport failed"));
    assert!(scope(&context, &mut req, unreachable).await.is_err());
}

#[tokio::test]
async fn a_bound_service_licenses_its_own_product_and_confirmed_add_ons_as_itself() {
    let context = bound_context();
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // The game alone needs no catalog at all.
    let mut req = bound_request(&["9teststore0i"], "1805509784", "");
    scope(&context, &mut req, lookup(&calls)).await.unwrap();
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);

    // The title claims another title's identity; the signed request does not.
    let mut req = bound_request(
        &["9TESTSTORE0I", "9TESTADDON00", "9TESTDELUXE00010"],
        "1298034544",
        "00000000-0000-0000-0000-000000000000",
    );
    scope(&context, &mut req, lookup(&calls)).await.unwrap();
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    let signed = std::sync::Arc::new(std::sync::Mutex::new(None));
    let seen = signed.clone();
    let result = fetch_with(
        req,
        URL,
        &client(HTTP_TIMEOUT).unwrap(),
        |request| async move {
            *seen.lock().unwrap() = Some((
                request.title_id,
                request.title_client_id,
                STANDARD.decode(request.body_base64).unwrap(),
            ));
            Err("stop before the network")
        },
    )
    .await;
    assert_eq!(result, Err("stop before the network"));
    let (title, client, body) = signed.lock().unwrap().take().unwrap();
    assert_eq!(title, "1805509784");
    assert_eq!(client, "00000000-0000-0000-0000-00004C26E6C9");
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["parentProductId"], "9TESTSTORE0I");
    assert_eq!(
        body["relatedProductIds"],
        "[\"9TESTSTORE0I\",\"9TESTADDON00\",\"9TESTDELUXE00010\"]"
    );

    // Confirmed products are remembered for the life of the service.
    let mut req = bound_request(&["9TESTADDON00"], "1805509784", "");
    scope(&context, &mut req, lookup(&calls)).await.unwrap();
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_unbound_service_signs_licence_requests_as_before() {
    let context = crate::simple_context::tests::context("owner-unbound", "player-unbound");
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut req = bound_request(&["9OTHERGAME00"], "1298034544", "client");
    scope(&context, &mut req, lookup(&calls)).await.unwrap();
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(req.title_id, "1298034544");
    assert_eq!(req.title_client_id, "client");
    assert_eq!(req.product_ids.ids, ["9OTHERGAME00"]);
}

#[tokio::test]
async fn a_product_bound_service_without_a_title_identity_refuses_a_titles_licence_request() {
    // No released launcher binds a product without the title identity, so a
    // title on the request has nothing to be held to.
    let mut context = crate::simple_context::tests::context("owner-product", "player-product");
    context.entitlement = Some(crate::entitlement::Entitlement::fixture("9TESTSTORE0I"));
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for (title, client) in [("1298034544", "client"), ("1805509784", "")] {
        let mut req = bound_request(&["9TESTSTORE0I"], title, client);
        assert_eq!(
            scope(&context, &mut req, lookup(&calls)).await,
            Err(
                "licence token request names a title, and this service has a product binding but no title"
            ),
            "{title}"
        );
    }
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    // A request naming no title is still held to the product.
    let mut req = bound_request(&["9TESTSTORE0I"], "", "");
    scope(&context, &mut req, lookup(&calls)).await.unwrap();
    let mut req = bound_request(&["9OTHERGAME00"], "0", "");
    assert!(scope(&context, &mut req, lookup(&calls)).await.is_err());
}

#[tokio::test]
async fn a_title_bound_service_without_a_product_refuses_licence_tokens() {
    let mut context = bound_context();
    context.entitlement = None;
    let calls = Default::default();
    let mut req = bound_request(&["9TESTSTORE0I"], "1805509784", "");
    assert_eq!(
        scope(&context, &mut req, lookup(&calls)).await,
        Err("licence token request without a bound product")
    );
}
