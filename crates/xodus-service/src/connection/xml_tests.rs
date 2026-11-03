use super::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::collections::HashMap;
use xodus::api::xbox::RequestSigner;

fn synthetic_signer(scalar: u8) -> RequestSigner {
    // Minimal PKCS#8 EC key using a deliberately public, synthetic scalar.
    let mut der = vec![
        0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25,
        0x02, 0x01, 0x01, 0x04, 0x20,
    ];
    der.extend_from_slice(&[0; 31]);
    der.push(scalar);
    RequestSigner::from_pkcs8(&der).expect("synthetic P-256 key")
}

fn cached_token(signer: RequestSigner) -> CachedToken {
    CachedToken {
        signer,
        token: "synthetic-authorization".to_string(),
        xuid: "synthetic-account".to_string(),
        gamertag: "Synthetic Player".to_string(),
        expiry: 2_000_000_000,
    }
}

#[test]
fn cached_tokens_are_isolated_by_session_title_client_audience_and_issuer() {
    let signer = synthetic_signer(1);
    let renewed_signer = synthetic_signer(2);
    let session = [11; 32];
    let other_session = [22; 32];
    let title = (12345, "synthetic-client".to_string());
    let other_title = (67890, title.1.clone());
    let other_client = (title.0, "another-client".to_string());
    let legacy_title = (title.0, String::new());
    let audience = "https://audience.example.test/";
    let key = token_cache_key(&session, Some(&title), audience, &signer);
    let cache = HashMap::from([(key, cached_token(signer.clone()))]);

    for (case, candidate) in [
        (
            "credential session",
            token_cache_key(&other_session, Some(&title), audience, &signer),
        ),
        (
            "title",
            token_cache_key(&session, Some(&other_title), audience, &signer),
        ),
        (
            "MSA client",
            token_cache_key(&session, Some(&other_client), audience, &signer),
        ),
        (
            "legacy title",
            token_cache_key(&session, Some(&legacy_title), audience, &signer),
        ),
        (
            "no title",
            token_cache_key(&session, None, audience, &signer),
        ),
        (
            "audience",
            token_cache_key(
                &session,
                Some(&title),
                "https://other.example.test/",
                &signer,
            ),
        ),
        (
            "issuer",
            token_cache_key(&session, Some(&title), audience, &renewed_signer),
        ),
    ] {
        assert!(
            cache.get(&candidate).is_none(),
            "cache crossed {case} boundary"
        );
    }

    let restored = RequestSigner::from_pkcs8(&signer.to_pkcs8().unwrap()).unwrap();
    let hit = cache
        .get(&token_cache_key(
            &session,
            Some(&title),
            audience,
            &restored,
        ))
        .expect("restoring the same issuer should reuse its cached token");
    assert_eq!(hit.token, "synthetic-authorization");
}

fn endpoints(max_body_bytes: usize) -> EndpointConfig {
    EndpointConfig {
        default: serde_json::from_value(serde_json::json!({
            "EndPoints": [{
                "Protocol": "https", "Host": "api.example.test",
                "RelyingParty": "https://audience.example.test/",
                "SignaturePolicyIndex": 0
            }],
            "SignaturePolicies": [{
                "Version": 1, "MaxBodyBytes": max_body_bytes,
                "SupportedAlgorithms": ["ES256"], "SupportedSignatureTypes": ["XBL"]
            }]
        }))
        .unwrap(),
        title: None,
    }
}

fn request(url: &str, method: &str, body: &[u8]) -> XSTSTokenRequest {
    XSTSTokenRequest {
        url: url.to_string(),
        relying_party: String::new(),
        method: method.to_string(),
        body_base64: STANDARD.encode(body),
        title_id: "12345".to_string(),
        title_client_id: String::new(),
    }
}

fn assert_signature(
    req: &XSTSTokenRequest,
    cached: &CachedToken,
    config: &EndpointConfig,
    issuer: &RequestSigner,
    expected_method: &str,
    expected_path: &str,
    expected_body: &[u8],
    max_body_bytes: usize,
) {
    // RequestSigner stamps signatures to whole seconds. Retry only if these
    // two calls straddle a clock tick, then compare the complete header.
    for _ in 0..8 {
        let actual = sign_for_with(req, &cached.token, config, &cached.signer);
        let expected = issuer.sign(
            1,
            expected_method,
            expected_path,
            &cached.token,
            expected_body,
            max_body_bytes,
        );
        let actual_bytes = STANDARD.decode(&actual).expect("base64 signature");
        let expected_bytes = STANDARD.decode(&expected).unwrap();
        assert_eq!(actual_bytes.len(), 76, "complete XBL signature header");
        if actual_bytes[4..12] == expected_bytes[4..12] {
            assert_eq!(
                actual, expected,
                "cached issuer must sign the current request"
            );
            return;
        }
    }
    panic!("clock changed during every signature comparison");
}

#[test]
fn cached_issuer_resigns_each_method_path_query_body_and_authorization() {
    let issuer = synthetic_signer(1);
    let restored = RequestSigner::from_pkcs8(&issuer.to_pkcs8().unwrap()).unwrap();
    let mut cached = cached_token(restored);
    let config = endpoints(8192);

    for (method, path, body) in [
        ("POST", "/sessions?version=1", b"first-body".as_slice()),
        ("PATCH", "/sessions?version=1", b"first-body".as_slice()),
        ("POST", "/sessions/new?version=1", b"first-body".as_slice()),
        ("POST", "/sessions?version=2", b"first-body".as_slice()),
        ("POST", "/sessions?version=1", b"changed-body".as_slice()),
    ] {
        let req = request(&format!("https://api.example.test{path}"), method, body);
        assert_signature(&req, &cached, &config, &issuer, method, path, body, 8192);
    }

    cached.token = "renewed-synthetic-authorization".to_string();
    let req = request("https://api.example.test/sessions", "", &[]);
    assert_signature(
        &req,
        &cached,
        &config,
        &issuer,
        "GET",
        "/sessions",
        &[],
        8192,
    );
}

#[test]
fn service_signatures_follow_the_selected_body_limit() {
    let issuer = synthetic_signer(1);
    let cached = cached_token(issuer.clone());
    let config = endpoints(4);
    let body = b"body beyond the policy limit";
    let req = request("https://api.example.test/sessions", "POST", body);
    assert_signature(
        &req,
        &cached,
        &config,
        &issuer,
        "POST",
        "/sessions",
        body,
        4,
    );
}

#[test]
fn endpoints_without_a_signature_policy_do_not_get_a_signature() {
    let cached = cached_token(synthetic_signer(1));
    let mut config = endpoints(8192);
    config.default.end_points[0].signature_policy_index = None;
    let req = request("https://api.example.test/sessions", "POST", b"body");
    assert!(sign_for_with(&req, &cached.token, &config, &cached.signer).is_empty());
}

#[tokio::test]
async fn pending_discovery_does_not_block_an_unrelated_title() {
    let cache = AsyncCache::new(Duration::from_secs(1), Duration::ZERO);
    let started = tokio::sync::Notify::new();
    let release = tokio::sync::Notify::new();
    let mut first = Box::pin(cache.get_or_try_init(
        12345,
        |_| true,
        || async {
            started.notify_one();
            release.notified().await;
            Ok("first title")
        },
    ));
    tokio::select! {
        _ = started.notified() => {}
        _ = &mut first => panic!("discovery must still be waiting"),
    }

    let other = tokio::time::timeout(
        Duration::from_millis(100),
        cache.get_or_try_init(67890, |_| true, || async { Ok("other title") }),
    )
    .await
    .expect("another title must not wait for the pending discovery")
    .unwrap();
    assert_eq!(other, "other title");
    release.notify_one();
    assert_eq!(first.await.unwrap(), "first title");
}

#[tokio::test]
async fn concurrent_requests_for_one_title_share_one_fetch() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let cache = AsyncCache::new(Duration::from_secs(1), Duration::ZERO);
    let calls = AtomicUsize::new(0);
    let started = tokio::sync::Notify::new();
    let release = tokio::sync::Notify::new();
    let mut first = Box::pin(cache.get_or_try_init(
        12345,
        |_| true,
        || async {
            calls.fetch_add(1, Ordering::SeqCst);
            started.notify_one();
            release.notified().await;
            Ok("shared discovery")
        },
    ));
    tokio::select! {
        _ = started.notified() => {}
        _ = &mut first => panic!("discovery must still be waiting"),
    }
    let second = cache.get_or_try_init(
        12345,
        |_| true,
        || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok("duplicate discovery")
        },
    );
    let (first, second) = tokio::join!(
        async {
            release.notify_one();
            first.await
        },
        second
    );
    assert_eq!(first.unwrap(), "shared discovery");
    assert_eq!(second.unwrap(), "shared discovery");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn failed_discovery_retries_after_backoff_and_then_stays_cached() {
    let cache = AsyncCache::new(Duration::from_secs(1), Duration::from_millis(20));
    let first = cache
        .get_or_try_init(
            (),
            |_| true,
            || async { Err::<&str, _>("temporary failure".into()) },
        )
        .await;
    assert_eq!(first.unwrap_err(), "temporary failure");
    let suppressed = cache
        .get_or_try_init(
            (),
            |_| true,
            || async { panic!("backoff must suppress another fetch") },
        )
        .await;
    assert_eq!(suppressed.unwrap_err(), "temporary failure");

    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        cache
            .get_or_try_init((), |_| true, || async { Ok("recovered endpoints") })
            .await
            .unwrap(),
        "recovered endpoints"
    );
    assert_eq!(
        cache
            .get_or_try_init(
                (),
                |_| true,
                || async { panic!("successful discovery is cached") }
            )
            .await
            .unwrap(),
        "recovered endpoints"
    );
}

#[tokio::test]
async fn a_timed_out_fetch_releases_its_key_for_retry() {
    let cache = AsyncCache::new(Duration::from_millis(10), Duration::ZERO);
    let first = cache
        .get_or_try_init(
            12345,
            |_| true,
            || std::future::pending::<Result<&str, String>>(),
        )
        .await;
    assert!(first.unwrap_err().contains("timed out"));
    assert_eq!(
        cache
            .get_or_try_init(12345, |_| true, || async { Ok("recovered identity") })
            .await
            .unwrap(),
        "recovered identity"
    );
}

#[tokio::test]
async fn expired_identity_is_replaced_under_the_same_key() {
    let cache = AsyncCache::new(Duration::from_secs(1), Duration::ZERO);
    assert_eq!(
        cache
            .get_or_try_init(12345, |_| true, || async { Ok(1) })
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        cache
            .get_or_try_init(12345, |value| *value > 1, || async { Ok(2) })
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        cache
            .get_or_try_init(
                12345,
                |value| *value > 1,
                || async { panic!("replacement is still valid") }
            )
            .await
            .unwrap(),
        2
    );
}
