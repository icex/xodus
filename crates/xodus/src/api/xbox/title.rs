use crate::api::xbox::signing::RequestSigner;
use crate::models::xbox::{TitleMgtEndPoint, TitleMgtResponse};

pub async fn get_title_management(client: &reqwest::Client) -> reqwest::Result<TitleMgtResponse> {
    let response = client
        .get("https://title.mgt.xboxlive.com/titles/default/endpoints?type=1")
        .send()
        .await?;
    response.json().await
}

/// Fetch endpoints for the title identified by the supplied authorization.
/// The authorization and signature must come from the same proof key.
/// Keep this response separate from the default list: policy indices are local.
pub async fn get_title_endpoints(
    client: &reqwest::Client,
    authorization: &str,
    signer: &RequestSigner,
) -> reqwest::Result<TitleMgtResponse> {
    let signature = signer.sign(
        1,
        "GET",
        "/titles/current/endpoints",
        authorization,
        &[],
        8192,
    );
    client
        .get("https://title.mgt.xboxlive.com/titles/current/endpoints")
        .header("Authorization", authorization)
        .header("Signature", signature)
        .header("x-xbl-contract-version", "1")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
}

// Host specificity wins first; an exact host breaks a wildcard tie, and a
// matching path restriction wins over the same host's unrestricted entry.
fn endpoint_specificity(
    url: &reqwest::Url,
    endpoint: &TitleMgtEndPoint,
    suffix_only: bool,
) -> Option<(usize, bool, usize)> {
    // WebSocket authentication uses the HTTP Upgrade request's protocol,
    // as in xal-rs SignaturePolicyCache's policy and relying-party lookups.
    let protocol = match url.scheme() {
        "wss" => "https",
        "ws" => "http",
        scheme => scheme,
    };
    if !endpoint.protocol.eq_ignore_ascii_case(protocol) {
        return None;
    }
    let host = url.host_str()?;
    let pattern = endpoint.host.to_ascii_lowercase();
    let matcher = globset::GlobBuilder::new(&pattern)
        .case_insensitive(true)
        .build()
        .ok()?
        .compile_matcher();
    // Some default entries name a service's parent domain without a glob.
    // Keep the service's subdomains, but never a lookalike suffix.
    let suffix = !pattern.contains(['*', '?', '[', '{', '\\'])
        && host
            .strip_suffix(&pattern)
            .is_some_and(|prefix| prefix.ends_with('.'));
    let matches_host = if suffix_only {
        suffix
    } else {
        matcher.is_match(host)
    };
    if !matches_host {
        return None;
    }
    let path = endpoint.path.as_deref().unwrap_or("");
    if !path.is_empty() && url.path() != path {
        let rest = url.path().strip_prefix(path)?;
        if !path.ends_with('/') && !rest.starts_with('/') {
            return None;
        }
    }
    Some((
        pattern.chars().filter(|c| !matches!(c, '*' | '?')).count(),
        host.eq_ignore_ascii_case(&pattern),
        path.len(),
    ))
}

pub fn get_endpoint<'a>(url: &str, response: &'a TitleMgtResponse) -> Option<&'a TitleMgtEndPoint> {
    let url = reqwest::Url::parse(url).ok()?;
    select_endpoint(&url, response, None, false).map(|(endpoint, _)| endpoint)
}

fn select_endpoint<'a>(
    url: &reqwest::Url,
    default: &'a TitleMgtResponse,
    title: Option<&'a TitleMgtResponse>,
    suffix_only: bool,
) -> Option<(&'a TitleMgtEndPoint, &'a TitleMgtResponse)> {
    [Some(default), title]
        .into_iter()
        .flatten()
        .flat_map(|source| {
            source
                .end_points
                .iter()
                .map(move |endpoint| (endpoint, source))
        })
        .filter(|(endpoint, _)| !suffix_only || endpoint.relying_party.is_some())
        .filter_map(|(endpoint, source)| {
            endpoint_specificity(url, endpoint, suffix_only)
                .map(|specificity| (specificity, endpoint, source))
        })
        .max_by_key(|(specificity, _, _)| *specificity)
        .map(|(_, endpoint, source)| (endpoint, source))
}

/// Select the most specific matching host/path across both endpoint lists.
/// Equal rules prefer the current title. Return the source list alongside the
/// endpoint so its SignaturePolicyIndex cannot address another list's policy.
/// If no matching rule supplies an RP, try bare service domains as suffixes,
/// retaining dot boundaries. That compatibility fallback never replaces an
/// explicitly matched RP, including one selected by a wildcard.
pub fn get_endpoint_with_title<'a>(
    url: &str,
    default: &'a TitleMgtResponse,
    title: Option<&'a TitleMgtResponse>,
) -> Option<(&'a TitleMgtEndPoint, &'a TitleMgtResponse)> {
    let url = reqwest::Url::parse(url).ok()?;
    let endpoint = select_endpoint(&url, default, title, false);
    if endpoint.is_some_and(|(entry, _)| entry.relying_party.is_some()) {
        return endpoint;
    }
    select_endpoint(&url, default, title, true).or(endpoint)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_endpoint_cases() {
        let string = r##"{"EndPoints":[{"Protocol":"https","Host":"musicdelivery-ssl.xboxlive.com","HostType":"fqdn","RelyingParty":"http://music.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"cloudcollection-ssl.xboxlive.com","HostType":"fqdn","RelyingParty":"http://music.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"websockets.platform.bing.com","HostType":"fqdn","RelyingParty":"http://platform.bing.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"websockets.platform.bing-int.com","HostType":"fqdn","RelyingParty":"http://platform.bing.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"inventory.xboxlive.com","HostType":"fqdn","RelyingParty":"http://licensing.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"licensing.xboxlive.com","HostType":"fqdn","RelyingParty":"http://licensing.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"accountstroubleshooter.xboxlive.com","HostType":"fqdn","RelyingParty":"http://accounts.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"gamertag.xboxlive.com","HostType":"fqdn","RelyingParty":"http://accounts.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"help.ui.xboxlive.com","HostType":"fqdn","RelyingParty":"http://uxservices.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"*.ui.xboxlive.com","HostType":"wildcard"},{"Protocol":"https","Host":"data-vef.xboxlive.com","HostType":"fqdn","RelyingParty":"http://data-vef.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":1},{"Protocol":"https","Host":"update.xboxlive.com","HostType":"fqdn","RelyingParty":"http://update.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"updatepc.xboxlive.com","HostType":"fqdn","RelyingParty":"http://update.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"update-cdn.xboxlive.com","HostType":"fqdn","RelyingParty":"http://update.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"packages.xboxlive.com","HostType":"fqdn","RelyingParty":"http://update.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"packagespc.xboxlive.com","HostType":"fqdn","RelyingParty":"http://update.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"instance.mgt.xboxlive.com","HostType":"fqdn","RelyingParty":"http://instance.mgt.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":2},{"Protocol":"https","Host":"device.mgt.xboxlive.com","HostType":"fqdn","RelyingParty":"http://device.mgt.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":1},{"Protocol":"https","Host":"device.mgt.xboxlive.com","HostType":"fqdn","Path":"/registrations/bestv","RelyingParty":"http://bestv.device.mgt.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":1},{"Protocol":"https","Host":"device.mgt.xboxlive.com","HostType":"fqdn","Path":"/devices/current/unlock","RelyingParty":"http://unlock.device.mgt.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":1},{"Protocol":"https","Host":"xkms.xboxlive.com","HostType":"fqdn","RelyingParty":"http://xkms.xboxlive.com","TokenType":"JWT","MinTlsVersion":"1.2","SignaturePolicyIndex":0},{"Protocol":"https","Host":"privileges.xboxlive.com","HostType":"fqdn","RelyingParty":"http://banning.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":1},{"Protocol":"https","Host":"privileges.xboxlive.com","HostType":"fqdn","Path":"/upsell","RelyingParty":"http://xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":1},{"Protocol":"https","Host":"settings.xboxlive.com","HostType":"fqdn","RelyingParty":"http://xboxlive.com","TokenType":"JWT","ServerCertIndex":[0,1],"SignaturePolicyIndex":1},{"Protocol":"https","Host":"*.experimentation.xboxlive.com","HostType":"wildcard","RelyingParty":"http://experimentation.xboxlive.com/","TokenType":"JWT","SignaturePolicyIndex":1},{"Protocol":"https","Host":"*.xboxlive.com","HostType":"wildcard","RelyingParty":"http://xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"xboxlive.com","HostType":"fqdn","RelyingParty":"http://xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"http","Host":"*.xboxlive.com","HostType":"wildcard"},{"Protocol":"https","Host":"xaaa.bbtv.cn","HostType":"fqdn","Path":"/xboxsms/OOBEService/AuthorizationStatus","RelyingParty":"http://bestvrp.bestv.com/","SubRelyingParty":"http://www.bestv.com.cn/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"*.data.microsoft.com","HostType":"wildcard","RelyingParty":"http://vortex.microsoft.com","TokenType":"JWT"},{"Protocol":"https","Host":"*.vortex-win-sandbox.data.microsoft.com","HostType":"wildcard","RelyingParty":"http://vortex-sbx.microsoft.com","TokenType":"JWT"},{"Protocol":"https","Host":"*.vortex-sandbox.data.microsoft.com","HostType":"wildcard","RelyingParty":"http://vortex-sbx.microsoft.com","TokenType":"JWT"},{"Protocol":"https","Host":"vortex-events.xboxlive.com","HostType":"fqdn","RelyingParty":"http://events.xboxlive.com","TokenType":"JWT"},{"Protocol":"https","Host":"*.pipe.int.trafficmanager.net","HostType":"wildcard","RelyingParty":"http://vortex-sbx.microsoft.com","TokenType":"JWT"},{"Protocol":"https","Host":"*.events-sandbox.data.microsoft.com","HostType":"wildcard","RelyingParty":"http://vortex-sbx.microsoft.com","TokenType":"JWT"},{"Protocol":"https","Host":"musicimage.xboxlive.com","HostType":"fqdn"},{"Protocol":"https","Host":"*.xboxservices.com","HostType":"wildcard","RelyingParty":"http://mp.microsoft.com/","TokenType":"JWT"},{"Protocol":"https","Host":"assets.xboxservices.com","HostType":"fqdn"},{"Protocol":"https","Host":"*.mp.microsoft.com","HostType":"wildcard","RelyingParty":"http://mp.microsoft.com/","TokenType":"JWT"},{"Protocol":"https","Host":"account.microsoft.com","HostType":"fqdn","RelyingParty":"http://mp.microsoft.com/","TokenType":"JWT"},{"Protocol":"https","Host":"*.account.microsoft.com","HostType":"wildcard","RelyingParty":"http://mp.microsoft.com/","TokenType":"JWT"},{"Protocol":"https","Host":"licensing.mp.microsoft.com","HostType":"fqdn","RelyingParty":"http://licensing.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"collections.mp.microsoft.com","HostType":"fqdn","RelyingParty":"http://licensing.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"api.twitch.tv","HostType":"fqdn","RelyingParty":"https://twitchxboxrp.twitch.tv/","TokenType":"JWT"},{"Protocol":"https","Host":"xdes.xboxlive.com","HostType":"fqdn","RelyingParty":"http://xdes.xboxlive.com/","TokenType":"JWT"},{"Protocol":"https","Host":"*.gameservices.xboxlive.com","HostType":"wildcard","RelyingParty":"https://gameservices.xboxlive.com/","TokenType":"JWT"},{"Protocol":"https","Host":"ssl.bing.com","HostType":"fqdn","Path":"/speechreco/xbox/accessibility","RelyingParty":"http://platform.bing.com/","TokenType":"JWT"},{"Protocol":"https","Host":"speech.bing.com","HostType":"fqdn","RelyingParty":"http://platform.bing.com/","TokenType":"JWT"},{"Protocol":"https","Host":"zto.dds.microsoft.com","HostType":"fqdn","RelyingParty":"http://dds.microsoft.com","TokenType":"JWT"},{"Protocol":"https","Host":"user.mgt.xboxlive.com","HostType":"fqdn","RelyingParty":"http://accounts.xboxlive.com","TokenType":"JWT"},{"Protocol":"https","Host":"gssv-auth-prod.xboxlive.com","HostType":"fqdn","RelyingParty":"http://gssv.xboxlive.com/","TokenType":"JWT"},{"Protocol":"https","Host":"gssv-auth-strs.xboxlive.com","HostType":"fqdn","RelyingParty":"http://gssv.xboxlive.com/","TokenType":"JWT"},{"Protocol":"https","Host":"*.gssv-play-prod.xboxlive.com","HostType":"wildcard","RelyingParty":"http://gssv.xboxlive.com/","TokenType":"JWT"},{"Protocol":"https","Host":"*.gssv-play-test.xboxlive.com","HostType":"wildcard","RelyingParty":"http://gssv.xboxlive.com/","TokenType":"JWT"},{"Protocol":"https","Host":"*.gssv-play-int.xboxlive.com","HostType":"wildcard","RelyingParty":"http://gssv.xboxlive.com/","TokenType":"JWT"},{"Protocol":"https","Host":"*.gssv-play-prod.xboxlive.com","HostType":"wildcard","Path":"/v5/sessions/cloud","RelyingParty":"http://connect.gssv.xboxlive.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"*.gssv-play-test.xboxlive.com","HostType":"wildcard","Path":"/v5/sessions/cloud","RelyingParty":"http://connect.gssv.xboxlive.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"*.gssv-play-int.xboxlive.com","HostType":"wildcard","Path":"/v5/sessions/cloud","RelyingParty":"http://connect.gssv.xboxlive.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"settings-sandbox.data.microsoft.com","HostType":"fqdn","RelyingParty":"http://onesettings-xbox-rp.com/","TokenType":"JWT"},{"Protocol":"https","Host":"settings-win.data.microsoft.com","HostType":"fqdn","RelyingParty":"http://onesettings-xbox-rp.com/","TokenType":"JWT","ServerCertIndex":[2]},{"Protocol":"https","Host":"settings-ppe.data.microsoft.com","HostType":"fqdn","RelyingParty":"http://onesettings-xbox-rp.com/","TokenType":"JWT"},{"Protocol":"https","Host":"settings.data.microsoft.com","HostType":"fqdn","RelyingParty":"http://onesettings-xbox-rp.com/","TokenType":"JWT","ServerCertIndex":[3,0]},{"Protocol":"https","Host":"playfabapi.com","HostType":"fqdn","RelyingParty":"http://playfab.xboxlive.com/","TokenType":"JWT"},{"Protocol":"https","Host":"sisu.xboxlive.com","HostType":"fqdn","RelyingParty":"http://sisu.xboxlive.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"beta-sisu.xboxlive.com","HostType":"fqdn","RelyingParty":"http://sisu.xboxlive.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"*.gamepass.com","HostType":"wildcard","RelyingParty":"http://xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"xflight.xboxlive.com","HostType":"fqdn","RelyingParty":"http://xflight.xboxlive.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"xrap.xboxlive.com","HostType":"fqdn","RelyingParty":"rp://rap.xboxflight.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"rap-fd.xboxlive.com","HostType":"fqdn","RelyingParty":"rp://rap.xboxflight.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"streaming.xboxlive.com","HostType":"fqdn","RelyingParty":"rp://streaming.xboxlive.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"*.support.xboxlive.com","HostType":"wildcard","RelyingParty":"rp://support.xboxlive.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"streaming-ppe.xboxlive.com","HostType":"fqdn","RelyingParty":"rp://streaming.xboxlive.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"xoobe.xboxlive.com","HostType":"fqdn","RelyingParty":"rp://xoobe.xboxlive.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"xoobe.platform.xboxservices.com","HostType":"fqdn","RelyingParty":"rp://xoobe.xboxlive.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"*.ide.platform.xboxservices.com","HostType":"wildcard","RelyingParty":"rp://ide.platform.xboxservices.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"*.ppe.exp.xboxservices.com","HostType":"wildcard","RelyingParty":"rp://ppe.exp.xboxservices.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"*.exp.xboxservices.com","HostType":"wildcard","RelyingParty":"rp://exp.xboxservices.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"contentaccess.exp.xboxservices.com","HostType":"fqdn","RelyingParty":"http://mp.microsoft.com/","TokenType":"JWT"},{"Protocol":"https","Host":"gamingconsent-staging.xboxlive.com","HostType":"fqdn","RelyingParty":"http://gamingconsent.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"gamingconsent.xboxlive.com","HostType":"fqdn","RelyingParty":"http://gamingconsent.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"*.sucu.xboxlive.com","HostType":"wildcard","RelyingParty":"http://update.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"xai.xboxservices.com","HostType":"fqdn","RelyingParty":"rp://xai.xboxservices.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"int.xai.xboxservices.com","HostType":"fqdn","RelyingParty":"rp://ppe.xai.xboxservices.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"test.xai.xboxservices.com","HostType":"fqdn","RelyingParty":"rp://ppe.xai.xboxservices.com/","TokenType":"JWT","SignaturePolicyIndex":0},{"Protocol":"https","Host":"xgrant.xboxlive.com","HostType":"fqdn","RelyingParty":"rp://rewards.xboxlive.com","TokenType":"JWT","SignaturePolicyIndex":0}],"SignaturePolicies":[{"Version":1,"SupportedAlgorithms":["ES256"],"MaxBodyBytes":8192,"SupportedSignatureTypes":["XBL"]},{"Version":1,"SupportedAlgorithms":["ES256"],"MaxBodyBytes":2147483647,"SupportedSignatureTypes":["XBL"]},{"Version":2,"SupportedAlgorithms":["ES256"],"MaxBodyBytes":0,"SupportedSignatureTypes":["DPoP","XBL"]}],"Certs":[{"Thumbprint":"54D9D20239080C32316ED9FF980A48988F4ADF2D","IsIssuer":true,"RootCertIndex":0},{"Thumbprint":"D5A9ACDB80066D0E67FF65A939BBBC952F8ED171","RootCertIndex":0},{"Thumbprint":"8F43288AD272F3103B6FB1428485EA3014C0BCFE","IsIssuer":true,"RootCertIndex":1},{"Thumbprint":"AD898AC73DF333EB60AC1F5FC6C4B2219DDB79B7","IsIssuer":true,"RootCertIndex":0}],"RootCerts":["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"]}"##;
        let response = serde_json::from_str::<TitleMgtResponse>(string).expect("Failed to parse");

        let live = get_endpoint("https://xboxlive.com", &response).expect("No xboxlive endpoint");
        assert_eq!(live.host, "xboxlive.com");
        assert_eq!(live.relying_party.as_deref(), Some("http://xboxlive.com"));
        let playfab =
            get_endpoint("https://playfabapi.com", &response).expect("No playfab endpoint found");
        assert_eq!(playfab.host, "playfabapi.com");
        assert_eq!(
            playfab.relying_party.as_deref(),
            Some("http://playfab.xboxlive.com/")
        );
        let updates =
            get_endpoint("https://update.xboxlive.com", &response).expect("No updates endpoint");

        assert_eq!(updates.host, "update.xboxlive.com");
        assert_eq!(
            updates.relying_party.as_deref(),
            Some("http://update.xboxlive.com")
        );
    }
}

#[cfg(test)]
mod nsal_tests {
    use super::*;
    use serde_json::json;

    fn response(endpoints: serde_json::Value, max_body_bytes: u64) -> TitleMgtResponse {
        serde_json::from_value(json!({
            "EndPoints": endpoints,
            "SignaturePolicies": [{
                "Version": 1,
                "SupportedAlgorithms": ["ES256"],
                "MaxBodyBytes": max_body_bytes,
                "SupportedSignatureTypes": ["XBL"]
            }]
        }))
        .unwrap()
    }

    #[test]
    fn websocket_schemes_use_only_the_matching_http_security_level() {
        for (websocket, http, other_websocket) in [("wss", "https", "ws"), ("ws", "http", "wss")] {
            let list = response(
                json!([{
                    "Protocol": http, "Host": "stream.example.test",
                    "RelyingParty": "rp://stream", "SignaturePolicyIndex": 0
                }]),
                8192,
            );
            for scheme in [websocket, http] {
                let endpoint = get_endpoint(
                    &format!("{scheme}://stream.example.test/connect?version=1"),
                    &list,
                )
                .expect("WebSocket handshake uses its HTTP endpoint policy");
                assert_eq!(endpoint.relying_party.as_deref(), Some("rp://stream"));
                assert_eq!(endpoint.signature_policy_index, Some(0));
            }
            assert!(
                get_endpoint(
                    &format!("{other_websocket}://stream.example.test/connect"),
                    &list
                )
                .is_none(),
                "secure and plain WebSockets must not share policies"
            );
        }
    }

    #[test]
    fn websocket_title_routes_preserve_path_boundaries_and_ignore_query_for_selection() {
        for (websocket, http) in [("wss", "https"), ("ws", "http")] {
            let default = response(
                json!([{
                    "Protocol": http, "Host": "*.example.test",
                    "RelyingParty": "rp://default", "SignaturePolicyIndex": 0
                }]),
                8192,
            );
            let title = response(
                json!([{
                    "Protocol": http, "Host": "stream.example.test", "Path": "/events",
                    "RelyingParty": "rp://events", "SignaturePolicyIndex": 0
                }]),
                123,
            );
            for (path, rp, max_bytes) in [
                ("/events?version=1", "rp://events", 123),
                ("/events/new?version=2", "rp://events", 123),
                ("/eventstream?next=/events", "rp://default", 8192),
                ("/other?next=/events", "rp://default", 8192),
            ] {
                let (endpoint, source) = get_endpoint_with_title(
                    &format!("{websocket}://stream.example.test{path}"),
                    &default,
                    Some(&title),
                )
                .expect("WebSocket endpoint rule");
                assert_eq!(endpoint.relying_party.as_deref(), Some(rp), "{path}");
                assert_eq!(
                    source.signature_policies[endpoint.signature_policy_index.unwrap() as usize]
                        .max_body_bytes,
                    max_bytes
                );
            }
        }
    }

    #[test]
    fn current_title_nsal_can_omit_signature_policies() {
        let title: TitleMgtResponse = serde_json::from_value(json!({
            "EndPoints": [{"Protocol": "https", "Host": "*.race.example.test",
                "RelyingParty": "https://race.example.test/"}]
        }))
        .unwrap();
        assert!(title.signature_policies.is_empty());
        assert_eq!(
            get_endpoint("https://api.race.example.test/player", &title)
                .unwrap()
                .relying_party
                .as_deref(),
            Some("https://race.example.test/")
        );
    }

    #[test]
    fn path_routes_do_not_capture_other_paths_on_the_same_host() {
        let list = response(
            json!([
                {"Protocol": "https", "Host": "api.example.test", "RelyingParty": "rp://general"},
                {"Protocol": "https", "Host": "api.example.test", "Path": "/private",
                 "RelyingParty": "rp://private"}
            ]),
            8192,
        );
        for (path, expected) in [
            ("/public", "rp://general"),
            ("/privately", "rp://general"),
            ("/private", "rp://private"),
            ("/private/player?x=1", "rp://private"),
        ] {
            assert_eq!(
                get_endpoint(&format!("https://api.example.test{path}"), &list)
                    .unwrap()
                    .relying_party
                    .as_deref(),
                Some(expected),
                "{path}"
            );
        }
    }

    #[test]
    fn malformed_host_globs_do_not_panic_or_hide_valid_entries() {
        let list = response(
            json!([
                {"Protocol": "https", "Host": "[invalid", "RelyingParty": "rp://invalid"},
                {"Protocol": "https", "Host": "*.example.test", "RelyingParty": "rp://valid"}
            ]),
            8192,
        );
        assert_eq!(
            get_endpoint("https://api.example.test/", &list)
                .unwrap()
                .relying_party
                .as_deref(),
            Some("rp://valid")
        );
        assert!(get_endpoint("data:text/plain,no-host", &list).is_none());
    }

    #[test]
    fn title_service_rp_and_signature_policy_keep_their_own_source() {
        let default = response(
            json!([
                {"Protocol": "https", "Host": "*.example.test", "RelyingParty": "rp://public",
                 "SignaturePolicyIndex": 0}
            ]),
            8192,
        );
        let title = response(
            json!([
                {"Protocol": "https", "Host": "*.race.example.test", "RelyingParty": "rp://race",
                 "SignaturePolicyIndex": 0}
            ]),
            123,
        );
        for (url, rp, max_bytes) in [
            ("https://api.race.example.test/player", "rp://race", 123),
            ("https://public.example.test/player", "rp://public", 8192),
        ] {
            let (endpoint, source) = get_endpoint_with_title(url, &default, Some(&title)).unwrap();
            assert_eq!(endpoint.relying_party.as_deref(), Some(rp));
            assert_eq!(
                source.signature_policies[endpoint.signature_policy_index.unwrap() as usize]
                    .max_body_bytes,
                max_bytes
            );
        }
    }

    #[test]
    fn equal_title_rules_override_default_without_overriding_more_specific_hosts() {
        let default = response(
            json!([
                {"Protocol": "https", "Host": "*.example.test", "RelyingParty": "rp://default"},
                {"Protocol": "https", "Host": "profile.example.test", "RelyingParty": "rp://profile"}
            ]),
            8192,
        );
        let title = response(
            json!([
                {"Protocol": "https", "Host": "*", "RelyingParty": "rp://catchall"},
                {"Protocol": "https", "Host": "*.example.test", "RelyingParty": "rp://title"}
            ]),
            8192,
        );
        for (url, rp) in [
            ("https://api.example.test/", "rp://title"),
            ("https://profile.example.test/", "rp://profile"),
        ] {
            assert_eq!(
                get_endpoint_with_title(url, &default, Some(&title))
                    .unwrap()
                    .0
                    .relying_party
                    .as_deref(),
                Some(rp)
            );
        }
    }

    #[test]
    fn title_configurations_are_isolated_even_when_hosts_match() {
        let default = response(json!([]), 8192);
        let one = response(
            json!([
                {"Protocol": "https", "Host": "api.example.test", "RelyingParty": "rp://one"}
            ]),
            8192,
        );
        let two = response(
            json!([
                {"Protocol": "https", "Host": "api.example.test", "RelyingParty": "rp://two"}
            ]),
            8192,
        );
        for (title, rp) in [(&one, "rp://one"), (&two, "rp://two"), (&one, "rp://one")] {
            assert_eq!(
                get_endpoint_with_title("https://api.example.test/", &default, Some(title))
                    .unwrap()
                    .0
                    .relying_party
                    .as_deref(),
                Some(rp)
            );
        }
        assert!(get_endpoint_with_title("https://api.example.test/", &default, None).is_none());
    }

    #[test]
    fn bare_domain_fallback_beats_an_empty_title_catchall_without_matching_lookalikes() {
        let default = response(
            json!([
                {"Protocol": "https", "Host": "backend.example.test", "RelyingParty": "rp://backend"}
            ]),
            8192,
        );
        let title = response(json!([{"Protocol": "https", "Host": "*"}]), 8192);
        let (endpoint, _) = get_endpoint_with_title(
            "https://api.site.backend.example.test/",
            &default,
            Some(&title),
        )
        .unwrap();
        assert_eq!(endpoint.relying_party.as_deref(), Some("rp://backend"));
        for host in ["evilbackend.example.test", "backend.example.test.evil.test"] {
            assert!(
                get_endpoint_with_title(&format!("https://{host}/"), &default, Some(&title))
                    .unwrap()
                    .0
                    .relying_party
                    .is_none()
            );
        }
    }

    #[test]
    fn implicit_domain_suffix_does_not_override_a_matching_wildcard_rp() {
        let default = response(
            json!([
                {"Protocol": "https", "Host": "*.example.test", "RelyingParty": "rp://explicit"},
                {"Protocol": "https", "Host": "service.example.test", "RelyingParty": "rp://suffix"}
            ]),
            8192,
        );
        let (endpoint, _) =
            get_endpoint_with_title("https://api.service.example.test/", &default, None).unwrap();
        assert_eq!(endpoint.relying_party.as_deref(), Some("rp://explicit"));
    }
}
