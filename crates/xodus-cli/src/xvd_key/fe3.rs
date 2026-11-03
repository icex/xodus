//! Anonymous download of a Microsoft Store package through the Store's
//! Windows Update delivery service (FE3), the way Windows fetches free apps.
//!
//! DisplayCatalog gives the product's Windows Update category; FE3's
//! `GetCookie` and `SyncUpdates` list the updates in that category with their
//! files and digests; `GetExtendedUpdateInfo2` gives each file's download URL.
//! Nothing here signs in: the ticket in every request is an empty MSA ticket.
//!
//! FE3's TLS certificate chains to Microsoft Root Certificate Authority 2011,
//! which Linux trust stores do not carry, and which this client does not carry
//! either. It is fetched from the address FE3's intermediate certificate gives
//! for it (Microsoft's PKI site, plain http) and used only if its SHA-256 is
//! the pinned one; it is then a trust anchor for the FE3 client only, and that
//! client talks to the FE3 host only. The files themselves come from plain
//! http CDN hosts; each is checked against the SHA-256 that FE3 gave for it.

use std::time::Duration;

use base64::Engine;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::xml::{self, Element, LIMITS};

/// Microsoft Gaming Services in the Store.
pub const GAMING_SERVICES_PRODUCT: &str = "9MWPM2CQNLHN";
/// The prefix of its package names.
pub const GAMING_SERVICES_PACKAGE: &str = "Microsoft.GamingServices_";

const DISPLAYCATALOG: &str = "https://displaycatalog.mp.microsoft.com/v7.0/products";
pub const FE3_HOST: &str = "fe3.delivery.mp.microsoft.com";
const FE3_URL: &str = "https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx";
const FE3_SECURED_URL: &str =
    "https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx/secured";
/// The download hosts FE3 hands out, and the only ones followed.
const DOWNLOAD_DOMAIN: &str = ".delivery.mp.microsoft.com";

/// Where Microsoft publishes Microsoft Root Certificate Authority 2011, the
/// root FE3's chain ends in: the CA Issuers address in FE3's intermediate.
const MICROSOFT_ROOT_2011_URL: &str =
    "http://www.microsoft.com/pki/certs/MicRooCerAut2011_2011_03_22.crt";
/// The root's SHA-256 fingerprint, over its DER encoding.
pub const MICROSOFT_ROOT_2011_SHA256: &str =
    "847df6a78497943f27fc72eb93f9a637320a02b561d0a91b09e87a7807ed7c61";
/// A certificate is about 1.5 KB.
const MAX_CERTIFICATE: usize = 16 << 10;

const USER_AGENT: &str = "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.50";
const DEVICE_ATTRIBUTES: &str = "BranchReadinessLevel=CB;CurrentBranch=ge_release;\
    OEMModel=Virtual Machine;FlightRing=Retail;AttrDataVer=331;InstallLanguage=en-US;\
    OSUILocale=en-US;InstallationType=Client;FlightingBranchName=;App=WU_STORE;AppVer=1.0;\
    OSArchitecture=AMD64;IsFlightingEnabled=0;TelemetryLevel=1;OSVersion=10.0.26100.1;\
    DeviceFamily=Windows.Desktop;";
/// Update IDs a fresh Windows reports as installed, so FE3 answers with what
/// applies to one.
const INSTALLED_NON_LEAF: &[u32] = &[
    1, 2, 3, 11, 19, 2359974, 5169044, 8788830, 23110993, 23110994, 59830006, 59830007, 59830008,
    60484010, 62450018, 62450019, 62450020, 98959022, 98959023, 98959024, 98959025, 98959026,
    129905029, 130040031, 138537048, 140377312, 143747671, 158941041, 158941042, 158941043,
    158941044, 159123858, 159130928,
];

/// `der` as a trust anchor, if its SHA-256 is `pin` (lower-case hex).
pub fn pinned_certificate(der: &[u8], pin: &str) -> Result<reqwest::Certificate, String> {
    let fingerprint = msixvc::signature::hex(&Sha256::digest(der));
    if fingerprint != pin {
        return Err(format!(
            "the Microsoft root certificate fetched has fingerprint {fingerprint}, not the \
             pinned {pin}"
        ));
    }
    reqwest::Certificate::from_der(der).map_err(|e| e.to_string())
}

/// Microsoft Root Certificate Authority 2011, fetched from Microsoft and
/// checked against its pinned fingerprint. The fingerprint is what makes it
/// trustworthy, not the plain http it comes over.
pub async fn microsoft_root(timeout: Duration) -> Result<reqwest::Certificate, String> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(20))
        .timeout(timeout)
        .build()
        .map_err(|e| e.to_string())?;
    let mut response = client
        .get(MICROSOFT_ROOT_2011_URL)
        .send()
        .await
        .map_err(|e| format!("could not fetch Microsoft's root certificate: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "Microsoft's root certificate answered {}",
            response.status()
        ));
    }
    let der = read_limited(&mut response, MAX_CERTIFICATE).await?;
    pinned_certificate(&der, MICROSOFT_ROOT_2011_SHA256)
}

/// The client for FE3: https only, no redirects, and `root` as an extra
/// trust anchor. Used for `FE3_HOST` and nothing else.
pub fn fe3_client(
    root: reqwest::Certificate,
    timeout: Duration,
) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .tls_certs_merge([root])
        .connect_timeout(Duration::from_secs(20))
        .timeout(timeout)
        .build()
        .map_err(|e| format!("could not set up the Store delivery client: {e}"))
}

/// The client for the catalogue and the file download: the system's trust
/// store, and redirects only within the delivery domain.
pub fn download_client(timeout: Duration) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 {
                attempt.error("too many redirects")
            } else if download_url_allowed(attempt.url()) {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .connect_timeout(Duration::from_secs(20))
        .timeout(timeout)
        .build()
        .map_err(|e| format!("could not set up the download client: {e}"))
}

/// Whether a file URL FE3 gave is one this fetches: http or https, on a
/// delivery host, with no credentials or port tricks.
pub fn download_url_allowed(url: &reqwest::Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url
            .host_str()
            .is_some_and(|h| h.to_ascii_lowercase().ends_with(DOWNLOAD_DOMAIN))
}

/// `text` escaped for XML element content.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn timestamp(now: chrono::DateTime<chrono::Utc>) -> String {
    now.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn message_id() -> Uuid {
    let seed = format!(
        "{:?}{}{:?}",
        std::time::SystemTime::now(),
        std::process::id(),
        std::thread::current().id()
    );
    let digest = Sha256::digest(seed.as_bytes());
    uuid::Builder::from_random_bytes(digest[..16].try_into().unwrap()).into_uuid()
}

/// A SOAP request to FE3, with the anonymous ticket.
pub fn envelope(action: &str, to: &str, body: &str, now: chrono::DateTime<chrono::Utc>) -> String {
    let created = timestamp(now);
    let expires = timestamp(now + chrono::Duration::minutes(5));
    format!(
        r#"<s:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><a:Action s:mustUnderstand="1">http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/{action}</a:Action><a:MessageID>urn:uuid:{id}</a:MessageID><a:To s:mustUnderstand="1">{to}</a:To><o:Security s:mustUnderstand="1" xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"><Timestamp xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><Created>{created}</Created><Expires>{expires}</Expires></Timestamp><wuws:WindowsUpdateTicketsToken wsu:id="ClientMSA" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wuws="http://schemas.microsoft.com/msus/2014/10/WindowsUpdateAuthorization"><TicketType Name="MSA" Version="1.0" Policy="MBI_SSL"><User/></TicketType></wuws:WindowsUpdateTicketsToken></o:Security></s:Header><s:Body>{body}</s:Body></s:Envelope>"#,
        id = message_id(),
    )
}

const CWS: &str = "http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService";

pub fn cookie_body(now: chrono::DateTime<chrono::Utc>) -> String {
    let t = timestamp(now);
    format!(
        r#"<GetCookie xmlns="{CWS}"><oldCookie></oldCookie><lastChange>{t}</lastChange><currentTime>{t}</currentTime><protocolVersion>1.40</protocolVersion></GetCookie>"#
    )
}

pub fn sync_body(cookie: &str, category: &Uuid) -> String {
    let installed: String = INSTALLED_NON_LEAF
        .iter()
        .map(|id| format!("<int>{id}</int>"))
        .collect();
    format!(
        r#"<SyncUpdates xmlns="{CWS}"><cookie><Expiration>2045-03-11T02:02:48Z</Expiration><EncryptedData>{cookie}</EncryptedData></cookie><parameters><ExpressQuery>false</ExpressQuery><InstalledNonLeafUpdateIDs>{installed}</InstalledNonLeafUpdateIDs><OtherCachedUpdateIDs/><SkipSoftwareSync>false</SkipSoftwareSync><NeedTwoGroupOutOfScopeUpdates>true</NeedTwoGroupOutOfScopeUpdates><FilterAppCategoryIds><CategoryIdentifier><Id>{category}</Id></CategoryIdentifier></FilterAppCategoryIds><TreatAppCategoryIdsAsInstalled>true</TreatAppCategoryIdsAsInstalled><AlsoPerformRegularSync>false</AlsoPerformRegularSync><ComputerSpec/><ExtendedUpdateInfoParameters><XmlUpdateFragmentTypes><XmlUpdateFragmentType>Extended</XmlUpdateFragmentType></XmlUpdateFragmentTypes><Locales><string>en-US</string><string>en</string></Locales></ExtendedUpdateInfoParameters><ClientPreferredLanguages><string>en-US</string></ClientPreferredLanguages><ProductsParameters><SyncCurrentVersionOnly>false</SyncCurrentVersionOnly><DeviceAttributes>{DEVICE_ATTRIBUTES}</DeviceAttributes><CallerAttributes>Interactive=1;IsSeeker=1;</CallerAttributes><Products/></ProductsParameters></parameters></SyncUpdates>"#,
        cookie = escape(cookie),
    )
}

pub fn file_url_body(update_id: &Uuid, revision: u32) -> String {
    format!(
        r#"<GetExtendedUpdateInfo2 xmlns="{CWS}"><updateIDs><UpdateIdentity><UpdateID>{update_id}</UpdateID><RevisionNumber>{revision}</RevisionNumber></UpdateIdentity></updateIDs><infoTypes><XmlUpdateFragmentType>FileUrl</XmlUpdateFragmentType><XmlUpdateFragmentType>FileDecryption</XmlUpdateFragmentType></infoTypes><deviceAttributes>{DEVICE_ATTRIBUTES}</deviceAttributes></GetExtendedUpdateInfo2>"#
    )
}

/// The Windows Update category of a product, from DisplayCatalog's answer.
pub fn parse_category(json: &[u8]) -> Result<Uuid, String> {
    let value: serde_json::Value =
        serde_json::from_slice(json).map_err(|e| format!("unreadable catalogue answer: {e}"))?;
    let skus = value["Products"][0]["DisplaySkuAvailabilities"]
        .as_array()
        .ok_or("the catalogue answer lists no SKUs")?;
    for sku in skus {
        let data = &sku["Sku"]["Properties"]["FulfillmentData"];
        let data = match data {
            serde_json::Value::String(s) => serde_json::from_str(s).unwrap_or_default(),
            other => other.clone(),
        };
        if let Some(id) = data["WuCategoryId"].as_str() {
            return Uuid::try_parse(id).map_err(|_| format!("not a category id: {id:?}"));
        }
    }
    Err("the catalogue answer has no WuCategoryId".into())
}

/// The cookie in a `GetCookie` answer.
pub fn parse_cookie(answer: &str) -> Result<String, String> {
    let root = xml::parse(answer, LIMITS)?;
    let cookie = root
        .descendants("EncryptedData")
        .first()
        .map(|e| e.text.trim().to_string())
        .filter(|c| !c.is_empty())
        .ok_or("the delivery service gave no cookie")?;
    if cookie.len() > 64 << 10 || !cookie.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("the delivery service's cookie is not plausible".into());
    }
    Ok(cookie)
}

/// A file of an update, as `SyncUpdates` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateFile {
    pub name: String,
    pub size: u64,
    /// The `Digest` attribute: base64 SHA-1, which `GetExtendedUpdateInfo2`
    /// uses to say which URL is which file.
    pub digest: String,
    /// The `AdditionalDigest` with algorithm SHA256.
    pub sha256: Option<[u8; 32]>,
    pub installer_id: Option<String>,
}

/// An update in a category, as `SyncUpdates` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    pub id: String,
    pub update_id: Uuid,
    pub revision: u32,
    pub moniker: Option<String>,
    pub secured: bool,
    pub files: Vec<UpdateFile>,
}

fn fragment(e: &Element) -> Result<Option<Element>, String> {
    match e.child("Xml") {
        Some(x) => xml::parse(&x.text, LIMITS).map(Some),
        None => Ok(None),
    }
}

/// The updates in a `SyncUpdates` answer, with the files its extended
/// information lists for each.
pub fn parse_sync(answer: &str) -> Result<Vec<Update>, String> {
    let root = xml::parse(answer, LIMITS)?;
    let mut updates: Vec<Update> = Vec::new();
    for info in root.descendants("UpdateInfo") {
        let Some(id) = info.child("ID").map(|e| e.text.trim().to_string()) else {
            continue;
        };
        let Some(frag) = fragment(info)? else {
            continue;
        };
        let Some(identity) = frag.descendants("UpdateIdentity").first().copied() else {
            continue;
        };
        let (Some(update_id), Some(revision)) = (
            identity
                .attribute("UpdateID")
                .and_then(|v| Uuid::try_parse(v).ok()),
            identity
                .attribute("RevisionNumber")
                .and_then(|v| v.parse().ok()),
        ) else {
            continue;
        };
        let moniker = frag
            .descendants("AppxMetadata")
            .iter()
            .find_map(|m| m.attribute("PackageMoniker").map(str::to_string));
        let secured = !frag.descendants("SecuredFragment").is_empty();
        updates.push(Update {
            id,
            update_id,
            revision,
            moniker,
            secured,
            files: Vec::new(),
        });
    }
    for extended in root.descendants("Update") {
        let Some(id) = extended.child("ID").map(|e| e.text.trim().to_string()) else {
            continue;
        };
        let Some(update) = updates.iter_mut().find(|u| u.id == id) else {
            continue;
        };
        let Some(frag) = fragment(extended)? else {
            continue;
        };
        for file in frag.descendants("File") {
            let (Some(name), Some(size), Some(digest)) = (
                file.attribute("FileName"),
                file.attribute("Size").and_then(|s| s.parse().ok()),
                file.attribute("Digest"),
            ) else {
                continue;
            };
            let sha256 = file
                .children_named("AdditionalDigest")
                .find(|d| d.attribute("Algorithm") == Some("SHA256"))
                .and_then(|d| {
                    base64::engine::general_purpose::STANDARD
                        .decode(d.text.trim())
                        .ok()
                })
                .and_then(|d| d.try_into().ok());
            update.files.push(UpdateFile {
                name: name.to_string(),
                size,
                digest: digest.to_string(),
                sha256,
                installer_id: file
                    .attribute("InstallerSpecificIdentifier")
                    .map(str::to_string),
            });
        }
    }
    Ok(updates)
}

/// The numeric parts of a package moniker's version, for picking the newest.
fn moniker_version(moniker: &str) -> Vec<u32> {
    moniker
        .split('_')
        .nth(1)
        .unwrap_or_default()
        .split('.')
        .map(|p| p.parse().unwrap_or(0))
        .collect()
}

/// The newest Gaming Services bundle among the updates, and its main file.
pub fn pick_bundle(updates: &[Update]) -> Result<(&Update, &UpdateFile), String> {
    updates
        .iter()
        .filter(|u| u.secured)
        .filter_map(|u| {
            let moniker = u.moniker.as_deref()?;
            if !moniker.starts_with(GAMING_SERVICES_PACKAGE) || !moniker.ends_with("8wekyb3d8bbwe")
            {
                return None;
            }
            let file = u.files.iter().find(|f| {
                f.installer_id.as_deref() == Some(moniker) && !f.name.starts_with("Abm_")
            })?;
            Some((u, file))
        })
        .max_by_key(|(u, _)| moniker_version(u.moniker.as_deref().unwrap_or_default()))
        .ok_or_else(|| "the delivery service listed no Gaming Services package".to_string())
}

/// The download URL for the file whose SHA-1 digest is `digest`, from a
/// `GetExtendedUpdateInfo2` answer.
pub fn parse_file_url(answer: &str, digest: &str) -> Result<reqwest::Url, String> {
    let root = xml::parse(answer, LIMITS)?;
    for location in root.descendants("FileLocation") {
        if location.child("FileDigest").map(|d| d.text.trim()) != Some(digest) {
            continue;
        }
        let url = location
            .child("Url")
            .map(|u| u.text.trim())
            .ok_or("the delivery service gave a file location without a URL")?;
        let url = reqwest::Url::parse(url).map_err(|e| format!("bad file URL: {e}"))?;
        if !download_url_allowed(&url) {
            return Err(format!(
                "the delivery service gave a file URL on {}, which is not a delivery host",
                url.host_str().unwrap_or("no host")
            ));
        }
        return Ok(url);
    }
    Err("the delivery service gave no URL for the package".into())
}

async fn post(
    client: &reqwest::Client,
    url: &str,
    action: &str,
    body: &str,
) -> Result<String, String> {
    debug_assert!(url.starts_with(&format!("https://{FE3_HOST}/")));
    let request = envelope(action, url, body, chrono::Utc::now());
    let mut response = client
        .post(url)
        .header("Content-Type", "application/soap+xml; charset=utf-8")
        .body(request)
        .send()
        .await
        .map_err(|e| format!("{action}: {e}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "{action}: the delivery service answered {}",
            response.status()
        ));
    }
    let text = read_limited(&mut response, LIMITS.max_bytes)
        .await
        .map_err(|e| format!("{action}: {e}"))?;
    String::from_utf8(text).map_err(|_| format!("{action}: the answer is not UTF-8"))
}

async fn read_limited(response: &mut reqwest::Response, limit: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if out.len() + chunk.len() > limit {
            return Err(format!("the answer is larger than {limit} bytes"));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// What to download: the bundle's URL, size and SHA-256, and its name.
#[derive(Debug, Clone)]
pub struct BundleLocation {
    pub moniker: String,
    pub url: reqwest::Url,
    pub size: u64,
    pub sha256: Option<[u8; 32]>,
}

/// Find the current Gaming Services bundle, anonymously.
pub async fn locate_bundle(timeout: Duration) -> Result<BundleLocation, String> {
    let web = download_client(timeout)?;
    let mut catalogue = web
        .get(format!(
            "{DISPLAYCATALOG}?bigIds={GAMING_SERVICES_PRODUCT}&market=US&languages=en-US,neutral"
        ))
        .send()
        .await
        .map_err(|e| format!("could not reach the Store catalogue: {e}"))?;
    if !catalogue.status().is_success() {
        return Err(format!(
            "the Store catalogue answered {}",
            catalogue.status()
        ));
    }
    let category = parse_category(&read_limited(&mut catalogue, 4 << 20).await?)?;

    let fe3 = fe3_client(microsoft_root(timeout).await?, timeout)?;
    let cookie =
        parse_cookie(&post(&fe3, FE3_URL, "GetCookie", &cookie_body(chrono::Utc::now())).await?)?;
    let updates =
        parse_sync(&post(&fe3, FE3_URL, "SyncUpdates", &sync_body(&cookie, &category)).await?)?;
    let (update, file) = pick_bundle(&updates)?;
    let answer = post(
        &fe3,
        FE3_SECURED_URL,
        "GetExtendedUpdateInfo2",
        &file_url_body(&update.update_id, update.revision),
    )
    .await?;
    Ok(BundleLocation {
        moniker: update.moniker.clone().unwrap_or_default(),
        url: parse_file_url(&answer, &file.digest)?,
        size: file.size,
        sha256: file.sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shaped like FE3's answers, with made-up identifiers, digests and URLs.
    const SYNC: &str = include_str!("testdata/sync-updates.xml");
    const FILE_URLS: &str = include_str!("testdata/get-extended-update-info2.xml");
    const COOKIE: &str = include_str!("testdata/get-cookie.xml");
    const CATALOGUE: &str = include_str!("testdata/displaycatalog.json");

    /// Reaches FE3 through the fetched, pinned Microsoft root and finds the
    /// Gaming Services bundle and its URL, anonymously; downloads nothing but
    /// the root certificate and the metadata. Run with `--ignored`.
    #[tokio::test]
    #[ignore = "talks to the Microsoft Store delivery service"]
    async fn live_the_bundle_is_located_anonymously() {
        let location = locate_bundle(Duration::from_secs(60)).await.unwrap();
        assert!(location.moniker.starts_with(GAMING_SERVICES_PACKAGE));
        assert!(download_url_allowed(&location.url));
        assert!(location.size > 1 << 20);
        assert!(location.sha256.is_some());
    }

    #[test]
    fn only_the_pinned_root_is_taken() {
        let der = b"not really a certificate, only bytes to pin";
        let pin = msixvc::signature::hex(&Sha256::digest(der));
        assert!(pinned_certificate(der, &pin).is_ok());
        let err = pinned_certificate(der, MICROSOFT_ROOT_2011_SHA256).unwrap_err();
        assert!(err.contains("not the pinned"), "{err}");
        assert_eq!(MICROSOFT_ROOT_2011_SHA256.len(), 64);
        assert!(MICROSOFT_ROOT_2011_SHA256.starts_with("847df6a7"));
        assert!(MICROSOFT_ROOT_2011_SHA256.ends_with("ed7c61"));
    }

    #[test]
    fn the_category_comes_from_the_fulfillment_data() {
        assert_eq!(
            parse_category(CATALOGUE.as_bytes()).unwrap(),
            Uuid::parse_str("aaaaaaaa-1111-4222-8333-444444444444").unwrap()
        );
        // As an object rather than a string.
        let json = br#"{"Products":[{"DisplaySkuAvailabilities":[{"Sku":{"Properties":{}}},{"Sku":{"Properties":{"FulfillmentData":{"WuCategoryId":"aaaaaaaa-1111-4222-8333-444444444445"}}}}]}]}"#;
        assert!(parse_category(json).is_ok());
        assert!(parse_category(br#"{"Products":[]}"#).is_err());
        assert!(parse_category(b"not json").is_err());
    }

    #[test]
    fn the_cookie_is_read() {
        assert_eq!(parse_cookie(COOKIE).unwrap(), "Q29va2llRm9yVGVzdHM=");
        assert!(parse_cookie("<a><b/></a>").is_err());
    }

    #[test]
    fn the_newest_gaming_services_bundle_is_picked_with_its_file() {
        let updates = parse_sync(SYNC).unwrap();
        // The category itself, two Gaming Services versions, a framework.
        assert_eq!(updates.len(), 4);
        let (update, file) = pick_bundle(&updates).unwrap();
        assert_eq!(
            update.moniker.as_deref(),
            Some("Microsoft.GamingServices_38.118.9001.0_neutral_~_8wekyb3d8bbwe")
        );
        assert_eq!(update.revision, 1);
        assert_eq!(
            update.update_id,
            Uuid::parse_str("cccccccc-1111-4222-8333-444444444444").unwrap()
        );
        assert_eq!(file.name, "bbbbbbbb-1111-4222-8333-444444444444.appxbundle");
        assert_eq!(file.size, 200_322_495);
        assert_eq!(file.digest, "c2hhMS1vZi10aGUtYnVuZGxlISE=");
        assert_eq!(file.sha256, Some([0x11; 32]));

        let url = parse_file_url(FILE_URLS, &file.digest).unwrap();
        assert_eq!(
            url.as_str(),
            "http://tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/bbbbbbbb-test?P1=1&P2=2"
        );
        // The other file's URL is not taken for it.
        assert!(parse_file_url(FILE_URLS, "bm8tc3VjaC1kaWdlc3Q=").is_err());
    }

    #[test]
    fn only_delivery_hosts_are_fetched_from() {
        let allowed = |u: &str| download_url_allowed(&reqwest::Url::parse(u).unwrap());
        assert!(allowed("http://tlu.dl.delivery.mp.microsoft.com/x"));
        assert!(allowed("https://dl.delivery.mp.microsoft.com/x"));
        assert!(!allowed("http://evil.example/x"));
        assert!(!allowed("http://delivery.mp.microsoft.com.evil.example/x"));
        assert!(!allowed("http://user@tlu.dl.delivery.mp.microsoft.com/x"));
        assert!(!allowed("http://tlu.dl.delivery.mp.microsoft.com:8080/x"));
        assert!(!allowed("file:///etc/passwd"));
        let evil = FILE_URLS.replace("tlu.dl.delivery.mp.microsoft.com", "evil.example");
        assert!(parse_file_url(&evil, "c2hhMS1vZi10aGUtYnVuZGxlISE=").is_err());
    }

    #[test]
    fn requests_carry_the_anonymous_ticket_and_escape_what_they_echo() {
        let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let e = envelope("GetCookie", FE3_URL, &cookie_body(now), now);
        assert!(e.contains("<User/>"));
        assert!(e.contains("2023-11-14T22:13:20.000Z"));
        assert!(xml::parse(&e, LIMITS).is_ok());
        let body = sync_body("a<b>&c", &Uuid::nil());
        assert!(body.contains("a&lt;b&gt;&amp;c"));
        assert!(xml::parse(&body, LIMITS).is_ok());
    }

    #[test]
    fn answers_that_are_not_what_they_should_be_are_refused() {
        assert!(parse_sync("<x>").is_err());
        let doctype = format!("<!DOCTYPE x>{SYNC}");
        assert!(parse_sync(&doctype).is_err());
        // An escaped fragment that is itself malformed.
        let broken = SYNC.replacen("&lt;UpdateIdentity", "&lt;UpdateIdentity &lt;", 1);
        assert!(parse_sync(&broken).is_err());
        // No Gaming Services at all.
        let none = SYNC.replace("Microsoft.GamingServices_", "Microsoft.Other_");
        assert!(pick_bundle(&parse_sync(&none).unwrap()).is_err());
    }
}
