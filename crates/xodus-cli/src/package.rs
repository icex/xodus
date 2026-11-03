use inquire::Select;
use xodus::XBOX_LIVE_PACKAGES_PC;
use xodus::api::displaycatalog::find_products_by_id;
use xodus::models::packagespc::{PackageDetails, PackageFile, PackageResponse};
use xodus::models::secrets::Token;
use xodus::tokens::TokenManager;

/// The build version the authenticated update service is offering.
///
/// DisplayCatalog reports every package as version `0`; this field is the one
/// that changes when Microsoft publishes a new MSIXVC build.
pub fn available_version(package: &PackageDetails) -> Option<&str> {
    let version = package.version.trim();
    let fields: Vec<&str> = version.split('.').take(4).collect();
    if fields.len() != 4 || fields.iter().any(|field| field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    let prefix_len = fields.iter().map(|field| field.len()).sum::<usize>() + 3;
    Some(&version[..prefix_len])
}

/// The top hash a package's header must carry, as the authenticated package
/// service gives it.
///
/// The package service is reached over TLS with the account's token; the CDN it
/// points to is usually plain http. Its `HashOfHashes` is taken to be the
/// header's `top_hash_block_hash`: the SHA-256 of the top page of the hash
/// tree, which is itself a page of hashes, and the one value that every other
/// check of the download hangs from. Holding the header to it means a download
/// rewritten on its way -- header, tree and pages together -- is refused rather
/// than installed.
///
/// A SHA-256 in hex or base64 is accepted. Anything else in that field is
/// refused, since a value this client cannot read is not one it can check.
/// `None` when the service gives no value, which so far is every package seen:
/// the install then goes ahead as before, and the caller says so.
///
/// The per-file `FileHash` is not used: nothing in the package header
/// corresponds to it, and a streaming install never reads a whole file to
/// compare it with a whole-file digest.
pub fn header_anchor(package: &PackageDetails) -> Result<Option<[u8; 32]>, String> {
    let Some(value) = package
        .hash_of_hashes
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    sha256_digest(value).map(Some).ok_or_else(|| {
        format!(
            "refusing this package: the package service vouches for it with HashOfHashes \
             {value:?}, which is not a SHA-256 digest, so the download cannot be checked \
             against it"
        )
    })
}

/// A SHA-256 digest written as 64 hex digits or as base64.
fn sha256_digest(value: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut digest = [0u8; 32];
        for (i, byte) in digest.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[2 * i..2 * i + 2], 16).ok()?;
        }
        return Some(digest);
    }
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .ok()?
        .try_into()
        .ok()
}

/// What to say about a package the service gave no header hash for.
pub fn unanchored_note(file: &PackageFile) -> String {
    let mut note = String::from(
        "note: the package service gave no HashOfHashes for this package, so its header \
         is checked against nothing outside the download",
    );
    if !file.file_hash.trim().is_empty() {
        note.push_str(
            " (it gave a FileHash, which has no counterpart in the package header and \
             is not used)",
        );
    }
    note
}

/// Set to `1` to refuse a download when the package service lists only plain
/// http CDN roots for it.
pub const REQUIRE_HTTPS_CDN_ENV: &str = "XODUS_REQUIRE_HTTPS_CDN";

/// Where to download a package file from, out of the CDN roots the package
/// service lists.
///
/// An https root is taken if there is one. Otherwise the first root is used as
/// it is, and so far that has meant plain `http://`: the Xbox package CDN hosts
/// answer https with a certificate for other names, so asking them for the
/// same path over https fails every time. Over http the pages are still
/// checked against the package's hash tree. The header that vouches for that
/// tree is held to the package service's hash when it gives one (see
/// `header_anchor`) and to its signature when the signing key is here (see
/// `crate::xvd_key`); `checked` says which. When neither, nothing vouches for
/// the header, and a note says so. `XODUS_REQUIRE_HTTPS_CDN=1` refuses a plain
/// http package either way. A root in any other scheme is refused.
pub fn package_url(
    cdn_roots: &[String],
    relative_url: &str,
    checked: HeaderCheck,
) -> Result<String, String> {
    let url = package_url_with(
        cdn_roots,
        relative_url,
        std::env::var(REQUIRE_HTTPS_CDN_ENV).is_ok_and(|v| v == "1"),
    )?;
    if !has_scheme(&url, "https://") {
        eprintln!(
            "note: the package service lists only plain http for this package; {}",
            checked.note()
        );
    }
    Ok(url)
}

/// What a package's header is checked against, besides itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderCheck {
    Nothing,
    ServiceHash,
    Signature,
    SignatureAndServiceHash,
}

impl HeaderCheck {
    pub fn new(signed: bool, anchored: bool) -> Self {
        match (signed, anchored) {
            (false, false) => HeaderCheck::Nothing,
            (false, true) => HeaderCheck::ServiceHash,
            (true, false) => HeaderCheck::Signature,
            (true, true) => HeaderCheck::SignatureAndServiceHash,
        }
    }

    pub fn note(self) -> &'static str {
        match self {
            HeaderCheck::Nothing => {
                "its pages are checked against its hash tree, but nothing vouches for its header"
            }
            HeaderCheck::ServiceHash => {
                "its header is held to the hash the package service gives, and its pages to \
                 the header's hash tree"
            }
            HeaderCheck::Signature => {
                "its header is held to its signature, and its pages to the header's hash tree"
            }
            HeaderCheck::SignatureAndServiceHash => {
                "its header is held to its signature and to the hash the package service \
                 gives, and its pages to the header's hash tree"
            }
        }
    }
}

fn has_scheme(url: &str, scheme: &str) -> bool {
    url.get(..scheme.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
}

fn package_url_with(
    cdn_roots: &[String],
    relative_url: &str,
    require_https: bool,
) -> Result<String, String> {
    if let Some(root) = cdn_roots.iter().find(|root| has_scheme(root, "https://")) {
        return Ok(format!("{root}{relative_url}"));
    }
    let Some(root) = cdn_roots.first() else {
        return Err("the package service listed no download location for this package".into());
    };
    if !has_scheme(root, "http://") {
        return Err(format!(
            "refusing the download location {root}: only http and https are used"
        ));
    }
    if require_https {
        return Err(format!(
            "refusing the download location {root}: it is plain http and \
             {REQUIRE_HTTPS_CDN_ENV}=1 asks for https"
        ));
    }
    Ok(format!("{root}{relative_url}"))
}

pub async fn get_content_id(
    client: &reqwest::Client,
    product: String,
    market: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let displaycatalog = find_products_by_id(
        client,
        product,
        market.clone().unwrap_or("neutral".to_owned()),
        vec!["en".to_string(), "neutral".to_string()],
    )
    .await?;

    let product_details = displaycatalog.product;

    let mut found_package = None;
    let mut fallback_package = None;
    let mut subprods: Vec<String> = vec![];
    'o: for availability in &product_details.display_sku_availabilities {
        for package in &availability.sku.properties.packages {
            let platform = |name: &str| {
                package
                    .platform_dependencies
                    .iter()
                    .any(|dep| dep.platform_name == name)
            };
            if platform("Windows.Desktop") {
                found_package = Some(package);
                break 'o;
            }
            // A UWP product declares Windows.Universal (or, for the older ones,
            // Windows.Windows8x) and no Windows.Desktop package at all. Taking
            // only Desktop meant every such product fell through to the picker
            // below -- which, in a launcher's non-interactive context, is not a
            // picker but a failure reading "Selection failed".
            //
            // Second, not first: where a product ships both, the Desktop
            // package is the one to fetch, and the loop above still wins.
            if fallback_package.is_none()
                && (platform("Windows.Universal") || platform("Windows.Windows8x"))
            {
                fallback_package = Some(package);
            }
        }
        for availability in &availability.availabilities {
            if let Some(licensing_data) = &availability.licensing_data {
                for satisfies in &licensing_data.satisfying_entitlement_keys {
                    for entitlement_key in &satisfies.entitlement_keys {
                        let key: Vec<&str> = entitlement_key.split(":").collect();
                        if key.len() == 3 && key[0] == "big" {
                            subprods.push(key[1].to_string());
                        }
                    }
                }
            }
        }
    }
    subprods.sort();
    subprods.dedup();

    let Some(package) = found_package.or(fallback_package) else {
        if !subprods.is_empty() {
            let Ok(item) = Select::new("Select files to download", subprods)
                .with_page_size(30)
                .prompt()
            else {
                return Err(Box::new(std::io::Error::other("Selection failed")));
            };
            return Box::pin(get_content_id(client, item, market)).await;
        }

        return Err(Box::new(std::io::Error::other(
            "no PC package found (Windows.Desktop, Windows.Universal or Windows.Windows8x); \
             if you believe this is an error, please report it",
        )));
    };

    let Some(content_id) = &package.content_id else {
        tracing::error!("ContentId not found, if you believe this is an error, please report it");
        return Err(Box::new(std::io::Error::other(
            "ContentId not found, if you believe this is an error, please report it",
        )));
    };
    Ok(content_id.to_owned())
}

pub async fn get_packages(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
) -> Result<PackageDetails, Box<dyn std::error::Error>> {
    // Each of these used to be an unwrap or an expect, so being offline or
    // signed out ended the client with a panic instead of a reason.
    let dev_token = tokens
        .get_device_sts_token()
        .map_err(|e| format!("no device token ({e}); sign in again"))?;
    let Token::Legacy(dev_token) = dev_token else {
        return Err(Box::new(std::io::Error::other("Invalid STS token")));
    };
    let user_token = tokens
        .get_user_sts_token()
        .map_err(|e| format!("no user token ({e}); sign in again"))?;
    let Token::Legacy(legacy) = user_token else {
        return Err(Box::new(std::io::Error::other("Unsupported user token")));
    };

    let xsts_token = xodus::api::xbox::try_run_with_signer(
        client,
        dev_token,
        legacy,
        "http://update.xboxlive.com",
        None,
    )
    .await
    .map_err(|e| format!("could not sign in to the package service: {e}"))?;

    let response = client
        .get(format!(
            "{XBOX_LIVE_PACKAGES_PC}/GetBasePackage/{content_id}"
        ))
        .header("x-xbl-contract-version", "3")
        .header(
            "Authorization",
            xodus::api::xbox::get_xsts_auth_header(xsts_token),
        )
        .send()
        .await
        .map_err(|e| format!("could not reach the package service: {e}"))?;

    let res: PackageResponse = response
        .json()
        .await
        .map_err(|e| format!("the package service sent an answer that could not be read: {e}"))?;

    let PackageResponse::Found(package) = res else {
        return Err(Box::new(std::io::Error::other(
            "Package was not found, is it owned by the user?",
        )));
    };
    Ok(package)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_version_comes_from_the_authenticated_package_response() {
        let package = PackageDetails {
            package_found: true,
            content_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            version_id: "version-id".into(),
            package_files: Vec::new(),
            version: "1.26.4600.0".into(),
            hash_of_hashes: None,
            update_predownload: false,
            availability_date: "2026-09-08T00:00:00Z".into(),
        };

        assert_eq!(available_version(&package), Some("1.26.4600.0"));

        let mut with_build_id = package;
        with_build_id.version = "3.688.109.0.3b6b700a-992b-45fc-b16b-4ea65141d98c".into();
        assert_eq!(available_version(&with_build_id), Some("3.688.109.0"));
    }

    fn details(hash_of_hashes: Option<&str>) -> PackageDetails {
        PackageDetails {
            package_found: true,
            content_id: "01234567-89ab-cdef-0123-456789abcdef".into(),
            version_id: "version-id".into(),
            package_files: Vec::new(),
            version: "1.0.0.0".into(),
            hash_of_hashes: hash_of_hashes.map(str::to_string),
            update_predownload: false,
            availability_date: "2026-09-08T00:00:00Z".into(),
        }
    }

    #[test]
    fn the_header_anchor_is_the_services_hash_of_hashes() {
        let digest: [u8; 32] = std::array::from_fn(|i| (i * 9 + 1) as u8);
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(digest);
        for value in [
            hex.clone(),
            hex.to_ascii_uppercase(),
            b64,
            format!(" {hex}\n"),
        ] {
            assert_eq!(
                header_anchor(&details(Some(&value))),
                Ok(Some(digest)),
                "{value:?}"
            );
        }
        // Absent, null or empty: nothing to hold the header to.
        for value in [None, Some(""), Some("  ")] {
            assert_eq!(header_anchor(&details(value)), Ok(None), "{value:?}");
        }
        // Present but not a SHA-256: refused, not ignored.
        for value in [
            "not a digest",
            &hex[..62],
            &format!("{hex}00"),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 20 bytes
            &format!("{}zz", &hex[..62]),
        ] {
            let err = header_anchor(&details(Some(value))).unwrap_err();
            assert!(err.starts_with("refusing this package"), "{value:?}: {err}");
        }
        // The service's answer as it comes, with the field missing or null.
        let missing: PackageDetails = serde_json::from_value(serde_json::json!({
            "PackageFound": true, "ContentId": "c", "VersionId": "v", "PackageFiles": [],
            "Version": "1.0.0.0", "UpdatePredownload": false, "AvailabilityDate": "d"
        }))
        .unwrap();
        assert_eq!(header_anchor(&missing), Ok(None));
        let given: PackageDetails = serde_json::from_value(serde_json::json!({
            "PackageFound": true, "ContentId": "c", "VersionId": "v", "PackageFiles": [],
            "Version": "1.0.0.0", "HashOfHashes": hex, "UpdatePredownload": false,
            "AvailabilityDate": "d"
        }))
        .unwrap();
        assert_eq!(header_anchor(&given), Ok(Some(digest)));
    }

    #[test]
    fn packages_are_fetched_from_the_roots_the_service_lists() {
        let roots = |r: &[&str]| r.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let rel = "/8/abc/package.msixvc";

        // A plain http root is used as it is: the CDN hosts do not answer
        // https for their own names, so rewriting it would fail every install.
        assert_eq!(
            package_url_with(&roots(&["http://assets1.xboxlive.com"]), rel, false).unwrap(),
            "http://assets1.xboxlive.com/8/abc/package.msixvc"
        );
        // An https root, wherever it is in the list, is preferred.
        assert_eq!(
            package_url_with(
                &roots(&[
                    "http://assets1.xboxlive.com",
                    "HTTPS://assets2.xboxlive.com"
                ]),
                rel,
                true
            )
            .unwrap(),
            "HTTPS://assets2.xboxlive.com/8/abc/package.msixvc"
        );
        // Only when asked for is a plain http list refused.
        assert!(package_url_with(&roots(&["http://assets1.xboxlive.com"]), rel, true).is_err());
        // No roots, or one in another scheme, is an error rather than a panic.
        assert!(package_url_with(&[], rel, false).is_err());
        assert!(package_url_with(&roots(&["ftp://x"]), rel, false).is_err());
        assert!(package_url_with(&roots(&["h"]), rel, false).is_err());
    }
}
