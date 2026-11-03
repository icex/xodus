use inquire::Select;
use xodus::XBOX_LIVE_PACKAGES_PC;
use xodus::api::displaycatalog::find_products_by_id;
use xodus::models::packagespc::{PackageDetails, PackageResponse};
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
    let dev_token = tokens.get_device_sts_token().unwrap();
    let Token::Legacy(dev_token) = dev_token else {
        return Err(Box::new(std::io::Error::other("Invalid STS token")));
    };
    let user_token = tokens.get_user_sts_token().unwrap();
    let Token::Legacy(legacy) = user_token else {
        return Err(Box::new(std::io::Error::other("Unsupported user token")));
    };

    let xsts_token =
        xodus::api::xbox::run(client, dev_token, legacy, "http://update.xboxlive.com").await;

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
        .unwrap();

    let res: PackageResponse = response.json().await.expect("Failed to get data");

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
}
