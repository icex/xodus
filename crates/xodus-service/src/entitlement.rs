//! A title-bound Store licence. No running-title or player ownership inference.
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use xodus::tokens::TokenManager;

pub struct Entitlement {
    product: String,
    content: String,
    cached: tokio::sync::Mutex<Option<Check>>,
    /// Products the Store catalog was asked about, and whether it ties each
    /// one to the bound product. Only answers the catalog gave are kept.
    family: tokio::sync::Mutex<HashMap<String, bool>>,
}

/// The relationships under which a product's own catalog entry names the game
/// it belongs to: an add-on or consumable to its game (`addOnParent`) and an
/// edition to the game it extends (`Parent`, `Extends`). Only the requested
/// product's entry counts: a game naming a bundle that contains it, or the
/// storefront that sells it, is not a reason to license that bundle or
/// storefront under this title, since either can grant other titles. Nor is
/// `SellableBy` alone, which names where a product is sold, not what it
/// belongs to; real add-ons carry it beside `addOnParent`. Dungeons II's own
/// licence request asks for exactly this shape: its Soul and Hero packs, each
/// naming the game as `addOnParent` (and `SellableBy`).
const FAMILY: [&str; 3] = ["addOnParent", "Parent", "Extends"];

/// Whether a catalog entry names `other` under one of the family relationships.
fn related(entry: &Value, other: &str) -> bool {
    entry["MarketProperties"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|market| market["RelatedProducts"].as_array())
        .flatten()
        .any(|relation| {
            relation["RelatedProductId"]
                .as_str()
                .is_some_and(|id| id.eq_ignore_ascii_case(other))
                && relation["RelationshipType"]
                    .as_str()
                    .is_some_and(|kind| FAMILY.iter().any(|f| f.eq_ignore_ascii_case(kind)))
        })
}

fn entry_id(entry: &Value) -> &str {
    entry["ProductId"].as_str().unwrap_or("")
}

/// The last answer, and when the licence was last actually granted.
#[derive(Clone, Copy)]
struct Check {
    at: Instant,
    valid: bool,
    granted: Option<Instant>,
}

/// How long a verified grant outlives failed checks. The licensing endpoint
/// cannot tell this service "denied" from "unreachable", and the runtime
/// treats a false answer as a lost licence -- so without this, a network blip
/// or going offline ends a game that was licensed a minute earlier. A real
/// revocation is honoured once the grace has run out.
const GRACE: Duration = Duration::from_secs(30 * 60);

impl Entitlement {
    pub fn from_env() -> Result<Option<Arc<Self>>, String> {
        match (
            std::env::var("XODUS_STORE_PRODUCT"),
            std::env::var("XODUS_STORE_CONTENT"),
        ) {
            (Err(_), Err(_)) => Ok(None),
            (Ok(product), Ok(content))
                if product.len() == 12
                    && product.bytes().all(|c| c.is_ascii_alphanumeric())
                    && uuid_valid(&content) =>
            {
                Ok(Some(Arc::new(Self {
                    product,
                    content,
                    cached: Default::default(),
                    family: Default::default(),
                })))
            }
            _ => Err("invalid Store title binding".into()),
        }
    }

    #[cfg(test)]
    pub(crate) fn fixture(product: &str) -> Arc<Self> {
        Arc::new(Self {
            product: product.into(),
            content: "00000000-0000-0000-0000-000000000001".into(),
            cached: Default::default(),
            family: Default::default(),
        })
    }

    /// The Store product this service is bound to.
    pub fn product(&self) -> &str {
        &self.product
    }

    /// Refuse licence tokens for products that are not this title's own.
    ///
    /// The bound product always passes. Any other ID must be a Store product
    /// ID (twelve characters, or sixteen with a SKU) whose own catalog entry
    /// names the bound product under one of the family relationships. That
    /// covers a game's add-ons, consumables, DLC and editions, and nothing the
    /// game merely lists, such as bundles. The
    /// catalog is the only source for those relationships; when it cannot be
    /// reached, or does not list a product, the request is refused rather
    /// than signed on the title's word. The licensing request needs the
    /// network as well, so an unreachable catalog costs nothing that would
    /// have worked.
    pub async fn admit_products<L, Fut>(&self, wanted: &[String], lookup: L) -> Result<(), String>
    where
        L: FnOnce(Vec<String>) -> Fut,
        Fut: std::future::Future<Output = Result<Vec<Value>, &'static str>>,
    {
        let mut products = Vec::new();
        for id in wanted {
            if !matches!(id.len(), 12 | 16) || !id.bytes().all(|c| c.is_ascii_alphanumeric()) {
                return Err(format!(
                    "refused a licence token for {id:?}: not a Store product ID"
                ));
            }
            let product = id[..12].to_ascii_uppercase();
            if !product.eq_ignore_ascii_case(&self.product) && !products.contains(&product) {
                products.push(product);
            }
        }
        if products.is_empty() {
            return Ok(());
        }
        let mut family = self.family.lock().await;
        let unknown: Vec<_> = products
            .iter()
            .filter(|id| !family.contains_key(*id))
            .cloned()
            .collect();
        if !unknown.is_empty() {
            let mut ask = vec![self.product.clone()];
            ask.extend(unknown.iter().cloned());
            let entries = lookup(ask).await.map_err(|cause| {
                format!(
                    "refused a licence token for {unknown:?}: the Store catalog could not confirm them as part of {} ({cause})",
                    self.product
                )
            })?;
            for id in &unknown {
                if let Some(entry) = entries
                    .iter()
                    .find(|entry| entry_id(entry).eq_ignore_ascii_case(id))
                {
                    family.insert(id.clone(), related(entry, &self.product));
                }
            }
        }
        let refused: Vec<_> = products
            .iter()
            .filter(|id| family.get(*id) != Some(&true))
            .collect();
        if refused.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "refused a licence token for {refused:?}: the Store catalog does not list them as add-ons or editions of {}",
                self.product
            ))
        }
    }

    pub async fn valid(
        &self,
        product: &str,
        client: &reqwest::Client,
        tokens: &TokenManager,
    ) -> bool {
        if !product.eq_ignore_ascii_case(&self.product)
            || tokens.get_user().is_err()
            || tokens.get_user_sts_token().is_err()
        {
            return false;
        }
        let mut cached = self.cached.lock().await;
        let previous = *cached;
        if let Some(check) = previous {
            if check.at.elapsed() < Duration::from_secs(if check.valid { 60 } else { 10 }) {
                return check.valid;
            }
        }
        let checked = tokio::time::timeout(
            Duration::from_secs(25),
            xodus::licensing::acquire::get_license(
                client,
                tokens,
                self.content.clone(),
                "neutral".into(),
            ),
        )
        .await;
        let signed_in = tokens.get_user().is_ok() && tokens.get_user_sts_token().is_ok();
        let now = Instant::now();
        let granted = match &checked {
            Ok(Ok(_)) => Some(now),
            _ => previous.and_then(|check| check.granted),
        };
        let valid = signed_in && granted.is_some_and(|at| now.duration_since(at) < GRACE);
        if !matches!(checked, Ok(Ok(_))) {
            let cause = match &checked {
                Ok(Err(e)) => e.clone(),
                _ => "timed out".to_string(),
            };
            tracing::warn!(
                product = %self.product,
                within_grace = valid,
                "Store account content licence check failed: {cause}"
            );
        }
        *cached = Some(Check {
            at: now,
            valid,
            granted,
        });
        valid
    }
}

fn uuid_valid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn cached_grant_stays_bound_to_title_and_current_store_credentials() {
        let context = crate::simple_context::tests::context("owner-cache", "player-cache");
        let owner = context.store_context().tokens().clone();
        let binding = Entitlement {
            product: "9TESTROLE0ID".into(),
            content: "00000000-0000-0000-0000-000000000001".into(),
            cached: tokio::sync::Mutex::new(Some(Check {
                at: Instant::now(),
                valid: true,
                granted: Some(Instant::now()),
            })),
            family: Default::default(),
        };
        assert!(binding.valid("9TESTROLE0ID", &context.client, &owner).await);
        assert!(!binding.valid("9OTHERROLE00", &context.client, &owner).await);
        context.tokens().remove_user().unwrap();
        assert!(binding.valid("9TESTROLE0ID", &context.client, &owner).await);
        owner.remove_user().unwrap();
        assert!(!binding.valid("9TESTROLE0ID", &context.client, &owner).await);
    }

    /// A refresh that fails -- here because the fixture has no device
    /// credentials, as a network failure would -- keeps a recent grant, and
    /// lets one older than the grace period go.
    #[tokio::test]
    async fn a_verified_grant_survives_failed_checks_only_for_the_grace_period() {
        let context = crate::simple_context::tests::context("owner-grace", "player-grace");
        let owner = context.store_context().tokens().clone();
        let binding = |granted_ago: Duration| {
            let now = Instant::now();
            Some(Entitlement {
                product: "9TESTROLE0ID".into(),
                content: "00000000-0000-0000-0000-000000000001".into(),
                cached: tokio::sync::Mutex::new(Some(Check {
                    at: now.checked_sub(Duration::from_secs(61))?,
                    valid: true,
                    granted: Some(now.checked_sub(granted_ago)?),
                })),
                family: Default::default(),
            })
        };
        if let Some(recent) = binding(Duration::from_secs(120)) {
            assert!(recent.valid("9testrole0id", &context.client, &owner).await);
        }
        // A machine up for less than the grace period cannot hold an older
        // instant; the check is skipped there rather than faked.
        if let Some(expired) = binding(GRACE + Duration::from_secs(1)) {
            assert!(!expired.valid("9TESTROLE0ID", &context.client, &owner).await);
        }
        let never = Entitlement::fixture("9TESTROLE0ID");
        assert!(!never.valid("9TESTROLE0ID", &context.client, &owner).await);
    }
}
