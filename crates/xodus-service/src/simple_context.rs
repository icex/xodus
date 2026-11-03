// Temporary context, full service design will be much more extensive

use std::sync::Arc;

use xodus::models::secrets::LegacyToken;
use xodus::tokens::TokenManager;

pub struct SimpleContext {
    pub entitlement: Option<Arc<crate::entitlement::Entitlement>>,
    pub client: reqwest::Client,
    pub device_token: Option<LegacyToken>,
    tokens: Arc<TokenManager>,
    store_tokens: Arc<TokenManager>,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use xodus::models::secrets::User;

    pub(crate) fn context(store: &str, player: &str) -> SimpleContext {
        let backend = TokenManager::with_memory();
        let owner = backend.scoped("11111111111111111111111111111111").unwrap();
        let gamer = backend.scoped("22222222222222222222222222222222").unwrap();
        owner
            .save_user(&User {
                puid: store.into(),
                username: "owner fixture".into(),
            })
            .unwrap();
        gamer
            .save_user(&User {
                puid: player.into(),
                username: "player fixture".into(),
            })
            .unwrap();
        owner
            .save_user_token(
                xodus::tokens::PASSPORT_STS.into(),
                xodus::models::secrets::Token::Compact("owner fixture".into()),
            )
            .unwrap();
        gamer
            .save_user_token(
                xodus::tokens::PASSPORT_STS.into(),
                xodus::models::secrets::Token::Compact("player fixture".into()),
            )
            .unwrap();
        SimpleContext {
            entitlement: None,
            client: reqwest::Client::new(),
            device_token: None,
            tokens: Arc::new(gamer.pin_user().unwrap()),
            store_tokens: Arc::new(owner.pin_user().unwrap()),
        }
    }

    #[test]
    fn role_routing_and_msa_comparison_use_the_selected_accounts() {
        let split = context("owner-fixture", "player-fixture");
        assert_eq!(split.account_roles(), [1, 1, 1, 0]);
        assert_eq!(split.tokens().get_user().unwrap().puid, "player-fixture");
        assert_eq!(
            split.store_context().tokens().get_user().unwrap().puid,
            "owner-fixture"
        );
        assert_eq!(
            context("same-fixture", "same-fixture").account_roles(),
            [1, 1, 1, 1]
        );
        split.store_tokens.remove_user().unwrap();
        assert_eq!(split.account_roles(), [1, 0, 1, 0]);
        assert_eq!(split.tokens().get_user().unwrap().puid, "player-fixture");
        let split = context("owner-fixture", "player-fixture");
        split.tokens.remove_user().unwrap();
        assert_eq!(split.account_roles(), [1, 1, 0, 0]);
        assert_eq!(
            split.store_context().tokens().get_user().unwrap().puid,
            "owner-fixture"
        );
    }
}

impl SimpleContext {
    pub fn new(device_token: LegacyToken, tokens: Arc<TokenManager>) -> Self {
        Self::with_roles(device_token, tokens.clone(), tokens)
    }

    pub fn with_roles(
        device_token: LegacyToken,
        store_tokens: Arc<TokenManager>,
        tokens: Arc<TokenManager>,
    ) -> Self {
        let client = reqwest::ClientBuilder::new()
            .user_agent(format!("xodus-service/{}", env!("CARGO_PKG_VERSION")))
            .connection_verbose(true)
            .build()
            .unwrap();

        Self {
            client,
            entitlement: None,
            device_token: Some(device_token),
            tokens,
            store_tokens,
        }
    }

    pub fn tokens(&self) -> &Arc<TokenManager> {
        &self.tokens
    }

    pub fn store_context(&self) -> Self {
        Self {
            entitlement: self.entitlement.clone(),
            client: self.client.clone(),
            device_token: self.device_token.clone(),
            tokens: self.store_tokens.clone(),
            store_tokens: self.store_tokens.clone(),
        }
    }

    pub fn account_roles(&self) -> [u32; 4] {
        let store = self
            .store_tokens
            .get_user()
            .ok()
            .filter(|u| !u.puid.is_empty() && self.store_tokens.get_user_sts_token().is_ok());
        let player = self
            .tokens
            .get_user()
            .ok()
            .filter(|u| !u.puid.is_empty() && self.tokens.get_user_sts_token().is_ok());
        [
            1,
            store.is_some() as u32,
            player.is_some() as u32,
            matches!((&store,&player),(Some(a),Some(b)) if a.puid==b.puid) as u32,
        ]
    }
}
