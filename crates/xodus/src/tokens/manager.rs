use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::models::secrets::{Device, Token, TokenStore, User};
use crate::models::xbox::XstsResponse;
use crate::tokens::backend::{KeychainBackend, MemoryBackend};
use crate::tokens::store::{ExpiringTokenBackend, TokenBackend, TokenStoreError};

mod keys {
    pub const DEV_LICENSE: &str = "dev_license";
    pub const DEVICE_TOKENS: &str = "device-tokens";
    pub const USER_TOKENS: &str = "user-tokens";
    pub const USER_INFO: &str = "user-DA";
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    use crate::tokens::store::TokenBackend;
    const OWNER: &str = "11111111111111111111111111111111";
    const PLAYER: &str = "22222222222222222222222222222222";

    fn user(puid: &str) -> User {
        User {
            puid: puid.into(),
            username: "offline fixture".into(),
        }
    }

    #[test]
    fn profiles_isolate_user_tokens_and_logout_without_replacing_the_device() {
        let legacy = TokenManager::with_memory();
        let owner = legacy.scoped(OWNER).unwrap();
        let player = legacy.scoped(PLAYER).unwrap();
        legacy.save_user(&user("legacy-fixture")).unwrap();
        owner.save_user(&user("owner-fixture")).unwrap();
        player.save_user(&user("player-fixture")).unwrap();
        owner
            .save_user_token(PASSPORT_STS.into(), Token::Compact("owner-fixture".into()))
            .unwrap();
        player
            .save_user_token(PASSPORT_STS.into(), Token::Compact("player-fixture".into()))
            .unwrap();
        owner
            .save_device_token(
                PASSPORT_STS.into(),
                Token::Compact("shared-device-fixture".into()),
            )
            .unwrap();
        assert_eq!(legacy.get_user().unwrap().puid, "legacy-fixture");
        assert_eq!(owner.get_user().unwrap().puid, "owner-fixture");
        assert_eq!(player.get_user().unwrap().puid, "player-fixture");
        assert!(
            matches!(owner.get_user_sts_token().unwrap(),Token::Compact(s) if s=="owner-fixture")
        );
        assert!(
            matches!(player.get_user_sts_token().unwrap(),Token::Compact(s) if s=="player-fixture")
        );
        assert!(
            matches!(player.get_device_sts_token().unwrap(),Token::Compact(s) if s=="shared-device-fixture")
        );
        owner.remove_persistent().unwrap();
        assert!(owner.get_user().is_err());
        assert_eq!(player.get_user().unwrap().puid, "player-fixture");
        assert!(legacy.get_device_sts_token().is_ok());
        assert!(player.scoped("../owner").is_err());
    }

    #[test]
    fn signing_out_a_migrated_account_removes_its_legacy_original_only() {
        let legacy = TokenManager::with_memory();
        legacy.save_user(&user("migrated-fixture")).unwrap();
        legacy
            .save_user_token(
                PASSPORT_STS.into(),
                Token::Compact("migrated-fixture".into()),
            )
            .unwrap();
        legacy
            .save_device_token(PASSPORT_STS.into(), Token::Compact("device-fixture".into()))
            .unwrap();
        legacy.migrate_user_to(OWNER).unwrap();
        let other = legacy.scoped(PLAYER).unwrap();
        other.save_user(&user("other-fixture")).unwrap();
        other
            .save_user_token(PASSPORT_STS.into(), Token::Compact("other-fixture".into()))
            .unwrap();

        // A different account's logout leaves the legacy sign-in alone.
        other.remove_persistent().unwrap();
        assert_eq!(legacy.get_user().unwrap().puid, "migrated-fixture");

        legacy.scoped(OWNER).unwrap().remove_persistent().unwrap();
        assert!(legacy.scoped(OWNER).unwrap().get_user().is_err());
        assert!(matches!(legacy.get_user(), Err(TokenStoreError::NotFound)));
        assert!(matches!(
            legacy.get_user_sts_token(),
            Err(TokenStoreError::NotFound)
        ));
        // The device registration is shared and survives every user logout.
        assert!(legacy.get_device_sts_token().is_ok());
        // Signing out an account that is already signed out is not an error.
        legacy.scoped(OWNER).unwrap().remove_persistent().unwrap();
    }

    #[test]
    fn a_live_service_cannot_follow_replacement_credentials_in_its_profile() {
        let backend = TokenManager::with_memory();
        let profile = backend.scoped(OWNER).unwrap();
        profile.save_user(&user("original-fixture")).unwrap();
        profile
            .save_user_token(
                PASSPORT_STS.into(),
                Token::Compact("original-fixture".into()),
            )
            .unwrap();
        let pinned = profile.clone().pin_user().unwrap();
        profile.save_user(&user("replacement-fixture")).unwrap();
        profile
            .save_user_token(
                PASSPORT_STS.into(),
                Token::Compact("replacement-fixture".into()),
            )
            .unwrap();
        assert!(pinned.get_user().is_err());
        assert!(pinned.get_user_sts_token().is_err());
    }

    struct InterruptCopy {
        inner: MemoryBackend,
        interrupt: std::sync::atomic::AtomicBool,
    }
    impl TokenBackend for InterruptCopy {
        fn get(&self, k: &str) -> Result<Option<Vec<u8>>, TokenStoreError> {
            self.inner.get(k)
        }
        fn set(&self, k: &str, v: &[u8]) -> Result<(), TokenStoreError> {
            if k.ends_with("/user-DA")
                && self
                    .interrupt
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(std::io::Error::other("simulated interrupted migration").into());
            }
            self.inner.set(k, v)
        }
        fn remove(&self, k: &str) -> Result<(), TokenStoreError> {
            self.inner.remove(k)
        }
    }

    #[test]
    fn interrupted_migration_keeps_legacy_credentials_and_retries_without_crossing_profiles() {
        let backend = Arc::new(InterruptCopy {
            inner: MemoryBackend::default(),
            interrupt: std::sync::atomic::AtomicBool::new(true),
        });
        let legacy = TokenManager::new(backend, Arc::new(MemoryBackend::default()));
        legacy.save_user(&user("original-fixture")).unwrap();
        legacy
            .save_user_token(
                PASSPORT_STS.into(),
                Token::Compact("original-fixture".into()),
            )
            .unwrap();
        assert!(legacy.migrate_user_to(OWNER).is_err());
        assert_eq!(legacy.get_user().unwrap().puid, "original-fixture");
        assert!(legacy.scoped(OWNER).unwrap().get_user().is_err());
        legacy.migrate_user_to(OWNER).unwrap();
        assert_eq!(
            legacy.scoped(OWNER).unwrap().get_user().unwrap().puid,
            "original-fixture"
        );
        assert!(legacy.scoped(PLAYER).unwrap().get_user().is_err());
        assert!(legacy.get_user_sts_token().is_ok());
    }
}

pub const PASSPORT_STS: &str = "http://Passport.NET/STS";

/// Semantic facade over the two storage tiers: a persistent, keychain-backed tier
/// for STS/device/user credentials, and an ephemeral tier for short-lived
/// per-relying-party XSTS tokens. Centralizes the read-merge-write pattern that was
/// previously duplicated across `xodus-cli` and `xodus-service`.
#[derive(Clone)]
pub struct TokenManager {
    persistent: Arc<dyn TokenBackend>,
    ephemeral: Arc<dyn ExpiringTokenBackend>,
    profile: Option<String>,
    expected_user: Option<String>,
}

impl TokenManager {
    pub fn new(
        persistent: Arc<dyn TokenBackend>,
        ephemeral: Arc<dyn ExpiringTokenBackend>,
    ) -> Self {
        Self {
            persistent,
            ephemeral,
            profile: None,
            expected_user: None,
        }
    }

    /// Keychain for persistent storage, in-memory for ephemeral - the default
    /// wiring for both `xodus-cli` and `xodus-service` today.
    pub fn with_keychain_and_memory() -> Self {
        Self::new(
            Arc::new(KeychainBackend),
            Arc::new(MemoryBackend::default()),
        )
    }

    /// Device registration is shared; only user credentials are namespaced.
    /// Every manager has its own ephemeral token cache, even for the same RP.
    pub fn for_profile(profile: &str) -> Result<Self, TokenStoreError> {
        Self::with_keychain_and_memory().scoped(profile)
    }

    pub fn profile_id(&self) -> Option<&str> {
        self.profile.as_deref()
    }

    pub fn scoped(&self, profile: &str) -> Result<Self, TokenStoreError> {
        if !crate::profiles::valid_id(profile) {
            return Err(std::io::Error::other("invalid account profile ID").into());
        }
        Ok(Self {
            persistent: self.persistent.clone(),
            ephemeral: Arc::new(MemoryBackend::default()),
            profile: Some(profile.into()),
            expected_user: None,
        })
    }

    fn user_key(&self, key: &str) -> String {
        match &self.profile {
            Some(id) => format!("profile/{id}/{key}"),
            None => key.into(),
        }
    }

    /// A running service may refresh credentials, but never change identity.
    pub fn pin_user(mut self) -> Result<Self, TokenStoreError> {
        let user = self.get_user()?;
        self.get_user_sts_token()?;
        if user.puid.is_empty() {
            return Err(std::io::Error::other("account has no verified MSA identity").into());
        }
        self.expected_user = Some(user.puid);
        Ok(self)
    }

    pub fn migrate_user_to(&self, profile: &str) -> Result<(), TokenStoreError> {
        let target = self.scoped(profile)?;
        for key in [keys::USER_TOKENS, keys::USER_INFO] {
            let value = self
                .persistent
                .get(&self.user_key(key))?
                .ok_or(TokenStoreError::NotFound)?;
            let dest = target.user_key(key);
            self.persistent.set(&dest, &value)?;
            if self.persistent.get(&dest)?.as_deref() != Some(value.as_slice()) {
                return Err(std::io::Error::other("account migration verification failed").into());
            }
        }
        Ok(())
    }

    pub fn remove_user(&self) -> Result<(), TokenStoreError> {
        for key in [keys::USER_TOKENS, keys::USER_INFO] {
            let key = self.user_key(key);
            if self.persistent.get(&key)?.is_some() {
                self.persistent.remove(&key)?;
            }
        }
        Ok(())
    }

    /// Keychain for persistent storage, in-memory for ephemeral - the default
    /// wiring for both `xodus-cli` and `xodus-service` today.
    pub fn with_memory() -> Self {
        Self::new(
            Arc::new(MemoryBackend::default()),
            Arc::new(MemoryBackend::default()),
        )
    }

    pub fn remove_persistent(&self) -> Result<(), TokenStoreError> {
        if self.profile.is_some() {
            // Migration copied the pre-profile sign-in and left the original
            // for older launchers. Signing that account out has to remove the
            // original too, or the refresh credential stays in the keyring and
            // a later migration would bring the signed-out account back. Only
            // the same Microsoft account's entries go; a different legacy
            // sign-in is not this logout's business.
            let puid = self.get_user().ok().map(|user| user.puid);
            self.remove_user()?;
            if let Some(puid) = puid.filter(|p| !p.is_empty()) {
                let legacy = Self {
                    persistent: self.persistent.clone(),
                    ephemeral: Arc::new(MemoryBackend::default()),
                    profile: None,
                    expected_user: None,
                };
                if legacy.get_user().is_ok_and(|user| user.puid == puid) {
                    legacy.remove_user()?;
                }
            }
            return Ok(());
        }
        self.persistent.remove(keys::DEVICE_TOKENS)?;
        self.persistent.remove(keys::USER_TOKENS)?;
        self.persistent.remove(keys::USER_INFO)
    }

    // ---- Device identity / license -----------------------------------------

    pub fn get_device_license(&self) -> Result<Device, TokenStoreError> {
        let bytes = self
            .persistent
            .get(keys::DEV_LICENSE)?
            .ok_or(TokenStoreError::NotFound)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save_device_license(&self, device: &Device) -> Result<(), TokenStoreError> {
        self.persistent
            .set(keys::DEV_LICENSE, &serde_json::to_vec(device)?)
    }

    pub fn remove_device_license(&self) -> Result<(), TokenStoreError> {
        self.persistent.remove(keys::DEV_LICENSE)
    }

    // ---- Device STS tokens (keyed by SOAP "applies_to" address) -----------

    pub fn get_device_token_for(&self, address: &str) -> Result<Option<Token>, TokenStoreError> {
        Self::read_token_store(&*self.persistent, keys::DEVICE_TOKENS, address)
    }

    pub fn save_device_token(&self, address: String, token: Token) -> Result<(), TokenStoreError> {
        Self::write_token_store(&*self.persistent, keys::DEVICE_TOKENS, address, token)
    }

    pub fn get_device_sts_token(&self) -> Result<Token, TokenStoreError> {
        self.get_device_token_for(PASSPORT_STS)?
            .ok_or(TokenStoreError::NotFound)
    }

    // ---- User STS tokens (keyed by SOAP "applies_to" address) --------------

    pub fn get_user_token_for(&self, address: &str) -> Result<Option<Token>, TokenStoreError> {
        if self.expected_user.is_some() {
            self.get_user()?;
        }
        Self::read_token_store(
            &*self.persistent,
            &self.user_key(keys::USER_TOKENS),
            address,
        )
    }

    pub fn save_user_token(&self, address: String, token: Token) -> Result<(), TokenStoreError> {
        if self.expected_user.is_some() {
            self.get_user()?;
        }
        Self::write_token_store(
            &*self.persistent,
            &self.user_key(keys::USER_TOKENS),
            address,
            token,
        )
    }

    pub fn get_user_sts_token(&self) -> Result<Token, TokenStoreError> {
        self.get_user_token_for(PASSPORT_STS)?
            .ok_or(TokenStoreError::NotFound)
    }

    // ---- User info -----------------------------------------------------------

    pub fn get_user(&self) -> Result<User, TokenStoreError> {
        let bytes = self
            .persistent
            .get(&self.user_key(keys::USER_INFO))?
            .ok_or(TokenStoreError::NotFound)?;
        let user: User = serde_json::from_slice(&bytes)?;
        if self
            .expected_user
            .as_ref()
            .is_some_and(|expected| *expected != user.puid)
        {
            return Err(std::io::Error::other(
                "account changed while a game was running; launch again",
            )
            .into());
        }
        Ok(user)
    }

    pub fn save_user(&self, user: &User) -> Result<(), TokenStoreError> {
        self.persistent
            .set(&self.user_key(keys::USER_INFO), &serde_json::to_vec(user)?)
    }

    // ---- Ephemeral XSTS-by-relying-party cache --------------------------------

    pub fn get_cached_xsts(&self, relying_party: &str) -> Option<XstsResponse> {
        if self.expected_user.is_some() && self.get_user().is_err() {
            return None;
        }
        let bytes = self.ephemeral.get(relying_party).ok()??;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn cache_xsts(&self, relying_party: &str, token: &XstsResponse) {
        self.cache_xsts_response(relying_party, token);
    }

    fn cache_xsts_response(&self, key: &str, token: &XstsResponse) {
        let Ok(bytes) = serde_json::to_vec(token) else {
            return;
        };
        let remaining = (token.not_after - chrono::Utc::now())
            .to_std()
            .unwrap_or(std::time::Duration::ZERO);
        let _ = self
            .ephemeral
            .set_with_expiry(key, &bytes, Instant::now() + remaining);
    }

    // ---- shared TokenStore read/modify/write helper ---------------------------

    fn read_token_store(
        backend: &dyn TokenBackend,
        key: &str,
        address: &str,
    ) -> Result<Option<Token>, TokenStoreError> {
        let Some(bytes) = backend.get(key)? else {
            return Ok(None);
        };
        let store: TokenStore = serde_json::from_slice(&bytes)?;
        Ok(store.tokens.get(address).cloned())
    }

    fn write_token_store(
        backend: &dyn TokenBackend,
        key: &str,
        address: String,
        token: Token,
    ) -> Result<(), TokenStoreError> {
        let mut tokens: HashMap<String, Token> = match backend.get(key)? {
            Some(bytes) if !bytes.is_empty() => {
                serde_json::from_slice::<TokenStore>(&bytes)?.tokens
            }
            _ => HashMap::new(),
        };
        tokens.insert(address, token);
        backend.set(key, &serde_json::to_vec(&TokenStore { tokens })?)
    }
}
