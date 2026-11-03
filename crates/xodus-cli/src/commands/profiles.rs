use std::path::Path;
use std::process::ExitCode;
use xodus::profiles::{self, Profile};
use xodus::tokens::{TokenManager, store::TokenStoreError};

pub fn manager(root: &Path, id: Option<&str>) -> Result<TokenManager, TokenStoreError> {
    match profiles::select(root, id)? {
        Some(id) => TokenManager::for_profile(&id),
        None => Ok(TokenManager::with_keychain_and_memory()),
    }
}

/// Removes a new sign-in's credentials unless the profile that owns them was
/// saved. Dropped on every early return and on a panic, so a failed Xbox
/// identity step cannot leave a refresh token under a profile ID that no
/// account list shows and so nothing can sign out.
struct Uncommitted<'a> {
    tokens: &'a TokenManager,
    committed: bool,
}

impl Drop for Uncommitted<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.tokens.remove_user();
        }
    }
}

pub fn list(root: &Path, json: bool) -> ExitCode {
    let result = (|| -> Result<serde_json::Value, TokenStoreError> {
        let mut result = Vec::new();
        for profile in profiles::list(root)? {
            let tokens = TokenManager::for_profile(&profile.id)?;
            let signed_in = match (tokens.get_user(), tokens.get_user_sts_token()) {
                (Ok(_), Ok(_)) => true,
                (Err(TokenStoreError::NotFound), _) | (_, Err(TokenStoreError::NotFound)) => false,
                (Err(e), _) | (_, Err(e)) => return Err(e),
            };
            let mut value = serde_json::to_value(profile)?;
            value["signed_in"] = signed_in.into();
            result.push(value);
        }
        Ok(
            serde_json::json!({"schema":1,"capabilities":["store-player-accounts"],
            "default_profile":profiles::default_id(root)?,"profiles":result}),
        )
    })();
    match result {
        Ok(value) => {
            if json {
                println!("{value}");
            } else {
                for profile in value["profiles"].as_array().unwrap() {
                    println!(
                        "{}  {}{}",
                        profile["id"].as_str().unwrap_or_default(),
                        profile["label"].as_str().unwrap_or_default(),
                        if profile["signed_in"] == true {
                            ""
                        } else {
                            " (signed out)"
                        }
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Account profiles: {e}");
            ExitCode::FAILURE
        }
    }
}

pub fn migrate(root: &Path) -> ExitCode {
    match profiles::migrate(root, &TokenManager::with_keychain_and_memory()) {
        Ok(profile) => {
            println!("{}", serde_json::json!({"profile":profile}));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Account migration: {e}");
            ExitCode::FAILURE
        }
    }
}

pub async fn add(client: &reqwest::Client, root: &Path) -> ExitCode {
    let id = uuid::Uuid::new_v4().simple().to_string();
    let tokens = match TokenManager::for_profile(&id) {
        Ok(tokens) => tokens,
        Err(e) => {
            eprintln!("New account: {e}");
            return ExitCode::FAILURE;
        }
    };
    xodus::tokens::device::ensure_device_credentials(client, &tokens).await;
    let mut pending = Uncommitted {
        tokens: &tokens,
        committed: false,
    };
    if super::login::run(client, &tokens).await != ExitCode::SUCCESS {
        return ExitCode::FAILURE;
    }
    // Publish the profile only after both sign-in and Xbox identity succeeded.
    // A cancelled/failed login never replaces either selected account.
    let account = match super::account::describe(client, &tokens).await {
        Ok(value) if value["gamertag"].as_str().is_some_and(|s| !s.is_empty()) => value,
        Ok(_) => {
            eprintln!("New account did not supply an Xbox identity");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("New account did not supply an Xbox identity: {e}");
            return ExitCode::FAILURE;
        }
    };
    let label = account["gamertag"].as_str().unwrap_or_default().to_owned();
    let user = match tokens.get_user() {
        Ok(user) => user,
        Err(e) => {
            eprintln!("New account identity: {e}");
            return ExitCode::FAILURE;
        }
    };
    match commit(root, &tokens, &id, &user.puid, &label) {
        Ok(profile) => {
            // The new sign-in is either kept under its own profile or was
            // copied into the one that already had this account.
            pending.committed = profile.id == id;
            println!("{}", serde_json::json!({"profile":profile}));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

/// Save the profile for a verified sign-in held under `id`, or refresh the
/// profile that already has this account, and make it the default when there
/// is none. The caller removes the sign-in under `id` unless the returned
/// profile is `id` itself.
fn commit(
    root: &Path,
    tokens: &TokenManager,
    id: &str,
    puid: &str,
    label: &str,
) -> Result<Profile, String> {
    let save_namespace = profiles::save_namespace(puid);
    // Unreadable is not empty: treating it as empty would give an account
    // that already has a profile a second one, with saves split between them.
    let known = profiles::list(root).map_err(|e| format!("Cannot read account profiles: {e}"))?;
    let profile = match known
        .into_iter()
        .find(|p| p.save_namespace == save_namespace)
    {
        Some(mut existing) => {
            tokens
                .migrate_user_to(&existing.id)
                .map_err(|e| format!("Cannot refresh account profile: {e}"))?;
            existing.label = label.into();
            existing
        }
        None => Profile {
            id: id.into(),
            label: label.into(),
            legacy_saves: false,
            save_namespace,
        },
    };
    profiles::save(root, &profile).map_err(|e| format!("Cannot save account profile: {e}"))?;
    // Without a default, a launch that is not told which account to use would
    // fall back to the empty legacy keychain and fail as signed out. The
    // profile is saved by now, so failing here would only lose the sign-in;
    // selection adopts a lone profile on its own later.
    if let Err(e) = profiles::adopt_default(root, &profile.id) {
        eprintln!("Cannot make the account the default: {e}");
    }
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xodus::models::secrets::{Token, User};

    fn signed_in(tokens: &TokenManager, puid: &str) {
        tokens
            .save_user(&User {
                puid: puid.into(),
                username: "offline fixture".into(),
            })
            .unwrap();
        tokens
            .save_user_token(
                xodus::tokens::PASSPORT_STS.into(),
                Token::Compact("offline fixture".into()),
            )
            .unwrap();
    }

    #[test]
    fn a_failed_sign_in_leaves_no_credentials_behind() {
        let tokens = TokenManager::with_memory()
            .scoped("0123456789abcdef0123456789abcdef")
            .unwrap();
        signed_in(&tokens, "orphan-fixture");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _pending = Uncommitted {
                tokens: &tokens,
                committed: false,
            };
            panic!("simulated Xbox identity failure");
        }));
        assert!(result.is_err());
        assert!(tokens.get_user().is_err());
        assert!(tokens.get_user_sts_token().is_err());

        signed_in(&tokens, "kept-fixture");
        drop(Uncommitted {
            tokens: &tokens,
            committed: true,
        });
        assert_eq!(tokens.get_user().unwrap().puid, "kept-fixture");
    }

    #[test]
    fn the_first_account_added_is_the_default_and_a_repeat_sign_in_reuses_it() {
        let root = std::env::temp_dir().join(format!("xodus-add-{}", uuid::Uuid::new_v4()));
        let backend = TokenManager::with_memory();
        let first = "0123456789abcdef0123456789abcdef";
        let tokens = backend.scoped(first).unwrap();
        signed_in(&tokens, "player-fixture");
        let profile = commit(&root, &tokens, first, "player-fixture", "Fixture").unwrap();
        assert_eq!(profile.id, first);
        assert_eq!(profiles::default_id(&root).unwrap().as_deref(), Some(first));
        assert_eq!(manager_id(&root), Some(first.to_owned()));

        // Signing in to the same account again refreshes the profile it has.
        let again = "fedcba9876543210fedcba9876543210";
        let retry = backend.scoped(again).unwrap();
        signed_in(&retry, "player-fixture");
        let profile = commit(&root, &retry, again, "player-fixture", "Renamed").unwrap();
        assert_eq!(profile.id, first);
        assert_eq!(profile.label, "Renamed");
        assert_eq!(profiles::list(&root).unwrap().len(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn manager_id(root: &Path) -> Option<String> {
        profiles::select(root, None).unwrap()
    }
}
