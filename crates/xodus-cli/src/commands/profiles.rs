use std::path::Path;
use std::process::ExitCode;
use xodus::profiles::{self, Profile};
use xodus::tokens::{TokenManager, store::TokenStoreError};

pub fn manager(root: &Path, id: Option<&str>) -> Result<TokenManager, TokenStoreError> {
    let id = match id {
        Some(id) => Some(id.to_owned()),
        None => profiles::default_id(root)?,
    };
    match id {
        Some(id) => {
            profiles::load(root, &id)?;
            TokenManager::for_profile(&id)
        }
        None => Ok(TokenManager::with_keychain_and_memory()),
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
    if super::login::run(client, &tokens).await != ExitCode::SUCCESS {
        let _ = tokens.remove_user();
        return ExitCode::FAILURE;
    }
    // Publish the profile only after both sign-in and Xbox identity succeeded.
    // A cancelled/failed login never replaces either selected account.
    let account = match super::account::describe(client, &tokens).await {
        Ok(value) if value["gamertag"].as_str().is_some_and(|s| !s.is_empty()) => value,
        _ => {
            let _ = tokens.remove_user();
            eprintln!("New account did not supply an Xbox identity");
            return ExitCode::FAILURE;
        }
    };
    let user = match tokens.get_user() {
        Ok(user) => user,
        Err(e) => {
            let _ = tokens.remove_user();
            eprintln!("New account identity: {e}");
            return ExitCode::FAILURE;
        }
    };
    let save_namespace = profiles::save_namespace(&user.puid);
    // Unreadable is not empty: treating it as empty would give an account
    // that already has a profile a second one, with saves split between them.
    let known = match profiles::list(root) {
        Ok(known) => known,
        Err(e) => {
            let _ = tokens.remove_user();
            eprintln!("Cannot read account profiles: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(mut existing) = known
        .into_iter()
        .find(|p| p.save_namespace == save_namespace)
    {
        if let Err(e) = tokens.migrate_user_to(&existing.id) {
            let _ = tokens.remove_user();
            eprintln!("Cannot refresh account profile: {e}");
            return ExitCode::FAILURE;
        }
        let _ = tokens.remove_user();
        existing.label = account["gamertag"].as_str().unwrap().into();
        if let Err(e) = profiles::save(root, &existing) {
            eprintln!("Cannot save account profile: {e}");
            return ExitCode::FAILURE;
        }
        println!("{}", serde_json::json!({"profile":existing}));
        return ExitCode::SUCCESS;
    }
    let profile = Profile {
        id,
        label: account["gamertag"].as_str().unwrap().into(),
        legacy_saves: false,
        save_namespace,
    };
    match profiles::save(root, &profile) {
        Ok(()) => {
            println!("{}", serde_json::json!({"profile":profile}));
            ExitCode::SUCCESS
        }
        Err(e) => {
            let _ = tokens.remove_user();
            eprintln!("Cannot save account profile: {e}");
            ExitCode::FAILURE
        }
    }
}
