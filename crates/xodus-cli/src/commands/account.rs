//! Who is signed in.
//!
//! Two sources, because neither has all of it. The gamertag is already a claim
//! on any XSTS token, so it costs nothing; the gamerpic is not, and comes from
//! the profile service.
//!
//! That service is the reason this is a command rather than something a caller
//! assembles out of `collections`: it answers **401** rather than 400 when
//! `x-xbl-contract-version` is missing, which reads as a token problem and
//! sends you chasing auth for an afternoon. The header is the whole fix.

use std::process::ExitCode;

use super::collections::{send, xsts_for};

const XBOXLIVE_RELYING_PARTY: &str = "http://xboxlive.com";
const PROFILE_SETTINGS: &str = "https://profile.xboxlive.com/users/me/profile/settings\
?settings=Gamertag,ModernGamertag,GameDisplayPicRaw,AccountTier";

/// Pull one setting out of the profile payload.
fn setting(profile: &serde_json::Value, id: &str) -> Option<String> {
    profile
        .get("profileUsers")?
        .as_array()?
        .first()?
        .get("settings")?
        .as_array()?
        .iter()
        .find(|s| s.get("id").and_then(|v| v.as_str()) == Some(id))?
        .get("value")?
        .as_str()
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

pub async fn describe(
    client: &reqwest::Client,
    tokens: &xodus::tokens::TokenManager,
) -> Result<serde_json::Value, String> {
    let xsts = match xsts_for(client, tokens, XBOXLIVE_RELYING_PARTY).await {
        Ok(xsts) => xsts,
        Err(message) => {
            return Err(message);
        }
    };
    // From the token itself, so these survive a profile service that is down.
    let mut account = serde_json::json!({
        "gamertag": xsts.gamertag().unwrap_or_default(),
        "xuid": xsts.xuid().unwrap_or_default(),
    });
    let auth = xodus::api::xbox::get_xsts_auth_header(xsts);

    let headers = ["x-xbl-contract-version:3".to_string()];
    match send(client, PROFILE_SETTINGS, None, &auth, &headers).await {
        Ok((status, text, cv)) if status.is_success() => {
            match serde_json::from_str::<serde_json::Value>(&text) {
                Ok(profile) => {
                    for (key, id) in [
                        ("gamerpic", "GameDisplayPicRaw"),
                        ("tier", "AccountTier"),
                        ("modern_gamertag", "ModernGamertag"),
                    ] {
                        if let Some(value) = setting(&profile, id) {
                            account[key] = serde_json::Value::String(value);
                        }
                    }
                }
                // The token already gave us a usable answer, so a profile that
                // cannot be parsed is a note, not a failure.
                Err(e) => eprintln!("profile response was not JSON ({e}); MS-CV {cv}"),
            }
        }
        Ok((status, _, cv)) => eprintln!("profile settings: HTTP {status} (MS-CV {cv})"),
        Err(message) => eprintln!("profile settings: {message}"),
    }

    if let Some(id) = tokens.profile_id() {
        if let Ok(root) = xodus::profiles::root() {
            if let Ok(mut profile) = xodus::profiles::load(&root, id) {
                if let Some(label) = account["gamertag"].as_str().filter(|s| !s.is_empty()) {
                    profile.label = label.into();
                    let _ = xodus::profiles::save(&root, &profile);
                }
            }
        }
    }
    Ok(account)
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &xodus::tokens::TokenManager,
    json: bool,
) -> ExitCode {
    let account = match describe(client, tokens).await {
        Ok(account) => account,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&account).unwrap_or_default()
        );
    } else {
        let gamertag = account["gamertag"].as_str().unwrap_or("");
        if gamertag.is_empty() {
            eprintln!("signed in, but the token carries no gamertag");
            return ExitCode::FAILURE;
        }
        println!("{gamertag}");
    }
    ExitCode::SUCCESS
}
