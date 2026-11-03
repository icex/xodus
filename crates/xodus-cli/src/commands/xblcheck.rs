//! Check that a title's Xbox Live calls will actually be authorised.
//!
//! A title never reports *why* an Xbox call failed. It sees a 403 and says
//! "failed to create party", or shows a sign-in error, or quietly does nothing.
//! The one distinction that matters is invisible from there: whether the token
//! it was handed carries a claim naming *this* title.
//!
//! So run the calls here instead, where the failure can be attributed. Each
//! probe is a real request to a real service, chosen so that the ones needing a
//! title claim and the ones not needing one are both represented -- if only the
//! claimed probes fail, the claim is the problem and nothing else is; if the
//! unclaimed ones fail too, the account or the sign-in is.
//!
//! Nothing here is destructive: every probe reads.

use std::path::Path;
use std::process::ExitCode;
use xodus::tokens::TokenManager;

/// One request, and what its failure would mean.
struct Probe {
    name: &'static str,
    url: &'static str,
    body: Option<&'static str>,
    headers: &'static [&'static str],
}

/// Reads that do not depend on which title is asking.
const UNCLAIMED: &[Probe] = &[
    Probe {
        name: "profile",
        url: "https://profile.xboxlive.com/users/me/profile/settings?settings=Gamertag",
        body: None,
        headers: &["x-xbl-contract-version:3"],
    },
    Probe {
        name: "social",
        url: "https://social.xboxlive.com/users/xuid({XUID})/people?view=FriendList",
        body: None,
        headers: &["x-xbl-contract-version:1"],
    },
];

/// Reads that are scoped by title. These are the ones a wrong claim breaks.
const CLAIMED: &[Probe] = &[Probe {
    name: "multiplayer (session directory)",
    url: "https://sessiondirectory.xboxlive.com/handles/query?include=relatedInfo,customProperties",
    body: Some(
        r#"{"type":"activity","scid":"{SCID}","owners":{"people":{"moniker":"people","monikerXuid":"{XUID}"}}}"#,
    ),
    headers: &["x-xbl-contract-version:107"],
}];

/// The title identity Xbox mints a claim from, out of a MicrosoftGame.config.
#[derive(Debug)]
pub struct TitleIdentity {
    pub title_id: i64,
    pub client_id: String,
}

impl TitleIdentity {
    /// The service config id a title's sessions live under. Titles are free to
    /// use another, but the convention -- and what the probe needs in order to
    /// address *something* of this title's -- is the title id in the last
    /// eight hexadecimal digits.
    fn scid(&self) -> String {
        format!("00000000-0000-0000-0000-0000{:08x}", self.title_id)
    }
}

/// Where a game directory keeps its MicrosoftGame.config.
///
/// The GDK documents the file as MicrosoftGame.config, but a package is free to
/// ship any spelling of it and Forza Horizon 5 ships MicrosoftGame.Config. On
/// the case-sensitive filesystem a Linux install lives on that is a different
/// file, so look for the documented name and then for whatever the directory
/// actually holds.
pub fn game_config_path(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("MicrosoftGame.config");
    if path.is_file() {
        return path;
    }
    std::fs::read_dir(dir)
        .ok()
        .and_then(|entries| {
            entries.filter_map(Result::ok).find(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.eq_ignore_ascii_case("MicrosoftGame.config"))
            })
        })
        .map_or(path, |e| e.path())
}

/// Read `TitleId` and optional `MSAAppId` from MicrosoftGame.config.
///
/// The config spells TitleId in hexadecimal and every Xbox endpoint wants it
/// decimal, which is a conversion worth doing in exactly one place. Legacy
/// packages omit MSAAppId and use Windows title authentication instead of SISU.
pub fn identity_from_game_dir(dir: &Path) -> Result<TitleIdentity, String> {
    let path = game_config_path(dir);
    let xml =
        std::fs::read_to_string(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let element = |name: &str| -> Option<String> {
        let open = format!("<{name}>");
        let start = xml.find(&open)? + open.len();
        let len = xml[start..].find('<')?;
        Some(xml[start..start + len].trim().to_string())
    };
    let hex = element("TitleId").ok_or_else(|| format!("{} has no <TitleId>", path.display()))?;
    let title_id = u32::from_str_radix(hex.trim_start_matches("0x"), 16)
        .ok()
        .filter(|id| *id != 0)
        .map(i64::from)
        .ok_or_else(|| {
            format!("<TitleId>{hex}</TitleId> must be a nonzero 32-bit hexadecimal integer")
        })?;
    let client_id = element("MSAAppId").unwrap_or_default();
    Ok(TitleIdentity {
        title_id,
        client_id,
    })
}

async fn title_claim_xsts(
    client: &reqwest::Client,
    tokens: &TokenManager,
    identity: &TitleIdentity,
) -> Result<xodus::models::xbox::XstsResponse, String> {
    let claim = if identity.client_id.is_empty() {
        xodus::auth::win32_identity_for(client, tokens, identity.title_id).await?
    } else {
        xodus::auth::sisu_identity_for(client, tokens, &identity.client_id, identity.title_id)
            .await?
    };
    let signer = xodus::api::xbox::RequestSigner::from_pkcs8(&claim.key_pkcs8)
        .ok_or("invalid title signing key")?;
    xodus::api::xbox::request_xsts_token(
        client,
        claim.user_token,
        Some(claim.device_token),
        Some(claim.title_token),
        "http://xboxlive.com",
        Some(&signer),
    )
    .await
    .map_err(|e| format!("xsts/authorize refused the title claim: {e}"))
}

async fn run_probe(
    client: &reqwest::Client,
    probe: &Probe,
    auth: &str,
    xuid: &str,
    scid: &str,
) -> (reqwest::StatusCode, String) {
    let fill = |s: &str| s.replace("{XUID}", xuid).replace("{SCID}", scid);
    let headers: Vec<String> = probe.headers.iter().map(|h| h.to_string()).collect();
    match super::collections::send(
        client,
        &fill(probe.url),
        probe.body.map(fill),
        auth,
        &headers,
    )
    .await
    {
        Ok((status, text, _)) => (status, text),
        Err(message) => (reqwest::StatusCode::SERVICE_UNAVAILABLE, message),
    }
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    identity: TitleIdentity,
) -> ExitCode {
    if identity.client_id.is_empty() {
        println!(
            ":: title {} (Windows title authentication)",
            identity.title_id
        );
    } else {
        println!(
            ":: title {} (SISU client id {})",
            identity.title_id, identity.client_id
        );
    }

    let plain = match super::collections::xsts_for(client, tokens, "http://xboxlive.com").await {
        Ok(xsts) => xsts,
        Err(message) => {
            eprintln!("!! no Xbox token at all: {message}");
            eprintln!("   Sign in first: xodus-cli login");
            return ExitCode::FAILURE;
        }
    };
    let xuid = plain.xuid().unwrap_or_default().to_string();
    let plain_auth = match super::collections::auth_header(plain) {
        Ok(auth) => auth,
        Err(message) => {
            eprintln!("!! {message}");
            return ExitCode::FAILURE;
        }
    };

    let mut failed = 0;
    for probe in UNCLAIMED {
        let (status, body) = run_probe(client, probe, &plain_auth, &xuid, "").await;
        if status.is_success() {
            println!("   ok    {}", probe.name);
        } else {
            failed += 1;
            println!(
                "   FAIL  {} -- HTTP {status} {}",
                probe.name,
                first_line(&body)
            );
        }
    }
    if failed > 0 {
        eprintln!(
            "!! calls that do not depend on the title are failing, so this is not a title-claim \
             problem. Check the sign-in (xodus-cli account) before looking further."
        );
        return ExitCode::FAILURE;
    }

    // The claim itself. A failure here is the interesting one, and it is the
    // failure a title reports as "failed to create party".
    let claimed = title_claim_xsts(client, tokens, &identity).await;
    let claimed_auth = match claimed.and_then(super::collections::auth_header) {
        Ok(auth) => auth,
        Err(message) => {
            eprintln!(
                "!! could not mint a token claiming title {}: {message}",
                identity.title_id
            );
            eprintln!(
                "   Everything scoped by title -- multiplayer, parties, presence -- will answer \
                 403 until this works."
            );
            return ExitCode::FAILURE;
        }
    };
    println!("   ok    title claim minted");

    let scid = identity.scid();
    for probe in CLAIMED {
        let (status, body) = run_probe(client, probe, &claimed_auth, &xuid, &scid).await;
        if status.is_success() {
            println!("   ok    {}", probe.name);
            continue;
        }
        failed += 1;
        println!(
            "   FAIL  {} -- HTTP {status} {}",
            probe.name,
            first_line(&body)
        );

        // Say which of the two it is: a claim Xbox will not accept for this
        // service, or a service that is unhappy for some other reason. The
        // same request with no claim distinguishes them.
        let (plain_status, _) = run_probe(client, probe, &plain_auth, &xuid, &scid).await;
        if plain_status.is_success() {
            println!(
                "         the same call succeeds with no title claim, so the claim is being \
                 refused -- check TitleId and MSAAppId (when present) against the running title"
            );
        }
    }

    if failed == 0 {
        println!(":: all Xbox Live diagnostic probes passed for this title");
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn first_line(body: &str) -> String {
    let line = body.lines().next().unwrap_or_default().trim();
    // At most 120 characters, cut on a character: a byte offset can land
    // inside a non-ASCII character of a localised error body and panic.
    match line.char_indices().nth(120) {
        Some((end, _)) => format!("{}...", &line[..end]),
        None => line.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_non_ascii_response_line_is_shortened_without_splitting_a_character() {
        // Byte 120 falls inside the 60th "é": slicing there panicked.
        let body = format!("a{}\nsecond line", "é".repeat(200));
        let line = first_line(&body);
        assert_eq!(line, format!("a{}...", "é".repeat(119)));
        assert_eq!(first_line(&"a".repeat(120)), "a".repeat(120));
        assert_eq!(first_line("  short  \nrest"), "short");
    }

    #[test]
    fn a_game_config_yields_the_pair_xbox_mints_a_claim_from() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("MicrosoftGame.config"),
            r#"<?xml version="1.0" encoding="utf-8"?>
<Game configVersion="1">
  <TitleId>69C7AA31</TitleId>
  <MSAAppId>cb41e2e1-503c-48ac-98b6-55b194b4ab66</MSAAppId>
</Game>"#,
        )
        .expect("write");
        let id = identity_from_game_dir(dir.path()).expect("parsed");
        assert_eq!(
            id.title_id, 1_774_692_913,
            "the config carries the title id in hexadecimal and Xbox wants it decimal"
        );
        assert_eq!(id.client_id, "cb41e2e1-503c-48ac-98b6-55b194b4ab66");
        assert_eq!(id.scid(), "00000000-0000-0000-0000-000069c7aa31");
    }

    #[test]
    fn the_config_is_found_whatever_the_package_spells_it() {
        // Forza Horizon 5 ships MicrosoftGame.Config, which on the
        // case-sensitive filesystem a Linux install lives on is a different
        // file from the one the GDK documents.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("MicrosoftGame.Config"),
            "<Game><TitleId>7900C3C7</TitleId><MSAAppId>an-app-id</MSAAppId></Game>",
        )
        .expect("write");
        let id = identity_from_game_dir(dir.path()).expect("parsed");
        assert_eq!(id.title_id, 0x7900_C3C7);
        assert_eq!(id.client_id, "an-app-id");
    }

    #[test]
    fn a_legacy_config_without_an_app_id_keeps_its_title_and_scid() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("MicrosoftGame.config"),
            r#"<Game configVersion="0"><TitleId>10203040</TitleId></Game>"#,
        )
        .expect("write");
        let id = identity_from_game_dir(dir.path()).expect("legacy title identity");
        assert_eq!(id.title_id, 0x1020_3040);
        assert!(id.client_id.is_empty(), "no SISU client ID is available");
        assert_eq!(id.scid(), "00000000-0000-0000-0000-000010203040");
    }

    #[test]
    fn an_empty_app_id_also_selects_the_legacy_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("MicrosoftGame.config"),
            "<Game><TitleId>FFFFFFFF</TitleId><MSAAppId> </MSAAppId></Game>",
        )
        .expect("write");
        let id = identity_from_game_dir(dir.path()).expect("empty app ID");
        assert_eq!(id.title_id, u32::MAX as i64);
        assert!(id.client_id.is_empty());
        assert_eq!(id.scid(), "00000000-0000-0000-0000-0000ffffffff");
    }

    #[test]
    fn invalid_title_ids_are_rejected_before_authentication() {
        let dir = tempfile::tempdir().expect("tempdir");
        for title_id in ["0", "-1", "100000000", "not-hex", ""] {
            std::fs::write(
                dir.path().join("MicrosoftGame.config"),
                format!(
                    "<Game><TitleId>{title_id}</TitleId><MSAAppId>synthetic-client</MSAAppId></Game>"
                ),
            )
            .expect("write");
            let err = identity_from_game_dir(dir.path()).expect_err("invalid title ID");
            assert!(err.contains("TitleId"), "{title_id}: {err}");
        }
    }
}
