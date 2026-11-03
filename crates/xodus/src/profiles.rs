//! Local account identifiers and metadata. Credentials stay in the keychain.
use crate::tokens::{TokenManager, store::TokenStoreError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const MIGRATED_PROFILE: &str = "00000000000000000000000000000001";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub id: String,
    pub label: String,
    /// Only this imported player may reuse the pre-profile Wine prefix.
    #[serde(default)]
    pub legacy_saves: bool,
    /// Stable across repeat sign-ins to the same verified MSA; never a raw ID.
    pub save_namespace: String,
}

pub fn save_namespace(puid: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(format!("ferestre-player-saves-v1:{puid}"))
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub fn root() -> Result<PathBuf, TokenStoreError> {
    if let Some(path) = std::env::var_os("XODUS_PROFILE_DIR").filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    let state = std::env::var_os("XDG_STATE_HOME")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local/state")))
        .ok_or_else(|| std::io::Error::other("HOME or XDG_STATE_HOME is required"))?;
    Ok(state.join("xodus/accounts"))
}

fn path(root: &Path, id: &str) -> Result<PathBuf, TokenStoreError> {
    if !valid_id(id) {
        return Err(std::io::Error::other("invalid account profile ID").into());
    }
    Ok(root.join(format!("{id}.json")))
}

pub fn load(root: &Path, id: &str) -> Result<Profile, TokenStoreError> {
    let profile: Profile = serde_json::from_slice(&std::fs::read(path(root, id)?)?)?;
    if profile.id != id {
        return Err(std::io::Error::other("account profile identity mismatch").into());
    }
    Ok(profile)
}

pub fn list(root: &Path) -> Result<Vec<Profile>, TokenStoreError> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut profiles = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        // `<id>.json~` or `<id>.bak` has the same stem: listed, it would be
        // the same profile twice.
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Some(id) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .filter(|s| valid_id(s))
        {
            profiles.push(load(root, id)?);
        }
    }
    profiles.sort_by(|a, b| a.label.cmp(&b.label).then_with(|| a.id.cmp(&b.id)));
    Ok(profiles)
}

pub fn default_id(root: &Path) -> Result<Option<String>, TokenStoreError> {
    let id = match std::fs::read_to_string(root.join("default")) {
        Ok(id) => id.trim().to_owned(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    load(root, &id)?;
    Ok(Some(id))
}

pub fn save(root: &Path, profile: &Profile) -> Result<(), TokenStoreError> {
    atomic(
        root,
        &path(root, &profile.id)?,
        &serde_json::to_vec(profile)?,
    )
}

fn atomic(root: &Path, dest: &Path, bytes: &[u8]) -> Result<(), TokenStoreError> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)?;
    let temporary = root.join(format!(".write-{}", uuid::Uuid::new_v4().simple()));
    let result = (|| -> Result<(), TokenStoreError> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, dest)?;
        Ok(())
    })();
    let _ = std::fs::remove_file(temporary);
    result
}

/// Copy both legacy entries before publishing the default. An interrupted copy
/// is retryable, and the original entries remain available to older launchers.
pub fn migrate(root: &Path, legacy: &TokenManager) -> Result<Option<Profile>, TokenStoreError> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(root)?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(root.join(".migration-lock"))?;
    lock.lock()?;
    if let Some(id) = default_id(root)? {
        return Ok(Some(load(root, &id)?));
    }
    let user = match legacy.get_user() {
        Ok(user) => user,
        Err(TokenStoreError::NotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    match legacy.get_user_sts_token() {
        Ok(_) => {}
        Err(TokenStoreError::NotFound) => return Ok(None),
        Err(error) => return Err(error),
    }
    // If the credentials/profile were already copied before a crash, commit
    // that original binding rather than overwrite it from a changed legacy login.
    if let Ok(existing) = load(root, MIGRATED_PROFILE) {
        let migrated = legacy.scoped(MIGRATED_PROFILE)?;
        if let Ok(original) = migrated.get_user() {
            if existing.save_namespace == save_namespace(&original.puid)
                && migrated.get_user_sts_token().is_ok()
            {
                atomic(root, &root.join("default"), existing.id.as_bytes())?;
                return Ok(Some(existing));
            }
        }
        if existing.save_namespace != save_namespace(&user.puid) {
            return Err(std::io::Error::other(
                "legacy sign-in changed during migration; existing profile kept",
            )
            .into());
        }
    }
    legacy.migrate_user_to(MIGRATED_PROFILE)?;
    let profile = Profile {
        id: MIGRATED_PROFILE.into(),
        label: "Existing account".into(),
        legacy_saves: true,
        save_namespace: save_namespace(&legacy.get_user()?.puid),
    };
    save(root, &profile)?;
    atomic(root, &root.join("default"), profile.id.as_bytes())?;
    Ok(Some(profile))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_rejects_paths_and_retains_the_default_binding() {
        let root = std::env::temp_dir().join(format!("xodus-profiles-{}", uuid::Uuid::new_v4()));
        let profile = Profile {
            id: MIGRATED_PROFILE.into(),
            label: "Fixture player".into(),
            legacy_saves: true,
            save_namespace: save_namespace("registry-fixture"),
        };
        assert!(load(&root, "../elsewhere").is_err());
        assert_eq!(list(&root).unwrap(), Vec::new());
        save(&root, &profile).unwrap();
        atomic(&root, &root.join("default"), profile.id.as_bytes()).unwrap();
        // An editor backup of a profile is not a second profile.
        std::fs::copy(
            root.join(format!("{MIGRATED_PROFILE}.json")),
            root.join(format!("{MIGRATED_PROFILE}.json~")),
        )
        .unwrap();
        assert_eq!(list(&root).unwrap(), vec![profile]);
        assert_eq!(
            default_id(&root).unwrap().as_deref(),
            Some(MIGRATED_PROFILE)
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
