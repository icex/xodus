pub static SERVICE_NAME: &str = "Xodus Service";

pub fn init_secrets() -> Result<(), keyring_core::Error> {
    #[cfg(feature = "key-chain-file")]
    {
        let path = secrets_backing_file()
            .map_err(|e| keyring_core::Error::NoStorageAccess(Box::new(e)))?;
        let store = keyring_core::sample::Store::new_with_backing(
            path.to_str().expect("Invalid secrets backing path"),
        )?;
        keyring_core::set_default_store(store);
    }

    #[cfg(not(feature = "key-chain-file"))]
    {
        #[cfg(target_os = "linux")]
        {
            keyring_core::set_default_store(dbus_secret_service_keyring_store::Store::new()?);
        }

        #[cfg(target_os = "macos")]
        {
            keyring_core::set_default_store(apple_native_keyring_store::keychain::Store::new()?);
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let store = keyring_core::sample::Store::new_with_configuration(
                &std::collections::HashMap::from([("persist", "true")]),
            )?;
            keyring_core::set_default_store(store);
        }
    }

    Ok(())
}

pub fn get_entry(user: &str) -> Result<keyring_core::Entry, keyring_core::Error> {
    keyring_core::Entry::new(SERVICE_NAME, user)
}

pub fn destroy_secrets() {
    keyring_core::unset_default_store();
}

/// The plain-file credential store: `.xodus-keyring.ron` in the home
/// directory, never anywhere shared. It holds refresh tokens in the clear, so
/// with no home directory this fails rather than fall back to the temporary
/// directory, where another user could read it or plant one first.
#[cfg(feature = "key-chain-file")]
fn secrets_backing_file() -> std::io::Result<std::path::PathBuf> {
    let home = home_dir(std::env::var_os("HOME"), std::env::var_os("USERPROFILE"))?;
    private_file(&home, ".xodus-keyring.ron")
}

#[cfg(any(test, feature = "key-chain-file"))]
fn home_dir(
    home: Option<std::ffi::OsString>,
    profile: Option<std::ffi::OsString>,
) -> std::io::Result<std::path::PathBuf> {
    home.filter(|p| !p.is_empty())
        .or_else(|| profile.filter(|p| !cfg!(unix) && !p.is_empty()))
        .map(std::path::PathBuf::from)
        .ok_or_else(|| {
            std::io::Error::other("HOME is not set; refusing to keep credentials elsewhere")
        })
}

/// Create `name` in `dir` readable by the owner only, holding an empty store,
/// or tighten an existing one to that, and refuse a directory someone else owns or can write to: the
/// store library rewrites the file in place, so the file's own mode is what
/// protects it.
#[cfg(any(test, feature = "key-chain-file"))]
fn private_file(dir: &std::path::Path, name: &str) -> std::io::Result<std::path::PathBuf> {
    let path = dir.join(name);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let refuse = |why: &str| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("{}: {why}", path.display()),
            ))
        };
        let parent = std::fs::metadata(dir)?;
        if !parent.is_dir() {
            return refuse("its directory is not a directory");
        }
        if parent.mode() & 0o022 != 0 {
            return refuse("its directory is writable by other users");
        }
        // Checked before opening: in a directory only this user can write,
        // nobody can swap a link in between.
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if !meta.file_type().is_file() => return refuse("not a regular file"),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)?;
        let meta = file.metadata()?;
        // The file is ours if we just created it; the directory must be too.
        if meta.uid() != parent.uid() {
            return refuse("owned by another user");
        }
        if meta.mode() & 0o077 != 0 {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        // The store reads any file that exists and an empty one is not valid
        // to it, so a new file starts as the empty map it would write itself.
        if meta.len() == 0 {
            use std::io::Write;
            (&file).write_all(b"{}")?;
        }
    }
    Ok(path)
}

#[cfg(all(test, unix))]
mod tests {
    use super::{home_dir, private_file};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn no_home_is_an_error_not_the_temporary_directory() {
        assert!(home_dir(None, None).is_err());
        assert!(home_dir(Some("".into()), None).is_err());
        assert!(home_dir(None, Some("/profile".into())).is_err());
        assert_eq!(
            home_dir(Some("/home/fixture".into()), None).unwrap(),
            std::path::Path::new("/home/fixture")
        );
    }

    struct Dir(std::path::PathBuf);
    impl Dir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("xodus-secrets-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            Dir(path)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn mode(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn the_credential_file_is_private_and_never_in_a_shared_directory() {
        let dir = Dir::new();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = private_file(dir.path(), ".xodus-keyring.ron").unwrap();
        assert_eq!(mode(&path), 0o600);

        // An existing, readable file is tightened, and its content kept.
        std::fs::write(&path, b"kept").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        private_file(dir.path(), ".xodus-keyring.ron").unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"kept");

        // A link planted in its place is refused, not followed.
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("linked")).unwrap();
        assert!(private_file(dir.path(), "linked").is_err());

        // So is a directory other users can write to, such as /tmp.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(private_file(dir.path(), "shared").is_err());
        assert!(!dir.path().join("shared").exists());
    }

    #[test]
    fn the_store_opens_the_credential_file_it_was_given() {
        let dir = Dir::new();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = private_file(dir.path(), ".xodus-keyring.ron").unwrap();
        let path = path.to_str().unwrap();

        // A fresh file must already be something the store can read, and so
        // must the empty one an earlier build of this code left behind.
        let store = keyring_core::sample::Store::new_with_backing(path).unwrap();
        drop(store);
        std::fs::write(path, b"").unwrap();
        private_file(dir.path(), ".xodus-keyring.ron").unwrap();
        let store = keyring_core::sample::Store::new_with_backing(path).unwrap();
        store.save().unwrap();
        drop(store);

        // Opening it again keeps what the store saved.
        let saved = std::fs::read(path).unwrap();
        private_file(dir.path(), ".xodus-keyring.ron").unwrap();
        assert_eq!(std::fs::read(path).unwrap(), saved);
        assert_eq!(mode(std::path::Path::new(path)), 0o600);
        keyring_core::sample::Store::new_with_backing(path).unwrap();
    }
}
