//! The plain-file credential store, end to end. It changes HOME, so it lives
//! in its own test binary where nothing else runs beside it.
#![cfg(all(unix, feature = "key-chain-file"))]

use std::os::unix::fs::PermissionsExt;

#[test]
fn a_fresh_home_gets_a_private_store_that_keeps_what_is_saved() {
    let home = std::env::temp_dir().join(format!("xodus-home-{}", std::process::id()));
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    // Nothing else runs in this binary, so no other thread reads the
    // environment while it changes.
    unsafe { std::env::set_var("HOME", &home) };
    let file = home.join(".xodus-keyring.ron");

    let result = (|| {
        xodus::secrets::init_secrets()?;
        xodus::secrets::get_entry("fixture")?.set_password("secret")?;
        xodus::secrets::destroy_secrets();
        // A second run reads back what the first one saved.
        xodus::secrets::init_secrets()?;
        let kept = xodus::secrets::get_entry("fixture")?.get_password()?;
        xodus::secrets::destroy_secrets();
        Ok::<_, keyring_core::Error>(kept)
    })();
    let mode = std::fs::metadata(&file).map(|m| m.permissions().mode() & 0o777);
    let _ = std::fs::remove_dir_all(&home);

    assert_eq!(result.unwrap(), "secret");
    assert_eq!(mode.unwrap(), 0o600);
}
