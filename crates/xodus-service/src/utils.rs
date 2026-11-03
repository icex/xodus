#[cfg(target_os = "linux")]
pub fn get_runtime_dir() -> String {
    std::env::var("XODUS_RUNTIME_DIR")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| std::env::var("XDG_RUNTIME_DIR").expect("Runtime dir not set"))
}

#[cfg(target_os = "macos")]
pub fn get_runtime_dir() -> String {
    return "/tmp/".to_string();
}
