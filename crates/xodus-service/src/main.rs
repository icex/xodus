use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use xodus::tokens::TokenManager;

mod connection;
mod entitlement;
mod simple_context;
mod utils;

const XML_MAGIC: u32 = 0x58445358;
const PROTO_MAGIC: u32 = 0x58445350;

#[tokio::main]
async fn main() {
    if std::env::args().any(|arg| arg == "--capabilities") {
        println!(
            "{{\"schema\":1,\"protocol\":\"FERESTRE_ACCOUNT_ROLES_SERVICE_V1\",\"capabilities\":[\"store-player-accounts\"]}}"
        );
        return;
    }
    // Default to info rather than to the EnvFilter's own error-only default.
    // The service's log is the only place the reason a title's Xbox call was
    // refused ever appears -- the title itself just sees the 403 -- and a log
    // that stays silent until someone knows to set XODUS_LOG is a log nobody
    // reads at the moment it would have helped.
    let filter = match std::env::var("XODUS_LOG") {
        Ok(value) if !value.trim().is_empty() => tracing_subscriber::EnvFilter::new(value),
        _ => tracing_subscriber::EnvFilter::new("info"),
    };
    let registry =
        tracing_subscriber::registry().with(tracing_subscriber::fmt::layer().with_filter(filter));

    #[cfg(feature = "tokio_console")]
    {
        use tracing::level_filters::LevelFilter;
        use tracing_subscriber::filter::Targets;

        let console_filter = Targets::new()
            .with_target("tokio", LevelFilter::TRACE)
            .with_target("runtime", LevelFilter::TRACE);
        let console_layer = console_subscriber::spawn().with_filter(console_filter);
        registry.with(console_layer).init();
    }
    #[cfg(not(feature = "tokio_console"))]
    {
        registry.init();
    }

    xodus::secrets::init_secrets().expect("Failed to init keychain");
    let root = xodus::profiles::root().expect("Account profile directory unavailable");
    let default = xodus::profiles::default_id(&root).expect("Invalid default account profile");
    let select = |role: &str| {
        let id = std::env::var(role).ok().or_else(|| default.clone());
        match id {
            Some(id) => {
                xodus::profiles::load(&root, &id).expect("Selected account profile is unavailable");
                TokenManager::for_profile(&id).expect("Invalid account profile")
            }
            None => TokenManager::with_keychain_and_memory(),
        }
        .pin_user()
        .expect("Selected account is signed out or invalid")
    };
    let tokens = Arc::new(select("XODUS_PLAYER_PROFILE"));
    let store_tokens = Arc::new(select("XODUS_STORE_PROFILE"));
    let entitlement = entitlement::Entitlement::from_env().expect("Invalid Store title binding");
    xodus::tokens::device::ensure_device_credentials(&reqwest::Client::new(), &tokens).await;
    let xodus::models::secrets::Token::Legacy(device_token) =
        tokens.get_device_sts_token().unwrap()
    else {
        panic!("Device token isnt legacy")
    };

    let runtime_dir = utils::get_runtime_dir();
    let cancellation = CancellationToken::new();
    let socket_path = format!("{runtime_dir}/xodus.sock");
    let trigger = cancellation.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failure to handle ctrl_c");
        trigger.cancel();
    });
    {
        let listener = UnixListener::bind(&socket_path).expect("Unable to bind to socket");
        let mode = 0o600;
        let perms = Permissions::from_mode(mode);
        _ = tokio::fs::set_permissions(&socket_path, perms).await;
        loop {
            let accept = tokio::select! {
                r = listener.accept() => r,
                _ = cancellation.cancelled() => break,
            }
            .expect("Failed to accept");

            let token = cancellation.clone();
            let device_token = device_token.clone();
            let tokens = tokens.clone();
            let store_tokens = store_tokens.clone();
            let entitlement = entitlement.clone();
            tokio::spawn(async move {
                connection::router::route(
                    accept.0,
                    token,
                    device_token,
                    tokens,
                    store_tokens,
                    entitlement,
                )
                .await
            });
        }
    }

    _ = tokio::fs::remove_file(socket_path).await;
}
