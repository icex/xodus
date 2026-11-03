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
mod title;
mod utils;

const XML_MAGIC: u32 = 0x58445358;
const PROTO_MAGIC: u32 = 0x58445350;

/// How long to wait after a failed accept before the next one. Out of file
/// descriptors or memory, accepting again at once would only fail again in a
/// tight loop; the pause lets connections close. Anything else is one bad
/// connection and costs a token pause.
fn accept_backoff(error: &std::io::Error) -> std::time::Duration {
    // EMFILE, ENFILE, ENOBUFS and ENOMEM on Linux.
    match error.raw_os_error() {
        Some(24 | 23 | 105 | 12) => std::time::Duration::from_millis(500),
        _ => std::time::Duration::from_millis(10),
    }
}

#[tokio::main]
async fn main() {
    if std::env::args().any(|arg| arg == "--capabilities") {
        println!(
            "{{\"schema\":1,\"protocol\":\"FERESTRE_ACCOUNT_ROLES_SERVICE_V1\",\"capabilities\":[\"store-player-accounts\",\"title-scoped-tokens\"]}}"
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
    let select = |role: &str| {
        let requested = std::env::var(role).ok().filter(|id| !id.is_empty());
        // The legacy, unscoped sign-in only while no profile exists at all;
        // once one does, an unnamed role is the default or an error.
        let id = match xodus::profiles::select(&root, requested.as_deref()) {
            Ok(id) => id,
            Err(e) => {
                eprintln!("{role}: {e}");
                std::process::exit(1);
            }
        };
        match id {
            Some(id) => TokenManager::for_profile(&id).expect("Invalid account profile"),
            None => TokenManager::with_keychain_and_memory(),
        }
        .pin_user()
        .expect("Selected account is signed out or invalid")
    };
    let tokens = Arc::new(select("XODUS_PLAYER_PROFILE"));
    let store_tokens = Arc::new(select("XODUS_STORE_PROFILE"));
    let entitlement = entitlement::Entitlement::from_env().expect("Invalid Store title binding");
    let title = title::TitleIdentity::from_env().expect("Invalid title identity binding");
    if entitlement.is_some() && title.is_none() {
        // No released launcher binds a product without the title identity.
        // The service still starts, but signs no request that claims a title.
        tracing::warn!(
            "bound to a Store product without XODUS_TITLE_ID; requests claiming a title will be refused"
        );
    }
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
            };
            // A failed accept is one connection lost, never the service: every
            // running title depends on it for sign-in and licences.
            let accept = match accept {
                Ok(accept) => accept,
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    tokio::select! {
                        _ = tokio::time::sleep(accept_backoff(&e)) => continue,
                        _ = cancellation.cancelled() => break,
                    }
                }
            };

            let token = cancellation.clone();
            let device_token = device_token.clone();
            let tokens = tokens.clone();
            let store_tokens = store_tokens.clone();
            let entitlement = entitlement.clone();
            let title = title.clone();
            tokio::spawn(async move {
                connection::router::route(
                    accept.0,
                    token,
                    device_token,
                    tokens,
                    store_tokens,
                    entitlement,
                    title,
                )
                .await
            });
        }
    }

    _ = tokio::fs::remove_file(socket_path).await;
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_failed_accept_backs_off_instead_of_ending_the_service() {
        let too_many_files = std::io::Error::from_raw_os_error(24);
        assert_eq!(
            super::accept_backoff(&too_many_files),
            std::time::Duration::from_millis(500)
        );
        let aborted = std::io::Error::from(std::io::ErrorKind::ConnectionAborted);
        assert!(super::accept_backoff(&aborted) < std::time::Duration::from_millis(100));
    }
}
