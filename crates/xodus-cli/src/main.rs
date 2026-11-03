use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod commands;
mod download_plan;
mod download_session;
mod download_state;
mod license;
mod package;
mod webview;
mod xvd_key;

#[derive(Subcommand)]
enum SubCommand {
    /// List local account profiles; credentials never leave the keychain.
    AccountProfiles {
        #[arg(long)]
        json: bool,
    },
    /// Import the existing sign-in without removing legacy credentials.
    MigrateAccounts,
    /// Sign in to a new, separate account profile.
    AddAccount,
    #[command(
        about = "Probe an authenticated Microsoft endpoint (research: owned-title enumeration)"
    )]
    Library {
        #[arg(
            long,
            default_value_t = 100,
            help = "Page size for the collections query"
        )]
        page_size: u32,
        #[arg(
            long,
            default_value = "www.microsoft.com",
            help = "MSA ticket target; the licensing path uses www.microsoft.com"
        )]
        msa_target: String,
        #[arg(
            long,
            default_value_t = false,
            help = "Keep add-ons, passes and inactive entitlements"
        )]
        all: bool,
        #[arg(long, default_value_t = false, help = "Emit JSON")]
        json: bool,
    },
    #[command(about = "Show the signed-in account: gamertag, xuid and gamerpic")]
    Account {
        #[arg(long, default_value_t = false, help = "Emit JSON")]
        json: bool,
    },
    #[command(about = "Raw probe of an authenticated Microsoft endpoint ({XUID} is substituted)")]
    Collections {
        #[clap(help = "Full URL to request")]
        url: String,
        #[arg(long, help = "JSON body; omitted means GET")]
        body: Option<String>,
        #[arg(
            long,
            default_value = "http://licensing.xboxlive.com",
            help = "XSTS relying party (collections.mp.microsoft.com routes with licensing.xboxlive.com)"
        )]
        relying_party: String,
        #[arg(
            long = "header",
            value_name = "NAME:VALUE",
            help = "Extra request header, repeatable (profile.xboxlive.com needs x-xbl-contract-version:3)"
        )]
        headers: Vec<String>,
        #[arg(
            long,
            value_name = "TITLEID",
            help = "Mint the token with a title claim for this decimal TitleId (needs --title-client-id)"
        )]
        title_id: Option<i64>,
        #[arg(
            long,
            value_name = "GUID",
            help = "The title's MSAAppId, from its MicrosoftGame.config"
        )]
        title_client_id: Option<String>,
    },
    #[command(
        name = "xbl-check",
        about = "Check that a title's Xbox Live calls will be authorised (multiplayer, presence)"
    )]
    XblCheck {
        #[arg(help = "The installed game directory holding MicrosoftGame.config")]
        game_dir: Option<std::path::PathBuf>,
        #[arg(long, help = "Decimal TitleId, instead of reading the game directory")]
        title_id: Option<i64>,
        #[arg(
            long,
            help = "The title's MSAAppId, instead of reading the game directory"
        )]
        title_client_id: Option<String>,
    },
    #[command(about = "Show the player as playing a game, or read the status friends see")]
    Presence {
        #[command(subcommand)]
        action: PresenceAction,
    },
    #[command(about = "Report the available version for an installed MSIXVC package")]
    Update {
        #[arg(help = "ContentId from the installed package header")]
        content_id: String,
        #[arg(long, help = "Emit JSON")]
        json: bool,
    },
    #[command(about = "Download msixvc or xsp files fo given game")]
    Download {
        product: String,
        #[arg(short, long)]
        market: Option<String>,
        #[arg(
            long,
            default_value_t = false,
            help = "Display download URLs instead of downloading"
        )]
        dry_run: bool,
    },
    #[command(about = "Dump CIKs for use with XvdTool")]
    License {
        #[clap(help = "Content Id of a license")]
        content_id: String,
        #[clap(help = "A path where to dump CIKs")]
        ciks: String,
        #[arg(short, long)]
        market: Option<String>,
    },
    #[command(about = "Extract locally stored msixvc file")]
    Extract {
        path: String,
        destination: String,
        #[arg(short, long)]
        market: Option<String>,
    },
    #[command(
        about = "Extract a locally stored EAppx/EMSIX package (research task, see issue #91)"
    )]
    ExtractEappx {
        path: String,
        destination: String,
        #[arg(short, long, help = "Path to a keyfile with content decryption keys")]
        key_file: Option<String>,
    },
    Login,
    Logout {
        #[arg(long, default_value_t = false, help = "Remove device license")]
        device: bool,
    },
    #[command(about = "Download and extract the game through streaming algorithm")]
    Streaming {
        source: String,
        destination: String,
        #[arg(
            long,
            default_value_t = false,
            help = "Attempt to skip downloading NTFS metadata to be faste while missing some files"
        )]
        try_skip_ntfs: bool,
        #[arg(short, long)]
        parallel: Option<usize>,
        #[arg(short, long)]
        market: Option<String>,
    },
    #[cfg(unix)]
    #[command(about = "Run a Game with xodus wine")]
    Run {
        source: String,
        wine: String,
        #[arg(short, long)]
        exe: Option<String>,
        #[arg(short, long)]
        market: Option<String>,
    },
    #[command(
        name = "xvd-key",
        about = "Show, fetch or remove the key package header signatures are checked with"
    )]
    XvdKey {
        #[command(subcommand)]
        action: Option<XvdKeyAction>,
        #[arg(long, default_value_t = false, help = "Emit JSON")]
        json: bool,
    },
    #[command(about = "Generate or decrypt base64-encoded CLEP challenge data")]
    Clep {
        #[command(subcommand)]
        action: ClepAction,
    },
    #[command(about = "Decode SPLicenseBlock")]
    SpLicense {
        block: String,
    },
}

#[derive(Subcommand)]
enum PresenceAction {
    #[command(
        about = "Keep the game's presence alive until stdin closes or SIGTERM, then remove it"
    )]
    Run {
        #[arg(long, default_value_t = false, help = "Emit JSON lines")]
        json: bool,
        #[arg(
            long,
            help = "The installed game directory holding MicrosoftGame.config"
        )]
        game_dir: Option<std::path::PathBuf>,
        #[arg(long, help = "Decimal TitleId, instead of reading the game directory")]
        title_id: Option<i64>,
        #[arg(
            long,
            help = "The title's MSAAppId, instead of reading the game directory"
        )]
        title_client_id: Option<String>,
    },
    #[command(about = "Read the signed-in account's own presence")]
    Get {
        #[arg(long, default_value_t = false, help = "Emit JSON")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum XvdKeyAction {
    #[command(about = "Whether the key is stored and usable (the default)")]
    Status {
        #[arg(long, default_value_t = false, help = "Emit JSON")]
        json: bool,
    },
    #[command(
        about = "Fetch Microsoft Gaming Services anonymously from the Store, keep the pinned key from it, delete the rest"
    )]
    Fetch {
        #[arg(long, default_value_t = false, help = "Emit JSON")]
        json: bool,
    },
    #[command(about = "Remove the stored key")]
    Forget {
        #[arg(long, default_value_t = false, help = "Emit JSON")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum ClepAction {
    #[command(
        about = "Generate a base64-encoded CLEP challenge (V2 and V4) from SMBIOS/disk serial data"
    )]
    Generate {
        #[arg(
            long,
            help = "Base64-encoded SMBIOS data (up to 256 bytes, zero-padded)"
        )]
        smbios: Option<String>,
        #[arg(
            long,
            help = "Base64-encoded disk serial (up to 64 bytes, zero-padded)"
        )]
        disk_serial: Option<String>,
    },
    #[command(about = "Decrypt a base64-encoded CLEP challenge back into its plaintext fields")]
    Decrypt {
        #[clap(help = "Base64-encoded, obfuscated CLEP challenge data (2048 bytes)")]
        data: String,
    },
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct CliArgs {
    /// Select an account profile for this command (defaults to the imported account).
    #[arg(long, global = true)]
    profile: Option<String>,
    #[command(subcommand)]
    command: SubCommand,
}

#[tokio::main]
async fn main() -> ExitCode {
    let filter = tracing_subscriber::EnvFilter::from_env("XODUS_LOG");
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
    // No connection_verbose: it logs the decrypted traffic, Authorization
    // headers and token bodies included, at trace level, and XODUS_LOG=trace
    // is what an issue report asks for.
    let client = reqwest::ClientBuilder::new()
        .user_agent(format!("xodus-cli/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap();
    let args = CliArgs::parse();

    // No account, keychain or device identity: the key is Microsoft's public
    // key, fetched anonymously, and a launcher asks for its status often.
    if let SubCommand::XvdKey { action, json } = &args.command {
        return match action {
            None => commands::xvd_key::status(*json),
            Some(XvdKeyAction::Status { json: j }) => commands::xvd_key::status(*json || *j),
            Some(XvdKeyAction::Fetch { json: j }) => commands::xvd_key::fetch(*json || *j).await,
            Some(XvdKeyAction::Forget { json: j }) => commands::xvd_key::forget(*json || *j),
        };
    }

    xodus::secrets::init_secrets().expect("Unable to initialize credentials");
    let profile_root = match xodus::profiles::root() {
        Ok(root) => root,
        Err(e) => {
            eprintln!("Account profiles: {e}");
            return ExitCode::FAILURE;
        }
    };
    match &args.command {
        SubCommand::AccountProfiles { json } => {
            return commands::profiles::list(&profile_root, *json);
        }
        SubCommand::MigrateAccounts => return commands::profiles::migrate(&profile_root),
        SubCommand::AddAccount => return commands::profiles::add(&client, &profile_root).await,
        _ => {}
    }
    let profile = args
        .profile
        .or_else(|| std::env::var("XODUS_ACCOUNT_PROFILE").ok());
    let tokens = match commands::profiles::manager(&profile_root, profile.as_deref()) {
        Ok(tokens) => tokens,
        Err(e) => {
            eprintln!("Account profile: {e}");
            return ExitCode::FAILURE;
        }
    };
    if tokens.profile_id().is_some() && matches!(args.command, SubCommand::Login) {
        eprintln!(
            "Use add-account for a separate sign-in; an existing profile cannot change identity"
        );
        return ExitCode::FAILURE;
    }

    // Clep/SpLicense are pure local data transforms and Logout only removes
    // stored credentials - none of them need a device identity, so don't
    // force provisioning (network + keychain access) just to run them. This
    // matters in practice: on a session with no usable secret-service
    // keychain, provisioning fails outright, which previously meant even
    // these fully offline commands were unusable.
    let needs_device_credentials = !matches!(
        args.command,
        SubCommand::Clep { .. } | SubCommand::SpLicense { .. } | SubCommand::Logout { .. }
    );
    if needs_device_credentials {
        xodus::tokens::device::ensure_device_credentials(&client, &tokens).await;
    }

    let code = match args.command {
        SubCommand::Download {
            product,
            market,
            dry_run,
        } => commands::download::run(&client, &tokens, product, market, dry_run).await,
        SubCommand::License {
            content_id,
            market,
            ciks,
        } => {
            commands::license::run(
                &client,
                &tokens,
                content_id,
                market.unwrap_or("neutral".to_string()),
                ciks,
            )
            .await
        }
        SubCommand::Login => commands::login::run(&client, &tokens).await,
        SubCommand::AccountProfiles { .. }
        | SubCommand::MigrateAccounts
        | SubCommand::AddAccount
        | SubCommand::XvdKey { .. } => unreachable!(),
        SubCommand::Logout { device } => commands::logout::run(&tokens, device).await,
        SubCommand::Extract {
            path,
            destination,
            market,
        } => {
            commands::extract::run(
                &client,
                &tokens,
                path,
                destination,
                market.unwrap_or("neutral".to_string()),
            )
            .await
        }
        SubCommand::ExtractEappx {
            path,
            destination,
            key_file,
        } => commands::extract_eappx::run(path, destination, key_file).await,
        SubCommand::Streaming {
            source,
            destination,
            try_skip_ntfs,
            market,
            parallel,
        } => {
            commands::streaming::run(
                &client,
                &tokens,
                source,
                destination,
                try_skip_ntfs,
                parallel,
                market,
            )
            .await
        }
        #[cfg(unix)]
        SubCommand::Run {
            source,
            wine,
            exe,
            market,
        } => commands::run::run(&client, &tokens, source, wine, exe, market).await,
        SubCommand::Clep { action } => match action {
            ClepAction::Generate {
                smbios,
                disk_serial,
            } => commands::clep::generate(smbios, disk_serial),
            ClepAction::Decrypt { data } => commands::clep::decrypt(data),
        },
        SubCommand::Account { json } => commands::account::run(&client, &tokens, json).await,
        SubCommand::XblCheck {
            game_dir,
            title_id,
            title_client_id,
        } => {
            let identity = match (title_id.zip(title_client_id), game_dir) {
                (Some((title_id, client_id)), _) => Ok(commands::xblcheck::TitleIdentity {
                    title_id,
                    client_id,
                }),
                (None, Some(dir)) => commands::xblcheck::identity_from_game_dir(&dir),
                (None, None) => Err(
                    "give the installed game directory, or --title-id with --title-client-id"
                        .to_string(),
                ),
            };
            match identity {
                Ok(identity) => commands::xblcheck::run(&client, &tokens, identity).await,
                Err(message) => {
                    eprintln!("{message}");
                    std::process::ExitCode::FAILURE
                }
            }
        }
        SubCommand::Presence { action } => {
            // Its own client: the shared one logs connection traffic at trace
            // level, and a heartbeat's traffic is an Authorization header.
            let client = reqwest::ClientBuilder::new()
                .user_agent(format!("xodus-cli/{}", env!("CARGO_PKG_VERSION")))
                .build()
                .unwrap_or(client);
            match action {
                PresenceAction::Run {
                    json,
                    game_dir,
                    title_id,
                    title_client_id,
                } => {
                    commands::presence::run(
                        &client,
                        &tokens,
                        json,
                        game_dir,
                        title_id,
                        title_client_id,
                    )
                    .await
                }
                PresenceAction::Get { json } => {
                    commands::presence::get(&client, &tokens, json).await
                }
            }
        }
        SubCommand::Update { content_id, json } => {
            match package::get_packages(&client, &tokens, content_id.clone()).await {
                Ok(package) => match package::available_version(&package) {
                    Some(version) => {
                        if json {
                            println!(
                                "{}",
                                serde_json::json!({
                                    "content_id": content_id,
                                    "version": version,
                                })
                            );
                        } else {
                            println!("{version}");
                        }
                        ExitCode::SUCCESS
                    }
                    None => {
                        eprintln!("update service returned no usable package version");
                        ExitCode::FAILURE
                    }
                },
                Err(error) => {
                    eprintln!("could not check for an update: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        SubCommand::Collections {
            url,
            body,
            relying_party,
            headers,
            title_id,
            title_client_id,
        } => {
            commands::collections::probe(
                &client,
                &tokens,
                url,
                body,
                relying_party,
                headers,
                title_id.zip(title_client_id),
            )
            .await
        }
        SubCommand::Library {
            page_size,
            msa_target,
            all,
            json,
        } => commands::collections::query(&client, &tokens, page_size, msa_target, all, json).await,
        SubCommand::SpLicense { block } => commands::splicense::run(block),
    };

    xodus::secrets::destroy_secrets();

    code
}
