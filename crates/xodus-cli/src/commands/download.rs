use std::process::ExitCode;

use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::MultiSelect;
use inquire::validator::Validation;
use tokio::io::AsyncWriteExt;
use xodus::models::packagespc::PackageFile;
use xodus::tokens::TokenManager;

use crate::package::{get_content_id, get_packages, package_url};

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    product: String,
    market: Option<String>,
    dry_run: bool,
) -> ExitCode {
    let content_id_task = get_content_id(client, product, market).await;
    let Ok(content_id) = content_id_task else {
        let Err(err) = content_id_task else {
            eprintln!("Unknown Error");
            return ExitCode::FAILURE;
        };
        eprintln!("{}", err);
        return ExitCode::FAILURE;
    };

    let package_result = get_packages(client, tokens, content_id.clone()).await;
    let Ok(package) = package_result else {
        let Err(err) = package_result else {
            eprintln!("Unknown Error");
            return ExitCode::FAILURE;
        };
        eprintln!("{}", err);
        return ExitCode::FAILURE;
    };

    let Ok(files) = MultiSelect::new("Select files to download", package.package_files)
        .with_page_size(30)
        .with_validator(|input: &[inquire::list_option::ListOption<&PackageFile>]| {
            if !input.is_empty() {
                Ok(Validation::Valid)
            } else {
                Ok(Validation::Invalid(
                    "At least one item has to be selected".into(),
                ))
            }
        })
        .prompt()
    else {
        tracing::error!("Selection failed");
        return ExitCode::FAILURE;
    };
    println!();
    for file in files {
        let url = match package_url(&file.cdn_root_paths, &file.relative_url) {
            Ok(url) => url,
            Err(err) => {
                eprintln!("{err}");
                return ExitCode::FAILURE;
            }
        };
        if dry_run {
            println!("{}", url);
            continue;
        }
        // Saved in the current directory under the name the service gives,
        // which must therefore be a plain file name and nothing more.
        let name = match msixvc::xvd::package_relative_path(&file.file_name) {
            Ok(name) if name.components().count() == 1 => name,
            Ok(_) => {
                eprintln!(
                    "refusing to save {:?}: not a plain file name",
                    file.file_name
                );
                return ExitCode::FAILURE;
            }
            Err(err) => {
                eprintln!("{err}");
                return ExitCode::FAILURE;
            }
        };

        let progress_bar = ProgressBar::new(file.file_size as u64).with_style(
            ProgressStyle::with_template("[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) ({eta})").unwrap()
            .progress_chars("#>-")
        );

        let res = match client
            .get(&url)
            .send()
            .await
            .and_then(|res| res.error_for_status())
        {
            Ok(res) => res,
            Err(err) => {
                eprintln!("could not download {url}: {err}");
                return ExitCode::FAILURE;
            }
        };
        let mut out = match tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&name)
            .await
        {
            Ok(out) => out,
            Err(err) => {
                eprintln!("could not write {}: {err}", name.display());
                return ExitCode::FAILURE;
            }
        };
        let mut stream = res.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let written = match chunk {
                Ok(chk) => out.write_all(&chk).await.map(|()| chk.len()),
                Err(err) => {
                    eprintln!("the download of {url} stopped: {err}");
                    return ExitCode::FAILURE;
                }
            };
            match written {
                Ok(n) => progress_bar.inc(n as u64),
                Err(err) => {
                    eprintln!("could not write {}: {err}", name.display());
                    return ExitCode::FAILURE;
                }
            }
        }
        if let Err(err) = out.flush().await {
            eprintln!("could not write {}: {err}", name.display());
            return ExitCode::FAILURE;
        }

        progress_bar.finish();
    }

    println!("ContentID: {content_id}");

    ExitCode::SUCCESS
}
