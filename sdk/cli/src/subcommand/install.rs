use anyhow::{bail, Result};
use clap::Parser;
use dirs::home_dir;
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use rand::{distributions::Alphanumeric, Rng};
use reqwest::Client;
use std::{
    fs,
    io::Read,
    os::unix::{self, fs::PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};
use target_lexicon::Triple;
use tokio::io::AsyncWriteExt;

const REPO: &str = "brevis-network/rust";
const RUSTUP_TOOLCHAIN_NAME: &str = "pico";
const TOOLCHAIN_VERSION_TAG: &str = "pico-8bd1f45";

#[derive(Parser)]
#[command(
    name = "install",
    about = "Install the riscv64im-pico-zkvm-elf toolchain."
)]
pub struct InstallCmd {}

impl InstallCmd {
    pub async fn run(&self) -> Result<()> {
        if Command::new("rustup")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
        {
            bail!(
                "Rust is not installed. Please install Rust from https://rustup.rs/ and try again.",
            );
        }

        let client = Client::builder()
            .timeout(Duration::from_secs(600))
            .build()?;

        let root_dir = home_dir().unwrap().join(".pico");
        fs::create_dir_all(&root_dir)?;

        let target = get_target();
        let toolchain_asset_name = format!("rust-toolchain-{target}.tar.gz");
        let toolchain_archive_path = root_dir.join(toolchain_asset_name.clone());
        let toolchain_dir = root_dir.join(&target);

        let toolchain_download_url = get_toolchain_download_url(&target);

        let artifact_exists = url_exists(&client, toolchain_download_url.as_str()).await;
        if !artifact_exists {
            bail!("Toolchain for target {target} not found. Please build from source.");
        }

        let client_head = Client::builder().timeout(Duration::from_secs(30)).build()?;
        let response = client_head.head(&toolchain_download_url).send().await;
        let total_size = match response {
            Ok(res) => res.content_length().unwrap_or(0),
            Err(_) => 0,
        };

        let start_offset = if toolchain_archive_path.exists() {
            let metadata = fs::metadata(&toolchain_archive_path)?;
            if total_size > 0 && metadata.len() >= total_size {
                println!("Download already complete ({} bytes).", metadata.len());
                let _ = Command::new("tar")
                    .current_dir(&root_dir)
                    .args([
                        "-xzf",
                        &toolchain_asset_name,
                        "-C",
                        &toolchain_dir.to_string_lossy(),
                    ])
                    .status();
                return Ok(());
            }
            println!("Resuming download from {} bytes...", metadata.len());
            metadata.len()
        } else {
            0
        };

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&toolchain_archive_path)
            .await
            .unwrap();

        let mut retries = 3;
        let mut last_error = None;
        while retries > 0 {
            match download_file(
                &client,
                toolchain_download_url.as_str(),
                &mut file,
                start_offset,
            )
            .await
            {
                Ok(_) => {
                    println!("Download completed successfully.");
                    break;
                }
                Err(e) => {
                    retries -= 1;
                    last_error = Some(e);
                    if retries > 0 {
                        println!("Download failed, retrying... ({} retries left)", retries);
                    }
                }
            }
        }
        if retries == 0 {
            bail!("Download failed after 3 attempts: {:?}", last_error);
        }

        let mut child = Command::new("rustup")
            .current_dir(&root_dir)
            .args(["toolchain", "remove", RUSTUP_TOOLCHAIN_NAME])
            .stdout(Stdio::piped())
            .spawn()?;
        let res = child.wait();
        match res {
            Ok(_) => {
                let mut stdout = child.stdout.take().unwrap();
                let mut content = String::new();
                stdout.read_to_string(&mut content).unwrap();
                if !content.contains("no toolchain installed") {
                    println!("Successfully removed existing toolchain.");
                }
            }
            Err(_) => println!("Failed to remove existing toolchain."),
        }

        fs::create_dir_all(toolchain_dir.clone())?;
        Command::new("tar")
            .current_dir(&root_dir)
            .args([
                "-xzf",
                &toolchain_asset_name,
                "-C",
                &toolchain_dir.to_string_lossy(),
            ])
            .status()?;

        let toolchains_dir = root_dir.join("toolchains");
        fs::create_dir_all(&toolchains_dir)?;
        let random_string: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        let new_toolchain_dir = toolchains_dir.join(random_string);
        fs::rename(&toolchain_dir, &new_toolchain_dir)?;

        let rust_toolchain_dir = new_toolchain_dir
            .join("rust")
            .join("build")
            .join("host")
            .join("stage2");
        Command::new("rustup")
            .current_dir(&root_dir)
            .args([
                "toolchain",
                "link",
                RUSTUP_TOOLCHAIN_NAME,
                &rust_toolchain_dir.to_string_lossy(),
            ])
            .status()?;
        println!("Successfully linked toolchain to rustup.");

        let rust_src_dir = rust_toolchain_dir.join("lib/rustlib/src");
        let nightly_sysroot = Command::new("rustc")
            .args(["+nightly-2025-08-04", "--print", "sysroot"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .ok();
        if let Some(sysroot) = nightly_sysroot {
            let src_path = Path::new(&sysroot).join("lib/rustlib/src");
            if src_path.exists() {
                println!("Linking rust-src from nightly toolchain...");
                if unix::fs::symlink(&src_path, &rust_src_dir).is_err() && rust_src_dir.exists() {
                    eprintln!("Warning: rust-src dir already exists, removing and re-linking...");
                    if let Err(e) = fs::remove_dir_all(&rust_src_dir) {
                        eprintln!("Warning: Failed to remove existing rust-src: {e}");
                    }
                    if let Err(e) = unix::fs::symlink(&src_path, &rust_src_dir) {
                        eprintln!("Warning: Failed to create symlink: {e}");
                    }
                }
            }
        }

        let bin_dir = rust_toolchain_dir.join("bin");
        let rustlib_bin_dir = rust_toolchain_dir.join(format!("lib/rustlib/{target}/bin"));
        if bin_dir.exists() {
            for entry in fs::read_dir(bin_dir)? {
                let entry = entry?;
                if entry.path().is_file() {
                    let mut perms = entry.metadata()?.permissions();
                    perms.set_mode(0o755);
                    let _ = fs::set_permissions(entry.path(), perms);
                }
            }
        }
        if rustlib_bin_dir.exists() {
            for entry in fs::read_dir(rustlib_bin_dir)? {
                let entry = entry?;
                if entry.path().is_file() {
                    let mut perms = entry.metadata()?.permissions();
                    perms.set_mode(0o755);
                    let _ = fs::set_permissions(entry.path(), perms);
                }
            }
        }

        Ok(())
    }
}

fn get_target() -> String {
    let mut target: Triple = Triple::host();
    if target.environment == target_lexicon::Environment::Musl {
        target.environment = target_lexicon::Environment::Gnu;
    }
    target.to_string()
}

async fn url_exists(client: &Client, url: &str) -> bool {
    let res = client.head(url).send().await;
    res.is_ok()
}

fn get_toolchain_download_url(target: &str) -> String {
    format!(
        "https://github.com/{REPO}/releases/download/{TOOLCHAIN_VERSION_TAG}/rust-toolchain-{target}.tar.gz",
    )
}

async fn download_file(
    client: &Client,
    url: &str,
    file: &mut (impl tokio::io::AsyncWrite + Unpin),
    start_offset: u64,
) -> Result<()> {
    let mut request = client.get(url);
    if start_offset > 0 {
        request = request.header("Range", format!("bytes={}-", start_offset));
    }

    let res = request
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to GET from '{}': {}", url, e))?;

    let content_length = res.content_length().unwrap_or(0);
    let total_size = start_offset + content_length;

    let pb = if start_offset > 0 {
        let pb = ProgressBar::new(total_size);
        pb.set_position(start_offset);
        pb
    } else {
        ProgressBar::new(total_size)
    };
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .unwrap()
            .progress_chars("#>-"),
    );

    let mut downloaded: u64 = start_offset;
    let mut stream = res.bytes_stream();
    while let Some(item) = stream.next().await {
        let chunk = item.map_err(|e| anyhow::anyhow!("Error while downloading file: {}", e))?;
        file.write_all(&chunk)
            .await
            .map_err(|e| anyhow::anyhow!("Error while writing to file: {}", e))?;
        downloaded += chunk.len() as u64;
        pb.set_position(downloaded);
    }
    pb.finish();
    println!("Download finished, total bytes: {}", downloaded);

    file.flush()
        .await
        .map_err(|e| anyhow::anyhow!("Error while flushing file: {}", e))?;

    Ok(())
}
