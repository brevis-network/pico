//! `cargo pico install`: the guest toolchain, linked into rustup as `pico`.
//!
//! Four steps, each checked before the next runs:
//! - [`resolve`] looks the release up in a table pinned in this file: its size and SHA-256 come from
//!   there, never from the server.
//! - [`fetch`] leaves a verified archive at `~/.pico/rust-toolchain-{tag}-{target}.tar.gz`, touching
//!   the network only when the cached copy does not verify.
//! - [`stage`] extracts it beside the installed toolchain, checks its compiler runs, and links the
//!   `std` sources and a cargo into it.
//! - [`activate`] swaps it in and links it, then removes every other toolchain directory. A failure
//!   puts back the directory and the link that were there before.
//!
//! [`install`] composes them against explicit roots, so all four run without the user's `~/.pico`,
//! rustup or GitHub, and skips the first three for a toolchain that is already this release.

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use dirs::home_dir;
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::{
    header::{CONTENT_RANGE, RANGE},
    Client, StatusCode,
};
use sha2::{Digest, Sha256};
use std::{
    fmt, fs,
    io::{self, Write},
    os::unix::{self, fs::PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
use target_lexicon::Triple;

use crate::{remove_path, run_captured, RUSTUP_TOOLCHAIN_NAME};

const REPO: &str = "brevis-network/rust";
const TOOLCHAIN_VERSION_TAG: &str = "pico-ae9fd31";
/// The nightly `TOOLCHAIN_VERSION_TAG` is built from. Guests build `std` from source
/// (`-Z build-std`), and a compiler builds only its own version's `std`, so the `rust-src` linked
/// into the guest toolchain comes from this nightly. It moves with the guest compiler, not with
/// the workspace's `rust-toolchain`.
const GUEST_STD_NIGHTLY: &str = "nightly-2026-09-27";
/// What a guest build takes from `GUEST_STD_NIGHTLY`'s sysroot, linked at the same path in the
/// guest toolchain: the `std` sources, and a cargo, which the published archives do not ship.
const FROM_GUEST_NIGHTLY: [&str; 2] = ["lib/rustlib/src", "bin/cargo"];
const DOWNLOAD_ATTEMPTS: u64 = 3;

/// One published archive. A new `TOOLCHAIN_VERSION_TAG` owes a row for every target it is built
/// for, each size and digest taken from a downloaded copy.
struct PinnedAsset {
    tag: &'static str,
    target: &'static str,
    size: u64,
    sha256: &'static str,
}

const PINNED_ASSETS: &[PinnedAsset] = &[
    PinnedAsset {
        tag: "pico-ae9fd31",
        target: "aarch64-apple-darwin",
        size: 303_442_087,
        sha256: "bf6e9cda00475ca8fe41748acc4a730e45cac1e52b01425dcfda809e2a9bc10c",
    },
    PinnedAsset {
        tag: "pico-ae9fd31",
        target: "x86_64-unknown-linux-gnu",
        size: 378_492_661,
        sha256: "4df75795be3305736534fcb56cb384bdaa4216397ef7cd5d53671132114b0a70",
    },
];

#[derive(Parser)]
#[command(
    name = "install",
    about = "Install the riscv64im-pico-zkvm-elf toolchain."
)]
pub struct InstallCmd {}

impl InstallCmd {
    pub async fn run(&self) -> Result<()> {
        // Only whether rustup runs at all: its exit status also reflects the directory's toolchain
        // override, which it would otherwise try to install.
        let rustup_found = Command::new("rustup")
            .arg("--version")
            .env("RUSTUP_AUTO_INSTALL", "0")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok();
        if !rustup_found {
            bail!(
                "Rust is not installed. Please install Rust from https://rustup.rs/ and try again.",
            );
        }

        let target = get_target();
        let asset = resolve(TOOLCHAIN_VERSION_TAG, &target)?;
        let home = home_dir().context("cannot find the home directory, where `.pico` lives")?;
        let layout = Layout::new(home.join(".pico"), TOOLCHAIN_VERSION_TAG, &target);
        let client = Client::builder()
            .timeout(Duration::from_secs(600))
            .build()?;
        let rustup = Rustup::default();
        install(&client, &asset, &layout, &rustup, || guest_sysroot(&rustup)).await
    }
}

/// A toolchain archive and what it must hash to.
#[derive(Debug)]
pub struct Asset {
    pub url: String,
    pub size: u64,
    pub sha256: [u8; 32],
}

/// The pinned archive of release `tag` for `target`. Needs no network.
pub fn resolve(tag: &str, target: &str) -> Result<Asset> {
    let Some(pinned) = PINNED_ASSETS
        .iter()
        .find(|asset| asset.tag == tag && asset.target == target)
    else {
        bail!("Toolchain for target {target} not found. Please build from source.");
    };
    let sha256 = hex::decode(pinned.sha256)
        .ok()
        .and_then(|digest| digest.try_into().ok())
        .ok_or_else(|| anyhow!("the pinned sha256 of {tag} for {target} is not 32 hex bytes"))?;
    Ok(Asset {
        url: format!(
            "https://github.com/{REPO}/releases/download/{tag}/rust-toolchain-{target}.tar.gz"
        ),
        size: pinned.size,
        sha256,
    })
}

/// Where one release lives under `~/.pico`.
pub struct Layout {
    root: PathBuf,
    tag: String,
    target: String,
}

impl Layout {
    pub fn new(root: impl Into<PathBuf>, tag: &str, target: &str) -> Self {
        Self {
            root: root.into(),
            tag: tag.to_string(),
            target: target.to_string(),
        }
    }

    /// Named after the release, so an archive another release left is never resumed into.
    pub fn archive(&self) -> PathBuf {
        self.root.join(format!(
            "rust-toolchain-{}-{}.tar.gz",
            self.tag, self.target
        ))
    }

    pub fn toolchains(&self) -> PathBuf {
        self.root.join("toolchains")
    }

    pub fn toolchain(&self) -> PathBuf {
        self.toolchains()
            .join(format!("{}-{}", self.tag, self.target))
    }

    pub fn staging(&self) -> PathBuf {
        with_suffix(&self.toolchain(), ".staging")
    }

    /// The installed toolchain while its replacement is being linked.
    fn replaced(&self) -> PathBuf {
        with_suffix(&self.toolchain(), ".old")
    }

    /// Where the archive was cached before the cache was keyed by tag. It may be from any release,
    /// so it is never read, only removed.
    fn untagged_archive(&self) -> PathBuf {
        self.root
            .join(format!("rust-toolchain-{}.tar.gz", self.target))
    }

    /// Release tags name the compiler's commit, which `rustc --version` prints in parentheses.
    fn reports_compiler(&self, version: &str) -> bool {
        let commit = self.tag.strip_prefix("pico-").unwrap_or(&self.tag);
        version.contains(&format!("({commit}"))
    }
}

/// The rustup `pico` is linked into: the user's, or the one under `home` as `RUSTUP_HOME`.
#[derive(Default)]
pub struct Rustup {
    home: Option<PathBuf>,
}

impl Rustup {
    pub fn with_home(home: impl Into<PathBuf>) -> Self {
        Self {
            home: Some(home.into()),
        }
    }

    fn rustup(&self) -> Command {
        self.command("rustup")
    }

    fn rustc(&self, toolchain: &str) -> Command {
        let mut command = self.command("rustc");
        // A probe must not install the toolchain it asks about, which rustup does by default.
        command
            .env("RUSTUP_AUTO_INSTALL", "0")
            .arg(format!("+{toolchain}"));
        command
    }

    fn command(&self, program: &str) -> Command {
        let mut command = Command::new(program);
        if let Some(home) = &self.home {
            command.env("RUSTUP_HOME", home);
        }
        command
    }

    /// Whether `rustc +{toolchain}` runs.
    pub fn installed(&self, toolchain: &str) -> bool {
        self.rustc(toolchain)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    /// The directory `pico` links to now, if it links to one that runs.
    fn linked(&self) -> Option<PathBuf> {
        let output = self
            .rustc(RUSTUP_TOOLCHAIN_NAME)
            .args(["--print", "sysroot"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        fs::canonicalize(String::from_utf8_lossy(&output.stdout).trim()).ok()
    }
}

/// Fetches the release in `layout`, then stages and activates it, unless the installed toolchain
/// already runs this release's compiler with `guest_sysroot`'s `std` sources and cargo: that one
/// is only linked again, with neither the archive nor the network.
pub async fn install(
    client: &Client,
    asset: &Asset,
    layout: &Layout,
    rustup: &Rustup,
    guest_sysroot: impl FnOnce() -> Result<PathBuf>,
) -> Result<()> {
    let guest_sysroot = guest_sysroot()?;
    if is_installed(layout, &guest_sysroot) {
        println!(
            "{} is already installed; linking it again.",
            layout.toolchain().display()
        );
        relink(rustup, layout)?;
    } else {
        fetch(client, asset, &layout.archive()).await?;
        stage(layout, &guest_sysroot)?;
        activate(rustup, layout)?;
    }

    let untagged = layout.untagged_archive();
    if untagged.exists() {
        match fs::remove_file(&untagged) {
            Ok(()) => println!("Removed the untagged archive {}.", untagged.display()),
            Err(e) => eprintln!("Warning: could not remove {}: {e}", untagged.display()),
        }
    }
    Ok(())
}

/// Leaves `archive` holding exactly `asset`. A file already there that verifies means no request
/// at all. Otherwise the download goes to `{archive}.part`, each attempt resuming from that file's
/// length, and only a copy that verifies is renamed to `archive`. A status in the 4xx range is not
/// tried again: it answers the request, not the moment.
pub async fn fetch(client: &Client, asset: &Asset, archive: &Path) -> Result<()> {
    let digest = hex::encode(asset.sha256);
    let part = with_suffix(archive, ".part");
    if archive.exists() {
        if verifies(archive, asset)? {
            println!("Using {} (sha256 {digest}).", archive.display());
            remove_path(&part)?;
            return Ok(());
        }
        println!(
            "{} does not match sha256 {digest}; downloading it again.",
            archive.display()
        );
        fs::remove_file(archive).with_context(|| format!("removing {}", archive.display()))?;
    }
    let dir = archive
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", archive.display()))?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

    let mut attempt = 1;
    loop {
        match download(client, asset, &part).await {
            Ok(()) => break,
            Err(e) if e.is::<Refused>() => return Err(e),
            Err(e) if attempt == DOWNLOAD_ATTEMPTS => {
                return Err(e.context(format!(
                    "downloading {} failed after {DOWNLOAD_ATTEMPTS} attempts",
                    asset.url
                )));
            }
            Err(e) => {
                println!("Download attempt {attempt} of {DOWNLOAD_ATTEMPTS} failed: {e:#}");
                tokio::time::sleep(Duration::from_secs(attempt)).await;
                attempt += 1;
            }
        }
    }

    let actual = hex::encode(sha256_of(&part)?);
    if actual != digest {
        fs::remove_file(&part).with_context(|| format!("removing {}", part.display()))?;
        bail!(
            "{} downloaded with sha256 {actual}, but {digest} is pinned: removed it",
            asset.url
        );
    }
    fs::rename(&part, archive)
        .with_context(|| format!("renaming {} to {}", part.display(), archive.display()))?;
    println!("Verified {} (sha256 {digest}).", archive.display());
    Ok(())
}

/// A status in the 4xx range: the server's answer to this request, which asking again would not
/// change.
#[derive(Debug)]
struct Refused {
    url: String,
    status: StatusCode,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GET {} answered {}", self.url, self.status)
    }
}

impl std::error::Error for Refused {}

/// One request, ending with `part` holding all `asset.size` bytes or with an error, a [`Refused`]
/// for a 4xx. Only bytes the server places at `part`'s current end are ever appended, and never
/// past `asset.size`.
async fn download(client: &Client, asset: &Asset, part: &Path) -> Result<()> {
    let mut offset = fs::metadata(part).map_or(0, |metadata| metadata.len());
    if offset > asset.size {
        truncate(part)?;
        offset = 0;
    }
    let mut request = client.get(&asset.url);
    if offset > 0 {
        println!("Resuming {} from byte {offset}.", part.display());
        request = request.header(RANGE, format!("bytes={offset}-"));
    } else {
        println!("Downloading {}.", asset.url);
    }
    let response = request
        .send()
        .await
        .with_context(|| format!("GET {}", asset.url))?;

    // Written through `std::fs` so that no write is still in flight when the next attempt measures
    // the file's length.
    let mut file = match response.status() {
        StatusCode::OK => {
            offset = 0;
            fs::File::create(part)
        }
        StatusCode::PARTIAL_CONTENT if offset > 0 => {
            let expected = format!("bytes {offset}-{}/{}", asset.size - 1, asset.size);
            let actual = response.headers().get(CONTENT_RANGE);
            if actual.and_then(|value| value.to_str().ok()) != Some(expected.as_str()) {
                // The next attempt asks for the whole file rather than trusting this server's
                // ranges again.
                truncate(part)?;
                bail!(
                    "{} answered `Range: bytes={offset}-` with Content-Range {actual:?}, not \
                     `{expected}`: truncated {}",
                    asset.url,
                    part.display()
                );
            }
            fs::OpenOptions::new().append(true).open(part)
        }
        StatusCode::RANGE_NOT_SATISFIABLE if offset > 0 => {
            if verifies(part, asset)? {
                return Ok(());
            }
            truncate(part)?;
            bail!(
                "{} refused `Range: bytes={offset}-`, and {} does not verify: truncated it",
                asset.url,
                part.display()
            );
        }
        status if status.is_client_error() => {
            return Err(Refused {
                url: asset.url.clone(),
                status,
            }
            .into());
        }
        status => bail!("GET {} answered {status}", asset.url),
    }
    .with_context(|| format!("opening {}", part.display()))?;

    let progress = ProgressBar::new(asset.size);
    progress.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")?
            .progress_chars("#>-"),
    );
    progress.set_position(offset);

    let mut written = offset;
    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.with_context(|| format!("reading the body of {}", asset.url))?;
        if written + chunk.len() as u64 > asset.size {
            bail!("{} sent more than {} bytes", asset.url, asset.size);
        }
        file.write_all(&chunk)
            .with_context(|| format!("writing {}", part.display()))?;
        written += chunk.len() as u64;
        progress.set_position(written);
    }
    progress.finish();
    if written != asset.size {
        bail!(
            "{} ended after {written} of {} bytes",
            asset.url,
            asset.size
        );
    }
    Ok(())
}

/// Extracts the archive into `layout.staging()`, checks the compiler there runs, and links the
/// `std` sources and cargo of `guest_sysroot`, a `GUEST_STD_NIGHTLY` sysroot, into it. The staging
/// directory is wiped first, and removed if a step fails.
pub fn stage(layout: &Layout, guest_sysroot: &Path) -> Result<()> {
    let staging = layout.staging();
    remove_path(&staging)?;
    fs::create_dir_all(&staging).with_context(|| format!("creating {}", staging.display()))?;
    let staged = stage_into(layout, &staging, guest_sysroot);
    if staged.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    staged
}

fn stage_into(layout: &Layout, staging: &Path, guest_sysroot: &Path) -> Result<()> {
    let archive = layout.archive();
    run_captured(
        Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(staging),
    )?;
    println!(
        "Extracted {} into {}.",
        archive.display(),
        staging.display()
    );

    let compiler = compiler_dir(staging);
    set_exec_bits(&compiler.join("bin"))?;
    set_exec_bits(&compiler.join(format!("lib/rustlib/{}/bin", layout.target)))?;

    let rustc = compiler.join("bin/rustc");
    let version = run_captured(Command::new(&rustc).arg("--version"))?;
    if !layout.reports_compiler(&version) {
        bail!(
            "{} reports `{version}`, not the compiler of {}",
            rustc.display(),
            layout.tag
        );
    }
    println!("Staged {version}.");

    if let Some(missing) = missing_from(guest_sysroot) {
        bail!("{} is missing, and guest builds need it", missing.display());
    }
    // The archive carries `lib/rustlib/src` as a directory holding a link into the machine that
    // built it.
    for path in FROM_GUEST_NIGHTLY {
        let source = guest_sysroot.join(path);
        let link = compiler.join(path);
        remove_path(&link)?;
        unix::fs::symlink(&source, &link)
            .with_context(|| format!("linking {} to {}", link.display(), source.display()))?;
        println!("Linked {path} from {}.", guest_sysroot.display());
    }
    Ok(())
}

/// Moves `layout.staging()` in as the toolchain and links it as `pico`. On failure, the toolchain
/// directory and the link that were there before are put back.
pub fn activate(rustup: &Rustup, layout: &Layout) -> Result<()> {
    let toolchain = layout.toolchain();
    let replaced = layout.replaced();
    let previous = rustup.linked();

    if replaced.exists() {
        if toolchain.exists() {
            remove_path(&replaced)?;
        } else {
            rename(&replaced, &toolchain)?;
        }
    }
    if toolchain.exists() {
        rename(&toolchain, &replaced)?;
    }
    let linked = rename(&layout.staging(), &toolchain).and_then(|()| link(rustup, layout));
    if let Err(e) = linked {
        // The directory before the link: `previous` may point into it.
        let restored = (|| -> Result<()> {
            remove_path(&toolchain)?;
            if replaced.exists() {
                rename(&replaced, &toolchain)?;
            }
            restore_link(rustup, previous.as_deref())
        })();
        return Err(with_restore(e, restored, previous.as_deref()));
    }
    prune(layout);
    Ok(())
}

/// Links the installed toolchain again, restoring the previous link if that fails.
fn relink(rustup: &Rustup, layout: &Layout) -> Result<()> {
    let previous = rustup.linked();
    if let Err(e) = link(rustup, layout) {
        let restored = restore_link(rustup, previous.as_deref());
        return Err(with_restore(e, restored, previous.as_deref()));
    }
    prune(layout);
    Ok(())
}

fn link(rustup: &Rustup, layout: &Layout) -> Result<()> {
    let compiler = compiler_dir(&layout.toolchain());
    run_captured(
        rustup
            .rustup()
            .args(["toolchain", "link", RUSTUP_TOOLCHAIN_NAME])
            .arg(&compiler),
    )?;
    let version = run_captured(rustup.rustc(RUSTUP_TOOLCHAIN_NAME).arg("--version"))?;
    if !layout.reports_compiler(&version) {
        bail!(
            "`rustc +{RUSTUP_TOOLCHAIN_NAME} --version` reports `{version}`, not the compiler of {}",
            layout.tag
        );
    }
    println!(
        "Linked `{RUSTUP_TOOLCHAIN_NAME}` to {}: {version}.",
        compiler.display()
    );
    Ok(())
}

fn restore_link(rustup: &Rustup, previous: Option<&Path>) -> Result<()> {
    let mut command = rustup.rustup();
    match previous.filter(|compiler| compiler.exists()) {
        Some(compiler) => command
            .args(["toolchain", "link", RUSTUP_TOOLCHAIN_NAME])
            .arg(compiler),
        // No toolchain ran as `pico` before, so the one that failed must not run as it now.
        None => command.args(["toolchain", "uninstall", RUSTUP_TOOLCHAIN_NAME]),
    };
    run_captured(&mut command).map(drop)
}

fn with_restore(
    error: anyhow::Error,
    restored: Result<()>,
    previous: Option<&Path>,
) -> anyhow::Error {
    match (restored, previous) {
        (Ok(()), Some(previous)) => error.context(format!(
            "`{RUSTUP_TOOLCHAIN_NAME}` still links to {}",
            previous.display()
        )),
        (Ok(()), None) => error.context(format!("`{RUSTUP_TOOLCHAIN_NAME}` is not linked")),
        (Err(undo), _) => error.context(format!(
            "restoring the previous toolchain failed too: {undo:#}"
        )),
    }
}

/// Removes every toolchain directory but the active one. The install has already succeeded, so a
/// failure here only warns.
fn prune(layout: &Layout) {
    let toolchains = layout.toolchains();
    let active = layout.toolchain();
    let entries = match fs::read_dir(&toolchains) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("Warning: could not list {}: {e}", toolchains.display());
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path != active && entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            if let Err(e) = fs::remove_dir_all(&path) {
                eprintln!("Warning: could not remove {}: {e}", path.display());
            }
        }
    }
}

/// The installed toolchain runs this release's compiler, and its `std` sources and cargo are
/// `guest_sysroot`'s, not another nightly's.
fn is_installed(layout: &Layout, guest_sysroot: &Path) -> bool {
    let compiler = compiler_dir(&layout.toolchain());
    let same = |path: &str| {
        let (link, source) = (
            fs::canonicalize(compiler.join(path)),
            fs::canonicalize(guest_sysroot.join(path)),
        );
        matches!((link, source), (Ok(link), Ok(source)) if link == source)
    };
    FROM_GUEST_NIGHTLY.iter().all(|path| same(path))
        && Command::new(compiler.join("bin/rustc"))
            .arg("--version")
            .output()
            .is_ok_and(|output| {
                output.status.success()
                    && layout.reports_compiler(&String::from_utf8_lossy(&output.stdout))
            })
}

/// The sysroot of `GUEST_STD_NIGHTLY`, installing the nightly, its `rust-src` and its cargo only
/// when one is missing: `rustup toolchain install` syncs the channel manifest even for an installed
/// nightly, so it fails offline.
fn guest_sysroot(rustup: &Rustup) -> Result<PathBuf> {
    if let Some(sysroot) = sysroot_of(rustup, GUEST_STD_NIGHTLY)? {
        if missing_from(&sysroot).is_none() {
            return Ok(sysroot);
        }
    }
    let toolchain_install: &[&str] = &[
        "toolchain",
        "install",
        GUEST_STD_NIGHTLY,
        "--profile",
        "minimal",
    ];
    let component_add: &[&str] = &[
        "component",
        "add",
        "rust-src",
        "cargo",
        "--toolchain",
        GUEST_STD_NIGHTLY,
    ];
    for args in [toolchain_install, component_add] {
        let status = rustup
            .rustup()
            .args(args)
            .status()
            .with_context(|| format!("running `rustup {}`", args.join(" ")))?;
        if !status.success() {
            bail!(
                "`rustup {}` failed: guest builds need {GUEST_STD_NIGHTLY}'s `rust-src` and cargo",
                args.join(" ")
            );
        }
    }
    let sysroot = sysroot_of(rustup, GUEST_STD_NIGHTLY)?.ok_or_else(|| {
        anyhow!("`rustc +{GUEST_STD_NIGHTLY} --print sysroot` fails after installing it")
    })?;
    if let Some(missing) = missing_from(&sysroot) {
        bail!("{} is missing, and guest builds need it", missing.display());
    }
    Ok(sysroot)
}

fn sysroot_of(rustup: &Rustup, toolchain: &str) -> Result<Option<PathBuf>> {
    let output = rustup
        .rustc(toolchain)
        .args(["--print", "sysroot"])
        .output()
        .with_context(|| format!("running `rustc +{toolchain} --print sysroot`"))?;
    Ok(output
        .status
        .success()
        .then(|| PathBuf::from(String::from_utf8_lossy(&output.stdout).trim())))
}

/// The first of `FROM_GUEST_NIGHTLY` that does not resolve under `sysroot`.
fn missing_from(sysroot: &Path) -> Option<PathBuf> {
    FROM_GUEST_NIGHTLY
        .iter()
        .map(|path| sysroot.join(path))
        .find(|path| !path.exists())
}

fn compiler_dir(toolchain: &Path) -> PathBuf {
    toolchain.join("rust/build/host/stage2")
}

fn set_exec_bits(dir: &Path) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
        let path = entry?.path();
        if path.is_file() {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
                .with_context(|| format!("making {} executable", path.display()))?;
        }
    }
    Ok(())
}

fn verifies(path: &Path, asset: &Asset) -> Result<bool> {
    let size = fs::metadata(path)
        .with_context(|| format!("reading {}", path.display()))?
        .len();
    Ok(size == asset.size && sha256_of(path)? == asset.sha256)
}

fn sha256_of(path: &Path) -> Result<[u8; 32]> {
    let mut file = fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher).with_context(|| format!("hashing {}", path.display()))?;
    Ok(hasher.finalize().into())
}

fn truncate(path: &Path) -> Result<()> {
    fs::File::create(path).with_context(|| format!("truncating {}", path.display()))?;
    Ok(())
}

fn rename(from: &Path, to: &Path) -> Result<()> {
    fs::rename(from, to).with_context(|| format!("renaming {} to {}", from.display(), to.display()))
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

fn get_target() -> String {
    let mut target: Triple = Triple::host();
    if target.environment == target_lexicon::Environment::Musl {
        target.environment = target_lexicon::Environment::Gnu;
    }
    target.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Listed apart from `PINNED_ASSETS`, so that moving the tag without new rows fails here.
    const SUPPORTED_TARGETS: &[&str] = &["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"];

    #[test]
    fn the_current_tag_is_pinned_for_every_supported_target() {
        for target in SUPPORTED_TARGETS {
            let asset = resolve(TOOLCHAIN_VERSION_TAG, target)
                .unwrap_or_else(|e| panic!("{TOOLCHAIN_VERSION_TAG} for {target}: {e}"));
            assert!(asset.size > 0, "{target}");
            assert!(asset.url.ends_with(&format!(
                "/{TOOLCHAIN_VERSION_TAG}/rust-toolchain-{target}.tar.gz"
            )));
        }
    }

    #[test]
    fn an_unpinned_target_is_refused() {
        let err = resolve(TOOLCHAIN_VERSION_TAG, "riscv64gc-unknown-linux-gnu").unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
    }

    #[test]
    fn a_rustup_without_the_toolchain_reports_it_absent() {
        let home = tempfile::TempDir::new().unwrap();
        assert!(!Rustup::with_home(home.path()).installed(RUSTUP_TOOLCHAIN_NAME));
    }

    #[test]
    fn the_compiler_check_reads_the_commit_from_the_tag() {
        let layout = Layout::new(
            "/nonexistent",
            TOOLCHAIN_VERSION_TAG,
            "aarch64-apple-darwin",
        );
        assert!(layout.reports_compiler("rustc 1.101.0-nightly (ae9fd31b7 2026-10-09)"));
        assert!(!layout.reports_compiler("rustc 1.101.0-nightly (0000000aa 2026-10-09)"));
    }
}
