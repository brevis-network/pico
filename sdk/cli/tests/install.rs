//! `cargo pico install`'s steps against a local HTTP server, a scratch `.pico` and a scratch
//! `RUSTUP_HOME`, so that no case reaches the network or the user's own toolchains.

use std::{
    fs,
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};

use pico_cli::subcommand::install::{activate, fetch, install, stage, Asset, Layout, Rustup};
use reqwest::Client;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const TAG: &str = "pico-8bd1f45";
const VERSION: &str = "rustc 1.91.0-nightly (8bd1f459c 2026-02-26)";
const EARLIER_TAG: &str = "pico-0c0ffee";
const EARLIER_VERSION: &str = "rustc 1.90.0-nightly (0c0ffee00 2026-01-01)";
const TARGET: &str = "test-host";
const CARGO_VERSION: &str = "cargo 1.91.0-nightly (0000000aa 2025-08-04)";

/// The bytes the download cases serve, with their digest taken by `shasum -a 256`, not by the code
/// under test.
const FIXTURE_LEN: usize = 200_000;
const FIXTURE_SHA256: &str = "2c4085b1ab9817526311b5a5b04451140dc922067c6922a59a77e1503918357b";
/// How much of the fixture a resumed download already has.
const PART_LEN: usize = 50_000;

/// Not an archive at all, so it passes `fetch` and fails `tar`.
const CORRUPT: &[u8] = b"not a gzip archive\n";
const CORRUPT_SHA256: &str = "9bf1d02c36d95a04d8ed7049b33afd0bde6b094d3092aff3677b9b5b89e1610a";

fn fixture() -> Vec<u8> {
    (0..FIXTURE_LEN as u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect()
}

fn digest(hex_digest: &str) -> [u8; 32] {
    hex::decode(hex_digest).unwrap().try_into().unwrap()
}

fn fixture_asset(server: &Server) -> Asset {
    Asset {
        url: server.url.clone(),
        size: FIXTURE_LEN as u64,
        sha256: digest(FIXTURE_SHA256),
    }
}

fn asset_of(bytes: &[u8], server: &Server) -> Asset {
    Asset {
        url: server.url.clone(),
        size: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    }
}

fn client() -> Client {
    Client::builder().no_proxy().build().unwrap()
}

fn part_of(archive: &Path) -> PathBuf {
    PathBuf::from(format!("{}.part", archive.display()))
}

fn write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

/// A request as the server saw it.
#[derive(Clone, Debug, PartialEq)]
struct Request {
    range: Option<String>,
}

fn unranged() -> Request {
    Request { range: None }
}

fn ranged_from(offset: usize) -> Request {
    Request {
        range: Some(format!("bytes={offset}-")),
    }
}

struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
    /// Closes the connection after this many body bytes, though `Content-Length` promised all.
    cut_after: Option<usize>,
}

impl Reply {
    fn status(status: u16) -> Self {
        Self {
            status,
            headers: vec![],
            body: format!("status {status}").into_bytes(),
            cut_after: None,
        }
    }

    fn whole(body: &[u8]) -> Self {
        Self {
            status: 200,
            headers: vec![],
            body: body.to_vec(),
            cut_after: None,
        }
    }

    fn from_byte(body: &[u8], start: usize) -> Self {
        Self {
            status: 206,
            headers: vec![(
                "Content-Range",
                format!("bytes {start}-{}/{}", body.len() - 1, body.len()),
            )],
            body: body[start..].to_vec(),
            cut_after: None,
        }
    }
}

/// What a server that implements `Range` correctly answers.
fn honour_range(body: &[u8], request: &Request) -> Reply {
    let start = request
        .range
        .as_deref()
        .and_then(|range| range.strip_prefix("bytes="))
        .and_then(|range| range.strip_suffix('-'))
        .map(|start| start.parse::<usize>().unwrap());
    match start {
        None => Reply::whole(body),
        Some(start) if start < body.len() => Reply::from_byte(body, start),
        Some(_) => Reply {
            headers: vec![("Content-Range", format!("bytes */{}", body.len()))],
            ..Reply::status(416)
        },
    }
}

/// Answers each request with `respond(index, request)` on its own connection, and logs it.
struct Server {
    url: String,
    log: Arc<Mutex<Vec<Request>>>,
}

impl Server {
    async fn start(respond: impl Fn(usize, &Request) -> Reply + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/rust-toolchain.tar.gz",
            listener.local_addr().unwrap()
        );
        let log = Arc::new(Mutex::new(Vec::new()));
        let seen = log.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let request = read_request(&mut stream).await;
                let index = {
                    let mut seen = seen.lock().unwrap();
                    seen.push(request.clone());
                    seen.len() - 1
                };
                let reply = respond(index, &request);
                let mut head = format!(
                    "HTTP/1.1 {} -\r\nContent-Length: {}\r\nConnection: close\r\n",
                    reply.status,
                    reply.body.len()
                );
                for (name, value) in &reply.headers {
                    head.push_str(&format!("{name}: {value}\r\n"));
                }
                head.push_str("\r\n");
                let body = &reply.body[..reply.cut_after.unwrap_or(reply.body.len())];
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(body).await;
                let _ = stream.shutdown().await;
            }
        });
        Self { url, log }
    }

    fn requests(&self) -> Vec<Request> {
        self.log.lock().unwrap().clone()
    }
}

async fn read_request(stream: &mut TcpStream) -> Request {
    let mut head = Vec::new();
    let mut buffer = [0; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await.unwrap();
        if read == 0 {
            break;
        }
        head.extend_from_slice(&buffer[..read]);
    }
    let range = String::from_utf8_lossy(&head).lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("range")
            .then(|| value.trim().to_string())
    });
    Request { range }
}

/// A scratch home: its own `.pico`, its own `RUSTUP_HOME`, and a stand-in for the guest nightly's
/// sysroot.
struct Scratch(TempDir);

impl Scratch {
    fn new() -> Self {
        Self(TempDir::new().unwrap())
    }

    fn layout(&self, tag: &str) -> Layout {
        Layout::new(self.0.path().join(".pico"), tag, TARGET)
    }

    fn rustup_home(&self) -> PathBuf {
        self.0.path().join("rustup")
    }

    fn rustup(&self) -> Rustup {
        Rustup::with_home(self.rustup_home())
    }

    /// `std` sources, and a cargo that prints `CARGO_VERSION`.
    fn guest_sysroot(&self) -> PathBuf {
        self.guest_sysroot_named("nightly")
    }

    /// The same, as another nightly would lay it out.
    fn guest_sysroot_named(&self, name: &str) -> PathBuf {
        let sysroot = self.0.path().join(name);
        write(
            &sysroot.join("lib/rustlib/src/rust/library/std/src/lib.rs"),
            b"",
        );
        let cargo = sysroot.join("bin/cargo");
        write(
            &cargo,
            format!("#!/bin/sh\necho '{CARGO_VERSION}'\n").as_bytes(),
        );
        fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();
        sysroot
    }

    /// Packs a toolchain laid out as a published archive is: a `rustc` that prints `version` and
    /// its own sysroot, packed without exec bits, and a `lib/rustlib/src` holding a dangling link.
    fn toolchain_archive(&self, version: &str) -> Vec<u8> {
        let tree = TempDir::new_in(self.0.path()).unwrap();
        let compiler = tree.path().join("rust/build/host/stage2");
        let rustc = compiler.join("bin/rustc");
        write(
            &rustc,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n--version) echo '{version}' ;;\n\
                 --print) cd \"$(dirname \"$0\")/..\" && pwd -P ;;\n*) exit 1 ;;\nesac\n"
            )
            .as_bytes(),
        );
        fs::set_permissions(&rustc, fs::Permissions::from_mode(0o644)).unwrap();
        fs::create_dir_all(compiler.join("lib/rustlib/src")).unwrap();
        symlink("/nonexistent/rust", compiler.join("lib/rustlib/src/rust")).unwrap();

        let archive = tree.path().join("toolchain.tar.gz");
        let status = Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(tree.path())
            .arg("rust")
            .status()
            .unwrap();
        assert!(status.success());
        fs::read(&archive).unwrap()
    }

    /// What `rustc +pico --version` prints under this scratch `RUSTUP_HOME`.
    fn linked_version(&self) -> String {
        self.linked("rustc")
    }

    /// What `{program} +pico --version` prints under this scratch `RUSTUP_HOME`, which has no
    /// other toolchain for rustup to fall back on.
    fn linked(&self, program: &str) -> String {
        let output = Command::new(program)
            .args(["+pico", "--version"])
            .env("RUSTUP_HOME", self.rustup_home())
            .env("RUSTUP_AUTO_INSTALL", "0")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    /// Installs `tag` from a server of its own, as a first `cargo pico install` would.
    async fn install(&self, tag: &str, version: &str) -> Layout {
        let archive = self.toolchain_archive(version);
        let served = archive.clone();
        let server = Server::start(move |_, request| honour_range(&served, request)).await;
        let layout = self.layout(tag);
        let sysroot = self.guest_sysroot();
        install(
            &client(),
            &asset_of(&archive, &server),
            &layout,
            &self.rustup(),
            || Ok(sysroot),
        )
        .await
        .unwrap();
        assert_eq!(self.linked_version(), version);
        assert_eq!(self.linked("cargo"), CARGO_VERSION);
        layout
    }
}

fn compiler_of(layout: &Layout) -> PathBuf {
    layout.toolchain().join("rust/build/host/stage2")
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn a_plain_download_is_verified_and_cached() {
    let scratch = Scratch::new();
    let body = fixture();
    let server = Server::start(move |_, request| honour_range(&body, request)).await;
    let archive = scratch.layout(TAG).archive();

    fetch(&client(), &fixture_asset(&server), &archive)
        .await
        .unwrap();

    assert_eq!(fs::read(&archive).unwrap(), fixture());
    assert!(!part_of(&archive).exists());
    assert_eq!(server.requests(), [unranged()]);
}

#[tokio::test]
async fn a_partial_download_resumes_from_the_part_length() {
    let scratch = Scratch::new();
    let body = fixture();
    let server = Server::start(move |_, request| honour_range(&body, request)).await;
    let archive = scratch.layout(TAG).archive();
    write(&part_of(&archive), &fixture()[..PART_LEN]);

    fetch(&client(), &fixture_asset(&server), &archive)
        .await
        .unwrap();

    assert_eq!(fs::read(&archive).unwrap(), fixture());
    assert_eq!(server.requests(), [ranged_from(PART_LEN)]);
}

#[tokio::test]
async fn a_server_that_ignores_range_is_read_from_the_start() {
    let scratch = Scratch::new();
    let body = fixture();
    let server = Server::start(move |_, _| Reply::whole(&body)).await;
    let archive = scratch.layout(TAG).archive();
    write(&part_of(&archive), &fixture()[..PART_LEN]);

    fetch(&client(), &fixture_asset(&server), &archive)
        .await
        .unwrap();

    assert_eq!(fs::read(&archive).unwrap(), fixture());
    assert_eq!(server.requests(), [ranged_from(PART_LEN)]);
}

// `start_paused`: the retry back-off sleeps on tokio's clock, which then advances when idle.
#[tokio::test(start_paused = true)]
async fn a_206_for_another_range_is_refused_and_the_file_fetched_whole() {
    let scratch = Scratch::new();
    let body = fixture();
    let server = Server::start(move |_, request| match request.range {
        Some(_) => Reply::from_byte(&body, 0),
        None => Reply::whole(&body),
    })
    .await;
    let archive = scratch.layout(TAG).archive();
    write(&part_of(&archive), &fixture()[..PART_LEN]);

    fetch(&client(), &fixture_asset(&server), &archive)
        .await
        .unwrap();

    assert_eq!(fs::read(&archive).unwrap(), fixture());
    assert_eq!(server.requests(), [ranged_from(PART_LEN), unranged()]);
}

#[tokio::test]
async fn a_416_keeps_a_part_that_verifies() {
    let scratch = Scratch::new();
    let body = fixture();
    let server = Server::start(move |_, request| honour_range(&body, request)).await;
    let archive = scratch.layout(TAG).archive();
    write(&part_of(&archive), &fixture());

    fetch(&client(), &fixture_asset(&server), &archive)
        .await
        .unwrap();

    assert_eq!(fs::read(&archive).unwrap(), fixture());
    assert_eq!(server.requests(), [ranged_from(FIXTURE_LEN)]);
}

#[tokio::test(start_paused = true)]
async fn a_416_truncates_a_part_that_does_not_verify_and_fetches_again() {
    let scratch = Scratch::new();
    let body = fixture();
    let server = Server::start(move |_, request| match request.range {
        Some(_) => Reply::status(416),
        None => Reply::whole(&body),
    })
    .await;
    let archive = scratch.layout(TAG).archive();
    write(&part_of(&archive), &[0xaa; PART_LEN]);

    fetch(&client(), &fixture_asset(&server), &archive)
        .await
        .unwrap();

    assert_eq!(fs::read(&archive).unwrap(), fixture());
    assert_eq!(server.requests(), [ranged_from(PART_LEN), unranged()]);
}

/// An error status appends nothing to the part, over `requests` of them: one for a status that
/// will not change, every attempt for one that may.
async fn an_error_status_appends_nothing(status: u16, requests: usize) {
    let scratch = Scratch::new();
    let server = Server::start(move |_, _| Reply::status(status)).await;
    let archive = scratch.layout(TAG).archive();
    write(&part_of(&archive), &fixture()[..PART_LEN]);

    let err = fetch(&client(), &fixture_asset(&server), &archive)
        .await
        .unwrap_err();

    assert!(format!("{err:#}").contains(&status.to_string()), "{err:#}");
    assert_eq!(fs::read(part_of(&archive)).unwrap(), &fixture()[..PART_LEN]);
    assert!(!archive.exists());
    assert_eq!(server.requests(), vec![ranged_from(PART_LEN); requests]);
}

#[tokio::test]
async fn a_404_appends_nothing_and_is_not_asked_again() {
    an_error_status_appends_nothing(404, 1).await;
}

#[tokio::test(start_paused = true)]
async fn a_500_appends_nothing_over_three_attempts() {
    an_error_status_appends_nothing(500, 3).await;
}

#[tokio::test(start_paused = true)]
async fn a_dropped_connection_resumes_from_the_new_part_length() {
    const CUT: usize = 60_000;
    let scratch = Scratch::new();
    let body = fixture();
    let server = Server::start(move |index, request| match index {
        0 => Reply {
            cut_after: Some(CUT),
            ..honour_range(&body, request)
        },
        _ => honour_range(&body, request),
    })
    .await;
    let archive = scratch.layout(TAG).archive();
    write(&part_of(&archive), &fixture()[..PART_LEN]);

    fetch(&client(), &fixture_asset(&server), &archive)
        .await
        .unwrap();

    assert_eq!(fs::read(&archive).unwrap(), fixture());
    assert_eq!(
        server.requests(),
        [ranged_from(PART_LEN), ranged_from(PART_LEN + CUT)]
    );
}

#[tokio::test]
async fn a_wrong_digest_fails_naming_both_digests() {
    let scratch = Scratch::new();
    let body = fixture();
    let server = Server::start(move |_, request| honour_range(&body, request)).await;
    let archive = scratch.layout(TAG).archive();
    let pinned = [0x11; 32];

    let err = fetch(
        &client(),
        &Asset {
            sha256: pinned,
            ..fixture_asset(&server)
        },
        &archive,
    )
    .await
    .unwrap_err()
    .to_string();

    assert!(err.contains(FIXTURE_SHA256), "{err}");
    assert!(err.contains(&hex::encode(pinned)), "{err}");
    assert!(!archive.exists());
    assert!(!part_of(&archive).exists());
}

#[tokio::test]
async fn a_verified_cache_sends_no_request_and_removes_a_part_left_behind() {
    let scratch = Scratch::new();
    let body = fixture();
    let server = Server::start(move |_, request| honour_range(&body, request)).await;
    let archive = scratch.layout(TAG).archive();
    write(&archive, &fixture());
    write(&part_of(&archive), &fixture()[..PART_LEN]);

    fetch(&client(), &fixture_asset(&server), &archive)
        .await
        .unwrap();

    assert!(server.requests().is_empty());
    assert!(!part_of(&archive).exists());
}

#[tokio::test]
async fn a_cache_with_one_byte_flipped_is_downloaded_again() {
    let scratch = Scratch::new();
    let body = fixture();
    let server = Server::start(move |_, request| honour_range(&body, request)).await;
    let archive = scratch.layout(TAG).archive();
    let mut flipped = fixture();
    flipped[PART_LEN] ^= 1;
    write(&archive, &flipped);

    fetch(&client(), &fixture_asset(&server), &archive)
        .await
        .unwrap();

    assert_eq!(fs::read(&archive).unwrap(), fixture());
    assert_eq!(server.requests(), [unranged()]);
}

#[tokio::test]
async fn a_fresh_install_links_the_toolchain_and_removes_what_older_installs_left() {
    let scratch = Scratch::new();
    let root = scratch.0.path().join(".pico");
    let untagged = root.join(format!("rust-toolchain-{TARGET}.tar.gz"));
    write(&untagged, b"an archive of an unknown release");
    write(&root.join("toolchains/FRnCnoNG20/rust/marker"), b"");

    let layout = scratch.install(TAG, VERSION).await;

    assert_eq!(entries(&layout.toolchains()), [format!("{TAG}-{TARGET}")]);
    let sysroot = scratch.guest_sysroot();
    for path in ["lib/rustlib/src", "bin/cargo"] {
        assert_eq!(
            fs::read_link(compiler_of(&layout).join(path)).unwrap(),
            sysroot.join(path)
        );
    }
    assert!(layout.archive().exists());
    assert!(!untagged.exists());
}

#[tokio::test]
async fn a_reinstall_only_links_again_and_needs_neither_the_archive_nor_the_network() {
    let scratch = Scratch::new();
    let layout = scratch.install(TAG, VERSION).await;
    let marker = layout.toolchain().join("marker");
    write(&marker, b"");
    fs::remove_file(layout.archive()).unwrap();

    let elsewhere = scratch.0.path().join("elsewhere");
    write(
        &elsewhere.join("bin/rustc"),
        format!("#!/bin/sh\necho '{EARLIER_VERSION}'\n").as_bytes(),
    );
    fs::set_permissions(
        elsewhere.join("bin/rustc"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::create_dir_all(elsewhere.join("lib")).unwrap();
    let status = Command::new("rustup")
        .args(["toolchain", "link", "pico"])
        .arg(&elsewhere)
        .env("RUSTUP_HOME", scratch.rustup_home())
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(scratch.linked_version(), EARLIER_VERSION);

    let server = Server::start(|_, _| Reply::status(500)).await;
    let asset = asset_of(b"never fetched", &server);
    let sysroot = scratch.guest_sysroot();
    install(&client(), &asset, &layout, &scratch.rustup(), || {
        Ok(sysroot)
    })
    .await
    .unwrap();

    assert!(server.requests().is_empty());
    assert!(marker.exists(), "the installed toolchain was staged again");
    assert!(
        !layout.archive().exists(),
        "the archive was fetched to link again"
    );
    assert_eq!(scratch.linked_version(), VERSION);
}

#[tokio::test]
async fn a_toolchain_linked_to_another_nightly_is_staged_again() {
    let scratch = Scratch::new();
    let layout = scratch.install(TAG, VERSION).await;
    let marker = layout.toolchain().join("marker");
    write(&marker, b"");
    // The guest nightly moved: the same files, in another sysroot.
    let moved = scratch.guest_sysroot_named("nightly-moved");

    let server = Server::start(|_, _| Reply::status(500)).await;
    let asset = asset_of(&fs::read(layout.archive()).unwrap(), &server);
    let sysroot = moved.clone();
    install(&client(), &asset, &layout, &scratch.rustup(), || {
        Ok(sysroot)
    })
    .await
    .unwrap();

    assert!(server.requests().is_empty());
    assert!(
        !marker.exists(),
        "the toolchain linked to the old nightly was only linked again"
    );
    for path in ["lib/rustlib/src", "bin/cargo"] {
        assert_eq!(
            fs::read_link(compiler_of(&layout).join(path)).unwrap(),
            moved.join(path)
        );
    }
}

#[tokio::test]
async fn a_broken_install_is_staged_again_from_the_cache() {
    let scratch = Scratch::new();
    let layout = scratch.install(TAG, VERSION).await;
    let marker = layout.toolchain().join("marker");
    write(&marker, b"");
    fs::remove_file(compiler_of(&layout).join("bin/rustc")).unwrap();

    let server = Server::start(|_, _| Reply::status(500)).await;
    let asset = asset_of(&fs::read(layout.archive()).unwrap(), &server);
    let sysroot = scratch.guest_sysroot();
    install(&client(), &asset, &layout, &scratch.rustup(), || {
        Ok(sysroot)
    })
    .await
    .unwrap();

    assert!(server.requests().is_empty());
    assert!(!marker.exists(), "the broken toolchain was kept");
    assert_eq!(scratch.linked_version(), VERSION);
}

#[tokio::test]
async fn an_installed_toolchain_without_cargo_is_staged_again() {
    let scratch = Scratch::new();
    let layout = scratch.install(TAG, VERSION).await;
    let marker = layout.toolchain().join("marker");
    write(&marker, b"");
    fs::remove_file(compiler_of(&layout).join("bin/cargo")).unwrap();

    let server = Server::start(|_, _| Reply::status(500)).await;
    let asset = asset_of(&fs::read(layout.archive()).unwrap(), &server);
    let sysroot = scratch.guest_sysroot();
    install(&client(), &asset, &layout, &scratch.rustup(), || {
        Ok(sysroot)
    })
    .await
    .unwrap();

    assert!(server.requests().is_empty());
    assert!(
        !marker.exists(),
        "the toolchain without cargo was only linked again"
    );
    assert_eq!(scratch.linked("cargo"), CARGO_VERSION);
}

#[test]
fn a_guest_sysroot_without_cargo_fails_stage_naming_it() {
    let scratch = Scratch::new();
    let layout = scratch.layout(TAG);
    write(&layout.archive(), &scratch.toolchain_archive(VERSION));
    let sysroot = scratch.0.path().join("nightly-without-cargo");
    write(
        &sysroot.join("lib/rustlib/src/rust/library/std/src/lib.rs"),
        b"",
    );

    let err = format!("{:#}", stage(&layout, &sysroot).unwrap_err());

    assert!(
        err.contains(&sysroot.join("bin/cargo").display().to_string()),
        "{err}"
    );
    assert!(!layout.staging().exists());
}

#[tokio::test]
async fn a_corrupt_archive_fails_in_stage_and_keeps_the_linked_toolchain() {
    let scratch = Scratch::new();
    let earlier = scratch.install(EARLIER_TAG, EARLIER_VERSION).await;

    let server = Server::start(|_, request| honour_range(CORRUPT, request)).await;
    let asset = Asset {
        url: server.url.clone(),
        size: CORRUPT.len() as u64,
        sha256: digest(CORRUPT_SHA256),
    };
    let layout = scratch.layout(TAG);
    let sysroot = scratch.guest_sysroot();
    let err = install(&client(), &asset, &layout, &scratch.rustup(), || {
        Ok(sysroot)
    })
    .await
    .unwrap_err();

    assert!(format!("{err:#}").contains("tar"), "{err:#}");
    assert_eq!(fs::read(layout.archive()).unwrap(), CORRUPT);
    assert!(!layout.staging().exists());
    assert!(!layout.toolchain().exists());
    assert!(earlier.toolchain().exists());
    assert_eq!(scratch.linked_version(), EARLIER_VERSION);
}

/// Replaces the staged compiler with one that reports `version`, so that the check after linking
/// is what fails.
fn swap_staged_compiler(layout: &Layout, version: &str) {
    let rustc = layout.staging().join("rust/build/host/stage2/bin/rustc");
    write(
        &rustc,
        format!(
            "#!/bin/sh\ncase \"$1\" in\n--version) echo '{version}' ;;\n\
             --print) cd \"$(dirname \"$0\")/..\" && pwd -P ;;\n*) exit 1 ;;\nesac\n"
        )
        .as_bytes(),
    );
    fs::set_permissions(&rustc, fs::Permissions::from_mode(0o755)).unwrap();
}

#[tokio::test]
async fn a_staged_compiler_of_another_release_is_refused_in_stage() {
    let scratch = Scratch::new();
    let layout = scratch.install(TAG, VERSION).await;
    write(
        &layout.archive(),
        &scratch.toolchain_archive(EARLIER_VERSION),
    );

    let err = stage(&layout, &scratch.guest_sysroot()).unwrap_err();

    assert!(format!("{err:#}").contains(EARLIER_VERSION), "{err:#}");
    assert!(!layout.staging().exists());
    assert_eq!(scratch.linked_version(), VERSION);
}

#[tokio::test]
async fn a_toolchain_that_fails_the_check_after_linking_is_rolled_back() {
    let scratch = Scratch::new();
    let layout = scratch.install(TAG, VERSION).await;
    let marker = layout.toolchain().join("marker");
    write(&marker, b"");

    stage(&layout, &scratch.guest_sysroot()).unwrap();
    swap_staged_compiler(&layout, EARLIER_VERSION);
    let err = activate(&scratch.rustup(), &layout).unwrap_err();

    assert!(format!("{err:#}").contains(EARLIER_VERSION), "{err:#}");
    assert!(marker.exists(), "the previous toolchain was not put back");
    assert_eq!(entries(&layout.toolchains()), [format!("{TAG}-{TARGET}")]);
    assert_eq!(scratch.linked_version(), VERSION);
}

#[tokio::test]
async fn an_activate_with_nothing_staged_keeps_the_installed_toolchain_and_its_link() {
    let scratch = Scratch::new();
    let layout = scratch.install(TAG, VERSION).await;
    let marker = layout.toolchain().join("marker");
    write(&marker, b"");

    let err = activate(&scratch.rustup(), &layout).unwrap_err();

    assert!(format!("{err:#}").contains("still links to"), "{err:#}");
    assert!(marker.exists(), "the installed toolchain was not put back");
    assert_eq!(entries(&layout.toolchains()), [format!("{TAG}-{TARGET}")]);
    assert_eq!(scratch.linked_version(), VERSION);
}

#[tokio::test]
async fn a_first_install_that_fails_the_check_after_linking_leaves_nothing_linked() {
    let scratch = Scratch::new();
    let layout = scratch.layout(TAG);
    write(&layout.archive(), &scratch.toolchain_archive(VERSION));

    stage(&layout, &scratch.guest_sysroot()).unwrap();
    swap_staged_compiler(&layout, EARLIER_VERSION);
    let err = activate(&scratch.rustup(), &layout).unwrap_err();

    assert!(format!("{err:#}").contains("is not linked"), "{err:#}");
    assert!(!layout.toolchain().exists());
    let toolchains = Command::new("rustup")
        .args(["toolchain", "list"])
        .env("RUSTUP_HOME", scratch.rustup_home())
        .output()
        .unwrap();
    let toolchains = String::from_utf8_lossy(&toolchains.stdout);
    assert!(
        !toolchains.contains("pico"),
        "`pico` is still linked: {toolchains}"
    );
}
