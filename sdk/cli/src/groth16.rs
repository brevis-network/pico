//! The Groth16 step of `prove --evm`: gnark proves the wrap circuit and witness the prover wrote,
//! and the proof is written out in the form the on-chain verifier is called with.
//!
//! gnark is the `pico-gnark` command built from `gnark/` ([`GNARK_BIN_ENV`]), or an image of it
//! built with `gnark/Dockerfile` ([`GNARK_IMAGE_ENV`]). The keys are never downloaded: they are a
//! directory a Groth16 setup wrote. The image is the caller's, which `docker run` pulls if it is
//! not local.

use std::{
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::Serialize;

use crate::options::mapped;

/// A `pico-gnark` binary, built with `go build -o pico-gnark ./sdk/main` in `gnark/`.
pub const GNARK_BIN_ENV: &str = "PICO_GNARK_BIN";
/// A Docker image built with `gnark/Dockerfile`, run with `docker run`.
pub const GNARK_IMAGE_ENV: &str = "PICO_GNARK_IMAGE";
/// Where `--evm` finds the Groth16 key directory when `--keys` is not given.
pub const KEYS_ENV: &str = "PICO_GROTH16_KEYS";

/// The proving key, in a Groth16 key directory as a setup writes it.
pub const PK_FILE: &str = "pk";
/// The verifying key, beside [`PK_FILE`].
pub const VK_FILE: &str = "vk";
/// The compiled constraint system, beside [`PK_FILE`].
pub const CCS_FILE: &str = "ccs";
/// What the keys were made from: the circuit's hash, and a hash of every file the setup wrote.
pub const MANIFEST_FILE: &str = "manifest.json";
/// The exported verifier contract for these keys.
pub const VERIFIER_FILE: &str = "Groth16Verifier.sol";

/// gnark's proof, written beside the wrap files.
pub const PROOF_FILE: &str = "proof.data";
/// What the verifier contract is called with, written beside the wrap files.
pub const INPUTS_FILE: &str = "inputs.json";

/// The circuit and witness a wrap proof writes for gnark, side by side in one directory.
pub struct WrapFiles {
    pub constraints: PathBuf,
    pub witness: PathBuf,
}

impl WrapFiles {
    /// The directory both are in, which is what a container mounts.
    fn dir(&self) -> Result<&Path> {
        let dir = self.constraints.parent().unwrap_or(Path::new("."));
        ensure!(
            self.witness.parent().unwrap_or(Path::new(".")) == dir,
            "`{}` and `{}` are not in one directory",
            self.constraints.display(),
            self.witness.display()
        );
        Ok(dir)
    }
}

/// A Groth16 key directory.
pub struct Keys {
    dir: PathBuf,
}

impl Keys {
    /// The keys of an earlier setup. The three files proving reads have to be there, so that a
    /// missing one is said before minutes of proving rather than after them.
    pub fn existing(dir: PathBuf) -> Result<Self> {
        for file in [PK_FILE, VK_FILE, CCS_FILE] {
            ensure!(
                dir.join(file).is_file(),
                "`{}` has no `{file}`: `--keys` is the directory a Groth16 setup wrote, which \
                 `--setup` makes",
                dir.display()
            );
        }
        Ok(Self { dir })
    }

    /// Where a new setup writes. A directory that already holds a proving key is refused: a
    /// setup would replace it, and no setup can be repeated, so a verifier deployed for the old
    /// keys would be left with nothing that proves against it.
    pub fn fresh(dir: PathBuf) -> Result<Self> {
        ensure!(
            !dir.join(PK_FILE).exists(),
            "`{}` already holds a proving key, which a setup would replace: remove it, or name \
             another directory with `--keys`",
            dir.display()
        );
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path(&self, file: &str) -> PathBuf {
        self.dir.join(file)
    }
}

/// How gnark is run.
#[derive(Debug, PartialEq, Eq)]
pub enum Gnark {
    Binary(PathBuf),
    Docker(String),
}

impl Gnark {
    /// From [`GNARK_BIN_ENV`] or [`GNARK_IMAGE_ENV`], each echoed like the prover's options.
    pub fn from_env() -> Result<Self> {
        let bin = mapped(GNARK_BIN_ENV, "gnark_bin", |v| Ok(PathBuf::from(v)))?;
        let image = mapped(GNARK_IMAGE_ENV, "gnark_image", |v| Ok(v.to_string()))?;
        match (bin, image) {
            (Some(bin), None) => Ok(Self::Binary(bin)),
            (None, Some(image)) => Ok(Self::Docker(image)),
            (Some(_), Some(_)) => {
                bail!("set one of {GNARK_BIN_ENV} and {GNARK_IMAGE_ENV}, not both")
            }
            (None, None) => bail!(
                "`--evm` runs gnark for the Groth16 proof: set {GNARK_BIN_ENV} to a `pico-gnark` \
                 binary (`go build -o pico-gnark ./sdk/main` in gnark/), or {GNARK_IMAGE_ENV} to \
                 an image built with gnark/Dockerfile"
            ),
        }
    }

    /// Run a Groth16 setup for the wrap circuit into `keys`: the keys, the verifier contract and
    /// the manifest.
    pub fn setup(&self, wrap: &WrapFiles, keys: &Keys) -> Result<()> {
        std::fs::create_dir_all(keys.dir())
            .with_context(|| format!("cannot create `{}`", keys.dir().display()))?;
        self.run("setup", wrap, keys, None)
    }

    /// Prove the wrap witness with `keys`, into `proof`. gnark verifies the proof before it writes
    /// it.
    pub fn prove(&self, wrap: &WrapFiles, keys: &Keys, proof: &Path) -> Result<Groth16Proof> {
        // A proof left from an earlier run must not be read as this one's.
        match std::fs::remove_file(proof) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(e).with_context(|| format!("cannot replace `{}`", proof.display()))
            }
            _ => {}
        }
        self.run("prove", wrap, keys, Some(proof))?;
        Groth16Proof::read(proof)
    }

    fn run(&self, cmd: &str, wrap: &WrapFiles, keys: &Keys, proof: Option<&Path>) -> Result<()> {
        let proof_name = proof
            .and_then(Path::file_name)
            .unwrap_or(PROOF_FILE.as_ref());
        let mut command = match self {
            Self::Binary(bin) => {
                let mut command = Command::new(bin);
                command.args(args(
                    cmd,
                    wrap,
                    keys.dir(),
                    &proof
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| keys.path(PROOF_FILE)),
                ));
                command
            }
            Self::Docker(image) => {
                let wrap_dir = absolute(wrap.dir()?)?;
                let keys_dir = absolute(keys.dir())?;
                let proof_dir = match proof.and_then(Path::parent) {
                    Some(dir) => absolute(dir)?,
                    None => keys_dir.clone(),
                };
                let mut command = Command::new("docker");
                command.args(["run", "--rm"]);
                if let Some(user) = owner(&keys_dir) {
                    // Files the container writes belong to the key directory's owner.
                    command.args(["--user", &user]);
                }
                for (host, guest) in [
                    (&wrap_dir, "/wrap"),
                    (&keys_dir, "/keys"),
                    (&proof_dir, "/proof"),
                ] {
                    command
                        .arg("--volume")
                        .arg(format!("{}:{guest}", host.display()));
                }
                let in_container = |file: &Path| {
                    Path::new("/wrap").join(file.file_name().unwrap_or(file.as_os_str()))
                };
                let wrap = WrapFiles {
                    constraints: in_container(&wrap.constraints),
                    witness: in_container(&wrap.witness),
                };
                command.arg(image).args(args(
                    cmd,
                    &wrap,
                    Path::new("/keys"),
                    &Path::new("/proof").join(proof_name),
                ));
                command
            }
        };
        eprintln!("gnark {cmd}: {}", render(&command));
        // gnark writes its log to stdout, which this CLI keeps for its results.
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("cannot run `{}`", command.get_program().to_string_lossy()))?;
        let stdout = child.stdout.take().expect("stdout is piped");
        for line in BufReader::new(stdout).lines() {
            eprintln!("gnark: {}", line.context("reading gnark's output")?);
        }
        let status = child.wait().context("waiting for gnark")?;
        ensure!(status.success(), "gnark `{cmd}` failed ({status})");
        Ok(())
    }
}

/// The `pico-gnark` flags for `cmd`: the wrap files, every key file under `keys_dir`, and the proof.
fn args(cmd: &str, wrap: &WrapFiles, keys_dir: &Path, proof: &Path) -> Vec<String> {
    let path = |p: PathBuf| p.to_string_lossy().into_owned();
    vec![
        "-cmd".into(),
        cmd.into(),
        "-constraints".into(),
        path(wrap.constraints.clone()),
        "-witness".into(),
        path(wrap.witness.clone()),
        "-pk".into(),
        path(keys_dir.join(PK_FILE)),
        "-vk".into(),
        path(keys_dir.join(VK_FILE)),
        "-ccs".into(),
        path(keys_dir.join(CCS_FILE)),
        "-manifest".into(),
        path(keys_dir.join(MANIFEST_FILE)),
        "-sol".into(),
        path(keys_dir.join(VERIFIER_FILE)),
        "-proof".into(),
        path(proof.to_path_buf()),
    ]
}

fn absolute(path: &Path) -> Result<PathBuf> {
    std::fs::canonicalize(path).with_context(|| format!("cannot resolve `{}`", path.display()))
}

#[cfg(unix)]
fn owner(dir: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(dir).ok()?;
    Some(format!("{}:{}", meta.uid(), meta.gid()))
}

#[cfg(not(unix))]
fn owner(_dir: &Path) -> Option<String> {
    None
}

fn render(command: &Command) -> String {
    std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// A gnark proof as `proof.data` holds it: fourteen 32-byte big-endian words, comma-separated.
/// The first twelve are the exported verifier's `proof`, `commitments` and `commitmentPok`
/// arguments, in that order; the last two its public inputs, `vkey_hash` then
/// `committed_values_digest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Groth16Proof {
    words: [[u8; 32]; 14],
}

impl Groth16Proof {
    pub fn read(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read `{}`", path.display()))?;
        Self::parse(&text).with_context(|| format!("`{}` is not a gnark proof", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let fields: Vec<&str> = text.trim().split(',').collect();
        ensure!(
            fields.len() == 14,
            "expected 14 comma-separated words, got {}",
            fields.len()
        );
        let mut words = [[0u8; 32]; 14];
        for (word, field) in words.iter_mut().zip(&fields) {
            let digits = field
                .trim()
                .strip_prefix("0x")
                .ok_or_else(|| anyhow!("`{field}` has no 0x prefix"))?;
            ensure!(digits.len() == 64, "`{field}` is not a 32-byte word");
            hex::decode_to_slice(digits, word).with_context(|| format!("`{field}` is not hex"))?;
        }
        Ok(Self { words })
    }

    /// The twelve words the verifier contract's `proof`, `commitments` and `commitmentPok`
    /// arguments take, in order.
    pub fn calldata(&self) -> &[[u8; 32]] {
        &self.words[..12]
    }

    /// `vkey_hash`, then `committed_values_digest`.
    pub fn public_inputs(&self) -> [[u8; 32]; 2] {
        [self.words[12], self.words[13]]
    }
}

/// `inputs.json`: what `PicoVerifier.verifyPicoProof` is called with, as a Foundry test reads it
/// with `vm.parseJson`, and the digest it recomputes from the public values.
#[derive(Serialize)]
struct Inputs {
    #[serde(rename = "riscvVKey")]
    riscv_vkey: String,
    #[serde(rename = "publicValues")]
    public_values: String,
    #[serde(rename = "committedValuesDigest")]
    committed_values_digest: String,
    proof: Vec<String>,
}

/// Write `inputs.json` for a proof of the program `vkey_hash` names, whose guest committed
/// `public_values`.
pub fn write_inputs(
    path: &Path,
    vkey_hash: [u8; 32],
    public_values: &[u8],
    proof: &Groth16Proof,
) -> Result<()> {
    let word = |w: &[u8; 32]| format!("0x{}", hex::encode(w));
    let inputs = Inputs {
        riscv_vkey: word(&vkey_hash),
        public_values: format!("0x{}", hex::encode(public_values)),
        committed_values_digest: word(&proof.public_inputs()[1]),
        proof: proof.calldata().iter().map(word).collect(),
    };
    let mut json = serde_json::to_string_pretty(&inputs).expect("inputs serialize");
    json.push('\n');
    std::fs::write(path, json).with_context(|| format!("cannot write `{}`", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 32]))
    }

    fn text() -> String {
        (0..14).map(word).collect::<Vec<_>>().join(",")
    }

    #[test]
    fn a_proof_file_splits_into_calldata_and_public_inputs() {
        let proof = Groth16Proof::parse(&format!("{}\n", text())).expect("parse");
        assert_eq!(proof.calldata().len(), 12);
        assert_eq!(proof.calldata()[0], [0; 32]);
        assert_eq!(proof.calldata()[11], [11; 32]);
        assert_eq!(proof.public_inputs(), [[12; 32], [13; 32]]);
    }

    #[test]
    fn a_malformed_proof_file_is_refused() {
        let fields: Vec<String> = (0..14).map(word).collect();
        let join = |fields: &[String]| fields.join(",");
        let mut short = fields.clone();
        short.pop();
        let mut bare = fields.clone();
        bare[3] = bare[3][2..].to_string();
        let mut narrow = fields.clone();
        narrow[5] = "0x01".into();
        let mut not_hex = fields.clone();
        not_hex[7] = format!("0x{}", "z".repeat(64));
        for bad in [
            join(&short),
            join(&bare),
            join(&narrow),
            join(&not_hex),
            String::new(),
        ] {
            assert!(Groth16Proof::parse(&bad).is_err(), "accepted: {bad}");
        }
    }

    #[test]
    fn inputs_hold_what_the_verifier_contract_is_called_with() {
        let proof = Groth16Proof::parse(&text()).expect("parse");
        let path =
            std::env::temp_dir().join(format!("pico_cli_inputs_{}.json", std::process::id()));
        write_inputs(&path, [0xab; 32], &[1, 2, 3], &proof).expect("write");
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        std::fs::remove_file(&path).ok();
        assert_eq!(json["riscvVKey"], word(0xab));
        assert_eq!(json["publicValues"], "0x010203");
        assert_eq!(json["committedValuesDigest"], word(13));
        let words: Vec<&str> = json["proof"]
            .as_array()
            .expect("proof array")
            .iter()
            .map(|w| w.as_str().expect("word"))
            .collect();
        assert_eq!(words, (0..12).map(word).collect::<Vec<_>>());
    }

    #[test]
    fn a_key_directory_needs_what_proving_reads_and_a_setup_does_not_overwrite_one() {
        let dir = std::env::temp_dir().join(format!("pico_cli_keys_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        assert!(
            Keys::existing(dir.clone()).is_err(),
            "an empty directory is a key set"
        );
        assert!(
            Keys::fresh(dir.clone()).is_ok(),
            "an empty directory is refused a setup"
        );
        for file in [PK_FILE, VK_FILE, CCS_FILE] {
            std::fs::write(dir.join(file), b"key").expect("write");
        }
        assert!(Keys::existing(dir.clone()).is_ok());
        assert!(
            Keys::fresh(dir.clone()).is_err(),
            "a setup overwrites a proving key"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn every_file_gnark_reads_or_writes_is_the_one_it_is_given() {
        let wrap = WrapFiles {
            constraints: "/wrap/wrap_constraints.json".into(),
            witness: "/wrap/wrap_groth16_witness.json".into(),
        };
        let args = args(
            "prove",
            &wrap,
            Path::new("/keys"),
            Path::new("/proof/proof.data"),
        );
        let flag = |name: &str| {
            let i = args
                .iter()
                .position(|a| a == name)
                .unwrap_or_else(|| panic!("no {name}"));
            args[i + 1].clone()
        };
        assert_eq!(flag("-cmd"), "prove");
        assert_eq!(flag("-constraints"), "/wrap/wrap_constraints.json");
        assert_eq!(flag("-witness"), "/wrap/wrap_groth16_witness.json");
        for (name, file) in [
            ("-pk", PK_FILE),
            ("-vk", VK_FILE),
            ("-ccs", CCS_FILE),
            ("-manifest", MANIFEST_FILE),
            ("-sol", VERIFIER_FILE),
        ] {
            assert_eq!(flag(name), format!("/keys/{file}"));
        }
        assert_eq!(flag("-proof"), "/proof/proof.data");
    }
}
