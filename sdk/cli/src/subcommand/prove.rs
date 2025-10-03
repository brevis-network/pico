use anyhow::{Error, Result};
use clap::{ArgAction, Parser};
use hex;
use log::{debug, info};
use std::{env, fs::File, io::Read, path::PathBuf};

use crate::{
    build::{
        build::{get_package, is_docker_installed},
        client::SDKProverClient,
    },
    get_target_directory, DEFAULT_ELF_DIR,
};

fn parse_input(s: &str) -> Result<Input, String> {
    // First try to parse as hex if it starts with 0x
    #[allow(clippy::manual_strip)]
    if s.starts_with("0x") {
        debug!("Parsing input as hex: {}", s);
        return hex::decode(&s[2..])
            .map(Input::HexBytes)
            .map_err(|e| format!("Invalid hex string: {}", e));
    }

    // Validate file path
    let path = PathBuf::from(s);
    if !path.exists() {
        return Err(format!("File path does not exist: {}", s));
    }

    Ok(Input::FilePath(path))
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
enum Input {
    FilePath(PathBuf),
    HexBytes(Vec<u8>),
}

#[derive(Parser)]
#[command(name = "prove", about = "prove program to get proof")]
pub struct ProveCmd {
    #[clap(long, help = "ELF file path")]
    elf: Option<String>,

    #[clap(long, value_parser = parse_input, help = "Input bytes or file path")]
    input: Option<Input>,

    #[clap(long, action, help = "proof output dir")]
    output: Option<String>,

    #[clap(long, action = ArgAction::SetTrue, help = "Perform a fast prove")]
    fast: bool,

    #[clap(long, action = ArgAction::SetTrue, help = "prove with evm mode to get g16 proof")]
    evm: bool,

    #[clap(long, action = ArgAction::SetTrue, help = "groth16 circuit setup, it must be used with --evm")]
    setup: bool,

    // Field to work on.
    // bb | m31 | kb
    #[clap(long, default_value = "kb")]
    pub field: String,
}

impl ProveCmd {
    fn get_input_bytes(input: &Option<Input>) -> Result<Vec<u8>> {
        match input {
            Some(Input::FilePath(path)) => {
                let mut file = File::open(path)?;
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)?;
                Ok(bytes)
            }
            Some(Input::HexBytes(bytes)) => Ok(bytes.clone()),
            None => Ok(Vec::new()),
        }
    }

    pub fn run(&self) -> Result<()> {
        #[cfg(not(debug_assertions))]
        {
            info!("Running in release mode!");
        }
        let elf_path = match self.elf {
            Some(ref elf) => PathBuf::from(elf),
            None => {
                let program_dir = std::env::current_dir().unwrap();
                let program_pkg = get_package(program_dir);
                let target_dir: PathBuf = get_target_directory(program_pkg.manifest_path.as_ref())?;
                target_dir
                    .parent()
                    .unwrap()
                    .join(DEFAULT_ELF_DIR)
                    .join("riscv32im-pico-zkvm-elf")
            }
        };
        let elf: Vec<u8> = std::fs::read(elf_path)?;
        let bytes = Self::get_input_bytes(&self.input)?;
        debug!("input data: {:0x?}", bytes);

        let client = SDKProverClient::new(&elf, &self.field);

        if self.fast {
            return prove_fast(client, bytes.as_slice());
        }

        if self.setup && !self.evm {
            return Err(Error::msg(
                "The --setup option must be used with the --evm option",
            ));
        }

        let program_dir = std::env::current_dir().unwrap();
        let program_pkg = get_package(program_dir);
        let target_dir: PathBuf = get_target_directory(program_pkg.manifest_path.as_ref())?;

        let pico_dir = match self.output {
            Some(ref output) => PathBuf::from(output),
            None => {
                let output_dir = target_dir.join("pico_out");
                if !output_dir.exists() {
                    std::fs::create_dir_all(output_dir.clone())?;
                    debug!("create dir: {:?}", output_dir.clone().display());
                }
                output_dir
            }
        };

        if self.evm && !is_docker_installed() {
            return Err(Error::msg(
                "Docker is not available on this system. Please install Docker first.",
            ));
        }
        prove(client, self.evm, self.setup, &bytes, pico_dir, &self.field)
    }
}

fn prove_fast(sdk_client: SDKProverClient, stdin_bytes: &[u8]) -> Result<()> {
    env::set_var("FRI_QUERIES", "1");
    info!("proving in fast mode.");
    match sdk_client {
        SDKProverClient::KoalaBearProver(client) => {
            let mut stdin = client.new_stdin_builder();
            stdin.write_slice(stdin_bytes);
            client.prove_fast(stdin)?;
            Ok(())
        }
        SDKProverClient::BabyBearProver(client) => {
            let mut stdin = client.new_stdin_builder();
            stdin.write_slice(stdin_bytes);
            client.prove_fast(stdin)?;
            Ok(())
        }
        SDKProverClient::M31Prover(client) => {
            let mut stdin = client.new_stdin_builder();
            stdin.write_slice(stdin_bytes);
            client.prove_fast(stdin)?;
            Ok(())
        }
    }
}

fn prove(
    sdk_client: SDKProverClient,
    is_evm: bool,
    need_setup: bool,
    bytes: &[u8],
    output: PathBuf,
    field_type: &str,
) -> Result<(), Error> {
    match sdk_client {
        SDKProverClient::KoalaBearProver(client) => {
            let mut stdin = client.new_stdin_builder();
            stdin.write_slice(bytes);
            if is_evm {
                client.prove_evm(stdin, need_setup, &output, field_type)?;
            } else {
                let (riscv_proof, embed_proof) = client.prove(stdin)?;
                client.write_onchain_data(&output, &riscv_proof, &embed_proof)?;
            }
            Ok(())
        }
        SDKProverClient::BabyBearProver(client) => {
            let mut stdin = client.new_stdin_builder();
            stdin.write_slice(bytes);
            if is_evm {
                client.prove_evm(stdin, need_setup, &output, field_type)?;
            } else {
                let (riscv_proof, embed_proof) = client.prove(stdin)?;
                client.write_onchain_data(&output, &riscv_proof, &embed_proof)?;
            }
            Ok(())
        }
        _ => Err(Error::msg(
            "not support config for prove, please check your config",
        )),
    }
}
