use anyhow::{Error, Result};
use clap::{ArgAction, Parser};
use hex;
use log::{debug, info};
use pico_sdk::{client::save_proof_data, vk_client::KoalaBearProveVKClient};
use std::{env, fs::File, io::Read, path::PathBuf};

use crate::{
    build::build::{get_package, is_docker_installed},
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

    #[clap(long, action = ArgAction::SetTrue, help = "enable vk verification in recursion circuit")]
    vk: bool,
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

        // todo: need to new client according to fieldand vk_verification options
        // let vk_verification = self.evm || self.vk;

        let prover_client = KoalaBearProveVKClient::new(&elf);

        if self.fast {
            env::set_var("FRI_QUERIES", "1");
            info!("proving in fast mode.");
            prover_client
                .get_stdin_builder()
                .borrow_mut()
                .write_slice(&bytes);
            prover_client.prove_fast()?;
            return Ok(());
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

        prover_client
            .get_stdin_builder()
            .borrow_mut()
            .write_slice(&bytes);

        if self.evm {
            if !is_docker_installed() {
                debug!("Docker is not available on this system. please install docker fisrt.");
                return Err(Error::msg(
                    "Docker is not available on this system. please install docker fisrt.",
                ));
            }
            prover_client.prove_evm(self.setup, pico_dir)?;
        } else {
            let (riscv_proof, embed_proof) = prover_client.prove(pico_dir.clone())?;

            save_proof_data(&riscv_proof, &embed_proof, pico_dir)?;
        }
        Ok(())
    }
}
