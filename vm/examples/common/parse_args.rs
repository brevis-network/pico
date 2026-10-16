use anyhow::Error;
use clap::Parser;
use pico_vm::{
    compiler::riscv::program::Program, configs::config::StarkGenericConfig,
    emulator::stdin::EmulatorStdin,
};
use std::fs;
use tracing::info;

fn load_elf(name: &str) -> &'static [u8] {
    let elf_file = format!("./perf/bench_data/rv64/{name}-elf");
    let bytes = std::fs::read(elf_file).expect("failed to read elf");
    bytes.leak()
}

fn load_reth() -> &'static [u8] {
    let elf_file = "./perf/bench_data/rv64/reth-elf".to_string();
    let bytes = std::fs::read(elf_file).expect("failed to read elf");
    bytes.leak()
}

/// `n` is a reth block number; the five long-standing fixtures keep their short aliases. Mirrors
/// the selector the bench binary uses, so an example and a bench run name the same block.
fn load_input(n: u32) -> Result<Vec<u8>, Error> {
    let block = match n {
        171 => 17106222,
        188 => 18884864,
        239 => 23993050,
        240 => 24000020,
        246 => 24600825,
        _ => n,
    };
    Ok(fs::read(format!(
        "./perf/bench_data/rv64/reth-{block}.bin"
    ))?)
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    // ELF to run.
    // [ fibonacci | fib | f ], [ keccak | k ], poseidon2, ed25519, coprocessor, reth; and
    // fibonacci-sha, whose ELF is not shipped, so it fails to load
    #[clap(long, default_value = "fibonacci")]
    pub elf: String,

    // fibonacci seq num (also fibonacci-sha's, and poseidon2's iteration count), keccak input str
    // len, ed25519 scalar seed, or reth block number; coprocessor reads nothing
    #[clap(long, default_value = "10")]
    pub n: u32,

    // Step to exit the test.
    // all | riscv | convert | combine | embed | wrap
    #[clap(long, default_value = "all")]
    pub step: String,

    // Field to work on. Only kb.
    #[clap(long, default_value = "kb")]
    pub field: String,

    // use benchmark config
    #[clap(long)]
    pub bench: bool,
}

pub fn parse_args<SC: StarkGenericConfig>() -> (&'static [u8], EmulatorStdin<Program, Vec<u8>>, Args)
{
    let args = Args::parse();
    let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<SC>();

    let elf: &[u8];
    if args.elf == "fibonacci" || args.elf == "fib" || args.elf == "f" {
        elf = load_elf("fib");
        stdin.write(&args.n);
        info!(
            "Test Fibonacci, sequence n={}, step={}, field={}",
            args.n, args.step, args.field
        );
    } else if args.elf == "keccak" || args.elf == "k" {
        elf = load_elf("tiny-keccak");
        let input_str = (0..args.n).map(|_| "x").collect::<String>();
        stdin.write(&input_str);
        info!(
            "Test Keccak, string len n={}, step={}, field={}",
            input_str.len(),
            args.step,
            args.field
        );
    } else if args.elf == "poseidon2" {
        elf = load_elf("poseidon2");
        // the guest's `hash_many` round count
        stdin.write(&args.n);
        info!("Test precompile poseidon2");
    } else if args.elf == "ed25519" {
        elf = load_elf("ed25519");
        // The guest reads two compressed points and two scalars.
        //
        // The points are the Ed25519 basepoint and its negation. The basepoint's compressed form
        // is `0x58` followed by 31 `0x66` bytes, and negating a point flips the sign bit, which
        // is the high bit of the last byte -- so the second point is the same string with
        // `0x66` turned into `0xE6`. That keeps the fixture free of a table of magic coordinates
        // while driving `ED_DECOMPRESS` down *both* of its branches: `sign = 0` writes the
        // square root back, `sign = 1` writes `neg_x`, which is the value `neg_x_range` guards.
        let mut basepoint = [0x66u8; 32];
        basepoint[0] = 0x58;
        stdin.write(&basepoint);
        let mut neg_basepoint = basepoint;
        neg_basepoint[31] |= 0x80;
        stdin.write(&neg_basepoint);
        // Two scalars, seeded from `--n` so a run can be made longer or just different. They are
        // reduced mod the group order by the guest.
        let mut scalar = [0u8; 32];
        scalar[..4].copy_from_slice(&args.n.to_le_bytes());
        stdin.write(&scalar);
        scalar[4] = 1;
        stdin.write(&scalar);
        info!(
            "Test precompile ed25519 (ED_ADD + ED_DECOMPRESS), scalar seed n={}",
            args.n
        );
    } else if args.elf == "coprocessor" {
        // The Pico-zkCoprocessor trading-volume guest. It builds its 64 receipts itself and reads
        // nothing, so `--n` does not apply.
        elf = load_elf("coprocessor");
        info!("Test coprocessor (trading volume over 64 receipts)");
    } else if args.elf == "fibonacci-sha" {
        elf = load_elf("fibonacci-sha");
        stdin.write(&args.n);
    } else if args.elf == "reth" {
        elf = load_reth();
        let input = load_input(args.n).unwrap();
        stdin.write_slice(&input);
        info!("Test reth: {}", args.n);
    } else {
        eprintln!("Invalid test elf.\n");
        std::process::exit(1);
    }

    let stdin = stdin.finalize();
    (elf, stdin, args)
}
