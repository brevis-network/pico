use clap::Parser;
use pico_vm::{
    compiler::riscv::program::Program,
    emulator::riscv::stdin::{EmulatorStdin, EmulatorStdinBuilder},
};
use tracing::info;

fn load_elf(elf: &str) -> &'static [u8] {
    let elf_file = format!("./vm/src/compiler/test_data/riscv32im-{}-elf", elf);
    let bytes = std::fs::read(elf_file).expect("failed to read elf");
    bytes.leak()
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    // ELF to run.
    // [ fibonacci | fib | f ], [ keccak | k ], [keccak_precompile], [ed_precompile]
    #[clap(long, default_value = "fibonacci")]
    pub elf: String,

    // fibonacci seq num or keccak input str len
    #[clap(long, default_value = "10")]
    pub n: u32,

    // Step to exit the test.
    // all | riscv | riscv_compress | riscv_combine | recur_combine | recur_compress | recur_embed
    #[clap(long, default_value = "all")]
    pub step: String,

    // Field to work on.
    // bb | m31 | kb
    #[clap(long, default_value = "bb")]
    pub field: String,

    // use benchmark config
    #[clap(long)]
    pub bench: bool,
}

pub fn parse_args() -> (&'static [u8], EmulatorStdin<Program, Vec<u8>>, Args) {
    let args = Args::parse();
    let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder();

    let elf: &[u8];
    if args.elf == "fibonacci" || args.elf == "fib" || args.elf == "f" {
        elf = load_elf("sp1-fibonacci");
        stdin.write(&args.n);
        info!(
            "Test Fibonacci, sequence n={}, step={}, field={}",
            args.n, args.step, args.field
        );
    } else if args.elf == "keccak" || args.elf == "k" {
        elf = load_elf("pico-keccak");
        let input_str = (0..args.n).map(|_| "x").collect::<String>();
        stdin.write(&input_str);
        info!(
            "Test Keccak, string len n={}, step={}, field={}",
            input_str.len(),
            args.step,
            args.field
        );
    } else if args.elf == "keccak_precompile" {
        elf = load_elf("keccak-example");
        info!("Test Keccak Precompile");
    } else if args.elf == "udiv" {
        elf = load_elf("sp1-udiv");
        info!("Test UDIV ELF");
    } else if args.elf == "sha2_precompile" {
        elf = load_elf("sp1-sha2-fibonacci");
        stdin.write(&args.n);
        info!(
            "Test precompile sha2 public inputs for Fibonacci, sequence n={}",
            &args.n
        );
    } else if args.elf == "bls" {
        elf = load_elf("bls381");
        info!("Test precompile fptower for BLS381");
    } else if args.elf == "bls-simple" {
        elf = load_elf("bls381-simple");
        info!("Test precompile fptower for BLS381 without pairings");
    } else if args.elf == "bls-simpler" {
        elf = load_elf("bls381-simpler");
        info!("Test precompile fptower for BLS381 without pairings and G1/G2");
    } else if args.elf == "secp-basefield" {
        elf = load_elf("secp-basefield");
        info!("Test secp256k1 base field operations via precompiles");
    } else if args.elf == "ed_precompile" {
        elf = load_elf("ed25519-example");
        info!("Test precompile ed25519");
    } else if args.elf == "uint256_precompile" {
        elf = load_elf("uint256-precompiled");
        info!("Test Uint256 Mul Precompile");
    } else if args.elf == "bn254_precompile" {
        elf = load_elf("bn254-add");
        info!("Test bn254 Precompile");
    } else if args.elf == "poseidon2_precompile" {
        elf = load_elf("poseidon2-permute");
        info!("Test Poseidon2 Permute Precompile");
    } else if args.elf == "multiple-precompile" {
        elf = load_elf("multiple-precompile");
        info!("Test multiple precompiles in a single elf");
    } else if args.elf == "tendermint" {
        (elf, stdin) = load_program(TENDERMINT_PROGRAM);
    } else if args.elf == "reth" {
        (elf, stdin) = load_program(RETH_PROGRAM);
    } else if args.elf == "reth-194" {
        (elf, stdin) = load_program(RETH_194_PROGRAM);
    } else if args.elf == "fibo-bench" {
        let elf_file = format!("./vm/src/compiler/test_data/bench/fib");
        let bytes = std::fs::read(elf_file).expect("failed to read elf");
        elf = bytes.leak();
        info!("Test fibonacci in bench, fixed n = 300k");
    } else {
        eprintln!("Invalid test elf.\n");
        std::process::exit(1);
    }

    (elf, stdin.finalize(), args)
}

// reorg this later
// used for tendermint test case

pub struct TesterProgram {
    pub elf: &'static [u8],
    pub input: &'static [u8],
}

impl TesterProgram {
    const fn new(elf: &'static [u8], input: &'static [u8]) -> Self {
        Self { elf, input }
    }
}

pub const TENDERMINT_PROGRAM: TesterProgram = TesterProgram::new(
    include_bytes!("../../../vm/src/compiler/test_data/bench/tendermint"),
    include_bytes!("../../../vm/src/compiler/test_data/bench/tendermint.in"),
);

pub const RETH_PROGRAM: TesterProgram = TesterProgram::new(
    include_bytes!("../../../vm/src/compiler/test_data/bench/reth"),
    include_bytes!("../../../vm/src/compiler/test_data/bench/reth-17106222.in"),
);

pub const RETH_194_PROGRAM: TesterProgram = TesterProgram::new(
    include_bytes!("../../../vm/src/compiler/test_data/bench/reth"),
    include_bytes!("../../../vm/src/compiler/test_data/bench/reth-19409768.in"),
);

pub fn load_program(program: TesterProgram) -> (&'static [u8], EmulatorStdinBuilder<Vec<u8>>) {
    let stdin = EmulatorStdinBuilder {
        buffer: bincode::deserialize(program.input).expect("failed to deserialize input"),
    };
    (program.elf, stdin)
}
