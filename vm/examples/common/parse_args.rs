use clap::Parser;
use pico_vm::emulator::riscv::stdin::EmulatorStdin;
use tracing::info;

fn load_elf(elf: &str) -> &'static [u8] {
    let elf_file = format!("./vm/src/compiler/test_data/riscv32im-{}-elf", elf);
    let bytes = std::fs::read(elf_file).expect("failed to read elf");
    bytes.leak()
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    // ELF to run.
    // [ fibonacci | fib | f ], [ keccak | k ], [keccak_precompile], [ed_precompile]
    #[clap(long, default_value = "fibonacci")]
    elf: String,

    // fibonacci seq num or keccak input str len
    #[clap(long, default_value = "10")]
    n: u32,

    // Step to exit the test.
    // all | riscv | riscv_compress | riscv_combine | recur_combine | recur_compress | recur_embed
    #[clap(long, default_value = "all")]
    step: String,
}

pub fn parse_args() -> (&'static [u8], EmulatorStdin<Vec<u8>>, String) {
    let args = Args::parse();
    let mut stdin = EmulatorStdin::default();

    let elf: &[u8];
    if args.elf == "fibonacci" || args.elf == "fib" || args.elf == "f" {
        elf = load_elf("sp1-fibonacci");
        stdin.write(&args.n);
        info!("Test Fibonacci, sequence n={}, step={}", args.n, args.step);
    } else if args.elf == "keccak" || args.elf == "k" {
        elf = load_elf("pico-keccak");
        let input_str = (0..args.n).map(|_| "x").collect::<String>();
        stdin.write(&input_str);
        info!(
            "Test Keccak, string len n={}, step={}",
            input_str.len(),
            args.step
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
    } else if args.elf == "ed_precompile" {
        elf = load_elf("ed25519-example");
        info!("Test precompile ed25519");
    } else if args.elf == "uint256_precompile" {
        elf = load_elf("uint256-precompiled");
        info!("Test Uint256 Mul Precompile");
    } else if args.elf == "poseidon2_precompile" {
        elf = load_elf("poseidon2-permute");
        info!("Test Poseidon2 Permute Precompile");
    } else {
        eprintln!("Invalid test elf. Accept: [ fibonacci | fib | f ], [ keccak | k ], [keccak_precompile], [ed_precompile]\n");
        std::process::exit(1);
    }

    (elf, stdin, args.step)
}
