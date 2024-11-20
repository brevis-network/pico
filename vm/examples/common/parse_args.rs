use clap::Parser;
use pico_vm::emulator::riscv::stdin::EmulatorStdin;
use tracing::info;

const ELF_FIB: &[u8] = include_bytes!("../../src/compiler/test_data/riscv32im-sp1-fibonacci-elf");
const ELF_KECCAK: &[u8] = include_bytes!("../../src/compiler/test_data/riscv32im-pico-keccak-elf");
const ELF_KECCAK_PRECOMPILE: &[u8] =
    include_bytes!("../../src/compiler/test_data/riscv32im-keccak-example-elf");
const ELF_FIB_WITH_SHA2: &[u8] =
    include_bytes!("../../src/compiler/test_data/riscv32im-sp1-sha2-fibonacci-elf");

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    // ELF to run.
    // [ fibonacci | fib | f ], [ keccak | k ], [keccak_precompile]
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
        elf = ELF_FIB;
        stdin.write(&args.n);
        info!("Test Fibonacci, sequence n={}, step={}", args.n, args.step);
    } else if args.elf == "keccak" || args.elf == "k" {
        elf = ELF_KECCAK;
        let input_str = (0..args.n).map(|_| "x").collect::<String>();
        stdin.write(&input_str);
        info!(
            "Test Keccak, string len n={}, step={}",
            input_str.len(),
            args.step
        );
    } else if args.elf == "keccak_precompile" {
        elf = ELF_KECCAK_PRECOMPILE;
        info!("Test Keccak Precompile");
    } else if args.elf == "sha2_precompile" {
        elf = ELF_FIB_WITH_SHA2;
        stdin.write(&args.n);
        info!(
            "Test precompile sha2 public inputs for Fibonacci, sequence n={}",
            &args.n
        );
    } else {
        eprintln!("Invalid test elf. Accept: [ fibonacci | fib | f ], [ keccak | k ], [keccak_precompile]\n");
        std::process::exit(1);
    }

    (elf, stdin, args.step)
}
