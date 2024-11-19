use clap::Parser;
use pico_vm::emulator::riscv::stdin::EmulatorStdin;
use tracing::info;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long, default_value = "10")]
    n: u32,

    // [ fibonacci | fib | f ], [ keccak | k ], [keccak_precompile]
    #[clap(long, default_value = "fibonacci")]
    case: String,

    // all | riscv | riscv_compress | riscv_combine | recur_combine | recur_compress | recur_embed
    #[clap(long, default_value = "all")]
    step: String,
}

const ELF_FIB: &[u8] = include_bytes!("../../src/compiler/test_data/riscv32im-sp1-fibonacci-elf");
const ELF_KECCAK: &[u8] = include_bytes!("../../src/compiler/test_data/riscv32im-pico-keccak-elf");
const ELF_KECCAK_PRECOMPILE: &[u8] =
    include_bytes!("../../src/compiler/test_data/riscv32im-keccak-example-elf");

pub fn parse_args() -> (&'static [u8], EmulatorStdin<Vec<u8>>, String) {
    let args = Args::parse();
    let mut stdin = EmulatorStdin::default();

    let elf: &[u8];
    if args.case == "fibonacci" || args.case == "fib" || args.case == "f" {
        elf = ELF_FIB;
        stdin.write(&args.n);
        info!("Test Fibonacci, sequence n={}, step={}", args.n, args.step);
    } else if args.case == "keccak" || args.case == "k" {
        elf = ELF_KECCAK;
        let input_str = (0..args.n).map(|_| "x").collect::<String>();
        stdin.write(&input_str);
        info!(
            "Test Keccak, string len n={}, step={}",
            input_str.len(),
            args.step
        );
    } else if args.case == "keccak_precompile" {
        elf = ELF_KECCAK_PRECOMPILE;
        info!("Test Keccak Precompile");
    } else {
        eprintln!("Invalid test case. Accept: [ fibonacci | fib | f ], [ keccak | k ], [keccak_precompile]\n");
        std::process::exit(1);
    }

    (elf, stdin, args.step)
}
