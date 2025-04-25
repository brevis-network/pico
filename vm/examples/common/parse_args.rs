use clap::Parser;
use pico_vm::{compiler::riscv::program::Program, emulator::stdin::EmulatorStdin};
use tracing::info;

fn load_elf(elf: &str) -> &'static [u8] {
    let elf_file = format!("./vm/src/compiler/test_elf/riscv32im-pico-{}-elf", elf);
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
    // all | riscv | convert | combine | compress | embed
    #[clap(long, default_value = "all")]
    pub step: String,

    // Field to work on.
    // bb | m31 | kb
    #[clap(long, default_value = "kb")]
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
        elf = load_elf("fibonacci");
        stdin.write(&args.n);
        info!(
            "Test Fibonacci, sequence n={}, step={}, field={}",
            args.n, args.step, args.field
        );
    } else if args.elf == "keccak" || args.elf == "k" {
        elf = load_elf("keccak");
        let input_str = (0..args.n).map(|_| "x").collect::<String>();
        stdin.write(&input_str);
        info!(
            "Test Keccak, string len n={}, step={}, field={}",
            input_str.len(),
            args.step,
            args.field
        );
    } else if args.elf == "precompile" {
        elf = load_elf("precompile");
        info!("Test multiple precompiles in a single elf");
    } else if args.elf == "poseidon2" {
        elf = load_elf("poseidon2");
        // pass in the expected hash value as input
        stdin.write(&args.n);
        info!("Test precompile poseidon2");
    } else if args.elf == "fibonacci-sha" {
        elf = load_elf("fibonacci-sha");
        stdin.write(&args.n);
    } else {
        eprintln!("Invalid test elf.\n");
        std::process::exit(1);
    }

    (elf, stdin.finalize(), args)
}
