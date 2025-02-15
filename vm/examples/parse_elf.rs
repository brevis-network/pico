use clap::Parser;
// use itertools::Itertools;
use pico_vm::compiler::riscv::compiler::{Compiler, SourceType};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long, help = "elf file path")]
    pub elf_path: String,
}
fn main() {
    let args = Args::parse();
    let elf_bytes = std::fs::read(args.elf_path).expect("failed to read elf");
    println!("byte length: {}", elf_bytes.len());

    let program = Compiler::new(SourceType::RISCV, elf_bytes.as_slice()).compile();

    let instructions = program.instructions.clone();

    println!("instructions length: {}", instructions.len());
    // group instructions by Opcode
    // let grouped = instructions.into_iter().group_by(|i| i.opcode);
}
