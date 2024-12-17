// use clap::Parser;
// use pico_sdk::sdk::SDKProverClient;
// use pico_vm::emulator::riscv::stdin::EmulatorStdin;
//
// #[derive(Parser, Debug)]
// #[clap(author, version, about, long_about = None)]
// struct Args {
//     // fibonacci seq num or keccak input str len
//     #[clap(long, default_value = "10")]
//     n: u32,
// }
//
// const ELF_FIB: &[u8] = include_bytes!("riscv32im-sp1-fibonacci-elf");
//
fn main() {
    // let args = Args::parse();
    // let mut stdin = EmulatorStdin::new_builder();
    // stdin.write(&args.n);
    //
    // let client = SDKProverClient::new(ELF_FIB.to_vec(), stdin.finalize());
    //
    // // dry run the program in simple mode
    // // client.dry_run();
    //
    // client.prove();
}
