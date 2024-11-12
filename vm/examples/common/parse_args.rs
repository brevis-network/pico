use log::info;
use pico_vm::emulator::riscv::stdin::EmulatorStdin;

pub fn parse_args(args: Vec<String>) -> (&'static [u8], EmulatorStdin<Vec<u8>>, String, u32) {
    const ELF_FIB: &[u8] =
        include_bytes!("../../src/compiler/test_data/riscv32im-sp1-fibonacci-elf");
    const ELF_KECCAK: &[u8] =
        include_bytes!("../../src/compiler/test_data/riscv32im-pico-keccak-elf");

    if args.len() > 3 {
        eprintln!("Invalid number of arguments");
        std::process::exit(1);
    }
    let mut test_case = String::from("fibonacci"); // default test_case is fibonacci
    let mut n = 0;
    let mut stdin = EmulatorStdin::default();

    if args.len() > 1 {
        test_case.clone_from(&args[1]);
        if args.len() > 2 {
            n = args[2].parse::<u32>().unwrap();
        }
    }
    if n == 0 {
        n = 20; // default fibonacci seq num or keccak input str len
    }
    let elf: &[u8];
    if test_case == "fibonacci" || test_case == "fib" || test_case == "f" {
        test_case = String::from("fibonacci");
        elf = ELF_FIB;
        stdin.write(&n);
        info!("Test Fibonacci, sequence n={}", n);
    } else if test_case == "keccak" || test_case == "k" {
        test_case = String::from("keccak");
        elf = ELF_KECCAK;
        let input_str = (0..n).map(|_| "x").collect::<String>();
        stdin.write(&input_str);
        info!("Test Keccak, string len n={}", input_str.len());
    } else {
        eprintln!("Invalid test case. Accept: [ fibonacci | fib | f ], [ keccak | k ]\n");
        std::process::exit(1);
    }

    (elf, stdin, test_case, n)
}
