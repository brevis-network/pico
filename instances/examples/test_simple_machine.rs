use log::{debug, info};
use p3_air::{Air, BaseAir};
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use pico_chips::chips::{
    alu::{add_sub::AddSubChip, bitwise::BitwiseChip, divrem::DivRemChip, mul::MulChip},
    byte::ByteChip,
    cpu::CpuChip,
    lt::LtChip,
    memory::initialize_finalize::{MemoryChipType, MemoryInitializeFinalizeChip},
    memory_program::MemoryProgramChip,
    program::ProgramChip,
    sll::SLLChip,
    sr::trace::ShiftRightChip,
};
use pico_compiler::{
    compiler::{Compiler, SourceType},
    program::Program,
};
use pico_configs::bb_poseidon2::BabyBearPoseidon2;
use pico_emulator::{
    opts::PicoCoreOpts,
    record::RecordBehavior,
    riscv::{record::EmulationRecord, riscv_emulator::RiscvEmulator},
    stdin::PicoStdin,
};
use pico_instances::simple_machine::SimpleMachine;
use pico_machine::{
    builder::ChipBuilder,
    chip::{ChipBehavior, MetaChip},
    machine::MachineBehavior,
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use std::{env, time::SystemTime};

pub enum TestChipType<F: Field> {
    Byte(ByteChip<F>),
    Program(ProgramChip<F>),
    Cpu(CpuChip<F>),
    MemoryProgram(MemoryProgramChip<F>),
    MemoryInitialize(MemoryInitializeFinalizeChip<F>),
    MemoryFinalize(MemoryInitializeFinalizeChip<F>),
    AddSub(AddSubChip<F>),
    Bitwise(BitwiseChip<F>),
    DivRem(DivRemChip<F>),
    Mul(MulChip<F>),
    Lt(LtChip<F>),
    SLL(SLLChip<F>),
    SR(ShiftRightChip<F>),
}

// NOTE: These trait implementations are used to save this `TestChipType` to `MetaChip`.
// Since MetaChip has a generic parameter which is one type (cannot be two chip types).
// This code is annoyed, we could refactor to use macro later (but less readable).
impl<F: PrimeField32> ChipBehavior<F> for TestChipType<F> {
    type Record = EmulationRecord;

    fn name(&self) -> String {
        match self {
            Self::Byte(chip) => chip.name(),
            Self::Program(chip) => chip.name(),
            Self::Cpu(chip) => chip.name(),
            Self::MemoryProgram(chip) => chip.name(),
            Self::MemoryInitialize(chip) => chip.name(),
            Self::MemoryFinalize(chip) => chip.name(),
            Self::AddSub(chip) => chip.name(),
            Self::Bitwise(chip) => chip.name(),
            Self::DivRem(chip) => chip.name(),
            Self::Mul(chip) => chip.name(),
            Self::Lt(chip) => chip.name(),
            Self::SLL(chip) => chip.name(),
            Self::SR(chip) => chip.name(),
        }
    }

    fn generate_preprocessed(&self, program: &Program) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Byte(chip) => chip.generate_preprocessed(program),
            Self::Program(chip) => chip.generate_preprocessed(program),
            Self::Cpu(chip) => chip.generate_preprocessed(program),
            Self::MemoryProgram(chip) => chip.generate_preprocessed(program),
            Self::MemoryInitialize(chip) => chip.generate_preprocessed(program),
            Self::MemoryFinalize(chip) => chip.generate_preprocessed(program),
            Self::AddSub(chip) => chip.generate_preprocessed(program),
            Self::Bitwise(chip) => chip.generate_preprocessed(program),
            Self::DivRem(chip) => chip.generate_preprocessed(program),
            Self::Mul(chip) => chip.generate_preprocessed(program),
            Self::Lt(chip) => chip.generate_preprocessed(program),
            Self::SLL(chip) => chip.generate_preprocessed(program),
            Self::SR(chip) => chip.generate_preprocessed(program),
        }
    }

    fn generate_main(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        match self {
            Self::Byte(chip) => chip.generate_main(input, output),
            Self::Program(chip) => chip.generate_main(input, output),
            Self::Cpu(chip) => chip.generate_main(input, output),
            Self::MemoryProgram(chip) => chip.generate_main(input, output),
            Self::MemoryInitialize(chip) => chip.generate_main(input, output),
            Self::MemoryFinalize(chip) => chip.generate_main(input, output),
            Self::AddSub(chip) => chip.generate_main(input, output),
            Self::Bitwise(chip) => chip.generate_main(input, output),
            Self::DivRem(chip) => chip.generate_main(input, output),
            Self::Mul(chip) => chip.generate_main(input, output),
            Self::Lt(chip) => chip.generate_main(input, output),
            Self::SLL(chip) => chip.generate_main(input, output),
            Self::SR(chip) => chip.generate_main(input, output),
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Byte(chip) => chip.preprocessed_width(),
            Self::Program(chip) => chip.preprocessed_width(),
            Self::Cpu(chip) => chip.preprocessed_width(),
            Self::MemoryProgram(chip) => chip.preprocessed_width(),
            Self::MemoryInitialize(chip) => chip.preprocessed_width(),
            Self::MemoryFinalize(chip) => chip.preprocessed_width(),
            Self::AddSub(chip) => chip.preprocessed_width(),
            Self::Bitwise(chip) => chip.preprocessed_width(),
            Self::DivRem(chip) => chip.preprocessed_width(),
            Self::Mul(chip) => chip.preprocessed_width(),
            Self::Lt(chip) => chip.preprocessed_width(),
            Self::SLL(chip) => chip.preprocessed_width(),
            Self::SR(chip) => chip.preprocessed_width(),
        }
    }

    fn extra_record(&self, input: &mut Self::Record, extra: &mut Self::Record) {
        match self {
            Self::Byte(chip) => chip.extra_record(input, extra),
            Self::Program(chip) => chip.extra_record(input, extra),
            Self::Cpu(chip) => chip.extra_record(input, extra),
            Self::MemoryProgram(chip) => chip.extra_record(input, extra),
            Self::MemoryInitialize(chip) => chip.extra_record(input, extra),
            Self::MemoryFinalize(chip) => chip.extra_record(input, extra),
            Self::AddSub(chip) => chip.extra_record(input, extra),
            Self::Bitwise(chip) => chip.extra_record(input, extra),
            Self::DivRem(chip) => chip.extra_record(input, extra),
            Self::Mul(chip) => chip.extra_record(input, extra),
            Self::Lt(chip) => chip.extra_record(input, extra),
            Self::SLL(chip) => chip.extra_record(input, extra),
            Self::SR(chip) => chip.extra_record(input, extra),
        }
    }
}

impl<F: Field> BaseAir<F> for TestChipType<F> {
    fn width(&self) -> usize {
        match self {
            Self::Byte(chip) => chip.width(),
            Self::Program(chip) => chip.width(),
            Self::Cpu(chip) => chip.width(),
            Self::MemoryProgram(chip) => chip.width(),
            Self::MemoryInitialize(chip) => chip.width(),
            Self::MemoryFinalize(chip) => chip.width(),
            Self::AddSub(chip) => chip.width(),
            Self::Bitwise(chip) => chip.width(),
            Self::DivRem(chip) => chip.width(),
            Self::Mul(chip) => chip.width(),
            Self::Lt(chip) => chip.width(),
            Self::SLL(chip) => chip.width(),
            Self::SR(chip) => chip.width(),
        }
    }

    /// todo: this should not be called. all should go to generate_preprocessed.
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Byte(chip) => chip.preprocessed_trace(),
            Self::Program(chip) => chip.preprocessed_trace(),
            Self::Cpu(chip) => chip.preprocessed_trace(),
            Self::MemoryProgram(chip) => chip.preprocessed_trace(),
            Self::MemoryInitialize(chip) => chip.preprocessed_trace(),
            Self::MemoryFinalize(chip) => chip.preprocessed_trace(),
            Self::AddSub(chip) => chip.preprocessed_trace(),
            Self::Bitwise(chip) => chip.preprocessed_trace(),
            Self::DivRem(chip) => chip.preprocessed_trace(),
            Self::Mul(chip) => chip.preprocessed_trace(),
            Self::Lt(chip) => chip.preprocessed_trace(),
            Self::SLL(chip) => chip.preprocessed_trace(),
            Self::SR(chip) => chip.preprocessed_trace(),
        }
    }
}

impl<F, CB> Air<CB> for TestChipType<F>
where
    F: PrimeField32,
    CB: ChipBuilder<F>,
{
    fn eval(&self, b: &mut CB) {
        match self {
            Self::Byte(chip) => chip.eval(b),
            Self::Program(chip) => chip.eval(b),
            Self::Cpu(chip) => chip.eval(b),
            Self::MemoryProgram(chip) => chip.eval(b),
            Self::MemoryInitialize(chip) => chip.eval(b),
            Self::MemoryFinalize(chip) => chip.eval(b),
            Self::AddSub(chip) => chip.eval(b),
            Self::Bitwise(chip) => chip.eval(b),
            Self::DivRem(chip) => chip.eval(b),
            Self::Mul(chip) => chip.eval(b),
            Self::Lt(chip) => chip.eval(b),
            Self::SLL(chip) => chip.eval(b),
            Self::SR(chip) => chip.eval(b),
        }
    }
}

impl<F: PrimeField32> TestChipType<F> {
    pub fn all_chips() -> Vec<MetaChip<F, Self>> {
        vec![
            MetaChip::new(Self::Program(ProgramChip::default())),
            MetaChip::new(Self::MemoryProgram(MemoryProgramChip::default())),
            MetaChip::new(Self::Cpu(CpuChip::default())),
            MetaChip::new(Self::MemoryInitialize(MemoryInitializeFinalizeChip::new(
                MemoryChipType::Initialize,
            ))),
            MetaChip::new(Self::MemoryFinalize(MemoryInitializeFinalizeChip::new(
                MemoryChipType::Finalize,
            ))),
            MetaChip::new(Self::DivRem(DivRemChip::default())),
            MetaChip::new(Self::Mul(MulChip::default())),
            MetaChip::new(Self::Lt(LtChip::default())),
            MetaChip::new(Self::SR(ShiftRightChip::default())),
            MetaChip::new(Self::SLL(SLLChip::default())),
            MetaChip::new(Self::AddSub(AddSubChip::default())),
            MetaChip::new(Self::Bitwise(BitwiseChip::default())),
            MetaChip::new(Self::Byte(ByteChip::default())),
        ]
    }
}

fn pars_args(args: Vec<String>) -> (&'static [u8], PicoStdin) {
    const ELF_FIB: &[u8] = include_bytes!("../../compiler/test_data/riscv32im-sp1-fibonacci-elf");
    const ELF_KECCAK: &[u8] = include_bytes!("../../compiler/test_data/riscv32im-pico-keccak-elf");

    if args.len() > 3 {
        eprintln!("Invalid number of arguments");
        std::process::exit(1);
    }
    let mut test_case = String::from("fib"); // default test_case is fibonacci
    let mut n = 0;
    let mut stdin = PicoStdin::new();

    if args.len() > 1 {
        test_case = args[1].clone();
        if args.len() > 2 {
            n = args[2].parse::<u32>().unwrap();
        }
    }

    let mut elf: &[u8];
    if test_case == "fibonacci" || test_case == "fib" || test_case == "f" {
        elf = ELF_FIB;
        if n == 0 {
            n = 40000; // default fibonacci seq num
        }
        stdin.write(&n);
        let mut input = [0u8; 4];
        stdin.read_slice(&mut input);
        info!("Test Fibonacci, sequence n={}, {:x?}", n, &input);
    } else if test_case == "keccak" || test_case == "k" {
        elf = ELF_KECCAK;
        if n == 0 {
            n = 100; // default keccak input str len
        }
        let input_str = (0..n).map(|_| "x").collect::<String>();
        stdin.write(&input_str);
        info!("Test Keccak, string len n={}", input_str.len());
    } else {
        eprintln!("Invalid test case. Accept: [ fibonacci | fib | f ], [ keccak | k ]\n");
        std::process::exit(1);
    }

    (elf, stdin)
}

fn main() {
    env_logger::init();
    let (elf, stdin) = pars_args(env::args().collect());
    let start = SystemTime::now();

    info!("\n Creating Program..");
    let compiler = Compiler::new(SourceType::RiscV, elf);
    let program = compiler.compile();

    info!(
        "\n Creating emulator (at {} ms)..",
        start.elapsed().unwrap().as_millis()
    );
    let mut emulator = RiscvEmulator::new(program, PicoCoreOpts::default());
    emulator.run_with_stdin(stdin).unwrap();

    // TRICKY: We copy the memory initialize and finalize events from the second (last)
    // record to this record, since the memory lookups could only work if has the
    // full lookups in the all records.
    assert_eq!(
        emulator.records.len(),
        2,
        "We could only test for one record for now and the last is the final one",
    );
    let mut record = emulator.records[0].clone();
    assert!(record.memory_initialize_events.is_empty());
    assert!(record.memory_finalize_events.is_empty());
    emulator.records[1]
        .memory_initialize_events
        .clone_into(&mut record.memory_initialize_events);
    emulator.records[1]
        .memory_finalize_events
        .clone_into(&mut record.memory_finalize_events);
    let program = record.program.clone();

    // for debugging emulator
    //for rcd in &emulator.records {
    //    debug!("record events: {:?}", rcd.stats());
    //}
    debug!("final record events: {:?}", record.stats());

    let mut records = vec![record];

    // Setup config and chips.
    info!(
        "\n Creating BaseMachine (at {} ms)..",
        start.elapsed().unwrap().as_millis()
    );
    let config = BabyBearPoseidon2::new();
    let chips = TestChipType::all_chips();

    // Create a new machine based on config and chips
    let simple_machine = SimpleMachine::new(config, chips);
    info!("{} created.", simple_machine.name());

    // Setup machine prover, verifier, pk and vk.
    info!(
        "\n Setup machine (at {} ms)..",
        start.elapsed().unwrap().as_millis()
    );
    let (pk, vk) = simple_machine.setup_keys(&program);

    info!(
        "\n Complement records (at {} ms)..",
        start.elapsed().unwrap().as_millis()
    );
    simple_machine.complement_record(&mut records);

    // Generate the proof.
    info!(
        "\n Generating proof (at {} ms)..",
        start.elapsed().unwrap().as_millis()
    );
    let proof = simple_machine.prove(&pk, &records);
    info!("{} generated.", proof.name());

    // Verify the proof.
    info!(
        "\n Verifying proof (at {} ms)..",
        start.elapsed().unwrap().as_millis()
    );
    let result = simple_machine.verify(&vk, &proof);
    info!(
        "The proof is verified: {} (at {} ms)..",
        result.is_ok(),
        start.elapsed().unwrap().as_millis()
    );
    assert_eq!(result.is_ok(), true);
}
