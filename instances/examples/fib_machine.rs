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
use std::time::SystemTime;

pub enum FibChipType<F: Field> {
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

// NOTE: These trait implementations are used to save this `FibChipType` to `MetaChip`.
// Since MetaChip has a generic parameter which is one type (cannot be two chip types).
// This code is annoyed, we could refactor to use macro later (but less readable).
impl<F: PrimeField32> ChipBehavior<F> for FibChipType<F> {
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

impl<F: Field> BaseAir<F> for FibChipType<F> {
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

impl<F, CB> Air<CB> for FibChipType<F>
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

impl<F: PrimeField32> FibChipType<F> {
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

fn pars_args(args: Vec<String>) -> PicoStdin {
    let mut n = 2; // default fib seq num is 2
    if args.len() > 1 {
        n = args[1].parse::<u32>().unwrap();
    }
    let mut stdin = PicoStdin::new();
    stdin.write(&n);

    let mut input = [0u8; 4];
    stdin.read_slice(&mut input);

    debug!("n={}, {:x?}", n, &input);
    stdin
}

// Emulate the Fibonacci.
fn emulate_fibonacci(n: u32) -> RiscvEmulator {
    const FIBONACCI_ELF: &[u8] =
        include_bytes!("../../compiler/test_data/riscv32im-pico-fibonacci-elf");

    info!("\n Creating Fibonacci Program..");
    let compiler = Compiler::new(SourceType::RiscV, FIBONACCI_ELF);
    let program = compiler.compile();

    info!("\n Creating Fibonacci Runtime..");
    let mut runtime = RiscvEmulator::new(program, PicoCoreOpts::default());

    let mut stdin = PicoStdin::new();
    stdin.write(&n);
    runtime.run_with_stdin(stdin).unwrap();

    runtime
}

// Emulate the Keccak.
fn emulate_keccak(input_num: usize) -> RiscvEmulator {
    const KECCAK_ELF: &[u8] = include_bytes!("../../compiler/test_data/riscv32im-pico-keccak-elf");

    // Generate the random Keccak input.
    let rng = &mut thread_rng();
    let keccak_input: String = rng
        .sample_iter(&Alphanumeric)
        .take(input_num)
        .map(char::from)
        .collect();

    info!("\n Creating Fibonacci Program..");
    let compiler = Compiler::new(SourceType::RiscV, KECCAK_ELF);
    let program = compiler.compile();

    info!("\n Creating Runtime..");
    let mut runtime = RiscvEmulator::new(program, PicoCoreOpts::default());

    let mut stdin = PicoStdin::new();
    stdin.write(&keccak_input);
    runtime.run_with_stdin(stdin).unwrap();

    runtime
}

fn main() {
    const FIBONACCI_INPUT: u32 = 836789;
    // const KECCAK_INPUT_NUM: usize = 20000;
    const KECCAK_INPUT_NUM: usize = 2;

    env_logger::init();
    let start = SystemTime::now();

    // emulate_fibonacci(FIBONACCI_INPUT);
    let runtime = emulate_keccak(KECCAK_INPUT_NUM);

    // TRICKY: We copy the memory initialize and finalize events from the seond (last)
    // record to this record, since the memory lookups could only work if has the
    // full lookups in the all records.
    assert_eq!(
        runtime.records.len(),
        2,
        "We could only test for one record for now and the last is the final one",
    );
    let mut record = runtime.records[0].clone();
    assert!(record.memory_initialize_events.is_empty());
    assert!(record.memory_finalize_events.is_empty());
    runtime.records[1]
        .memory_initialize_events
        .clone_into(&mut record.memory_initialize_events);
    runtime.records[1]
        .memory_finalize_events
        .clone_into(&mut record.memory_finalize_events);
    let program = record.program.clone();

    let mut records = vec![record];

    // Setup config and chips.
    info!(
        "\n Creating BaseMachine (at {} sec)..",
        start.elapsed().unwrap().as_secs()
    );
    let config = BabyBearPoseidon2::new();
    let chips = FibChipType::all_chips();

    // Create a new machine based on config and chips
    let simple_machine = SimpleMachine::new(config, chips);
    info!("{} created.", simple_machine.name());

    // Setup machine prover, verifier, pk and vk.
    info!(
        "\n Setup machine (at {} sec)..",
        start.elapsed().unwrap().as_secs()
    );
    let (pk, vk) = simple_machine.setup_keys(&program);

    info!(
        "\n Complement records (at {} sec)..",
        start.elapsed().unwrap().as_secs()
    );
    simple_machine.complement_record(&mut records);

    // Generate the proof.
    info!(
        "\n Generating proof (at {} sec)..",
        start.elapsed().unwrap().as_secs()
    );
    let proof = simple_machine.prove(&pk, &records);
    info!("{} generated.", proof.name());

    // Verify the proof.
    info!(
        "\n Verifying proof (at {} sec)..",
        start.elapsed().unwrap().as_secs()
    );
    let result = simple_machine.verify(&vk, &proof);
    info!("The proof is verified: {}", result.is_ok());
    assert_eq!(result.is_ok(), true);
}
