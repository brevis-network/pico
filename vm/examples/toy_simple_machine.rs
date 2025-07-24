use p3_air::{Air, BaseAir};
use p3_baby_bear::BabyBear;
use p3_field::{Field, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_mersenne_31::Mersenne31;
use pico_vm::{
    chips::chips::toys::toy::ToyChip,
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::config::StarkGenericConfig,
    emulator::{
        opts::EmulatorOpts,
        riscv::{record::EmulationRecord, riscv_emulator::RiscvEmulator},
    },
    instances::{
        configs::{
            riscv_bb_poseidon2::StarkConfig as RiscvBBSC,
            riscv_kb_poseidon2::StarkConfig as RiscvKBSC,
            riscv_m31_poseidon2::StarkConfig as RiscvM31SC,
        },
        machine::simple::SimpleMachine,
    },
    machine::{
        builder::ChipBuilder,
        chip::{ChipBehavior, MetaChip},
        logger::setup_logger,
        machine::MachineBehavior,
    },
    primitives::consts::RISCV_NUM_PVS,
};
use tracing::info;

use pico_vm::machine::witness::ProvingWitness;

#[path = "common/parse_args.rs"]
mod parse_args;

pub enum ToyChipType<F: Field> {
    Toy(ToyChip<F>),
}

// NOTE: These trait implementations are used to save this `ToyChipType` to `MetaChip`.
// Since MetaChip has a generic parameter which is one type (cannot be two chip types).
// This code is annoyed, we could refactor to use macro later (but less readable).
impl<F: PrimeField32> ChipBehavior<F> for ToyChipType<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        match self {
            Self::Toy(chip) => chip.name(),
        }
    }

    fn generate_preprocessed(&self, program: &Program) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Toy(chip) => chip.generate_preprocessed(program),
        }
    }

    fn generate_main(&self, input: &Self::Record, output: &mut Self::Record) -> RowMajorMatrix<F> {
        match self {
            Self::Toy(chip) => chip.generate_main(input, output),
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Toy(chip) => chip.preprocessed_width(),
        }
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        match self {
            Self::Toy(chip) => chip.is_active(record),
        }
    }
}

impl<F: Field> BaseAir<F> for ToyChipType<F> {
    fn width(&self) -> usize {
        match self {
            Self::Toy(chip) => chip.width(),
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Toy(chip) => chip.preprocessed_trace(),
        }
    }
}

impl<F, CB> Air<CB> for ToyChipType<F>
where
    F: Field,
    CB: ChipBuilder<F>,
{
    fn eval(&self, b: &mut CB) {
        match self {
            Self::Toy(chip) => chip.eval(b),
        }
    }
}

impl<F: PrimeField32> ToyChipType<F> {
    pub fn all_chips() -> Vec<MetaChip<F, Self>> {
        vec![MetaChip::new(Self::Toy(ToyChip::default()))]
    }
}

fn main() {
    setup_logger();

    info!("Setting-up..");
    let (elf, _, _) = parse_args::parse_args();
    let compiler = Compiler::new(SourceType::RISCV, elf);

    /*
    KoalaBear Test
    */
    info!("\n *********** Testing for KoalaBear ***********");
    let program = compiler.compile();
    let mut runtime =
        RiscvEmulator::new_single::<KoalaBear>(program, EmulatorOpts::default(), None);
    runtime.state.input_stream.push(vec![2, 0, 0, 0]);
    let batch_records = runtime.run(None).unwrap();

    let record = &batch_records[0];
    let mut records = vec![record.clone(), record.clone()];

    // Setup config and chips.
    info!("Creating SimpleMachine..");
    let config = RiscvKBSC::new();
    let chips = ToyChipType::all_chips();

    // Create a new machine based on config and chips
    let simple_machine = SimpleMachine::new(config, chips, RISCV_NUM_PVS);

    // Setup machine prover, verifier, pk and vk.
    let (pk, vk) = simple_machine.setup_keys(&record.program);

    simple_machine.complement_record(&mut records);

    let witness = ProvingWitness::setup_with_keys_and_records(pk, vk.clone(), records);

    // Generate the proof.
    info!("Generating proof..");
    let proof = simple_machine.prove(&witness);

    // Verify the proof.
    info!("Verifying proof..");
    let result = simple_machine.verify(&proof, &vk);
    info!("The proof is verified: {}", result.is_ok());

    assert!(result.is_ok());

    /*
    BabyBear Test
    */
    info!("\n *********** Testing for BabyBear ***********");
    let program = compiler.compile();
    let mut runtime = RiscvEmulator::new_single::<BabyBear>(program, EmulatorOpts::default(), None);
    runtime.state.input_stream.push(vec![2, 0, 0, 0]);
    let batch_records = runtime.run(None).unwrap();

    let record = &batch_records[0];
    let mut records = vec![record.clone(), record.clone()];

    // Setup config and chips.
    info!("Creating SimpleMachine..");
    let config = RiscvBBSC::new();
    let chips = ToyChipType::all_chips();

    // Create a new machine based on config and chips
    let simple_machine = SimpleMachine::new(config, chips, RISCV_NUM_PVS);

    // Setup machine prover, verifier, pk and vk.
    let (pk, vk) = simple_machine.setup_keys(&record.program);

    simple_machine.complement_record(&mut records);

    let witness = ProvingWitness::setup_with_keys_and_records(pk, vk.clone(), records);

    // Generate the proof.
    info!("Generating proof..");
    let proof = simple_machine.prove(&witness);

    // Verify the proof.
    info!("Verifying proof..");
    let result = simple_machine.verify(&proof, &vk);
    info!("The proof is verified: {}", result.is_ok());

    assert!(result.is_ok());

    /*
    Mersenne31 Test
    */
    info!("\n *********** Testing for Mersenne31 ***********");
    let program = compiler.compile();
    let mut runtime =
        RiscvEmulator::new_single::<Mersenne31>(program, EmulatorOpts::default(), None);
    runtime.state.input_stream.push(vec![2, 0, 0, 0]);
    let batch_records = runtime.run(None).unwrap();

    let record = &batch_records[0];
    let mut records = vec![record.clone(), record.clone()];

    // Setup config and chips.
    info!("Creating SimpleMachine..");
    let config = RiscvM31SC::new();
    let chips = ToyChipType::all_chips();

    // Create a new machine based on config and chips
    let simple_machine = SimpleMachine::new(config, chips, RISCV_NUM_PVS);

    // Setup machine prover, verifier, pk and vk.
    let (pk, vk) = simple_machine.setup_keys(&record.program);

    simple_machine.complement_record(&mut records);

    let witness = ProvingWitness::setup_with_keys_and_records(pk, vk.clone(), records);

    // Generate the proof.
    info!("Generating proof..");
    let proof = simple_machine.prove(&witness);

    // Verify the proof.
    info!("Verifying proof..");
    let result = simple_machine.verify(&proof, &vk);
    info!("The proof is verified: {}", result.is_ok());
}
