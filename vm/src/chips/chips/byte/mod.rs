use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod event;
pub mod traces;
pub mod utils;

/// A chip for computing byte operations.
///
/// The chip contains a preprocessed table of all possible byte operations. Other chips can then
/// use lookups into this table to compute their own operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct ByteChip<F>(PhantomData<F>);

#[cfg(test)]
pub(crate) mod tests {
    use crate::{
        chips::chips::byte::ByteChip,
        compiler::riscv::{
            compiler::{Compiler, SourceType},
            program::Program,
        },
        configs::stark_config::KoalaBearPoseidon2,
        emulator::{
            emulator::MetaEmulator, opts::EmulatorOpts, riscv::record::EmulationRecord,
            stdin::EmulatorStdin,
        },
        instances::{chiptype::riscv_chiptype::RiscvChipType, machine::riscv::RiscvMachine},
        machine::{chip::ChipBehavior, machine::MachineBehavior, witness::ProvingWitness},
        primitives::consts::RISCV_NUM_PVS,
    };
    use p3_koala_bear::KoalaBear;
    use std::{fs, path::PathBuf};

    type F = KoalaBear;

    #[allow(dead_code)]
    pub(crate) enum TestElf {
        Fib,
        Reth,
    }

    impl TestElf {
        fn elf(&self) -> Vec<u8> {
            let filename = match self {
                Self::Fib => "fibonacci-elf",
                Self::Reth => "reth-elf",
            };
            let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            ["..", "perf", "bench_data", filename]
                .iter()
                .for_each(|dir| path.push(dir));

            fs::read(path).unwrap()
        }
    }

    #[allow(dead_code)]
    pub(crate) enum TestInput {
        Fib(u32),
        Reth171,
        Reth188,
    }

    impl TestInput {
        fn input_bytes(&self) -> Vec<u8> {
            match self {
                Self::Fib(n) => bincode::serialize(n).unwrap(),
                Self::Reth171 => {
                    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
                    ["..", "perf", "bench_data", "reth-17106222.bin"]
                        .iter()
                        .for_each(|dir| path.push(dir));

                    fs::read(path).unwrap()
                }
                Self::Reth188 => {
                    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
                    ["..", "perf", "bench_data", "reth-18884864.bin"]
                        .iter()
                        .for_each(|dir| path.push(dir));

                    fs::read(path).unwrap()
                }
            }
        }
    }

    #[test]
    fn test_byte_chip_trace_benchmark() {
        println!("creating machine");
        let machine = RiscvMachine::new(
            KoalaBearPoseidon2::default(),
            RiscvChipType::all_chips(),
            RISCV_NUM_PVS,
        );
        println!("creating byte chip");
        let chip: ByteChip<F> = ByteChip::default();
        println!("generating chunks");
        let mut chunks = generate_record(TestElf::Reth, TestInput::Reth188);
        machine.complement_record(&mut chunks);

        let mut old_durations = vec![];
        let mut new_durations = vec![];
        for (i, chunk) in chunks.iter().enumerate() {
            println!("chunk-{i} has {} byte lookups", chunk.byte_lookups.len());

            println!("old generate_main for chunk-{i}");
            let start = std::time::Instant::now();
            let old_trace = chip.generate_main(chunk, &mut EmulationRecord::default());
            old_durations.push(start.elapsed());

            println!("new generate_main for chunk-{i}");
            let start = std::time::Instant::now();
            let new_trace = chip.generate_main_new(chunk, &mut EmulationRecord::default());
            new_durations.push(start.elapsed());

            assert_eq!(old_trace.values.len(), new_trace.values.len());
            assert_eq!(old_trace, new_trace);
        }

        let old_total: std::time::Duration = old_durations.iter().sum();
        let new_total: std::time::Duration = new_durations.iter().sum();

        println!(
            "[byte-chip] old_total = {:?}, new_total = {:?}",
            old_total, new_total,
        );
    }

    pub(crate) fn generate_record(elf: TestElf, input: TestInput) -> Vec<EmulationRecord> {
        let elf = elf.elf();

        let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder();
        let input_bytes = input.input_bytes();
        stdin_builder.write_slice(&input_bytes);
        let stdin = stdin_builder.finalize();

        let program = Compiler::new(SourceType::RISCV, &elf).compile();
        let machine = RiscvMachine::new(
            KoalaBearPoseidon2::default(),
            RiscvChipType::all_chips(),
            RISCV_NUM_PVS,
        );
        let (pk, vk) = machine.setup_keys(&program);
        let witness = ProvingWitness::<KoalaBearPoseidon2, RiscvChipType<F>, _>::setup_for_riscv(
            program,
            stdin,
            EmulatorOpts::bench_riscv_ops(),
            pk,
            vk,
        );
        let mut emulator = MetaEmulator::setup_riscv(&witness);
        let mut records = vec![];
        emulator.next_record_batch(&mut |r| records.push(r));

        records
    }
}
