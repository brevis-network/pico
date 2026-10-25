use hashbrown::HashMap;
use p3_field::PrimeField32;
use p3_util::log2_ceil_usize;
use tracing::{debug, warn};

use crate::{
    chips::chips::{
        riscv_global::GlobalChip,
        riscv_memory::initialize_finalize::{
            MemoryChipType::{Finalize, Initialize},
            MemoryInitializeFinalizeChip,
        },
        syscall::SyscallChip,
    },
    configs::config::StarkGenericConfig,
    emulator::{record::RecordBehavior, riscv::record::EmulationRecord},
    instances::{
        chiptype::riscv_chiptype::RiscvChipType,
        compiler::shapes::riscv_shape::{
            precompile_rows_per_event, precompile_syscall_code, RiscvShapeConfig, RiscvShapeError,
        },
        preparer::EventCounter,
    },
    machine::{chip::ChipBehavior, field::FieldSpecificPoseidon2Config},
    primitives::consts::{
        ADD_DATAPAR, BITWISE_DATAPAR, DIVREM_DATAPAR, LOCAL_MEMORY_DATAPAR, LT_DATAPAR,
        MEMORY_RW_DATAPAR, MUL_DATAPAR, RISCV_POSEIDON2_DATAPAR, SLL_DATAPAR, SR_DATAPAR,
        SUB_DATAPAR,
    },
};

pub fn padding_shape<SC>(
    shape_config: &RiscvShapeConfig<SC::Val>,
    record: &mut EmulationRecord,
    counter: &EventCounter,
) -> Result<(), RiscvShapeError>
where
    SC: StarkGenericConfig + Send + 'static,
    SC::Val: Ord + PrimeField32 + FieldSpecificPoseidon2Config,
{
    debug!("-------RISCV Padding Shape with Counter------");
    if record.program.preprocessed_shape.is_none() {
        return Err(RiscvShapeError::PreprocessedShapeMissing);
    }
    if record.shape.is_some() {
        return Err(RiscvShapeError::ShapeAlreadyFixed);
    }

    // Set the shape of the chips with preprocessed shapes to match the preprocessed shape from the
    // program.
    record.shape.clone_from(&record.program.preprocessed_shape);

    // If CPU is included, try to fix the shape as a RISCV.
    if counter.num_cpu_events > 0 {
        // Get the heights of the core airs in the record.
        let heights = riscv_heights::<SC::Val>(counter);

        // Try to find a shape within the included shapes.
        for (i, allowed_log_heights) in shape_config.allowed_log_heights.iter().enumerate() {
            if let Some(shape) = RiscvShapeConfig::<SC::Val>::find_shape_from_allowed_heights(
                &heights,
                allowed_log_heights,
            ) {
                debug!(
                    "Chunk Lifted: Index={}, Cluster={}",
                    record.public_values.chunk, i
                );
                for (chip_name, height) in heights.iter() {
                    if shape.inner.contains_key(chip_name) {
                        debug!(
                            "Chip {:<20}: {:<3} -> {:<3}, height: {}",
                            chip_name,
                            log2_ceil_usize(*height),
                            shape.inner[chip_name],
                            height
                        );
                    } else if *height != 0 {
                        warn!(
                            "Unexpected: Chip {} not found in shape, height: {}, log size: {}",
                            chip_name,
                            height,
                            log2_ceil_usize(*height)
                        );
                    }
                }

                record.shape.as_mut().unwrap().extend(shape);
                return Ok(());
            }
        }

        // No shape found, so return an error.
        let log2_stats = modify_stats_with_log2(&record.stats());
        println!(
            "Cannot find shape for RISCV with heights {:?} and allowed log heights {:?}",
            heights, shape_config.allowed_log_heights
        );
        return Err(RiscvShapeError::ShapeError(log2_stats));
    }

    if counter.num_memory_initialize_events > 0 || counter.num_memory_finalize_events > 0 {
        let heights = get_memory_init_final_heights::<SC::Val>(counter);
        let shape = RiscvShapeConfig::<SC::Val>::find_shape_from_allowed_heights(
            &heights,
            &shape_config.memory_allowed_log_heights,
        )
        .ok_or(RiscvShapeError::ShapeError(modify_stats_with_log2(
            &record.stats(),
        )))?;
        for (chip_name, height) in heights.iter() {
            if shape.inner.contains_key(chip_name) {
                debug!(
                    "Chip {:<20}: {:<3} -> {:<3}",
                    chip_name,
                    log2_ceil_usize(*height),
                    shape.inner[chip_name],
                );
            } else {
                warn!(
                    "Unexpected: Chip {} not found in shape, log size: {}",
                    chip_name,
                    log2_ceil_usize(*height)
                );
            }
        }
        record.shape.as_mut().unwrap().extend(shape);
        return Ok(());
    }

    for (chip_name, (mem_events_per_row, allowed_log_heights)) in
        shape_config.precompile_allowed_log_heights.iter()
    {
        if let Some((precompile_events, mem_events, num_global_events)) =
            // RiscvChipType::<F>::get_precompile_heights(chip_name, record)
            get_precompile_heights(chip_name, counter)
        {
            for allowed_log_height in allowed_log_heights {
                if precompile_events <= (1usize << allowed_log_height) {
                    for shape in shape_config.get_precompile_shapes(
                        chip_name.clone(),
                        *mem_events_per_row,
                        *allowed_log_height,
                    ) {
                        let mem_events_height = shape[2].1;
                        let global_events_height = shape[3].1;
                        if mem_events <= (1 << mem_events_height) * LOCAL_MEMORY_DATAPAR
                            // Strict: the Global trace's last row must be padding.
                            && num_global_events < (1 << global_events_height)
                        {
                            debug!(
                                "Chunk Lifted: Precompile={}, AllowedLogHeight={}",
                                chip_name, allowed_log_height
                            );

                            let old_height_log = log2_ceil_usize(precompile_events);
                            let new_height_log = allowed_log_height;

                            let old_mem_events_log =
                                log2_ceil_usize(mem_events.div_ceil(LOCAL_MEMORY_DATAPAR));
                            let new_mem_events_log = mem_events_height;

                            let old_global_events_log = log2_ceil_usize(num_global_events + 1);
                            let new_global_events_log = global_events_height;

                            debug!(
                                "Chip {:<20}: precompile height: {:<3} -> {:<3}",
                                chip_name, old_height_log, new_height_log
                            );
                            debug!(
                                "Chip {:<20}: mem local height  : {:<3} -> {:<3}",
                                chip_name, old_mem_events_log, new_mem_events_log
                            );
                            debug!(
                                "Chip {:<20}: global height: {:<3} -> {:<3}",
                                chip_name, old_global_events_log, new_global_events_log
                            );

                            record.shape.as_mut().unwrap().extend(shape);
                            return Ok(());
                        }
                    }
                }
            }
            warn!(
                    "Cannot find shape for precompile {:?}, precompile_events {:?}, and mem events {:?}",
                    chip_name, precompile_events, mem_events
                );
            return Err(RiscvShapeError::ShapeError(modify_stats_with_log2(
                &record.stats(),
            )));
        }
    }

    Err(RiscvShapeError::PrecompileNotIncluded(
        modify_stats_with_log2(&record.stats()),
    ))
}

/// Get the heights of the chips for a given execution record.
fn riscv_heights<F>(counter: &EventCounter) -> Vec<(String, usize)>
where
    F: PrimeField32 + FieldSpecificPoseidon2Config,
{
    // let num_global_events =
    // 2 * record.get_local_mem_events().count() + record.syscall_events.len();
    vec![
        (
            RiscvChipType::<F>::Cpu(Default::default()).name(),
            counter.num_cpu_events,
            // record.cpu_events.len(),
        ),
        (
            RiscvChipType::<F>::DivRem(Default::default()).name(),
            // record.divrem_events.len().div_ceil(DIVREM_DATAPAR),
            counter.num_divrem_events.div_ceil(DIVREM_DATAPAR),
        ),
        (
            RiscvChipType::<F>::Add(Default::default()).name(),
            counter.num_add_sub_events.div_ceil(ADD_DATAPAR),
        ),
        (
            RiscvChipType::<F>::Sub(Default::default()).name(),
            counter.num_add_sub_events.div_ceil(SUB_DATAPAR),
        ),
        (
            RiscvChipType::<F>::Bitwise(Default::default()).name(),
            // record.bitwise_events.len().div_ceil(BITWISE_DATAPAR),
            counter.num_bitwise_events.div_ceil(BITWISE_DATAPAR),
        ),
        (
            RiscvChipType::<F>::Mul(Default::default()).name(),
            // record.mul_events.len().div_ceil(MUL_DATAPAR),
            counter.num_mul_events.div_ceil(MUL_DATAPAR),
        ),
        (
            RiscvChipType::<F>::SR(Default::default()).name(),
            // record.shift_right_events.len().div_ceil(SR_DATAPAR),
            counter.num_shift_right_events.div_ceil(SR_DATAPAR),
        ),
        (
            RiscvChipType::<F>::SLL(Default::default()).name(),
            // record.shift_left_events.len().div_ceil(SLL_DATAPAR),
            counter.num_shift_left_events.div_ceil(SLL_DATAPAR),
        ),
        (
            RiscvChipType::<F>::Lt(Default::default()).name(),
            // record.lt_events.len().div_ceil(LT_DATAPAR),
            counter.num_lt_events.div_ceil(LT_DATAPAR),
        ),
        (
            RiscvChipType::<F>::MemoryLocal(Default::default()).name(),
            // record
            //     .get_local_mem_events()
            //     .count()
            //     .div_ceil(LOCAL_MEMORY_DATAPAR),
            counter
                .num_cpu_local_memory_access
                .div_ceil(LOCAL_MEMORY_DATAPAR),
        ),
        (
            RiscvChipType::<F>::MemoryReadWrite(Default::default()).name(),
            // record
            //     .cpu_events
            //     .iter()
            //     .filter(|e| e.instruction.is_memory_instruction())
            //     .count()
            //     .div_ceil(MEMORY_RW_DATAPAR),
            counter.num_memory_read_writes.div_ceil(MEMORY_RW_DATAPAR),
        ),
        (
            RiscvChipType::<F>::Global(Default::default()).name(),
            counter.num_global_lookup_events + 1,
        ),
        (
            <F as FieldSpecificPoseidon2Config>::riscv_poseidon2_name().to_string(),
            (counter.num_global_lookup_events + 1).div_ceil(RISCV_POSEIDON2_DATAPAR),
        ),
        (
            RiscvChipType::<F>::SyscallRiscv(SyscallChip::riscv()).name(),
            // record.syscall_events.len(),
            counter.num_syscall_events,
        ),
    ]
}

fn modify_stats_with_log2(stats: &HashMap<String, usize>) -> HashMap<String, usize> {
    stats
        .iter()
        .map(|(key, &value)| {
            let log_value = if value > 0 {
                (value as f64).log2().ceil() as usize
            } else {
                0 // log2(0) is undefined; handle it as 0
            };
            (key.clone(), log_value)
        })
        .collect()
}

fn get_memory_init_final_heights<F>(counter: &EventCounter) -> Vec<(String, usize)>
where
    F: PrimeField32 + FieldSpecificPoseidon2Config,
{
    // TODO: check and change this later
    let num_global_events =
        counter.num_memory_finalize_events + counter.num_memory_initialize_events;
    vec![
        (
            RiscvChipType::<F>::MemoryInitialize(MemoryInitializeFinalizeChip::new(Initialize))
                .name(),
            // record.memory_initialize_events.len(),
            counter.num_memory_initialize_events,
        ),
        (
            RiscvChipType::<F>::MemoryFinalize(MemoryInitializeFinalizeChip::new(Finalize)).name(),
            // record.memory_finalize_events.len(),
            counter.num_memory_finalize_events,
        ),
        (
            RiscvChipType::<F>::Global(GlobalChip::default()).name(),
            num_global_events + 1,
        ),
        (
            <F as FieldSpecificPoseidon2Config>::riscv_poseidon2_name().to_string(),
            // Must be div_ceil, matching the trace side: `RiscvPoseidon2Chip::generate_main`
            // computes its height as `events.len().div_ceil(RISCV_POSEIDON2_DATAPAR)`. Plain
            // division truncates, so a count that is not a multiple of the datapar width picks a
            // shape one row short and the generated trace does not fit it.
            (num_global_events + 1).div_ceil(RISCV_POSEIDON2_DATAPAR),
        ),
    ]
}

/// Get the height of the corresponding precompile chip.
///
/// If the precompile is not included in the record, returns `None`. Otherwise, returns
/// `Some(num_rows, num_local_mem_events, num_global_events)`, where `num_rows` is the number of rows of the
/// corresponding chip, `num_local_mem_events` is the number of local memory events, and `num_global_events`
/// is the number of global lookup events
fn get_precompile_heights(
    chip_name: &str,
    counter: &EventCounter,
) -> Option<(usize, usize, usize)> {
    // record
    //     .precompile_events
    //     .get_events(precompile_syscall_code(chip_name))
    //     .filter(|events| !events.is_empty())
    //     .map(|events| {
    //         (
    //             events.len() * precompile_rows_per_event(chip_name),
    //             events.get_local_mem_events().into_iter().count(),
    //             record.global_lookup_events.len(),
    //         )
    //     })
    let syscall_code = precompile_syscall_code(chip_name);
    let num_events = counter.get_precompile_event_num(syscall_code);
    if num_events == 0 {
        return None;
    }
    Some((
        num_events * precompile_rows_per_event(chip_name),
        counter.get_precomplie_local_mem_event_num(syscall_code),
        counter.num_global_lookup_events,
    ))
}
