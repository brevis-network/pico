use std::{marker::PhantomData, sync::Arc};

use crate::{
    instances::compiler::shapes::ProofShape, machine::field::FieldSpecificPoseidon2Config,
};
use hashbrown::{HashMap, HashSet};
use itertools::Itertools;
use p3_field::PrimeField;
use serde::{Deserialize, Serialize};

use crate::{
    chips::chips::{
        alu::{
            add_sub::AddSubChip, bitwise::BitwiseChip, divrem::DivRemChip, lt::LtChip,
            mul::MulChip, sll::SLLChip, sr::traces::ShiftRightChip,
        },
        byte::ByteChip,
        riscv_cpu::CpuChip,
        riscv_global::GlobalChip,
        riscv_memory::{
            initialize_finalize::{
                MemoryChipType::{Finalize, Initialize},
                MemoryInitializeFinalizeChip,
            },
            local::MemoryLocalChip,
            read_write::MemoryReadWriteChip,
        },
        riscv_program::ProgramChip,
        syscall::SyscallChip,
    },
    compiler::riscv::program::Program,
    emulator::{
        record::RecordBehavior,
        riscv::{record::EmulationRecord, syscalls::SyscallCode},
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::chip::ChipBehavior,
    primitives::consts::{LOCAL_MEMORY_DATAPAR, RISCV_POSEIDON2_DATAPAR},
};
use p3_field::PrimeField32;
use p3_util::log2_ceil_usize;
use thiserror::Error;
use tracing::{debug, warn};

/// The shape of a riscv proof.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RiscvPadShape {
    /// Keys are the chip names and values are the log-heights of the chips.
    pub inner: HashMap<String, usize>,
}

impl RiscvPadShape {
    /// Create a dummy program with this shape.
    ///
    /// This can be used to generate a dummy preprocessed traces.
    #[must_use]
    pub fn dummy_program(&self) -> Program {
        let mut program = Program::new(vec![], 1 << 5, 1 << 5);
        program.preprocessed_shape = Some(self.clone());
        program
    }

    /// Create a dummy execution record with this shape.
    ///
    /// This can be used to generate dummy traces.
    #[must_use]
    pub fn dummy_record(&self) -> EmulationRecord {
        let program = Arc::new(self.dummy_program());
        let mut record = EmulationRecord::new(program);
        record.shape = Some(self.clone());
        record
    }

    /// Determines whether the execution record contains a trace for a given chip.
    pub fn included<F: PrimeField, CB: ChipBehavior<F>>(&self, air: &CB) -> bool {
        self.inner.contains_key(&air.name())
    }
}

impl Extend<RiscvPadShape> for RiscvPadShape {
    fn extend<T: IntoIterator<Item = RiscvPadShape>>(&mut self, iter: T) {
        for shape in iter {
            self.inner.extend(shape.inner);
        }
    }
}

impl Extend<(String, usize)> for RiscvPadShape {
    fn extend<T: IntoIterator<Item = (String, usize)>>(&mut self, iter: T) {
        self.inner.extend(iter);
    }
}

impl IntoIterator for RiscvPadShape {
    type Item = (String, usize);

    type IntoIter = hashbrown::hash_map::IntoIter<String, usize>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl FromIterator<(String, usize)> for RiscvPadShape {
    fn from_iter<T: IntoIterator<Item = (String, usize)>>(iter: T) -> Self {
        Self {
            inner: iter.into_iter().collect(),
        }
    }
}

impl From<ProofShape> for RiscvPadShape {
    fn from(value: ProofShape) -> Self {
        Self {
            inner: value.into_iter().collect(),
        }
    }
}

impl From<RiscvPadShape> for ProofShape {
    fn from(value: RiscvPadShape) -> Self {
        value.inner.into_iter().collect()
    }
}

impl PartialOrd for RiscvPadShape {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let set = self.inner.keys().collect::<HashSet<_>>();
        let other_set = other.inner.keys().collect::<HashSet<_>>();

        if set.is_subset(&other_set) {
            let mut less_seen = false;
            let mut greater_seen = false;
            for (name, &height) in self.inner.iter() {
                let other_height = other.inner[name];
                match height.cmp(&other_height) {
                    std::cmp::Ordering::Less => less_seen = true,
                    std::cmp::Ordering::Greater => greater_seen = true,
                    std::cmp::Ordering::Equal => {}
                }
            }
            if less_seen && greater_seen {
                return None;
            }

            if less_seen {
                return Some(std::cmp::Ordering::Less);
            }
        }

        if other_set.is_subset(&set) {
            let mut less_seen = false;
            let mut greater_seen = false;
            for (name, &height) in other.inner.iter() {
                let other_height = self.inner[name];
                match height.cmp(&other_height) {
                    std::cmp::Ordering::Less => less_seen = true,
                    std::cmp::Ordering::Greater => greater_seen = true,
                    std::cmp::Ordering::Equal => {}
                }
            }

            if less_seen && greater_seen {
                return None;
            }

            if greater_seen {
                return Some(std::cmp::Ordering::Greater);
            }
        }

        None
    }
}

#[derive(Debug, Error)]
pub enum RiscvShapeError {
    #[error("no preprocessed shape found")]
    PreprocessedShapeError,
    #[error("Preprocessed shape already fixed")]
    PreprocessedShapeAlreadyFixed,
    #[error("no shape found {0:?}")]
    ShapeError(HashMap<String, usize>),
    #[error("Preprocessed shape missing")]
    PreprocessedShapeMissing,
    #[error("Shape already fixed")]
    ShapeAlreadyFixed,
    #[error("Precompile not included in allowed shapes {0:?}")]
    PrecompileNotIncluded(HashMap<String, usize>),
}

// helper functions

// TODO: remove hardcode chip_names here
pub(crate) fn precompile_rows_per_event(chip_name: &str) -> usize {
    match chip_name {
        "ShaCompress" => 80,
        "ShaExtend" => 48,
        "KeccakPermute" => 24,
        _ => 1,
    }
}

// TODO: remove hardcode chip_names here
pub(crate) fn precompile_syscall_code(chip_name: &str) -> SyscallCode {
    match chip_name {
        "Bls12381AddAssign" => SyscallCode::BLS12381_ADD,
        "Bn254AddAssign" => SyscallCode::BN254_ADD,
        "Bn254DoubleAssign" => SyscallCode::BN254_DOUBLE,
        "Bn254FpOp" => SyscallCode::BN254_FP_ADD,
        "Bn254Fp2AddSub" => SyscallCode::BN254_FP2_ADD,
        "Bn254Fp2Mul" => SyscallCode::BN254_FP2_MUL,
        "EdAddAssign" => SyscallCode::ED_ADD,
        "EdDecompress" => SyscallCode::ED_DECOMPRESS,
        "KeccakPermute" => SyscallCode::KECCAK_PERMUTE,
        "Secp256k1AddAssign" => SyscallCode::SECP256K1_ADD,
        "Secp256k1DoubleAssign" => SyscallCode::SECP256K1_DOUBLE,
        "ShaCompress" => SyscallCode::SHA_COMPRESS,
        "ShaExtend" => SyscallCode::SHA_EXTEND,
        "Uint256MulMod" => SyscallCode::UINT256_MUL,
        "Bls12381Decompress" => SyscallCode::BLS12381_DECOMPRESS,
        "Secp256k1Decompress" => SyscallCode::SECP256K1_DECOMPRESS,
        "Bls12381DoubleAssign" => SyscallCode::BLS12381_DOUBLE,
        "Bls381FpOp" => SyscallCode::BLS12381_FP_ADD,
        "Bls381Fp2Mul" => SyscallCode::BLS12381_FP2_MUL,
        "Bls381Fp2AddSub" => SyscallCode::BLS12381_FP2_ADD,
        "Secp256k1FpOp" => SyscallCode::SECP256K1_FP_ADD,
        "Poseidon2Permute" => SyscallCode::POSEIDON2_PERMUTE,
        _ => {
            unreachable!("precompile {} not supported yet", chip_name);
        }
    }
}

fn filter_shapes<F: FieldSpecificPoseidon2Config>(
    shapes: impl Iterator<Item = ProofShape>,
) -> impl Iterator<Item = ProofShape> {
    shapes.filter(|shape| {
        // Extract the names and heights for Global and Poseidon2Riscv
        let global_height = shape
            .chip_information
            .iter()
            .find(|(name, _)| *name == "Global")
            .map(|(_, height)| *height);

        let poseidon2_height = shape
            .chip_information
            .iter()
            .find(|(name, _)| name == <F as FieldSpecificPoseidon2Config>::riscv_poseidon2_name())
            .map(|(_, height)| *height);

        match (global_height, poseidon2_height) {
            (Some(global), Some(poseidon2)) if global == poseidon2 + 2 => true,
            (None, None) => true,
            _ => false,
        }
    })
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

fn add_none_if_missing(shapes: &mut [RiscvShapeSpec]) {
    for shape in shapes.iter_mut() {
        if !shape.add_sub_height.contains(&None) {
            shape.add_sub_height.insert(0, None);
        }
        if !shape.lt_height.contains(&None) {
            shape.lt_height.insert(0, None);
        }
        if !shape.memory_local_height.contains(&None) {
            shape.memory_local_height.insert(0, None);
        }
        if !shape.syscall_riscv_height.contains(&None) {
            shape.syscall_riscv_height.insert(0, None);
        }
        if !shape.mul_height.contains(&None) {
            shape.mul_height.insert(0, None);
        }
        if !shape.divrem_height.contains(&None) {
            shape.divrem_height.insert(0, None);
        }
        if !shape.memory_read_write_height.contains(&None) {
            shape.memory_read_write_height.insert(0, None);
        }
        if !shape.bitwise_height.contains(&None) {
            shape.bitwise_height.insert(0, None);
        }
        if !shape.shift_left_height.contains(&None) {
            shape.shift_left_height.insert(0, None);
        }
        if !shape.shift_right_height.contains(&None) {
            shape.shift_right_height.insert(0, None);
        }
        if !shape.global_height.contains(&None) {
            shape.global_height.insert(0, None);
        }
        if !shape.riscv_poseidon2_height.contains(&None) {
            shape.riscv_poseidon2_height.insert(0, None);
        }
    }
}

/// A structure that enables fixing the shape of an EmulationRecord.
#[derive(Debug, Clone)]
pub struct RiscvShapeConfig<F> {
    included_shapes: Vec<HashMap<String, usize>>,
    allowed_preprocessed_log_heights: HashMap<String, Vec<Option<usize>>>,
    allowed_log_heights: Vec<HashMap<String, Vec<Option<usize>>>>,
    memory_allowed_log_heights: HashMap<String, Vec<Option<usize>>>,
    precompile_allowed_log_heights: HashMap<String, (usize, Vec<usize>)>,
    phantom_data: PhantomData<F>,
}

struct RiscvShapeSpec {
    cpu_height: Vec<Option<usize>>,
    add_sub_height: Vec<Option<usize>>,
    divrem_height: Vec<Option<usize>>,
    bitwise_height: Vec<Option<usize>>,
    mul_height: Vec<Option<usize>>,
    shift_right_height: Vec<Option<usize>>,
    shift_left_height: Vec<Option<usize>>,
    lt_height: Vec<Option<usize>>,
    memory_read_write_height: Vec<Option<usize>>,
    memory_local_height: Vec<Option<usize>>,
    syscall_riscv_height: Vec<Option<usize>>,
    riscv_poseidon2_height: Vec<Option<usize>>,
    global_height: Vec<Option<usize>>,
}

impl<F: PrimeField32 + FieldSpecificPoseidon2Config> RiscvShapeConfig<F> {
    /// Fix the preprocessed shape of the proof.
    pub fn padding_preprocessed_shape(&self, program: &mut Program) -> Result<(), RiscvShapeError> {
        if program.preprocessed_shape.is_some() {
            return Err(RiscvShapeError::PreprocessedShapeAlreadyFixed);
        }

        let heights = RiscvChipType::<F>::preprocessed_heights(program);
        let prep_shape =
            Self::find_shape_from_allowed_heights(&heights, &self.allowed_preprocessed_log_heights)
                .ok_or(RiscvShapeError::PreprocessedShapeError)?;

        debug!("-------------RISCV Padding Shape-------------");
        for (chip_name, height) in heights.iter() {
            if prep_shape.inner.contains_key(chip_name) {
                debug!(
                    "Chip {:<20}: {:<3} -> {:<3}",
                    chip_name,
                    log2_ceil_usize(*height),
                    prep_shape.inner[chip_name],
                );
            } else {
                warn!(
                    "Unexpected: Chip {} not found in preprocess shape, height: {}, log size: {}",
                    chip_name,
                    height,
                    log2_ceil_usize(*height)
                );
            }
        }

        program.preprocessed_shape = Some(prep_shape);
        Ok(())
    }

    #[inline]
    fn find_shape_from_allowed_heights(
        heights: &[(String, usize)],
        allowed_log_heights: &HashMap<String, Vec<Option<usize>>>,
    ) -> Option<RiscvPadShape> {
        let shape: Option<HashMap<String, usize>> = heights
            .iter()
            .map(|(chip_name, height)| {
                for maybe_allowed_log_height in
                    allowed_log_heights.get(chip_name).into_iter().flatten()
                {
                    let allowed_log_height = maybe_allowed_log_height.unwrap_or_default();
                    let allowed_height = if allowed_log_height != 0 {
                        1 << allowed_log_height
                    } else {
                        0
                    };
                    if *height == 0 && allowed_log_height != 0 {
                        continue;
                    }
                    if *height <= allowed_height {
                        return Some((chip_name.clone(), allowed_log_height));
                    }
                }
                None
            })
            .collect();

        let mut inner = shape?;
        inner.retain(|_, &mut value| value != 0);

        let shape = RiscvPadShape { inner };
        Some(shape)
    }

    /// Padding the shape of the proof.
    pub fn padding_shape(&self, record: &mut EmulationRecord) -> Result<(), RiscvShapeError> {
        debug!("-------------RISCV Padding Shape-------------");
        if record.program.preprocessed_shape.is_none() {
            return Err(RiscvShapeError::PreprocessedShapeMissing);
        }
        if record.shape.is_some() {
            return Err(RiscvShapeError::ShapeAlreadyFixed);
        }

        // Set the shape of the chips with preprocessed shapes to match the preprocessed shape from the
        // program.
        record.shape.clone_from(&record.program.preprocessed_shape);

        // If cpu is included, try to fix the shape as a riscv.
        if !record.cpu_events.is_empty() {
            // Get the heights of the core airs in the record.
            let heights = RiscvChipType::<F>::riscv_heights(record);

            // Try to find a shape within the included shapes.
            for (i, allowed_log_heights) in self.allowed_log_heights.iter().enumerate() {
                if let Some(shape) =
                    Self::find_shape_from_allowed_heights(&heights, allowed_log_heights)
                {
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
            return Err(RiscvShapeError::ShapeError(log2_stats));
        }

        // If the record is a global memory init/finalize record, try to fix the shape as such.
        if !record.memory_initialize_events.is_empty() || !record.memory_finalize_events.is_empty()
        {
            let heights = RiscvChipType::<F>::get_memory_init_final_heights(record);
            let shape =
                Self::find_shape_from_allowed_heights(&heights, &self.memory_allowed_log_heights)
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

        // Try to pad the shape as a precompile record.
        for (chip_name, (mem_events_per_row, allowed_log_heights)) in
            self.precompile_allowed_log_heights.iter()
        {
            if let Some((precompile_events, mem_events, num_global_events)) =
                RiscvChipType::<F>::get_precompile_heights(chip_name, record)
            {
                for allowed_log_height in allowed_log_heights {
                    if precompile_events <= (1usize << allowed_log_height) {
                        for shape in self.get_precompile_shapes(
                            chip_name.clone(),
                            *mem_events_per_row,
                            *allowed_log_height,
                        ) {
                            let mem_events_height = shape[2].1;
                            let global_events_height = shape[3].1;
                            if mem_events <= (1 << mem_events_height) * LOCAL_MEMORY_DATAPAR
                                && num_global_events <= (1 << global_events_height)
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

                                let old_global_events_log = log2_ceil_usize(num_global_events);
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
                        return Ok(());
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

    fn get_precompile_shapes(
        &self,
        chip_name: String,
        mem_events_per_row: usize,
        allowed_log_height: usize,
    ) -> Vec<[(String, usize); 5]> {
        // TODO: this is a temporary workaround to the precompile chunk shape
        // vec![1, precompile_rows_per_event(&chip_name)]
        // .into_iter()
        (1..=4 * precompile_rows_per_event(&chip_name))
            .rev()
            .map(|event_rows| {
                let num_local_mem_events =
                    ((1 << allowed_log_height) * mem_events_per_row).div_ceil(event_rows);
                let num_global_events = 2 * num_local_mem_events
                    + ((1 << allowed_log_height) as usize)
                        .div_ceil(precompile_rows_per_event(&chip_name));

                [
                    (chip_name.clone(), allowed_log_height),
                    (
                        SyscallChip::<F>::precompile().name(),
                        ((1usize << allowed_log_height)
                            .div_ceil(precompile_rows_per_event(&chip_name))
                            .next_power_of_two()
                            .ilog2() as usize)
                            .clamp(4, 23),
                    ),
                    (
                        MemoryLocalChip::<F>::default().name(),
                        (num_local_mem_events
                            .div_ceil(LOCAL_MEMORY_DATAPAR)
                            .next_power_of_two()
                            .ilog2() as usize)
                            .clamp(4, 23),
                    ),
                    (
                        RiscvChipType::<F>::Global(GlobalChip::default()).name(),
                        (num_global_events.next_power_of_two().ilog2() as usize).clamp(4, 23),
                    ),
                    (
                        <F as FieldSpecificPoseidon2Config>::riscv_poseidon2_name().to_string(),
                        (num_global_events
                            .div_ceil(RISCV_POSEIDON2_DATAPAR)
                            .next_power_of_two()
                            .ilog2() as usize)
                            .clamp(4, 21),
                    ),
                ]
            })
            .collect()
    }

    fn generate_all_shapes_from_allowed_log_heights(
        allowed_log_heights: impl IntoIterator<Item = (String, Vec<Option<usize>>)>,
    ) -> impl Iterator<Item = ProofShape> {
        // for chip in allowed_heights.
        allowed_log_heights
            .into_iter()
            .map(|(name, heights)| {
                heights
                    .into_iter()
                    .map(move |height| (name.clone(), height))
            })
            .multi_cartesian_product()
            .map(|iter| {
                iter.into_iter()
                    .filter_map(|(name, maybe_height)| {
                        maybe_height.map(|log_height| (name, log_height))
                    })
                    .collect::<ProofShape>()
            })
    }

    pub fn generate_all_allowed_shapes(&self) -> impl Iterator<Item = ProofShape> + '_ {
        let preprocessed_heights = self
            .allowed_preprocessed_log_heights
            .iter()
            .map(|(air_name, heights)| (air_name.clone(), heights.clone()));

        let mut memory_heights = self
            .memory_allowed_log_heights
            .iter()
            .map(|(air_name, heights)| (air_name.clone(), heights.clone()))
            .collect::<HashMap<_, _>>();
        memory_heights.extend(preprocessed_heights.clone());

        let included_shapes = self
            .included_shapes
            .iter()
            .cloned()
            .map(|map| map.into_iter().collect::<ProofShape>());

        let precompile_only_shapes = self.precompile_allowed_log_heights.iter().flat_map(
            move |(chip_name, (mem_events_per_row, allowed_log_heights))| {
                allowed_log_heights
                    .iter()
                    .flat_map(move |allowed_log_height| {
                        self.get_precompile_shapes(
                            chip_name.clone(),
                            *mem_events_per_row,
                            *allowed_log_height,
                        )
                    })
            },
        );

        let precompile_shapes =
            Self::generate_all_shapes_from_allowed_log_heights(preprocessed_heights.clone())
                .flat_map(move |preprocessed_shape| {
                    precompile_only_shapes.clone().map(move |precompile_shape| {
                        preprocessed_shape
                            .clone()
                            .into_iter()
                            .chain(precompile_shape)
                            .collect::<ProofShape>()
                    })
                });

        included_shapes
            .chain(filter_shapes::<F>(
                self.allowed_log_heights
                    .iter()
                    .flat_map(move |allowed_log_heights| {
                        Self::generate_all_shapes_from_allowed_log_heights({
                            let mut log_heights = allowed_log_heights
                                .iter()
                                .map(|(air_name, heights)| (air_name.clone(), heights.clone()))
                                .collect::<HashMap<_, _>>();
                            log_heights.extend(preprocessed_heights.clone());
                            log_heights
                        })
                    }),
            ))
            .chain(filter_shapes::<F>(
                Self::generate_all_shapes_from_allowed_log_heights(memory_heights),
            ))
            .chain(precompile_shapes)
    }
}

impl<F: PrimeField32 + FieldSpecificPoseidon2Config> Default for RiscvShapeConfig<F> {
    fn default() -> Self {
        // Preprocessed chip heights.
        let program_heights = vec![Some(19), Some(20), Some(22)];

        let allowed_preprocessed_log_heights = HashMap::from([
            (
                RiscvChipType::<F>::Program(ProgramChip::default()).name(),
                program_heights,
            ),
            (
                RiscvChipType::<F>::Byte(ByteChip::default()).name(),
                vec![Some(16)],
            ),
        ]);

        let mut riscv_shapes = [
            // small shapes
            RiscvShapeSpec {
                cpu_height: vec![Some(15)],
                add_sub_height: vec![Some(11)],
                lt_height: vec![Some(10)],
                bitwise_height: vec![Some(12)],
                shift_right_height: vec![Some(10)],
                shift_left_height: vec![Some(10)],
                syscall_riscv_height: vec![Some(10)],
                memory_local_height: vec![Some(10)],
                mul_height: vec![Some(10)],
                divrem_height: vec![Some(10)],
                memory_read_write_height: vec![Some(14)],
                global_height: vec![Some(12)],
                riscv_poseidon2_height: vec![Some(10)],
            },
            RiscvShapeSpec {
                cpu_height: vec![Some(19)],
                add_sub_height: vec![Some(16)],
                lt_height: vec![Some(17)],
                bitwise_height: vec![Some(18)],
                shift_right_height: vec![Some(18)],
                shift_left_height: vec![Some(18)],
                syscall_riscv_height: vec![Some(18)],
                memory_local_height: vec![Some(18)],
                mul_height: vec![Some(18)],
                divrem_height: vec![Some(18)],
                memory_read_write_height: vec![Some(18)],
                global_height: vec![Some(19)],
                riscv_poseidon2_height: vec![Some(17)],
            },
            // fibonacci
            RiscvShapeSpec {
                cpu_height: vec![Some(22)],
                add_sub_height: vec![Some(19)],
                lt_height: vec![Some(19)],
                bitwise_height: vec![Some(12)],
                shift_right_height: vec![Some(19)],
                shift_left_height: vec![Some(10)],
                syscall_riscv_height: vec![Some(10)],
                memory_local_height: vec![Some(12)],
                mul_height: vec![Some(19)],
                divrem_height: vec![Some(10)],
                memory_read_write_height: vec![Some(12)],
                global_height: vec![Some(10)],
                riscv_poseidon2_height: vec![Some(8)],
            },
            // reth
            RiscvShapeSpec {
                cpu_height: vec![Some(21), Some(22)],
                add_sub_height: vec![Some(19)],
                lt_height: vec![Some(19), Some(20)],
                bitwise_height: vec![Some(18), Some(19)],
                shift_right_height: vec![Some(17), Some(18)],
                shift_left_height: vec![Some(16), Some(17)],
                syscall_riscv_height: vec![Some(16)],
                memory_local_height: vec![Some(16), Some(18), Some(20)],
                mul_height: vec![Some(16)],
                divrem_height: vec![Some(10)],
                memory_read_write_height: vec![Some(21)],
                global_height: vec![Some(19), Some(21)],
                riscv_poseidon2_height: vec![Some(17), Some(19)],
            },
            // tendermint
            RiscvShapeSpec {
                cpu_height: vec![Some(22)],
                add_sub_height: vec![Some(19)],
                lt_height: vec![Some(19)],
                bitwise_height: vec![Some(20)],
                shift_right_height: vec![Some(18)],
                shift_left_height: vec![Some(17)],
                syscall_riscv_height: vec![Some(15)],
                memory_local_height: vec![Some(18)],
                mul_height: vec![Some(18)],
                divrem_height: vec![Some(8)],
                memory_read_write_height: vec![Some(20)],
                global_height: vec![Some(17)],
                riscv_poseidon2_height: vec![Some(15)],
            },
            // coprocessor integration
            RiscvShapeSpec {
                cpu_height: vec![Some(22)],
                add_sub_height: vec![Some(19)],
                lt_height: vec![Some(19), Some(20)],
                bitwise_height: vec![Some(17)],
                shift_right_height: vec![Some(16)],
                shift_left_height: vec![Some(16)],
                syscall_riscv_height: vec![Some(14)],
                memory_local_height: vec![Some(19)],
                mul_height: vec![Some(14)],
                divrem_height: vec![Some(10)],
                memory_read_write_height: vec![Some(22)],
                global_height: vec![Some(21), Some(22)],
                riscv_poseidon2_height: vec![Some(19), Some(20)],
            },
            // maximal riscv shape (22 divide by DATAPAR)
            RiscvShapeSpec {
                cpu_height: vec![Some(22)],
                add_sub_height: vec![Some(19)],
                lt_height: vec![Some(21)],
                bitwise_height: vec![Some(22)],
                shift_right_height: vec![Some(21)],
                shift_left_height: vec![Some(20)],
                syscall_riscv_height: vec![Some(20)],
                memory_local_height: vec![Some(20)],
                mul_height: vec![Some(21)],
                divrem_height: vec![Some(21)],
                memory_read_write_height: vec![Some(22)],
                global_height: vec![Some(23)],
                riscv_poseidon2_height: vec![Some(21)],
            },
        ];

        add_none_if_missing(&mut riscv_shapes);

        let mut allowed_log_heights = vec![];
        for spec in riscv_shapes {
            let short_allowed_log_heights = HashMap::from([
                (
                    RiscvChipType::<F>::Cpu(CpuChip::default()).name(),
                    spec.cpu_height,
                ),
                (
                    RiscvChipType::<F>::AddSub(AddSubChip::default()).name(),
                    spec.add_sub_height,
                ),
                (
                    RiscvChipType::<F>::Bitwise(BitwiseChip::default()).name(),
                    spec.bitwise_height,
                ),
                (
                    RiscvChipType::<F>::DivRem(DivRemChip::default()).name(),
                    spec.divrem_height,
                ),
                (
                    RiscvChipType::<F>::Mul(MulChip::default()).name(),
                    spec.mul_height,
                ),
                (
                    RiscvChipType::<F>::SR(ShiftRightChip::default()).name(),
                    spec.shift_right_height,
                ),
                (
                    RiscvChipType::<F>::SLL(SLLChip::default()).name(),
                    spec.shift_left_height,
                ),
                (
                    RiscvChipType::<F>::Lt(LtChip::default()).name(),
                    spec.lt_height,
                ),
                (
                    RiscvChipType::<F>::MemoryLocal(MemoryLocalChip::default()).name(),
                    spec.memory_local_height,
                ),
                (
                    RiscvChipType::<F>::MemoryReadWrite(MemoryReadWriteChip::default()).name(),
                    spec.memory_read_write_height,
                ),
                (
                    RiscvChipType::<F>::SyscallRiscv(SyscallChip::riscv()).name(),
                    spec.syscall_riscv_height,
                ),
                (
                    RiscvChipType::<F>::Global(GlobalChip::default()).name(),
                    spec.global_height,
                ),
                (
                    <F as FieldSpecificPoseidon2Config>::riscv_poseidon2_name().to_string(),
                    spec.riscv_poseidon2_height,
                ),
            ]);
            allowed_log_heights.push(short_allowed_log_heights);
        }

        // Set the memory init and finalize heights.
        let memory_init_heights = vec![
            None,
            Some(10),
            Some(16),
            Some(18),
            Some(19),
            Some(20),
            Some(21),
            Some(22),
            Some(23),
        ];
        let memory_finalize_heights = vec![
            None,
            Some(10),
            Some(16),
            Some(18),
            Some(19),
            Some(20),
            Some(21),
            Some(22),
            Some(23),
        ];

        let memory_allowed_log_heights = HashMap::from([
            (
                RiscvChipType::<F>::MemoryInitialize(MemoryInitializeFinalizeChip::new(Initialize))
                    .name(),
                memory_init_heights,
            ),
            (
                RiscvChipType::<F>::MemoryFinalize(MemoryInitializeFinalizeChip::new(Finalize))
                    .name(),
                memory_finalize_heights,
            ),
            (
                RiscvChipType::<F>::Global(GlobalChip::default()).name(),
                vec![
                    None,
                    Some(11),
                    Some(17),
                    Some(20),
                    Some(21),
                    Some(22),
                    Some(23),
                ],
            ),
            (
                <F as FieldSpecificPoseidon2Config>::riscv_poseidon2_name().to_string(),
                vec![
                    None,
                    Some(9),
                    Some(15),
                    Some(18),
                    Some(19),
                    Some(20),
                    Some(21),
                ],
            ),
        ]);

        let mut precompile_allowed_log_heights = HashMap::new();
        let precompile_heights = (4..21).collect::<Vec<_>>();
        for (chip_name, mem_events_per_row) in RiscvChipType::<F>::get_all_precompile_chips() {
            precompile_allowed_log_heights
                .insert(chip_name, (mem_events_per_row, precompile_heights.clone()));
        }

        Self {
            included_shapes: vec![],
            allowed_preprocessed_log_heights,
            allowed_log_heights,
            memory_allowed_log_heights,
            precompile_allowed_log_heights,
            phantom_data: PhantomData::<F>,
        }
    }
}

impl<F: PrimeField32 + FieldSpecificPoseidon2Config> RiscvShapeConfig<F> {
    pub fn maximal_only() -> Self {
        // Preprocessed chip heights.
        // let program_heights = vec![Some(19)];
        let program_heights = vec![Some(22)];

        let allowed_preprocessed_log_heights = HashMap::from([
            (
                RiscvChipType::<F>::Program(ProgramChip::default()).name(),
                program_heights,
            ),
            (
                RiscvChipType::<F>::Byte(ByteChip::default()).name(),
                vec![Some(16)],
            ),
        ]);

        let mut riscv_shapes = [
            // maximal riscv shape (22 divide by DATAPAR)
            RiscvShapeSpec {
                cpu_height: vec![Some(22)],
                add_sub_height: vec![Some(19)],
                lt_height: vec![Some(21)],
                bitwise_height: vec![Some(22)],
                shift_right_height: vec![Some(21)],
                shift_left_height: vec![Some(20)],
                syscall_riscv_height: vec![Some(20)],
                memory_local_height: vec![Some(20)],
                mul_height: vec![Some(21)],
                divrem_height: vec![Some(21)],
                memory_read_write_height: vec![Some(22)],
                global_height: vec![Some(23)],
                riscv_poseidon2_height: vec![Some(21)],
            },
        ];

        add_none_if_missing(&mut riscv_shapes);

        let mut allowed_log_heights = vec![];
        for spec in riscv_shapes {
            let short_allowed_log_heights = HashMap::from([
                (
                    RiscvChipType::<F>::Cpu(CpuChip::default()).name(),
                    spec.cpu_height,
                ),
                (
                    RiscvChipType::<F>::AddSub(AddSubChip::default()).name(),
                    spec.add_sub_height,
                ),
                (
                    RiscvChipType::<F>::Bitwise(BitwiseChip::default()).name(),
                    spec.bitwise_height,
                ),
                (
                    RiscvChipType::<F>::DivRem(DivRemChip::default()).name(),
                    spec.divrem_height,
                ),
                (
                    RiscvChipType::<F>::Mul(MulChip::default()).name(),
                    spec.mul_height,
                ),
                (
                    RiscvChipType::<F>::SR(ShiftRightChip::default()).name(),
                    spec.shift_right_height,
                ),
                (
                    RiscvChipType::<F>::SLL(SLLChip::default()).name(),
                    spec.shift_left_height,
                ),
                (
                    RiscvChipType::<F>::Lt(LtChip::default()).name(),
                    spec.lt_height,
                ),
                (
                    RiscvChipType::<F>::MemoryLocal(MemoryLocalChip::default()).name(),
                    spec.memory_local_height,
                ),
                (
                    RiscvChipType::<F>::MemoryReadWrite(MemoryReadWriteChip::default()).name(),
                    spec.memory_read_write_height,
                ),
                (
                    RiscvChipType::<F>::SyscallRiscv(SyscallChip::riscv()).name(),
                    spec.syscall_riscv_height,
                ),
                (
                    RiscvChipType::<F>::Global(GlobalChip::default()).name(),
                    spec.global_height,
                ),
                (
                    <F as FieldSpecificPoseidon2Config>::riscv_poseidon2_name().to_string(),
                    spec.riscv_poseidon2_height,
                ),
            ]);
            allowed_log_heights.push(short_allowed_log_heights);
        }

        // Set the memory init and finalize heights.
        let memory_init_heights = vec![None, Some(23)];
        let memory_finalize_heights = vec![None, Some(23)];

        let memory_allowed_log_heights = HashMap::from([
            (
                RiscvChipType::<F>::MemoryInitialize(MemoryInitializeFinalizeChip::new(Initialize))
                    .name(),
                memory_init_heights,
            ),
            (
                RiscvChipType::<F>::MemoryFinalize(MemoryInitializeFinalizeChip::new(Finalize))
                    .name(),
                memory_finalize_heights,
            ),
            (
                RiscvChipType::<F>::Global(GlobalChip::default()).name(),
                vec![None, Some(23)],
            ),
            (
                <F as FieldSpecificPoseidon2Config>::riscv_poseidon2_name().to_string(),
                vec![None, Some(21)],
            ),
        ]);

        let mut precompile_allowed_log_heights = HashMap::new();
        // let precompile_heights = (4..21).collect::<Vec<_>>();
        let precompile_heights = vec![20];
        for (chip_name, mem_events_per_row) in RiscvChipType::<F>::get_all_precompile_chips() {
            precompile_allowed_log_heights
                .insert(chip_name, (mem_events_per_row, precompile_heights.clone()));
        }
        debug!(
            "precompile_allowed_log_heights: {:?}",
            precompile_allowed_log_heights
        );

        Self {
            included_shapes: vec![],
            allowed_preprocessed_log_heights,
            allowed_log_heights,
            memory_allowed_log_heights,
            precompile_allowed_log_heights,
            phantom_data: PhantomData::<F>,
        }
    }

    pub fn test_only() -> Self {
        // Preprocessed chip heights.
        // let program_heights = vec![Some(19)];
        let program_heights = vec![Some(14)];

        let allowed_preprocessed_log_heights = HashMap::from([
            (
                RiscvChipType::<F>::Program(ProgramChip::default()).name(),
                program_heights,
            ),
            (
                RiscvChipType::<F>::Byte(ByteChip::default()).name(),
                vec![Some(16)],
            ),
        ]);

        let mut riscv_shapes = [
            // test riscv shape
            RiscvShapeSpec {
                cpu_height: vec![Some(16)],
                add_sub_height: vec![Some(16)],
                lt_height: vec![Some(16)],
                bitwise_height: vec![Some(16)],
                shift_right_height: vec![Some(16)],
                shift_left_height: vec![Some(16)],
                syscall_riscv_height: vec![Some(16)],
                memory_local_height: vec![Some(16)],
                mul_height: vec![Some(16)],
                divrem_height: vec![Some(16)],
                memory_read_write_height: vec![Some(16)],
                global_height: vec![Some(16)],
                riscv_poseidon2_height: vec![Some(14)],
            },
        ];

        add_none_if_missing(&mut riscv_shapes);

        let mut allowed_log_heights = vec![];
        for spec in riscv_shapes {
            let short_allowed_log_heights = HashMap::from([
                (
                    RiscvChipType::<F>::Cpu(CpuChip::default()).name(),
                    spec.cpu_height,
                ),
                (
                    RiscvChipType::<F>::AddSub(AddSubChip::default()).name(),
                    spec.add_sub_height,
                ),
                (
                    RiscvChipType::<F>::Bitwise(BitwiseChip::default()).name(),
                    spec.bitwise_height,
                ),
                (
                    RiscvChipType::<F>::DivRem(DivRemChip::default()).name(),
                    spec.divrem_height,
                ),
                (
                    RiscvChipType::<F>::Mul(MulChip::default()).name(),
                    spec.mul_height,
                ),
                (
                    RiscvChipType::<F>::SR(ShiftRightChip::default()).name(),
                    spec.shift_right_height,
                ),
                (
                    RiscvChipType::<F>::SLL(SLLChip::default()).name(),
                    spec.shift_left_height,
                ),
                (
                    RiscvChipType::<F>::Lt(LtChip::default()).name(),
                    spec.lt_height,
                ),
                (
                    RiscvChipType::<F>::MemoryLocal(MemoryLocalChip::default()).name(),
                    spec.memory_local_height,
                ),
                (
                    RiscvChipType::<F>::MemoryReadWrite(MemoryReadWriteChip::default()).name(),
                    spec.memory_read_write_height,
                ),
                (
                    RiscvChipType::<F>::SyscallRiscv(SyscallChip::riscv()).name(),
                    spec.syscall_riscv_height,
                ),
                (
                    RiscvChipType::<F>::Global(GlobalChip::default()).name(),
                    spec.global_height,
                ),
                (
                    <F as FieldSpecificPoseidon2Config>::riscv_poseidon2_name().to_string(),
                    spec.riscv_poseidon2_height,
                ),
            ]);
            allowed_log_heights.push(short_allowed_log_heights);
        }

        // Set the memory init and finalize heights.
        let memory_init_heights = vec![Some(16)];
        let memory_finalize_heights = vec![Some(16)];

        let memory_allowed_log_heights = HashMap::from([
            (
                RiscvChipType::<F>::MemoryInitialize(MemoryInitializeFinalizeChip::new(Initialize))
                    .name(),
                memory_init_heights,
            ),
            (
                RiscvChipType::<F>::MemoryFinalize(MemoryInitializeFinalizeChip::new(Finalize))
                    .name(),
                memory_finalize_heights,
            ),
            (
                RiscvChipType::<F>::Global(GlobalChip::default()).name(),
                vec![Some(17)],
            ),
            (
                <F as FieldSpecificPoseidon2Config>::riscv_poseidon2_name().to_string(),
                vec![Some(15)],
            ),
        ]);

        let mut precompile_allowed_log_heights = HashMap::new();
        // let precompile_heights = (4..21).collect::<Vec<_>>();
        let precompile_heights = vec![12];
        for (chip_name, mem_events_per_row) in RiscvChipType::<F>::get_all_precompile_chips() {
            precompile_allowed_log_heights
                .insert(chip_name, (mem_events_per_row, precompile_heights.clone()));
        }
        debug!(
            "precompile_allowed_log_heights: {:?}",
            precompile_allowed_log_heights
        );

        Self {
            included_shapes: vec![],
            allowed_preprocessed_log_heights,
            allowed_log_heights,
            memory_allowed_log_heights,
            precompile_allowed_log_heights,
            phantom_data: PhantomData::<F>,
        }
    }
}
