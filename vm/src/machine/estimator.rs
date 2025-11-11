use crate::{
    chips::{
        chips::{
            alu::{
                bitwise::BitwiseChip, divrem::DivRemChip, sll::SLLChip, sr::traces::ShiftRightChip,
            },
            riscv_cpu::CpuChip,
            riscv_global::GlobalChip,
            riscv_memory::{
                initialize_finalize::MemoryInitializeFinalizeChip, local::MemoryLocalChip,
                read_write::MemoryReadWriteChip,
            },
            syscall::SyscallChip,
        },
        utils::next_power_of_two,
    },
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{precompiles::PrecompileLocalMemory, SyscallCode},
    },
    primitives::consts::{
        ADD_SUB_DATAPAR, BITWISE_DATAPAR, DIVREM_DATAPAR, LOCAL_MEMORY_DATAPAR, LT_DATAPAR,
        MEMORY_RW_DATAPAR, MUL_DATAPAR, POSEIDON2_DATAPAR, SLL_DATAPAR, SR_DATAPAR,
    },
};
use hashbrown::HashMap;
use p3_keccak_air::NUM_ROUNDS;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub(crate) trait EventCapture {
    fn count_extra_records(_input: &EmulationRecord, _event_counter: &mut EventSizeCapture) {}
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PrecompileEstimator {
    events: usize,
    local_mem: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct PrecompileCache {
    cache: HashMap<SyscallCode, (usize, usize)>,
}

impl PrecompileCache {
    fn new() -> Self {
        Self::default()
    }

    fn get_syscall_info(
        &mut self,
        record: &EmulationRecord,
        code: SyscallCode,
    ) -> PrecompileEstimator {
        if let Some((events, local_mem)) = self.cache.get(&code) {
            PrecompileEstimator {
                events: *events,
                local_mem: *local_mem,
            }
        } else {
            let (events, local_mem) = record
                .precompile_events
                .get_events(code)
                .map_or((0, 0), |v| {
                    (v.len(), v.get_local_mem_events().into_iter().count())
                });

            self.cache.insert(code, (events, local_mem));

            PrecompileEstimator { events, local_mem }
        }
    }
}

/// This struct contains the event size that will be used to calculate the chip
/// trace heights before being sent to the prover. Most importantly, some
/// events such as DivRem may add additional events, and this logic must be
/// accounted for.
#[derive(Clone, Debug, Default)]
pub struct EventSizeCapture<'a> {
    pub(crate) num_program_events: usize,
    pub(crate) num_cpu_events: usize,
    pub(crate) num_add_events: usize,
    pub(crate) num_sub_events: usize,
    pub(crate) num_mul_events: usize,
    pub(crate) num_bitwise_events: usize,
    pub(crate) num_shift_left_events: usize,
    pub(crate) num_shift_right_events: usize,
    pub(crate) num_divrem_events: usize,
    pub(crate) num_lt_events: usize,
    pub(crate) num_memory_initialize_events: usize,
    pub(crate) num_memory_finalize_events: usize,
    pub(crate) num_cpu_local_memory_access: usize,
    pub(crate) num_memory_read_writes: usize,

    // precompiles

    // Hash functions
    sha_compress: PrecompileEstimator,
    sha_extend: PrecompileEstimator,
    keccak_p: PrecompileEstimator,
    poseidon2_p: PrecompileEstimator,

    // Edwards curves
    ed_add: PrecompileEstimator,
    ed_decompress: PrecompileEstimator,

    // Weierstrass curves
    secp256k1_add: PrecompileEstimator,
    secp256k1_double: PrecompileEstimator,
    secp256k1_decompress: PrecompileEstimator,
    bn254_add: PrecompileEstimator,
    bn254_double: PrecompileEstimator,
    bls381_add: PrecompileEstimator,
    bls381_double: PrecompileEstimator,
    bls381_decompress: PrecompileEstimator,

    // Field operations
    fp_bn254: PrecompileEstimator,
    fp_bls381: PrecompileEstimator,
    fp_secp256k1: PrecompileEstimator,
    fp2_add_sub_bn254: PrecompileEstimator,
    fp2_mul_bn254: PrecompileEstimator,
    fp2_add_sub_bls381: PrecompileEstimator,
    fp2_mul_bls381: PrecompileEstimator,

    // Other
    u256_mul: PrecompileEstimator,

    total_precompile_local_mem_events: usize,
    total_precompile_events: usize,

    // System events
    pub(crate) num_syscall_events: usize,
    pub(crate) num_precompile_syscall_events: usize,
    pub(crate) num_poseidon2_events: usize,
    pub(crate) num_global_lookup_events: usize,

    // this is an option to make default work, because I am lazy
    record: Option<&'a EmulationRecord>,
    field: &'a str,
}

impl<'a> EventSizeCapture<'a> {
    pub fn snapshot(record: &'a EmulationRecord, field: &'a str) -> Self {
        let mut result = Self {
            num_lt_events: record.lt_events.len(),
            num_add_events: record.add_events.len(),
            num_sub_events: record.sub_events.len(),
            num_mul_events: record.mul_events.len(),
            num_program_events: record.program.instructions.len(),
            num_global_lookup_events: record.global_lookup_events.len(),
            num_poseidon2_events: record.poseidon2_events.len(),
            record: Some(record),
            field,
            ..Self::default()
        };

        CpuChip::<()>::count_extra_records(record, &mut result);

        MemoryInitializeFinalizeChip::<()>::count_extra_records(record, &mut result);

        // deal with precompiles
        let mut cache = PrecompileCache::new();
        result.sha_compress = cache.get_syscall_info(record, SyscallCode::SHA_COMPRESS);
        result.sha_extend = cache.get_syscall_info(record, SyscallCode::SHA_EXTEND);
        result.keccak_p = cache.get_syscall_info(record, SyscallCode::KECCAK_PERMUTE);
        result.poseidon2_p = cache.get_syscall_info(record, SyscallCode::POSEIDON2_PERMUTE);
        result.ed_add = cache.get_syscall_info(record, SyscallCode::ED_ADD);
        result.ed_decompress = cache.get_syscall_info(record, SyscallCode::ED_DECOMPRESS);
        result.secp256k1_add = cache.get_syscall_info(record, SyscallCode::SECP256K1_ADD);
        result.secp256k1_double = cache.get_syscall_info(record, SyscallCode::SECP256K1_DOUBLE);
        result.secp256k1_decompress =
            cache.get_syscall_info(record, SyscallCode::SECP256K1_DECOMPRESS);
        result.bn254_add = cache.get_syscall_info(record, SyscallCode::BN254_ADD);
        result.bn254_double = cache.get_syscall_info(record, SyscallCode::BN254_DOUBLE);
        result.bls381_add = cache.get_syscall_info(record, SyscallCode::BLS12381_ADD);
        result.bls381_double = cache.get_syscall_info(record, SyscallCode::BLS12381_DOUBLE);
        result.bls381_decompress = cache.get_syscall_info(record, SyscallCode::BLS12381_DECOMPRESS);
        result.fp_bn254 = cache.get_syscall_info(record, SyscallCode::BN254_FP_ADD);
        result.fp_bls381 = cache.get_syscall_info(record, SyscallCode::BLS12381_FP_ADD);
        result.fp_secp256k1 = cache.get_syscall_info(record, SyscallCode::SECP256K1_ADD);
        result.fp2_add_sub_bn254 = cache.get_syscall_info(record, SyscallCode::BN254_FP2_ADD);
        result.fp2_mul_bn254 = cache.get_syscall_info(record, SyscallCode::BN254_FP2_MUL);
        result.fp2_add_sub_bls381 = cache.get_syscall_info(record, SyscallCode::BLS12381_FP2_ADD);
        result.fp2_mul_bls381 = cache.get_syscall_info(record, SyscallCode::BLS12381_FP2_MUL);
        result.u256_mul = cache.get_syscall_info(record, SyscallCode::UINT256_MUL);

        let precompiles = [
            &result.sha_compress,
            &result.sha_extend,
            &result.keccak_p,
            &result.poseidon2_p,
            &result.ed_add,
            &result.ed_decompress,
            &result.secp256k1_add,
            &result.secp256k1_double,
            &result.secp256k1_decompress,
            &result.bn254_add,
            &result.bn254_double,
            &result.bls381_add,
            &result.bls381_double,
            &result.bls381_decompress,
            &result.fp_bn254,
            &result.fp_bls381,
            &result.fp_secp256k1,
            &result.fp2_add_sub_bn254,
            &result.fp2_mul_bn254,
            &result.fp2_add_sub_bls381,
            &result.fp2_mul_bls381,
            &result.u256_mul,
        ];

        let total_precompile_local_mem_events = precompiles.map(|x| x.local_mem).into_iter().sum();
        let total_precompile_events = precompiles.map(|x| x.events).into_iter().sum();

        result.total_precompile_events = total_precompile_events;
        result.total_precompile_local_mem_events = total_precompile_local_mem_events;

        MemoryLocalChip::<()>::count_extra_records(record, &mut result);
        MemoryReadWriteChip::<()>::count_extra_records(record, &mut result);
        DivRemChip::<()>::count_extra_records(record, &mut result);
        SyscallChip::<()>::count_extra_records(record, &mut result);

        // final batch
        ShiftRightChip::<()>::count_extra_records(record, &mut result);
        SLLChip::<()>::count_extra_records(record, &mut result);
        BitwiseChip::<()>::count_extra_records(record, &mut result);
        GlobalChip::<()>::count_extra_records(record, &mut result);

        result
    }

    pub fn estimate(&self) -> CycleEstimator {
        let mut data = [0; NUM_RISCV_CHIPS];

        let record = self.record.expect("hack");

        // program: 1 row per instruction
        data[CHIP_PROGRAM] = self.num_program_events;
        let nb_rows = record.shape_chip_size("Program");
        data[CHIP_PROGRAM] = next_power_of_two(data[CHIP_PROGRAM], nb_rows);
        // cpu: 1 row per event
        data[CHIP_CPU] = self.num_cpu_events;
        let nb_rows = record.shape_chip_size("Cpu");
        data[CHIP_CPU] = next_power_of_two(data[CHIP_CPU], nb_rows);
        // sha256 compress: 1 + 64 + 1 = 66 rows per event
        data[CHIP_SHACOMPRESS] = self.sha_compress.events * 66;
        let nb_rows = record.shape_chip_size("ShaCompress");
        data[CHIP_SHACOMPRESS] = next_power_of_two(data[CHIP_SHACOMPRESS], nb_rows);
        // curve related: 1 row per event
        data[CHIP_ED25519ADD] = self.ed_add.events;
        let nb_rows = record.shape_chip_size("EdAddAssign");
        data[CHIP_ED25519ADD] = next_power_of_two(data[CHIP_ED25519ADD], nb_rows);
        data[CHIP_ED25519DECOMPRESS] = self.ed_decompress.events;
        let nb_rows = record.shape_chip_size("EdDecompress");
        data[CHIP_ED25519DECOMPRESS] = next_power_of_two(data[CHIP_ED25519DECOMPRESS], nb_rows);
        data[CHIP_WSBN254ADD] = self.bn254_add.events;
        let nb_rows = record.shape_chip_size("Bn254AddAssign");
        data[CHIP_WSBN254ADD] = next_power_of_two(data[CHIP_WSBN254ADD], nb_rows);
        data[CHIP_WSBLS381ADD] = self.bls381_add.events;
        let nb_rows = record.shape_chip_size("Bls12381AddAssign");
        data[CHIP_WSBLS381ADD] = next_power_of_two(data[CHIP_WSBLS381ADD], nb_rows);
        data[CHIP_WSSECP256K1ADD] = self.secp256k1_add.events;
        let nb_rows = record.shape_chip_size("Secp256k1AddAssign");
        data[CHIP_WSSECP256K1ADD] = next_power_of_two(data[CHIP_WSSECP256K1ADD], nb_rows);
        data[CHIP_WSDECOMPRESSBLS381] = self.bls381_decompress.events;
        let nb_rows = record.shape_chip_size("Bls12381Decompress");
        data[CHIP_WSDECOMPRESSBLS381] = next_power_of_two(data[CHIP_WSDECOMPRESSBLS381], nb_rows);
        data[CHIP_WSDECOMPRESSSECP256K1] = self.secp256k1_decompress.events;
        let nb_rows = record.shape_chip_size("Secp256k1Decompress");
        data[CHIP_WSDECOMPRESSSECP256K1] =
            next_power_of_two(data[CHIP_WSDECOMPRESSSECP256K1], nb_rows);
        data[CHIP_WSDOUBLEBN254] = self.bn254_double.events;
        let nb_rows = record.shape_chip_size("Bn254DoubleAssign");
        data[CHIP_WSDOUBLEBN254] = next_power_of_two(data[CHIP_WSDOUBLEBN254], nb_rows);
        data[CHIP_WSDOUBLEBLS381] = self.bls381_double.events;
        let nb_rows = record.shape_chip_size("Bls12381DoubleAssign");
        data[CHIP_WSDOUBLEBLS381] = next_power_of_two(data[CHIP_WSDOUBLEBLS381], nb_rows);
        data[CHIP_WSDOUBLESECP256K1] = self.secp256k1_double.events;
        let nb_rows = record.shape_chip_size("Secp256k1DoubleAssign");
        data[CHIP_WSDOUBLESECP256K1] = next_power_of_two(data[CHIP_WSDOUBLESECP256K1], nb_rows);
        // sha256 extend: 48 rows per event
        data[CHIP_SHAEXTEND] = self.sha_extend.events * 48;
        let nb_rows = record.shape_chip_size("ShaExtend");
        data[CHIP_SHAEXTEND] = next_power_of_two(data[CHIP_SHAEXTEND], nb_rows);
        // mem init/fini: 1 row per event
        data[CHIP_MEMORYINITIALIZE] = self.num_memory_initialize_events;
        let nb_rows = record.shape_chip_size("MemoryInitialize");
        data[CHIP_MEMORYINITIALIZE] = next_power_of_two(data[CHIP_MEMORYINITIALIZE], nb_rows);
        data[CHIP_MEMORYFINALIZE] = self.num_memory_finalize_events;
        let nb_rows = record.shape_chip_size("MemoryFinalize");
        data[CHIP_MEMORYFINALIZE] = next_power_of_two(data[CHIP_MEMORYFINALIZE], nb_rows);
        // mem local: use datapar
        data[CHIP_MEMORYLOCAL] = (self.num_cpu_local_memory_access
            + self.total_precompile_local_mem_events)
            .div_ceil(LOCAL_MEMORY_DATAPAR);
        let nb_rows = record.shape_chip_size("MemoryLocal");
        data[CHIP_MEMORYLOCAL] = next_power_of_two(data[CHIP_MEMORYLOCAL], nb_rows);
        // mem rw: use datapar
        data[CHIP_MEMORYREADWRITE] = self.num_memory_read_writes.div_ceil(MEMORY_RW_DATAPAR);
        let nb_rows = record.shape_chip_size("MemoryReadWrite");
        data[CHIP_MEMORYREADWRITE] = next_power_of_two(data[CHIP_MEMORYREADWRITE], nb_rows);
        // alu: use datapar
        data[CHIP_DIVREM] = self.num_divrem_events.div_ceil(DIVREM_DATAPAR);
        let nb_rows = record.shape_chip_size("DivRem");
        data[CHIP_DIVREM] = next_power_of_two(data[CHIP_DIVREM], nb_rows);
        data[CHIP_MUL] = self.num_mul_events.div_ceil(MUL_DATAPAR);
        let nb_rows = record.shape_chip_size("Mul");
        data[CHIP_MUL] = next_power_of_two(data[CHIP_MUL], nb_rows);
        data[CHIP_LT] = self.num_lt_events.div_ceil(LT_DATAPAR);
        let nb_rows = record.shape_chip_size("LessThan");
        data[CHIP_LT] = next_power_of_two(data[CHIP_LT], nb_rows);
        data[CHIP_SR] = self.num_shift_right_events.div_ceil(SR_DATAPAR);
        let nb_rows = record.shape_chip_size("ShiftRight");
        data[CHIP_SR] = next_power_of_two(data[CHIP_SR], nb_rows);
        data[CHIP_SLL] = self.num_shift_left_events.div_ceil(SLL_DATAPAR);
        let nb_rows = record.shape_chip_size("ShiftLeft");
        data[CHIP_SLL] = next_power_of_two(data[CHIP_SLL], nb_rows);
        data[CHIP_ADDSUB] = (self.num_add_events + self.num_sub_events).div_ceil(ADD_SUB_DATAPAR);
        let nb_rows = record.shape_chip_size("AddSub");
        data[CHIP_ADDSUB] = next_power_of_two(data[CHIP_ADDSUB], nb_rows);
        data[CHIP_BITWISE] = self.num_bitwise_events.div_ceil(BITWISE_DATAPAR);
        let nb_rows = record.shape_chip_size("Bitwise");
        data[CHIP_BITWISE] = next_power_of_two(data[CHIP_BITWISE], nb_rows);
        // keccak permute: events * NUM_ROUNDS
        // also does not conform to the shape padding
        data[CHIP_KEECAKP] = (self.keccak_p.events * NUM_ROUNDS).next_power_of_two();
        // fp related: 1 row per event
        data[CHIP_FPBN254] = self.fp_bn254.events;
        let nb_rows = record.shape_chip_size("Bn254FpOp");
        data[CHIP_FPBN254] = next_power_of_two(data[CHIP_FPBN254], nb_rows);
        data[CHIP_FP2ADDSUBBN254] = self.fp2_add_sub_bn254.events;
        let nb_rows = record.shape_chip_size("Bn254Fp2AddSub");
        data[CHIP_FP2ADDSUBBN254] = next_power_of_two(data[CHIP_FP2ADDSUBBN254], nb_rows);
        data[CHIP_FP2MULBN254] = self.fp2_mul_bn254.events;
        let nb_rows = record.shape_chip_size("Bn254Fp2Mul");
        data[CHIP_FP2MULBN254] = next_power_of_two(data[CHIP_FP2MULBN254], nb_rows);
        data[CHIP_FPBLS381] = self.fp_bls381.events;
        let nb_rows = record.shape_chip_size("Bls381FpOp");
        data[CHIP_FPBLS381] = next_power_of_two(data[CHIP_FPBLS381], nb_rows);
        data[CHIP_FP2ADDSUBBLS381] = self.fp2_add_sub_bls381.events;
        let nb_rows = record.shape_chip_size("Bls381Fp2AddSub");
        data[CHIP_FP2ADDSUBBLS381] = next_power_of_two(data[CHIP_FP2ADDSUBBLS381], nb_rows);
        data[CHIP_FP2MULBLS381] = self.fp2_mul_bls381.events;
        let nb_rows = record.shape_chip_size("Bls381Fp2Mul");
        data[CHIP_FP2MULBLS381] = next_power_of_two(data[CHIP_FP2MULBLS381], nb_rows);
        data[CHIP_FPSECP256K1] = self.fp_secp256k1.events;
        let nb_rows = record.shape_chip_size("Secp256k1FpOp");
        data[CHIP_FPSECP256K1] = next_power_of_two(data[CHIP_FPSECP256K1], nb_rows);
        data[CHIP_U256MUL] = self.u256_mul.events;
        let nb_rows = record.shape_chip_size("Uint256MulMod");
        data[CHIP_U256MUL] = next_power_of_two(data[CHIP_U256MUL], nb_rows);
        // poseidon2 permute: 1 row per event
        data[CHIP_POSEIDON2P] = self.poseidon2_p.events;
        let nb_rows = record.shape_chip_size("Poseidon2Permute");
        data[CHIP_POSEIDON2P] = next_power_of_two(data[CHIP_POSEIDON2P], nb_rows);
        // syscalls: 1 row per event
        data[CHIP_SYSCALLRISCV] = self.num_syscall_events;
        let nb_rows = record.shape_chip_size("SyscallRiscv");
        data[CHIP_SYSCALLRISCV] = next_power_of_two(data[CHIP_SYSCALLRISCV], nb_rows);
        data[CHIP_SYSCALLPRECOMPILE] = self.num_precompile_syscall_events;
        let nb_rows = record.shape_chip_size("SyscallPrecompile");
        data[CHIP_SYSCALLPRECOMPILE] = next_power_of_two(data[CHIP_SYSCALLPRECOMPILE], nb_rows);
        // riscv global: 1 row per event
        data[CHIP_GLOBAL] = self.num_global_lookup_events;
        let nb_rows = record.shape_chip_size("Global");
        data[CHIP_GLOBAL] = next_power_of_two(data[CHIP_GLOBAL], nb_rows);
        // byte: fixed 2^16
        // therefore no need to pad
        data[CHIP_BYTE] = 1 << 16;
        // poseidon2: use datapar
        data[CHIP_POSEIDON2] = self.num_poseidon2_events.div_ceil(POSEIDON2_DATAPAR);
        let nb_rows = record.shape_chip_size(&format!("Riscv{}Poseidon2", self.field));
        data[CHIP_POSEIDON2] = next_power_of_two(data[CHIP_POSEIDON2], nb_rows);

        CycleEstimator { data }
    }
}

const CHIP_PROGRAM: usize = 0;
const CHIP_CPU: usize = 1;
const CHIP_SHACOMPRESS: usize = 2;
const CHIP_ED25519ADD: usize = 3;
const CHIP_ED25519DECOMPRESS: usize = 4;
const CHIP_WSBN254ADD: usize = 5;
const CHIP_WSBLS381ADD: usize = 6;
const CHIP_WSSECP256K1ADD: usize = 7;
const CHIP_WSDECOMPRESSBLS381: usize = 8;
const CHIP_WSDECOMPRESSSECP256K1: usize = 9;
const CHIP_WSDOUBLEBN254: usize = 10;
const CHIP_WSDOUBLEBLS381: usize = 11;
const CHIP_WSDOUBLESECP256K1: usize = 12;
const CHIP_SHAEXTEND: usize = 13;
const CHIP_MEMORYINITIALIZE: usize = 14;
const CHIP_MEMORYFINALIZE: usize = 15;
const CHIP_MEMORYLOCAL: usize = 16;
const CHIP_MEMORYREADWRITE: usize = 17;
const CHIP_DIVREM: usize = 18;
const CHIP_MUL: usize = 19;
const CHIP_LT: usize = 20;
const CHIP_SR: usize = 21;
const CHIP_SLL: usize = 22;
const CHIP_ADDSUB: usize = 23;
const CHIP_BITWISE: usize = 24;
const CHIP_KEECAKP: usize = 25;
const CHIP_FPBN254: usize = 26;
const CHIP_FP2ADDSUBBN254: usize = 27;
const CHIP_FP2MULBN254: usize = 28;
const CHIP_FPBLS381: usize = 29;
const CHIP_FP2ADDSUBBLS381: usize = 30;
const CHIP_FP2MULBLS381: usize = 31;
const CHIP_FPSECP256K1: usize = 32;
const CHIP_U256MUL: usize = 33;
const CHIP_POSEIDON2P: usize = 34;
const CHIP_SYSCALLRISCV: usize = 35;
const CHIP_SYSCALLPRECOMPILE: usize = 36;
const CHIP_GLOBAL: usize = 37;
const CHIP_BYTE: usize = 38;
const CHIP_POSEIDON2: usize = 39;
const NUM_RISCV_CHIPS: usize = 40;

/// This struct contains the information that will be used to estimate the
/// number of CPU cycles that will be consumed by an R7a.48xlarge machine when
/// proving the a specific chunk. In particular it snapshots the event heights
/// for each chip before it is sent to the prover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CycleEstimator {
    data: [usize; NUM_RISCV_CHIPS],
}

impl Default for CycleEstimator {
    fn default() -> Self {
        Self {
            data: [0; NUM_RISCV_CHIPS],
        }
    }
}

impl CycleEstimator {
    // computes Sum[coeff * (size - mean)] + intercept
    pub fn estimate(&self, model: &EstimatorModel) -> usize {
        use itertools::izip;

        let result = izip!(
            &self.data,
            &model.means,
            &model.coeffs,
            &model.log_means,
            &model.log_coeffs
        )
        .map(|(size, mean, coeff, log_mean, log_coeff)| {
            let size_next = (*size).next_power_of_two();
            let size = *size as f64;
            let log_size = size_next as f64;

            let main_contrib = *coeff * (size - *mean);
            let log_contrib = *log_coeff * (log_size - *log_mean);

            main_contrib + log_contrib
        })
        .sum::<f64>();

        // divide by 1000 to avoid overflow
        ((result + model.global_intercept) / 1_000_000.0) as usize
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EstimatorModel {
    means: [f64; NUM_RISCV_CHIPS],
    coeffs: [f64; NUM_RISCV_CHIPS],
    log_means: [f64; NUM_RISCV_CHIPS],
    log_coeffs: [f64; NUM_RISCV_CHIPS],
    global_intercept: f64,
}

impl Default for EstimatorModel {
    fn default() -> Self {
        Self {
            means: [0.0; NUM_RISCV_CHIPS],
            coeffs: [0.0; NUM_RISCV_CHIPS],
            log_means: [0.0; NUM_RISCV_CHIPS],
            log_coeffs: [0.0; NUM_RISCV_CHIPS],
            global_intercept: 0.0,
        }
    }
}

impl EstimatorModel {
    pub fn from_json(path: impl AsRef<Path>) -> Self {
        let bytes = std::fs::read(path).expect("bad model path");
        let value: EstimatorJson = serde_json::from_slice(&bytes).expect("bad json");

        let mut result = Self::default();

        assert_eq!(value.feature_names.len(), 2 * NUM_RISCV_CHIPS);
        assert_eq!(
            value.standardized_space.coefficients.len(),
            2 * NUM_RISCV_CHIPS
        );
        assert_eq!(value.original_space.coefficients.len(), 2 * NUM_RISCV_CHIPS);
        assert_eq!(value.scaler.mean.len(), 2 * NUM_RISCV_CHIPS);
        assert_eq!(value.scaler.scale.len(), 2 * NUM_RISCV_CHIPS);

        for i in 0..NUM_RISCV_CHIPS {
            result.means[i] = value.scaler.mean[2 * i];
            result.coeffs[i] = value.original_space.coefficients[2 * i];
            result.log_means[i] = value.scaler.mean[2 * i + 1];
            result.log_coeffs[i] = value.original_space.coefficients[2 * i + 1];
        }
        result.global_intercept = value.original_space.intercept;

        result
    }
}

#[derive(Deserialize, Serialize)]
struct EstimatorJson {
    feature_names: Vec<String>,
    standardized_space: Info,
    original_space: Info,
    scaler: Scaler,
}

#[derive(Deserialize, Serialize)]
struct Info {
    coefficients: Vec<f64>,
    intercept: f64,
}

#[derive(Deserialize, Serialize)]
struct Scaler {
    mean: Vec<f64>,
    scale: Vec<f64>,
}

#[cfg(test)]
mod tests {
    use super::{EstimatorJson, EstimatorModel};

    #[test]
    fn test_model_deserialize() {
        let bytes = std::fs::read("../model.json").expect("bad model path");
        let _: EstimatorJson = serde_json::from_slice(&bytes).expect("bad json");
    }

    #[test]
    fn test_model2_deserialize() {
        let _model = EstimatorModel::from_json("../model.json");
    }
}
