use crate::{
    chips::{
        chips::riscv_memory::event::FfiMemoryLocalEvent,
        gadgets::{
            curves::weierstrass::secp256r1::Secp256r1BaseField,
            field::{
                bls381::Bls381BaseField, bn254::Bn254BaseField, secp256k1::Secp256k1BaseField,
            },
            utils::field_params::NumWords,
        },
        precompiles::{
            fptower::ffi::{FfiFp2AddSubEvent, FfiFp2MulEvent, FfiFpEvent},
            sha256::{compress::ffi::ShaCompressFfiEvent, extend::ffi::ShaExtendFfiEvent},
        },
    },
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{
            precompiles::{
                ec::event::{EllipticCurveDecompressEventFFI, EllipticCurveDoubleFfiEvent},
                edwards::event::EllipticCurveAddEventFFI,
                keccak256::event::FFIKeccakPermuteEvent,
                uint256::event::FfiUint256MulEvent,
                PrecompileEvent,
            },
            SyscallCode, SyscallEvent,
        },
    },
    instances::{compiler::shapes::riscv_shape::RiscvPadShape, preparer::EventCounter},
};
use std::{collections::HashMap, sync::Arc};

#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct PreparedGpuEvents {
    pub chunk_index: usize,

    // Direct events - no FFI conversion needed (MemoryLocal: the event plus the host-decided
    // `has_initial` / `global_slot`, see `FfiMemoryLocalEvent`)
    pub memory_local_events: Vec<FfiMemoryLocalEvent>,
    pub precompile_syscall_events: Vec<SyscallEvent>,

    // FFI events - only for events that need Vec to fixed array conversion.
    //
    // The poseidon2 and Ed25519 precompiles have none: their traces are generated on the host
    // from the record (see their `gpu_generate_extra_record_and_main`), so staging their events
    // here would only copy them.
    pub bn254_fp_add_events: Vec<FfiFpEvent<<Bn254BaseField as NumWords>::WordsFieldElement>>,
    pub bls12381_fp_add_events: Vec<FfiFpEvent<<Bls381BaseField as NumWords>::WordsFieldElement>>,
    pub secp256k1_fp_add_events:
        Vec<FfiFpEvent<<Secp256k1BaseField as NumWords>::WordsFieldElement>>,
    pub bn254_fp2_add_sub_events:
        Vec<FfiFp2AddSubEvent<<Bn254BaseField as NumWords>::WordsCurvePoint>>,
    pub bls12381_fp2_add_sub_events:
        Vec<FfiFp2AddSubEvent<<Bls381BaseField as NumWords>::WordsCurvePoint>>,
    pub bn254_fp2_mul_events: Vec<FfiFp2MulEvent<<Bn254BaseField as NumWords>::WordsCurvePoint>>,
    pub bls12381_fp2_mul_events:
        Vec<FfiFp2MulEvent<<Bls381BaseField as NumWords>::WordsCurvePoint>>,
    pub keccak_events: Vec<FFIKeccakPermuteEvent>,
    pub sha_compress_events: Vec<ShaCompressFfiEvent>,
    pub sha_extend_events: Vec<ShaExtendFfiEvent>,
    pub bn254_weierstrass_add_events: Vec<EllipticCurveAddEventFFI<Bn254BaseField>>,
    pub bls12381_weierstrass_add_events: Vec<EllipticCurveAddEventFFI<Bls381BaseField>>,
    pub secp256k1_weierstrass_add_events: Vec<EllipticCurveAddEventFFI<Secp256k1BaseField>>,
    pub secp256r1_weierstrass_add_events: Vec<EllipticCurveAddEventFFI<Secp256r1BaseField>>,
    pub bn254_weierstrass_double_events: Vec<EllipticCurveDoubleFfiEvent<Bn254BaseField>>,
    pub bls12381_weierstrass_double_events: Vec<EllipticCurveDoubleFfiEvent<Bls381BaseField>>,
    pub secp256k1_weierstrass_double_events: Vec<EllipticCurveDoubleFfiEvent<Secp256k1BaseField>>,
    pub secp256r1_weierstrass_double_events: Vec<EllipticCurveDoubleFfiEvent<Secp256r1BaseField>>,
    pub bls12381_weierstrass_decompress_events:
        Vec<EllipticCurveDecompressEventFFI<Bls381BaseField>>,
    pub secp256k1_weierstrass_decompress_events:
        Vec<EllipticCurveDecompressEventFFI<Secp256k1BaseField>>,
    pub secp256r1_weierstrass_decompress_events:
        Vec<EllipticCurveDecompressEventFFI<Secp256r1BaseField>>,
    pub uint256_mul_events: Vec<FfiUint256MulEvent>,

    pub event_counter: EventCounter,

    pub shape: Option<RiscvPadShape>,

    /// Packed compact staging of the cpu/mem/add_sub/lt event families
    /// (`MLE_PACKED_EVENTS=1`; `None` = fat path for this chunk).
    pub packed: Option<Arc<super::packed_events::PackedEventStage>>,

    /// Pinned re-staging of the fat bitwise/shift_left uploads. Independent of `packed` on
    /// purpose (see `StagedAluEvents`): it must survive `try_stage`'s all-or-nothing fallback.
    pub staged_alu: Arc<super::packed_events::StagedAluEvents>,
}

impl PreparedGpuEvents {
    pub fn init_with_event_counter(counter: EventCounter) -> Self {
        Self {
            chunk_index: counter.chunk_index,

            memory_local_events: Vec::with_capacity(counter.num_cpu_local_memory_access),
            precompile_syscall_events: Vec::with_capacity(counter.num_precompile_syscall_events),
            bn254_fp_add_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::BN254_FP_ADD),
            ),
            bls12381_fp_add_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::BLS12381_FP_ADD),
            ),
            secp256k1_fp_add_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::SECP256K1_FP_ADD),
            ),
            bn254_fp2_add_sub_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::BN254_FP2_ADD),
            ),
            bls12381_fp2_add_sub_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::BLS12381_FP2_ADD),
            ),
            bn254_fp2_mul_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::BN254_FP2_MUL),
            ),
            bls12381_fp2_mul_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::BLS12381_FP2_MUL),
            ),
            keccak_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::KECCAK_PERMUTE),
            ),
            sha_compress_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::SHA_COMPRESS),
            ),
            sha_extend_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::SHA_EXTEND),
            ),
            bn254_weierstrass_add_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::BN254_ADD),
            ),
            bls12381_weierstrass_add_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::BLS12381_ADD),
            ),
            secp256k1_weierstrass_add_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::SECP256K1_ADD),
            ),
            secp256r1_weierstrass_add_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::SECP256R1_ADD),
            ),
            bn254_weierstrass_double_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::BN254_DOUBLE),
            ),
            bls12381_weierstrass_double_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::BLS12381_DOUBLE),
            ),
            secp256k1_weierstrass_double_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::SECP256K1_DOUBLE),
            ),
            secp256r1_weierstrass_double_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::SECP256R1_DOUBLE),
            ),
            bls12381_weierstrass_decompress_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::BLS12381_DECOMPRESS),
            ),
            secp256k1_weierstrass_decompress_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::SECP256K1_DECOMPRESS),
            ),
            secp256r1_weierstrass_decompress_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::SECP256R1_DECOMPRESS),
            ),
            uint256_mul_events: Vec::with_capacity(
                counter.get_precompile_event_num(SyscallCode::UINT256_MUL),
            ),

            event_counter: counter,

            shape: None,
            packed: None,
            staged_alu: Arc::default(),
        }
    }

    pub fn new(record: &EmulationRecord, counter: EventCounter) -> Self {
        let mut prepared_events = PreparedGpuEvents::init_with_event_counter(counter);
        prepared_events.shape = record.shape.clone();
        // MLE_PACKED_EVENTS=1: stage the compact FFI event mirror on this (preparer) thread;
        // None means this chunk uses the fat path (gate off, pool busy, or invariant fallback).
        prepared_events.packed =
            super::packed_events::try_stage(record, &prepared_events.event_counter).map(Arc::new);
        prepared_events.staged_alu = Arc::new(super::packed_events::try_stage_alu(
            record,
            prepared_events.event_counter.chunk_index,
        ));

        // Pre-fetch all precompile events to avoid repeated HashMap lookups
        // Use with_capacity to avoid reallocations
        let mut precompile_events_cache = HashMap::with_capacity(22);
        let syscall_codes = [
            SyscallCode::BN254_FP_ADD,
            SyscallCode::BLS12381_FP_ADD,
            SyscallCode::SECP256K1_FP_ADD,
            SyscallCode::BN254_FP2_ADD,
            SyscallCode::BLS12381_FP2_ADD,
            SyscallCode::BN254_FP2_MUL,
            SyscallCode::BLS12381_FP2_MUL,
            SyscallCode::KECCAK_PERMUTE,
            SyscallCode::SHA_COMPRESS,
            SyscallCode::SHA_EXTEND,
            SyscallCode::BN254_ADD,
            SyscallCode::BLS12381_ADD,
            SyscallCode::SECP256K1_ADD,
            SyscallCode::SECP256R1_ADD,
            SyscallCode::BN254_DOUBLE,
            SyscallCode::BLS12381_DOUBLE,
            SyscallCode::SECP256K1_DOUBLE,
            SyscallCode::SECP256R1_DOUBLE,
            SyscallCode::BLS12381_DECOMPRESS,
            SyscallCode::SECP256K1_DECOMPRESS,
            SyscallCode::SECP256R1_DECOMPRESS,
            SyscallCode::UINT256_MUL,
        ];

        for code in syscall_codes {
            precompile_events_cache.insert(code, record.get_precompile_events(code));
        }

        // Process memory and syscall events. The MemoryLocal entries get their `has_initial`
        // and the Global-event prefix sum here, in the order host trace generation enumerates
        // them (`get_local_mem_events`: precompile entries, then CPU), so the kernel writes the
        // same Global events at the same positions as `MemoryLocalChip::extra_record`.
        FfiMemoryLocalEvent::stage(
            record.get_local_mem_events(),
            &record.program.memory_image,
            &mut prepared_events.memory_local_events,
        );

        prepared_events.precompile_syscall_events.extend(
            record
                .precompile_events
                .sorted_groups()
                .into_iter()
                .flat_map(|(_, v)| v.iter().map(|(e, _)| *e)),
        );

        // Process all precompile events sequentially (most chunks only have one type)
        // BN254 FP operations
        prepared_events.bn254_fp_add_events.extend(
            precompile_events_cache[&SyscallCode::BN254_FP_ADD]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::Bn254Fp(e) => FfiFpEvent::from(e),
                    _ => unreachable!(),
                }),
        );

        // BLS12381 FP operations
        prepared_events.bls12381_fp_add_events.extend(
            precompile_events_cache[&SyscallCode::BLS12381_FP_ADD]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::Bls12381Fp(e) => FfiFpEvent::from(e),
                    _ => unreachable!(),
                }),
        );

        // Secp256k1 FP operations
        prepared_events.secp256k1_fp_add_events.extend(
            precompile_events_cache[&SyscallCode::SECP256K1_FP_ADD]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::Secp256k1Fp(e) => FfiFpEvent::from(e),
                    _ => unreachable!(),
                }),
        );

        // BN254 FP2 operations
        prepared_events.bn254_fp2_add_sub_events.extend(
            precompile_events_cache[&SyscallCode::BN254_FP2_ADD]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::Bn254Fp2AddSub(e) => FfiFp2AddSubEvent::from(e),
                    _ => unreachable!(),
                }),
        );
        prepared_events.bn254_fp2_mul_events.extend(
            precompile_events_cache[&SyscallCode::BN254_FP2_MUL]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::Bn254Fp2Mul(e) => FfiFp2MulEvent::from(e),
                    _ => unreachable!(),
                }),
        );

        // BLS12381 FP2 operations
        prepared_events.bls12381_fp2_add_sub_events.extend(
            precompile_events_cache[&SyscallCode::BLS12381_FP2_ADD]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::Bls12381Fp2AddSub(e) => FfiFp2AddSubEvent::from(e),
                    _ => unreachable!(),
                }),
        );
        prepared_events.bls12381_fp2_mul_events.extend(
            precompile_events_cache[&SyscallCode::BLS12381_FP2_MUL]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::Bls12381Fp2Mul(e) => FfiFp2MulEvent::from(e),
                    _ => unreachable!(),
                }),
        );

        // Hash operations
        prepared_events.keccak_events.extend(
            precompile_events_cache[&SyscallCode::KECCAK_PERMUTE]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::KeccakPermute(e) => FFIKeccakPermuteEvent::from(e),
                    _ => unreachable!(),
                }),
        );
        prepared_events.sha_compress_events.extend(
            precompile_events_cache[&SyscallCode::SHA_COMPRESS]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::ShaCompress(e) => ShaCompressFfiEvent::from(e),
                    _ => unreachable!(),
                }),
        );
        prepared_events.sha_extend_events.extend(
            precompile_events_cache[&SyscallCode::SHA_EXTEND]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::ShaExtend(e) => ShaExtendFfiEvent::from(e),
                    _ => unreachable!(),
                }),
        );

        // Weierstrass curve operations (add)
        prepared_events.bn254_weierstrass_add_events.extend(
            precompile_events_cache[&SyscallCode::BN254_ADD]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::Bn254Add(e) => EllipticCurveAddEventFFI::from(e),
                    _ => unreachable!(),
                }),
        );
        prepared_events.bls12381_weierstrass_add_events.extend(
            precompile_events_cache[&SyscallCode::BLS12381_ADD]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::Bls12381Add(e) => EllipticCurveAddEventFFI::from(e),
                    _ => unreachable!(),
                }),
        );
        prepared_events.secp256k1_weierstrass_add_events.extend(
            precompile_events_cache[&SyscallCode::SECP256K1_ADD]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::Secp256k1Add(e) => EllipticCurveAddEventFFI::from(e),
                    _ => unreachable!(),
                }),
        );
        prepared_events.secp256r1_weierstrass_add_events.extend(
            precompile_events_cache[&SyscallCode::SECP256R1_ADD]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::Secp256r1Add(e) => EllipticCurveAddEventFFI::from(e),
                    _ => unreachable!(),
                }),
        );

        // Weierstrass curve operations (double)
        prepared_events.bn254_weierstrass_double_events.extend(
            precompile_events_cache[&SyscallCode::BN254_DOUBLE]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::Bn254Double(e) => EllipticCurveDoubleFfiEvent::from(e),
                    _ => unreachable!(),
                }),
        );
        prepared_events.bls12381_weierstrass_double_events.extend(
            precompile_events_cache[&SyscallCode::BLS12381_DOUBLE]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::Bls12381Double(e) => EllipticCurveDoubleFfiEvent::from(e),
                    _ => unreachable!(),
                }),
        );
        prepared_events.secp256k1_weierstrass_double_events.extend(
            precompile_events_cache[&SyscallCode::SECP256K1_DOUBLE]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::Secp256k1Double(e) => EllipticCurveDoubleFfiEvent::from(e),
                    _ => unreachable!(),
                }),
        );
        prepared_events.secp256r1_weierstrass_double_events.extend(
            precompile_events_cache[&SyscallCode::SECP256R1_DOUBLE]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::Secp256r1Double(e) => EllipticCurveDoubleFfiEvent::from(e),
                    _ => unreachable!(),
                }),
        );

        // Decompress and other operations
        prepared_events
            .bls12381_weierstrass_decompress_events
            .extend(
                precompile_events_cache[&SyscallCode::BLS12381_DECOMPRESS]
                    .iter()
                    .map(|(_, event)| match event {
                        PrecompileEvent::Bls12381Decompress(e) => {
                            EllipticCurveDecompressEventFFI::from(e)
                        }
                        _ => unreachable!(),
                    }),
            );
        prepared_events
            .secp256k1_weierstrass_decompress_events
            .extend(
                precompile_events_cache[&SyscallCode::SECP256K1_DECOMPRESS]
                    .iter()
                    .map(|(_, event)| match event {
                        PrecompileEvent::Secp256k1Decompress(e) => {
                            EllipticCurveDecompressEventFFI::from(e)
                        }
                        _ => unreachable!(),
                    }),
            );
        prepared_events
            .secp256r1_weierstrass_decompress_events
            .extend(
                precompile_events_cache[&SyscallCode::SECP256R1_DECOMPRESS]
                    .iter()
                    .map(|(_, event)| match event {
                        PrecompileEvent::Secp256r1Decompress(e) => {
                            EllipticCurveDecompressEventFFI::from(e)
                        }
                        _ => unreachable!(),
                    }),
            );
        prepared_events.uint256_mul_events.extend(
            precompile_events_cache[&SyscallCode::UINT256_MUL]
                .iter()
                .map(|(_, event)| match event {
                    PrecompileEvent::Uint256Mul(e) => FfiUint256MulEvent::from(e),
                    _ => unreachable!(),
                }),
        );

        prepared_events
    }
}
