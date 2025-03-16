//! Syscall definitions & implementations for the [`crate::Emulator`].

pub mod code;
mod commit;
mod halt;
mod hint;
pub mod precompiles;
pub mod syscall_context;
mod unconstrained;
mod write;

use crate::{
    chips::gadgets::{
        curves::{
            edwards::ed25519::{Ed25519, Ed25519Parameters},
            weierstrass::{bls381::Bls12381, bn254::Bn254, secp256k1::Secp256k1},
        },
        field::field_op::FieldOperation,
    },
    emulator::riscv::syscalls::{
        commit::CommitSyscall, halt::HaltSyscall, syscall_context::SyscallContext,
    },
    primitives::Poseidon2Init,
};
pub use code::*;
use hashbrown::HashMap;
use hint::{HintLenSyscall, HintReadSyscall};
use p3_field::PrimeField32;
use p3_symmetric::Permutation;
use precompiles::{
    edwards::{add::EdwardsAddAssignSyscall, decompress::EdwardsDecompressSyscall},
    fptower::{fp::FpSyscall, fp2_addsub::Fp2AddSubSyscall, fp2_mul::Fp2MulSyscall},
    keccak256::permute::Keccak256PermuteSyscall,
    poseidon2::permute::Poseidon2PermuteSyscall,
    sha256::{compress::Sha256CompressSyscall, extend::Sha256ExtendSyscall},
    uint256::syscall::Uint256MulSyscall,
    weierstrass::{
        add::WeierstrassAddAssignSyscall, decompress::WeierstrassDecompressSyscall,
        double::WeierstrassDoubleAssignSyscall,
    },
};
use serde::{Deserialize, Serialize};
use std::{marker::PhantomData, sync::Arc};
use unconstrained::{EnterUnconstrainedSyscall, ExitUnconstrainedSyscall};
use write::WriteSyscall;

/// A system call in the Pico RISC-V zkVM.
///
/// This trait implements methods needed to emulate a system call inside the [`crate::Emulator`].
pub trait Syscall: Send + Sync {
    /// Emulates the syscall.
    ///
    /// Returns the resulting value of register a0. `arg1` and `arg2` are the values in registers
    /// X10 and X11, respectively. While not a hard requirement, the convention is that the return
    /// value is only for system calls such as `HALT`. Most precompiles use `arg1` and `arg2` to
    /// denote the addresses of the input data, and write the result to the memory at `arg1`.
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32>;

    /// The number of extra cycles that the syscall takes to emulate.
    ///
    /// Unless this syscall is complex and requires many cycles, this should be zero.
    fn num_extra_cycles(&self) -> u32 {
        0
    }
}

/// Creates the default syscall map.
#[must_use]
pub fn default_syscall_map<F>() -> HashMap<SyscallCode, Arc<dyn Syscall>>
where
    F: PrimeField32 + Poseidon2Init,
    F::Poseidon2: Permutation<[F; 16]>,
{
    use crate::chips::gadgets::field::{
        bls381::Bls381BaseField, bn254::Bn254BaseField, secp256k1::Secp256k1BaseField,
    };

    let mut syscall_map = HashMap::<SyscallCode, Arc<dyn Syscall>>::default();

    syscall_map.insert(
        SyscallCode::ENTER_UNCONSTRAINED,
        Arc::new(EnterUnconstrainedSyscall),
    );
    syscall_map.insert(
        SyscallCode::EXIT_UNCONSTRAINED,
        Arc::new(ExitUnconstrainedSyscall),
    );

    syscall_map.insert(SyscallCode::WRITE, Arc::new(WriteSyscall));

    syscall_map.insert(SyscallCode::HINT_LEN, Arc::new(HintLenSyscall));

    syscall_map.insert(SyscallCode::HINT_READ, Arc::new(HintReadSyscall));

    syscall_map.insert(SyscallCode::COMMIT, Arc::new(CommitSyscall));

    syscall_map.insert(SyscallCode::SHA_EXTEND, Arc::new(Sha256ExtendSyscall));

    syscall_map.insert(SyscallCode::SHA_COMPRESS, Arc::new(Sha256CompressSyscall));

    syscall_map.insert(SyscallCode::HALT, Arc::new(HaltSyscall));

    syscall_map.insert(
        SyscallCode::KECCAK_PERMUTE,
        Arc::new(Keccak256PermuteSyscall),
    );

    // bls12-381 fp operations
    syscall_map.insert(
        SyscallCode::BLS12381_FP_ADD,
        Arc::new(FpSyscall::<Bls381BaseField>::new(FieldOperation::Add)),
    );
    syscall_map.insert(
        SyscallCode::BLS12381_FP_SUB,
        Arc::new(FpSyscall::<Bls381BaseField>::new(FieldOperation::Sub)),
    );
    syscall_map.insert(
        SyscallCode::BLS12381_FP_MUL,
        Arc::new(FpSyscall::<Bls381BaseField>::new(FieldOperation::Mul)),
    );
    syscall_map.insert(
        SyscallCode::BLS12381_FP2_ADD,
        Arc::new(Fp2AddSubSyscall::<Bls381BaseField>::new(
            FieldOperation::Add,
        )),
    );
    syscall_map.insert(
        SyscallCode::BLS12381_FP2_SUB,
        Arc::new(Fp2AddSubSyscall::<Bls381BaseField>::new(
            FieldOperation::Sub,
        )),
    );
    syscall_map.insert(
        SyscallCode::BLS12381_FP2_MUL,
        Arc::new(Fp2MulSyscall::<Bls381BaseField>::new()),
    );

    // bn254 fp operations
    syscall_map.insert(
        SyscallCode::BN254_FP_ADD,
        Arc::new(FpSyscall::<Bn254BaseField>::new(FieldOperation::Add)),
    );
    syscall_map.insert(
        SyscallCode::BN254_FP_SUB,
        Arc::new(FpSyscall::<Bn254BaseField>::new(FieldOperation::Sub)),
    );
    syscall_map.insert(
        SyscallCode::BN254_FP_MUL,
        Arc::new(FpSyscall::<Bn254BaseField>::new(FieldOperation::Mul)),
    );
    syscall_map.insert(
        SyscallCode::BN254_FP2_ADD,
        Arc::new(Fp2AddSubSyscall::<Bn254BaseField>::new(FieldOperation::Add)),
    );
    syscall_map.insert(
        SyscallCode::BN254_FP2_SUB,
        Arc::new(Fp2AddSubSyscall::<Bn254BaseField>::new(FieldOperation::Sub)),
    );
    syscall_map.insert(
        SyscallCode::BN254_FP2_MUL,
        Arc::new(Fp2MulSyscall::<Bn254BaseField>::new()),
    );

    // secp256k1 fp operations
    syscall_map.insert(
        SyscallCode::SECP256K1_FP_ADD,
        Arc::new(FpSyscall::<Secp256k1BaseField>::new(FieldOperation::Add)),
    );
    syscall_map.insert(
        SyscallCode::SECP256K1_FP_SUB,
        Arc::new(FpSyscall::<Secp256k1BaseField>::new(FieldOperation::Sub)),
    );
    syscall_map.insert(
        SyscallCode::SECP256K1_FP_MUL,
        Arc::new(FpSyscall::<Secp256k1BaseField>::new(FieldOperation::Mul)),
    );

    // edwards
    syscall_map.insert(
        SyscallCode::ED_ADD,
        Arc::new(EdwardsAddAssignSyscall::<Ed25519>::new()),
    );
    syscall_map.insert(
        SyscallCode::ED_DECOMPRESS,
        Arc::new(EdwardsDecompressSyscall::<Ed25519Parameters>::new()),
    );

    syscall_map.insert(SyscallCode::UINT256_MUL, Arc::new(Uint256MulSyscall));

    syscall_map.insert(
        SyscallCode::SECP256K1_ADD,
        Arc::new(WeierstrassAddAssignSyscall::<Secp256k1>::new()),
    );
    syscall_map.insert(
        SyscallCode::BN254_ADD,
        Arc::new(WeierstrassAddAssignSyscall::<Bn254>::new()),
    );
    syscall_map.insert(
        SyscallCode::BLS12381_ADD,
        Arc::new(WeierstrassAddAssignSyscall::<Bls12381>::new()),
    );

    syscall_map.insert(
        SyscallCode::SECP256K1_DOUBLE,
        Arc::new(WeierstrassDoubleAssignSyscall::<Secp256k1>::new()),
    );
    syscall_map.insert(
        SyscallCode::BN254_DOUBLE,
        Arc::new(WeierstrassDoubleAssignSyscall::<Bn254>::new()),
    );
    syscall_map.insert(
        SyscallCode::BLS12381_DOUBLE,
        Arc::new(WeierstrassDoubleAssignSyscall::<Bls12381>::new()),
    );

    syscall_map.insert(
        SyscallCode::BLS12381_DECOMPRESS,
        Arc::new(WeierstrassDecompressSyscall::<Bls12381>::new()),
    );
    syscall_map.insert(
        SyscallCode::SECP256K1_DECOMPRESS,
        Arc::new(WeierstrassDecompressSyscall::<Secp256k1>::new()),
    );

    syscall_map.insert(
        SyscallCode::POSEIDON2_PERMUTE,
        Arc::new(Poseidon2PermuteSyscall::<F>(PhantomData)),
    );

    syscall_map
}

/// Syscall Event.
///
/// This object encapsulated the information needed to prove a syscall invocation from the CPU table.
/// This includes its chunk, clk, syscall id, arguments, other relevant information.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SyscallEvent {
    /// The chunk number.
    pub chunk: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The syscall id.
    pub syscall_id: u32,
    /// The first argument.
    pub arg1: u32,
    /// The second operand.
    pub arg2: u32,
}
