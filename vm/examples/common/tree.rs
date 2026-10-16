//! Convert + combine a program's chunk proofs into one verified complete root.
//!
//! Shared by the deferred examples, which both need a real root before they have anything to say:
//! one to hand a deferred node a sub-proof, the other to vary what the tree carries.

use std::sync::Arc;

use pico_mle_core::{config::recursion_params_with_100_bits_security, protocol::proof::Proof};
use pico_vm::{
    mle::machine::{
        combine::CombineMachine,
        convert::{ConvertMachine, ProofWithVk},
        exe::RiscvVmVk,
        recursion::{Kb, Sc},
    },
    primitives::consts::DIGEST_SIZE,
};

/// `deferred_digest` is what every leaf passes through the deferred-proof chain (zero when the
/// tree has no deferred nodes), and `prefix` are the deferred nodes that lead the child list.
pub fn build_tree(
    riscv_vk: &Arc<pico_mle_core::keygen::types::MultiStarkVerifyingKey<Sc>>,
    vm_vk: &RiscvVmVk,
    riscv_proofs: &[Proof<Sc>],
    deferred_digest: [Kb; DIGEST_SIZE],
    prefix: &[ProofWithVk],
) -> eyre::Result<ProofWithVk> {
    let mut convert = ConvertMachine::new(
        riscv_vk.clone(),
        vm_vk.clone(),
        riscv_proofs,
        recursion_params_with_100_bits_security(),
        false,
    )?;
    convert.set_final_deferred_digest(deferred_digest);
    let mut children = prefix.to_vec();
    children.extend(convert.prove_with_vks(riscv_proofs)?);
    let mut combine = CombineMachine::new(
        recursion_params_with_100_bits_security(),
        vm_vk.clone(),
        false,
    );
    let root = combine.prove_tree(children)?;
    combine.verify(&root)?;
    Ok(root)
}
