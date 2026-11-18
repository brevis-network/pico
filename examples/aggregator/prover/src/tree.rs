//! Convert + combine a program's chunk proofs into one verified complete root.
//!
//! A copy of `vm/examples/common/tree.rs`, which is not part of the `pico-vm` library.

use std::sync::Arc;

use p3_field::PrimeCharacteristicRing;
use pico_mle_core::config::recursion_params_with_128_bits_security;
use pico_vm::{
    mle::machine::{
        combine::CombineMachine,
        convert::{ConvertMachine, ProofWithVk},
        exe::RiscvVmVk,
        global_logup_nodes::prove_global_logup_nodes,
        recursion::Kb,
        riscv::RiscvProof,
    },
    primitives::consts::DIGEST_SIZE,
};

/// `riscv` is the block's RISC-V proof: its chunk proofs become the tree's leaves, and its
/// global LogUp the nodes that lead the tree. `deferred_digest` is what every leaf passes
/// through the deferred-proof chain (zero when the tree has no deferred nodes), and `prefix`
/// are the deferred nodes, which come after the global LogUp's nodes and before the leaves.
///
/// The global LogUp's nodes pass the deferred chain through at its start, zero, ahead of
/// deferred nodes. With none, they are handed the leaves' value, which an honest caller has at
/// zero as well: a caller that forges it then meets the root's closure, not a seam.
pub fn build_tree(
    riscv: &RiscvProof,
    vm_vk: &RiscvVmVk,
    deferred_digest: [Kb; DIGEST_SIZE],
    prefix: &[ProofWithVk],
) -> eyre::Result<ProofWithVk> {
    let mut convert = ConvertMachine::new(
        Arc::clone(&riscv.vk),
        vm_vk.clone(),
        &riscv.chunk_proofs,
        recursion_params_with_128_bits_security(),
        false,
    )?;
    convert.set_final_deferred_digest(deferred_digest);
    let chain_start = if prefix.is_empty() {
        deferred_digest
    } else {
        [Kb::ZERO; DIGEST_SIZE]
    };
    let mut children = prove_global_logup_nodes(riscv, vm_vk, chain_start)?;
    children.extend_from_slice(prefix);
    children.extend(convert.prove_with_vks(&riscv.chunk_proofs)?);
    let mut combine = CombineMachine::new(
        recursion_params_with_128_bits_security(),
        vm_vk.clone(),
        false,
    );
    let root = combine.prove_tree(children)?;
    combine.verify(&root)?;
    Ok(root)
}
