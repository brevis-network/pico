//! Deferred-verifier node: prove one, verify it, and check what it published.
//!
//! Proves a guest end to end (riscv → convert → combine root), then feeds that root back in as a
//! *sub-proof* and proves one deferred node over it. The node is not spliced into a tree here, so
//! what this gate covers is the node itself:
//!
//!   1. it proves and verifies under the honestly keygen'd VK;
//!   2. every public value but `digest` matches the contract the aggregation tree will rely on
//!      (chunk cursors at 1, no execution chunk, neutral GCS, the MAIN program's exe identity and
//!      entry pc, `flag_complete == 0` so it can never pose as a root). `digest` is left to the
//!      parent that consumes the node, which recomputes it;
//!   3. **the chain step it computed in-circuit equals the host's `hash_deferred_proof`** — the
//!      same function the guest runs behind `verify_pico_proof`. That equality is what makes the
//!      guest's claimed digest and the tree's reconstructed one comparable at all.
//!
//! Usage:
//!   cargo run --release -p pico-vm --example test_mle_deferred -- --elf fib --n 10 --field kb

use p3_field::PrimeCharacteristicRing;
use pico_mle_core::config::recursion_params_with_100_bits_security;
use pico_vm::{
    compiler::riscv::compiler::{Compiler, SourceType},
    configs::stark_config::KoalaBearPoseidon2,
    emulator::recursion::public_values::RECURSION_PUBLIC_VALUES_COL_MAP,
    machine::logger::setup_logger,
    mle::machine::{
        deferred::DeferredMachine,
        exe::RiscvVmVk,
        recursion::{recursion_public_values, Kb},
        riscv,
    },
    primitives::{consts::DIGEST_SIZE, hash_deferred_proof},
};
use tracing::info;

#[path = "common/emulate.rs"]
mod emulate;
#[path = "common/parse_args.rs"]
mod parse_args;
#[path = "common/tree.rs"]
mod tree;
use tree::build_tree;

fn main() {
    setup_logger();
    // The GPU riscv prover allocates from the shared pool; a CPU build has none to set up.
    #[cfg(feature = "cuda")]
    riscv::init_mle_gpu_pool(riscv::MLE_GPU_DEVICE);
    let (elf, stdin, args) = parse_args::parse_args::<KoalaBearPoseidon2>();
    assert_eq!(
        args.field, "kb",
        "test_mle_deferred is KoalaBear-only by design; got --field {}",
        args.field
    );
    // Dev mode only: the whitelist path is `test_mle_deferred_whitelist`'s.
    let whitelist = std::env::var("VK_VERIFICATION")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    assert!(
        !whitelist,
        "test_mle_deferred runs outside the whitelist; use test_mle_deferred_whitelist for it"
    );

    let compiler = Compiler::new(SourceType::RISCV, elf).expect("failed to parse ELF");
    let program = compiler.compile();

    let log_stacked_height: usize = std::env::var("MLE_LOG_STACKED_HEIGHT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(23);
    let opts = emulate::opts_from_env_chunk_size(1 << 23);
    // A chunk wider than the stacked height proves the wrong shape, and both are env-settable.
    assert!(
        (opts.chunk_size as u64) <= (1u64 << log_stacked_height),
        "chunk_size {} exceeds 2^{log_stacked_height}: raise MLE_LOG_STACKED_HEIGHT with CHUNK_SIZE",
        opts.chunk_size
    );
    let emulated = emulate::emulate_with_opts(program.clone(), &stdin, opts);
    info!("emulated {} chunk(s)", emulated.records.len());

    // ── The sub-proof: an ordinary end-to-end run of the guest ──────────────────────────────
    let bundle = riscv::prove_riscv(
        program.clone(),
        &emulated.records,
        log_stacked_height,
        false,
    )
    .expect("riscv prove failed");
    let (riscv_vk, riscv_proofs) = bundle.into_parts();
    let riscv_vm_vk = RiscvVmVk::from_program_and_vk(&program, &riscv_vk);
    // No deferred nodes and no chain value: an ordinary tree, which is what a sub-proof is.
    let sub_root = build_tree(
        &riscv_vk,
        &riscv_vm_vk,
        &riscv_proofs,
        [Kb::ZERO; DIGEST_SIZE],
        &[],
    )
    .expect("sub-proof tree failed");
    info!("sub-proof: complete root proved + verified ✓");

    // ── One deferred node over it ───────────────────────────────────────────────────────────
    // The node publishes the MAIN program's identity. This run has only one program, so the
    // sub-proof's own guest stands in for it; in a tree the two differ and continuity is what
    // forces this field to the main program's value.
    let mut deferred = DeferredMachine::new(
        recursion_params_with_100_bits_security(),
        riscv_vm_vk.clone(),
        false,
    );
    let (nodes, final_digest) = deferred
        .prove_chain(std::slice::from_ref(&sub_root))
        .expect("deferred prove_chain failed");
    assert_eq!(nodes.len(), 1, "one sub-proof should give one node");
    deferred
        .verify(&nodes[0])
        .expect("deferred node verify failed");
    info!(
        "deferred: 1 node proved + verified ({} distinct shape(s)) ✓",
        deferred.num_distinct_shapes()
    );

    // ── What the node published ─────────────────────────────────────────────────────────────
    let pvs = recursion_public_values(&nodes[0].0.public_values).expect("node public values");
    let col = RECURSION_PUBLIC_VALUES_COL_MAP;
    let one = Kb::ONE;
    let zero = Kb::ZERO;

    // Chunk and execution-chunk cursors sit at 1 and the node contains no execution chunk: that
    // is what makes it transparent to the tree's chunk chain, and it is also what pins it to the
    // head of the tree (a riscv leaf's next_chunk is >= 2, so nothing can follow one).
    assert_eq!(pvs[col.start_chunk], one, "start_chunk");
    assert_eq!(pvs[col.next_chunk], one, "next_chunk");
    assert_eq!(pvs[col.start_execution_chunk], one, "start_execution_chunk");
    assert_eq!(pvs[col.next_execution_chunk], one, "next_execution_chunk");
    assert_eq!(
        pvs[col.contains_execution_chunk], zero,
        "contains_execution_chunk"
    );
    // A deferred node can never pose as a complete root.
    assert_eq!(pvs[col.flag_complete], zero, "flag_complete");
    assert_eq!(pvs[col.exit_code], zero, "exit_code");
    // Outside the whitelist the node carries no root, as no node does.
    for j in 0..DIGEST_SIZE {
        assert_eq!(pvs[col.vk_root[j]], zero, "vk_root[{j}]");
    }
    // `digest` is not checked here: it is the parent's `assert_child_pv_digests` that has to
    // recompute it, and this node has no parent yet.
    // It makes no claim about the program's output or its own deferred digest: the merge's
    // consistency lock reads a zero output as "no opinion", and it sums deferred digests.
    for (j, word) in col.committed_value_digest.iter().enumerate() {
        for (k, &idx) in word.0.iter().enumerate() {
            assert_eq!(pvs[idx], zero, "committed_value_digest[{j}][{k}]");
        }
    }
    for j in 0..DIGEST_SIZE {
        assert_eq!(pvs[col.deferred_proofs_digest[j]], zero, "deferred[{j}]");
    }
    // Memory cursors stay closed, so the first execution leaf inherits `previous_* == 0` through
    // continuity.
    for j in 0..3 {
        assert_eq!(pvs[col.previous_init_addr_limbs[j]], zero, "prev_init[{j}]");
        assert_eq!(pvs[col.last_init_addr_limbs[j]], zero, "last_init[{j}]");
        assert_eq!(
            pvs[col.previous_finalize_addr_limbs[j]], zero,
            "prev_fin[{j}]"
        );
        assert_eq!(pvs[col.last_finalize_addr_limbs[j]], zero, "last_fin[{j}]");
    }
    // pc: frozen at the MAIN program's entry, which continuity welds to the chunk-1 leaf.
    for j in 0..3 {
        assert_eq!(
            pvs[col.start_pc[j]], riscv_vm_vk.pc_start[j],
            "start_pc[{j}]"
        );
        assert_eq!(pvs[col.next_pc[j]], riscv_vm_vk.pc_start[j], "next_pc[{j}]");
    }
    // The MAIN program's exe identity — NOT the sub-program's, which travels in the chain.
    let main_digest = riscv_vm_vk.digest();
    for j in 0..DIGEST_SIZE {
        assert_eq!(
            pvs[col.riscv_vk_digest[j]], main_digest[j],
            "riscv_vk_digest[{j}]"
        );
    }
    // The GCS fold is `Σ d_i − (n−1)·zero`, so contributing exactly `zero` leaves the tree's sum
    // untouched.
    for j in 0..7 {
        assert_eq!(
            pvs[col.global_cumulative_sum.0.x.0[j]],
            Kb::from_u32(
                <Kb as pico_vm::machine::septic::FieldSepticCurve>::CURVE_CUMULATIVE_SUM_START_X[j]
            ),
            "gcs.x[{j}]"
        );
        assert_eq!(
            pvs[col.global_cumulative_sum.0.y.0[j]],
            Kb::from_u32(
                <Kb as pico_vm::machine::septic::FieldSepticCurve>::CURVE_CUMULATIVE_SUM_START_Y[j]
            ),
            "gcs.y[{j}]"
        );
    }

    // ── The chain step: in-circuit vs the guest's own hash ───────────────────────────────────
    // The node starts the chain at zero (it is the first step) and ends at
    // H(start ‖ child.riscv_vk_digest ‖ child.committed_value_digest). Recomputing that with
    // `hash_deferred_proof` — the function the guest runs behind `verify_pico_proof` — is the
    // parity that the whole design rests on: if these two ever diverge, a tree would close its
    // chain on a digest no guest could ever have produced.
    for j in 0..DIGEST_SIZE {
        assert_eq!(
            pvs[col.start_reconstruct_deferred_digest[j]], zero,
            "start_reconstruct[{j}]"
        );
    }
    let child_pvs = recursion_public_values(&sub_root.0.public_values).expect("sub-root pvs");
    let child_vk_digest: [Kb; DIGEST_SIZE] =
        std::array::from_fn(|j| child_pvs[col.riscv_vk_digest[j]]);
    let mut child_cvd = [Kb::ZERO; 32];
    for (slot, &idx) in child_cvd.iter_mut().zip(
        col.committed_value_digest
            .iter()
            .flat_map(|word| word.0.iter()),
    ) {
        *slot = child_pvs[idx];
    }
    let expected = hash_deferred_proof(&[Kb::ZERO; DIGEST_SIZE], &child_vk_digest, &child_cvd);
    for j in 0..DIGEST_SIZE {
        assert_eq!(
            pvs[col.end_reconstruct_deferred_digest[j]], expected[j],
            "end_reconstruct[{j}]: the in-circuit chain step disagrees with hash_deferred_proof"
        );
    }
    // The digest the host hands back drives the next step and, at the end, the value a tree has
    // to close on. It is computed from the same function, so what this catches is the field
    // extraction around it — that `chain_step` reads the child's digest and output digest from
    // the slots this example reads them from.
    assert_eq!(final_digest, expected, "returned chain digest");

    info!("deferred node public values + chain-step parity ✓");
}
