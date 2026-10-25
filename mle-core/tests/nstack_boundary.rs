//! Boundary regression: an AIR whose padded trace height equals the full stacked height
//! (`log_height == l_skip + n_stack`, i.e. `n_max == n_stack` — the trace fills the entire
//! stacked matrix) must still prove and verify.
//!
//! The boundary once broke at `CHUNK_SIZE=2^23` / `MLE_LOG_STACKED_HEIGHT=23`: the batch-constraint
//! univariate round-0 polynomial disagreed with the GKR sum claims, so verification failed with
//! `BatchConstraintError::SumClaimMismatch`. A half-height chip (`CHUNK_SIZE=2^22`) verified clean,
//! and a chunk whose tallest chip merely *padded* to the stacked height failed identically — the
//! trigger was the padded-height boundary alone.
//!
//! These are the CPU (reference-device) cases, so a future regression here means the shared
//! mle-core prover logic broke; the cuda-mle suite covers the GPU path.

use pico_mle_core::{
    engine::koala_bear_poseidon2::KoalaBearPoseidon2RefEngine,
    test_utils::{test_system_params_small, FibFixture, MixtureFixture, TestFixture},
    StarkEngine,
};

const L_SKIP: usize = 4;
const N_STACK: usize = 8;
const K_WHIR: usize = 4;
/// log2 of the stacked height; a trace at this log-height has n == n_stack.
const LOG_STACKED: usize = L_SKIP + N_STACK;

fn engine() -> KoalaBearPoseidon2RefEngine {
    KoalaBearPoseidon2RefEngine::new(test_system_params_small(L_SKIP, N_STACK, K_WHIR))
}

fn fib_roundtrip_at(log_height: usize) {
    let engine = engine();
    let fib = FibFixture::new(0, 1, 1usize << log_height);
    let (pk, vk) = fib.keygen(&engine);
    let proof = fib.prove(&engine, &pk);
    engine.verify(&vk, &proof).unwrap_or_else(|e| {
        panic!("verify failed at log_height={log_height} (stacked={LOG_STACKED}): {e:?}")
    });
}

/// Control: tallest trace at half the stacked height (the everyday case) — must pass.
#[test]
fn fib_below_boundary() {
    fib_roundtrip_at(LOG_STACKED - 1);
}

/// The boundary: trace height == stacked height (n_max == n_stack).
#[test]
fn fib_at_boundary() {
    fib_roundtrip_at(LOG_STACKED);
}

/// The boundary with a realistic AIR mix (interactions/logup + preprocessed + cached traces),
/// tallest member at the full stacked height — closest small-scale analogue of the reth chunk.
#[test]
fn mixture_at_boundary() {
    let engine = engine();
    let fx = MixtureFixture::standard(LOG_STACKED, engine.config().clone());
    let (pk, vk) = fx.keygen(&engine);
    let proof = fx.prove(&engine, &pk);
    engine
        .verify(&vk, &proof)
        .expect("mixture verify failed at the n_max == n_stack boundary");
}
