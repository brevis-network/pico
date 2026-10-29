//! `n_max == n_stack` boundary regression on the KoalaBear GPU engine.
//!
//! A trace whose padded height equals the full stacked height (`log_height == l_skip + n_stack`)
//! once failed verification with `BatchConstraintError::SumClaimMismatch` on the GPU path at
//! `CHUNK_SIZE=2^23` / `MLE_LOG_STACKED_HEIGHT=23`, while the CPU reference engine passed the
//! identical cases (`mle-core/tests/nstack_boundary.rs`). These cases keep that boundary covered.
//!
//! Run: `cargo test -p cuda-mle --features mle-core/test-utils --test nstack_boundary`
//!
//! The production-scale cases (stacked height 2^23) are `#[ignore]`d: each proves a full-height
//! matrix, so they take minutes and need most of a card. Run them deliberately, and serially —
//! several at once on one GPU exhaust its memory and fail as a false negative:
//!   `cargo test -p cuda-mle --test nstack_boundary -- --ignored --test-threads=1`
//!
//! KoalaBear-only by nature — every fixture here is built on `KoalaBearPoseidon2GpuEngine`. Without
//! this gate the file cannot compile under `--no-default-features`, which made
//! `clippy --lib --tests --no-default-features` fail to build before reaching any crate source.
//! All seven cases still run under the default (KoalaBear) feature set; nothing is suppressed.
use cuda_mle::KoalaBearPoseidon2GpuEngine;
use mle_core::{
    test_utils::{test_system_params_small, FibFixture, MixtureFixture, TestFixture},
    StarkEngine,
};

const L_SKIP: usize = 4;
const N_STACK: usize = 8;
const K_WHIR: usize = 4;
/// log2 of the stacked height; a trace at this log-height has n == n_stack.
const LOG_STACKED: usize = L_SKIP + N_STACK;

fn engine() -> KoalaBearPoseidon2GpuEngine {
    KoalaBearPoseidon2GpuEngine::new(test_system_params_small(L_SKIP, N_STACK, K_WHIR))
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

/// Control: tallest trace at half the stacked height — the everyday case.
#[test]
fn fib_below_boundary() {
    fib_roundtrip_at(LOG_STACKED - 1);
}

/// The boundary: trace height == stacked height (n_max == n_stack).
#[test]
fn fib_at_boundary() {
    fib_roundtrip_at(LOG_STACKED);
}

/// The boundary with a realistic AIR mix (interactions/logup + preprocessed + cached),
/// tallest member at the full stacked height — small-scale analogue of the reth chunk.
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

// ===========================================================================
// Same boundary at PRODUCTION scale (stacked height 2^23, n_stack = 19)
// ===========================================================================
// The toy-scale (2^12) cases above pass on GPU, so the reth failure needs scale as an
// ingredient, not just the n_max == n_stack boundary. These narrow-Fib cases isolate
// "chip height == stacked height" at the real stacked height 2^23.

fn engine_at(n_stack: usize) -> KoalaBearPoseidon2GpuEngine {
    KoalaBearPoseidon2GpuEngine::new(test_system_params_small(L_SKIP, n_stack, K_WHIR))
}

fn fib_roundtrip_scaled(n_stack: usize, log_height: usize) {
    let engine = engine_at(n_stack);
    let fib = FibFixture::new(0, 1, 1usize << log_height);
    let (pk, vk) = fib.keygen(&engine);
    let proof = fib.prove(&engine, &pk);
    engine.verify(&vk, &proof).unwrap_or_else(|e| {
        panic!(
            "verify failed at log_height={log_height} (stacked={}): {e:?}",
            L_SKIP + n_stack
        )
    });
}

/// Control at production scale: chip at half the stacked height (like CHUNK_SIZE=2^22 runs).
#[test]
#[ignore = "production scale (stacked 2^23): minutes and most of a card; run with --ignored --test-threads=1"]
fn fib_below_boundary_stacked23() {
    fib_roundtrip_scaled(19, 22);
}

/// Production-scale boundary: chip height == stacked height == 2^23 (the reth 2^23 case).
#[test]
#[ignore = "production scale (stacked 2^23): minutes and most of a card; run with --ignored --test-threads=1"]
fn fib_at_boundary_stacked23() {
    fib_roundtrip_scaled(19, 23);
}

/// Production-scale boundary with logup: the SumClaimMismatch equation ties the GKR
/// interaction claims to the univariate round — Fib alone has no interactions, so this
/// mixture (interactions + preprocessed + cached, tallest at 2^23) is the next ingredient.
#[test]
#[ignore = "production scale (stacked 2^23): minutes and most of a card; run with --ignored --test-threads=1"]
fn mixture_at_boundary_stacked23() {
    let engine = engine_at(19);
    let fx = MixtureFixture::standard(23, engine.config().clone());
    let (pk, vk) = fx.keygen(&engine);
    let proof = fx.prove(&engine, &pk);
    engine
        .verify(&vk, &proof)
        .expect("mixture verify failed at the production-scale n_max == n_stack boundary");
}

/// The boundary under the EXACT production parameters (`riscv_params_with_100_bits_security(23)`:
/// max_constraint_degree=3, w_stack=2048, production WHIR/pow params) — the remaining parameter
/// delta between the passing synthetic cases above and the failing reth run.
#[test]
#[ignore = "production scale (stacked 2^23): minutes and most of a card; run with --ignored --test-threads=1"]
fn mixture_at_boundary_prod_params() {
    use mle_core::config::riscv_params_with_100_bits_security;
    let engine = KoalaBearPoseidon2GpuEngine::new(riscv_params_with_100_bits_security(23));
    let fx = MixtureFixture::standard(23, engine.config().clone());
    let (pk, vk) = fx.keygen(&engine);
    let proof = fx.prove(&engine, &pk);
    engine
        .verify(&vk, &proof)
        .expect("mixture verify failed at boundary under production params");
}
