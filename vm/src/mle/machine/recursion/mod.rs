//! Shared helpers for the MLE/WHIR recursion provers, organized by role. Intended consumers are
//! Convert, Combine, Embed, and Compress; **Convert** and **Combine** are wired today (Embed and
//! Compress are sibling drivers that consume the same helpers).
//!
//! - [`chips`] — the recursion chip set, keygen AIR refs, and proving-context construction.
//! - [`layout`] — stacking layout, constraint-DAG extraction, and VK-layout extraction.
//! - [`witness`] — WHIR query-index derivation, the proof → witness-stream serializer, and the
//!   convert and combine setup drivers.
//! - [`root_check`] — the host-side acceptance checks on a complete root's public values.
//!   Config-free (public values are `Kb` under any config), which is what lets combine and embed
//!   share them.

mod chips;
#[cfg(feature = "cuda")]
pub mod gpu;
mod layout;
mod root_check;
mod witness;

// Recursion (Convert / Combine) proves on CPU; `Sc` / `Kb` are shared with riscv.
pub use super::riscv::{Kb, Sc};
pub type Engine = pico_mle_cpu::KoalaBearPoseidon2CpuEngine;
pub type Pb = pico_mle_cpu::CpuBackend<Sc>;

pub use chips::{
    build_proving_ctx, check_recursion_tier, pad_convert_program, pad_recursion_program,
    recursion_air_refs_with_preprocessed, recursion_natural_rows, recursion_poseidon2_chip,
    recursion_poseidon2_packed_chip, recursion_tier_fit, select_convert_row, RecursionPrepAir,
};
pub use layout::{
    extract_recursion_vk_layout, extract_recursion_vk_layout_from_heights,
    recursion_vk_layouts_equal, stacking_layout_for_commit,
};
pub use root_check::{check_complete_root_public_values, recursion_public_values};
pub(crate) use witness::digest_to_u32s;
pub use witness::{
    setup_for_combine_with_program, setup_for_convert, setup_for_convert_with_program,
    setup_for_deferred_with_program, witness_flags, CombineChild,
};

/// Log a recursion proof's serialized size plus a per-field attribution, `label`-prefixed
/// (e.g. `"Combine: root"`). One copy, shared by the CPU e2e example and the GPU driver.
///
/// Two codecs, deliberately:
///   - the TOTAL is the canonical wire codec (`Encode`/`Decode`) — the bytes that would actually
///     be transmitted or stored. The verifying key is excluded: it is a fixed, separately known
///     artifact, not part of the proof.
///   - the per-field breakdown is postcard, which encodes the same 4-byte felts and so tracks
///     where growth comes from. **The fields do not add up to the total**: postcard's per-vector
///     length prefixes cost real bytes, and on a combine root the field sum measured ~22% above
///     the wire size. Read the breakdown as SHARES, not as bytes on the wire.
///
/// Costs one full serialization of the proof; intended for once-per-run reporting, not a hot path.
///
/// Logged on the `bench` target: the `RUST_LOG` these runs use filters this module's path out.
/// The proof in `mle-core`'s canonical versioned wire format.
///
/// The same encoding [`log_proof_size`] measures, exposed for a caller that has to SHIP the proof
/// rather than only report its size. Deliberately not the `serde` derive on `Proof`, whose own doc
/// comment marks it as debug/interop only: bytes that leave this process have to carry the codec's
/// version, or a later decode has nothing to key on.
pub fn proof_wire_bytes(
    proof: &pico_mle_core::protocol::proof::Proof<Sc>,
) -> std::io::Result<Vec<u8>> {
    use pico_mle_core::codec::Encode;
    proof.encode_to_vec()
}

pub fn log_proof_size(label: &str, proof: &pico_mle_core::protocol::proof::Proof<Sc>) {
    use pico_mle_core::codec::Encode;

    fn sz<T: serde::Serialize>(v: &T) -> usize {
        postcard::to_allocvec(v).map(|b| b.len()).unwrap_or(0)
    }

    let bytes = match proof.encode_to_vec() {
        Ok(b) => b.len(),
        // Reporting must never take down a run that has already produced a verified proof.
        Err(e) => {
            tracing::warn!("{label} proof: wire encode failed, size not reported: {e:?}");
            return;
        }
    };
    tracing::info!(
        target: "bench",
        "{label} proof serialized size = {bytes} bytes ({:.2} KiB)",
        bytes as f64 / 1024.0
    );
    tracing::info!(
        target: "bench",
        "{label} proof size breakdown: common_main_commit={} trace_vdata={} public_values={} \
         gkr={} batch_constraint={} stacking={} whir={}",
        sz(&proof.common_main_commit),
        sz(&proof.trace_vdata),
        sz(&proof.public_values),
        sz(&proof.gkr_proof),
        sz(&proof.batch_constraint_proof),
        sz(&proof.stacking_proof),
        sz(&proof.whir_proof),
    );
    let w = &proof.whir_proof;
    tracing::info!(
        target: "bench",
        "{label} whir breakdown: sumcheck_polys={} codeword_commits={} ood={} fold_pow={} \
         query_pow={} initial_opened_rows={} initial_merkle={} codeword_opened={} \
         codeword_merkle={}",
        sz(&w.whir_sumcheck_polys),
        sz(&w.codeword_commits),
        sz(&w.ood_values),
        sz(&w.folding_pow_witnesses),
        sz(&w.query_phase_pow_witnesses),
        sz(&w.initial_round_opened_rows),
        sz(&w.initial_round_merkle_proofs),
        sz(&w.codeword_opened_values),
        sz(&w.codeword_merkle_proofs),
    );
    let b = &proof.batch_constraint_proof;
    tracing::info!(
        target: "bench",
        "{label} batch_constraint breakdown: numer={} denom={} univariate={} sumcheck_rounds={} \
         column_openings={}",
        sz(&b.numerator_term_per_air),
        sz(&b.denominator_term_per_air),
        sz(&b.univariate_round_coeffs),
        sz(&b.sumcheck_round_polys),
        sz(&b.column_openings),
    );
}
