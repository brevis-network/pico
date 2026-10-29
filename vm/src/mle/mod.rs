//! Brevis RISCV glue for the MLE/WHIR proving backend.
//!
//! The protocol core (config, transcript, symbolic AIR, interaction model, polynomial primitives,
//! PCS / sumcheck / logup / WHIR prover & verifier, the col-major reference device, and the
//! `StarkEngine`) was extracted into the standalone `pico-mle-core` crate, and the optimized
//! row-major CPU device into `pico-mle-cpu`; import them as `pico_mle_core::…` / `pico_mle_cpu::…`.
//! Only the RISCV chip driver stays here: `machine/riscv.rs` (Phase-1 prove/verify/debug over the
//! full RISCV chip set) and `machine/air.rs` (per-chip `PartitionedBaseAir` /
//! `BaseAirWithPublicValues` wiring, so existing chips run on the MLE backend unchanged) — plus the
//! recursion (Convert) layer: `machine/convert.rs`, `machine/recursion/` and `compiler/` (the
//! verifier-program lowering).
pub mod compiler;
pub mod config;
pub mod machine;
pub mod spans;

pub use pico_mle_core::proof;
// Re-exported so drivers (distributed-vm) can configure the recursion provers without
// depending on pico-mle-core directly.
pub use pico_mle_core::config::recursion_params_with_100_bits_security;
// Re-exported for the same reason: `distributed-vm` enables the GPU backend only through
// `pico-vm/cuda` and has no direct dependency on the crate, so the per-chunk
// `MLE_BREAKDOWN` reporting in its worker loop reaches it as `pico_vm::mle::cuda_mle`.
#[cfg(feature = "cuda")]
pub use cuda_mle;

/// Read an env var as an opt-**out**: only `0` / `off` / `no` / `false` disable it, everything else
/// — including an unrecognised word — leaves the default in place, with a warning.
///
/// For a knob that ships ON: an unrecognised value must not read as "off", or someone bisecting a
/// regression would silently keep running the new path while believing they had turned it off.
pub fn env_opt_out(name: &str) -> bool {
    let Ok(raw) = std::env::var(name) else {
        return true;
    };
    let v = raw.trim().to_ascii_lowercase();
    if v.is_empty() {
        return true;
    }
    if matches!(v.as_str(), "0" | "off" | "no" | "false") {
        return false;
    }
    if matches!(v.as_str(), "1" | "on" | "yes" | "true") {
        return true;
    }
    tracing::warn!("{name}={raw:?} is not an on/off word; leaving it on");
    true
}

/// How many ways one chunk's replay may be cut.
///
/// An explicit request is a decision, `0` — the natural way to write "off" — included. Unset,
/// follow the shape of the run: the replay pool is shared across cards, so a card's share is
/// `threads / cards`, and that share is how many ways one chunk's replay can go. It stops at two,
/// where the measurements stop. A run that never said how many cards it drives cannot be sized,
/// so it stays off.
pub fn chosen_segments(
    requested: Option<u32>,
    threads: u32,
    cards: Option<std::num::NonZeroU32>,
) -> u32 {
    match (requested, cards) {
        (Some(segments), _) => segments.clamp(1, 16),
        (None, Some(cards)) => (threads / cards).clamp(1, 2),
        (None, None) => 1,
    }
}

/// Read an env var as a `u32`. A value that is not a number is a typo rather than a preference,
/// so it is reported instead of silently becoming the default.
pub fn env_u32(name: &str) -> Option<u32> {
    let raw = std::env::var(name).ok()?;
    match raw.trim().parse::<u32>() {
        Ok(value) => Some(value),
        Err(_) => {
            tracing::warn!("{name}={raw:?} is not a number; ignoring it");
            None
        }
    }
}

/// Read an env var as a boolean flag: present and not `0` / `false` / empty → enabled.
/// (A bare `std::env::var(..).is_ok()` would treat `FLAG=0` as on.)
pub fn env_flag(name: &str) -> bool {
    matches!(std::env::var(name).as_deref(), Ok(v) if !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false"))
}

#[cfg(test)]
mod tests {
    use super::chosen_segments;
    use std::num::NonZeroU32;

    fn cards(n: u32) -> Option<NonZeroU32> {
        NonZeroU32::new(n)
    }

    #[test]
    fn an_explicit_request_is_honoured() {
        assert_eq!(chosen_segments(Some(0), 8, cards(4)), 1, "`0` means off");
        assert_eq!(chosen_segments(Some(1), 8, cards(4)), 1);
        assert_eq!(
            chosen_segments(Some(3), 8, cards(4)),
            3,
            "above the derived cap"
        );
        assert_eq!(
            chosen_segments(Some(99), 8, cards(4)),
            16,
            "capped, not ignored"
        );
    }

    #[test]
    fn unset_follows_the_shape_of_the_run() {
        assert_eq!(chosen_segments(None, 8, cards(4)), 2, "the measured shape");
        assert_eq!(
            chosen_segments(None, 8, cards(8)),
            1,
            "no spare thread per card is off"
        );
        assert_eq!(
            chosen_segments(None, 8, cards(1)),
            2,
            "capped where the measurements stop"
        );
        assert_eq!(chosen_segments(None, 1, cards(1)), 1);
        assert_eq!(chosen_segments(None, 0, cards(4)), 1, "never zero segments");
    }

    /// Without a card count there is no honest size for the split, and cutting the first chunk
    /// alone is the shape it exists to avoid.
    #[test]
    fn an_unknown_card_count_is_off() {
        assert_eq!(chosen_segments(None, 8, None), 1);
    }
}
