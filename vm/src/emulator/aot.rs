use crate::{
    compiler::riscv::program::Program,
    emulator::{
        opts::EmulatorOpts,
        riscv::{
            public_values::RecordFinalPvsState, riscv_emulator::EmulationError,
            state::RiscvEmulationState,
        },
    },
    machine::report::EmulationReport,
};
use alloc::{boxed::Box, sync::Arc};
use std::sync::OnceLock;

use crate::mle::{chosen_segments, env_u32};
use std::num::NonZeroU32;

/// The card count this process drives, or `None` when nothing said.
///
/// `PROVER_COUNT` is the env binding of a CLI field, so it is missing when a caller passes the
/// flag instead. Read once: both knobs below ask, and a typo should be reported once, not twice.
fn prover_count() -> Option<NonZeroU32> {
    static COUNT: OnceLock<Option<NonZeroU32>> = OnceLock::new();
    *COUNT.get_or_init(|| env_u32("PROVER_COUNT").and_then(NonZeroU32::new))
}

/// What `MLE_SPLIT_REPLAY` asked for, or `None` when it said nothing and the run's shape decides.
///
/// A value that cannot be read counts as off. It is not a licence to turn the split on, and `off`
/// / `no` / `false` are how the switches next door spell it — falling through to a derived value
/// would enable the split for someone who just tried to disable it.
fn requested_segments() -> Option<u32> {
    let raw = std::env::var("MLE_SPLIT_REPLAY").ok()?;
    Some(raw.trim().parse::<u32>().unwrap_or_else(|_| {
        tracing::warn!("MLE_SPLIT_REPLAY={raw:?} is not a number; leaving split replay off");
        1
    }))
}

/// `MLE_SPLIT_REPLAY=S` cuts the replay of the leading chunks into `S` segments so it can run on
/// several threads. `0` and `1` are both off.
///
/// Only the AOT snapshot runtime reads this, and only `emulate_snapshot_pipeline` consumes what
/// it hands back: the prover pipeline, the AOT validation harness, and `pico-prover`'s AOT path
/// through `mle::machine::riscv::emulate_with_pipeline`.
pub fn split_segments() -> u32 {
    static SEGMENTS: OnceLock<u32> = OnceLock::new();
    *SEGMENTS.get_or_init(|| {
        let threads = env_u32("NUM_THREADS").unwrap_or(1);
        let segments = chosen_segments(requested_segments(), threads, prover_count());
        // Splitting without knowing the card count cuts the first chunk alone, which moves the
        // stall rather than removing it. Only an explicit request gets here, so say so and go on.
        if segments > 1 && prover_count().is_none() {
            tracing::warn!(
                "split replay is on but PROVER_COUNT is unset, so only the first chunk is cut; \
                 set PROVER_COUNT, or MLE_SPLIT_CHUNKS, to cut one per card"
            );
        }
        // A split bigger than the memory pool waits on it forever, and
        // `proverchain::riscv::check_pipeline` refuses one before the run starts.
        segments
    })
}

/// `MLE_SPLIT_CHUNKS=K` is how many leading chunks get split. Unset, one per card: each card waits
/// for a chunk of its own before the run is up to speed, so fewer would move the stall rather than
/// remove it, and more would cut chunks whose card is already busy.
pub fn split_chunks() -> u32 {
    static CHUNKS: OnceLock<u32> = OnceLock::new();
    *CHUNKS.get_or_init(|| {
        env_u32("MLE_SPLIT_CHUNKS")
            .unwrap_or_else(|| prover_count().map_or(1, NonZeroU32::get))
            .min(64)
    })
}

pub trait AotSnapshotEmulator: Send {
    fn next_state_batch(
        &mut self,
    ) -> Result<(RiscvEmulationState, EmulationReport), EmulationError>;
    fn cycles(&self) -> u64;
    fn get_pv_stream(&mut self) -> Vec<u8>;

    /// The batch's replay segments, in clock order, as `(start state, target global clock)`.
    ///
    /// One segment — this default — is the shipped shape. An implementation that can hand back
    /// mid-chunk overrides it so the replay of one chunk can run on several threads and still
    /// prove once.
    fn next_state_batch_segments(
        &mut self,
    ) -> Result<(Vec<(RiscvEmulationState, u64)>, EmulationReport), EmulationError> {
        let (state, report) = self.next_state_batch()?;
        let target = report.current_cycle;
        Ok((vec![(state, target)], report))
    }
}

type AotFactory = fn(
    Arc<Program>,
    Vec<Vec<u8>>,
    EmulatorOpts,
    Arc<RecordFinalPvsState>,
) -> Box<dyn AotSnapshotEmulator>;

static AOT_FACTORY: OnceLock<AotFactory> = OnceLock::new();

/// Installs `factory` unless the process already holds one, and says whether it did: the first
/// install wins, and `false` means another caller's factory holds the slot.
pub fn register_aot_factory(factory: AotFactory) -> bool {
    AOT_FACTORY.set(factory).is_ok()
}

pub fn is_aot_factory_registered() -> bool {
    AOT_FACTORY.get().is_some()
}

pub fn create_aot_emulator(
    program: Arc<Program>,
    input_stream: Vec<Vec<u8>>,
    opts: EmulatorOpts,
    final_pvs_state: Arc<RecordFinalPvsState>,
) -> Option<Box<dyn AotSnapshotEmulator>> {
    AOT_FACTORY
        .get()
        .map(|factory| factory(program, input_stream, opts, final_pvs_state))
}

#[cfg(test)]
mod tests {
    use super::*;

    // OnceLock is process-wide and cannot be reset between tests; all
    // assertions that observe registration share a single test fn.
    struct DummyAot;
    impl AotSnapshotEmulator for DummyAot {
        fn next_state_batch(
            &mut self,
        ) -> Result<(RiscvEmulationState, EmulationReport), EmulationError> {
            unreachable!("dummy AOT emulator never invoked in tests")
        }
        fn cycles(&self) -> u64 {
            0
        }
        fn get_pv_stream(&mut self) -> Vec<u8> {
            Vec::new()
        }
    }

    fn dummy_factory(
        _p: Arc<Program>,
        _i: Vec<Vec<u8>>,
        _o: EmulatorOpts,
        _s: Arc<RecordFinalPvsState>,
    ) -> Box<dyn AotSnapshotEmulator> {
        Box::new(DummyAot)
    }

    #[test]
    fn factory_registration_and_creation() {
        assert!(!is_aot_factory_registered());

        register_aot_factory(dummy_factory);
        assert!(is_aot_factory_registered());

        // Registering a factory does NOT change EmulatorOpts::default() --
        // callers must opt in explicitly via `.with_snapshot_main(Aot)`.
        assert_eq!(
            EmulatorOpts::default().snapshot_main,
            crate::emulator::opts::SnapshotMainMode::Interpreter
        );

        // Factory is callable.
        let prog = Arc::new(Program::default());
        let boxed = create_aot_emulator(
            prog,
            Vec::new(),
            EmulatorOpts::default(),
            Arc::new(RecordFinalPvsState::default()),
        );
        assert!(boxed.is_some());
    }
}
