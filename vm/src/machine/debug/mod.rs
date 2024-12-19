mod constraints;
mod lookups;

use super::{
    chip::{ChipBehavior, MetaChip},
    folder::{DebugConstraintFolder, ProverConstraintFolder, VerifierConstraintFolder},
    keys::BaseProvingKey,
    lookup::{LookupScope, LookupType},
};
use crate::{configs::config::StarkGenericConfig, emulator::record::RecordBehavior};
use constraints::IncrementalConstraintDebugger;
use k256::pkcs8::DecodePublicKey;
use log::info;
use lookups::IncrementalLookupDebugger;
use p3_air::Air;
use p3_field::PrimeField64;
use std::slice;

#[allow(dead_code)]
pub(crate) enum DebuggerMessageLevel {
    Info,
    Debug,
    Error,
}

pub fn debug_all_constraints<SC, C>(
    pk: &BaseProvingKey<SC>,
    challenger: &mut SC::Challenger,
    chips: &[MetaChip<SC::Val, C>],
    chunks: &[C::Record],
) where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val> + for<'b> Air<DebugConstraintFolder<'b, SC::Val, SC::Challenge>>,
{
    let mut debugger = IncrementalConstraintDebugger::new(pk, challenger);

    debugger.debug_incremental(chips, chunks);
    debugger.print_results();
}

pub fn debug_all_lookups<SC, C>(
    pk: &BaseProvingKey<SC>,
    chips: &[MetaChip<SC::Val, C>],
    chunks: &[C::Record],
    types: Option<&[LookupType]>,
) where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
    SC::Val: PrimeField64,
{
    chunks.iter().for_each(|chunk| {
        info!(
            "Debugging regional lookups for chunk-{}",
            chunk.chunk_index(),
        );
        let mut debugger = IncrementalLookupDebugger::new(pk, LookupScope::Regional, types);
        debugger.debug_incremental(chips, slice::from_ref(chunk));
        debugger.print_results();
    });

    info!("Debugging global lookups");
    let mut debugger = IncrementalLookupDebugger::new(pk, LookupScope::Global, types);
    debugger.debug_incremental(chips, chunks);
    debugger.print_results();
}
