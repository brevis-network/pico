use super::DebuggerMessageLevel;
use crate::{
    configs::config::StarkGenericConfig,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseProvingKey,
        lookup::{LookupScope, LookupType, VirtualPairLookup},
    },
};
use itertools::multizip;
use log::{debug, error, info};
use p3_air::Air;
use p3_field::{Field, FieldAlgebra, PrimeField64};
use p3_matrix::Matrix;
use std::{collections::BTreeMap, fmt::Display, iter::repeat};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LookupData<F> {
    pub chip_name: String,
    pub kind: LookupType,
    pub row: usize,
    pub number: usize,
    pub is_looking: bool,
    pub mult: F,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DebugLookupKey<F> {
    pub kind: LookupType,
    pub values: Box<[F]>,
}

impl<F: Display> Display for DebugLookupKey<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} => [", self.kind)?;
        for i in 0..self.values.len() {
            if i != self.values.len() - 1 {
                write!(f, "{}, ", self.values[i])?;
            } else {
                write!(f, "{}", self.values[i])?;
            }
        }
        write!(f, "]")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct DebugLookup<F> {
    // key => (data, sum(data.mult))
    pub lookup_data: BTreeMap<DebugLookupKey<F>, (Vec<LookupData<F>>, F)>,
}

impl<F> DebugLookup<F>
where
    F: Field + PrimeField64,
{
    pub fn debug_lookups<SC, C>(
        pk: &BaseProvingKey<SC>,
        chip: &MetaChip<F, C>,
        chunk: &C::Record,
        scope: LookupScope,
        types: Option<&[LookupType]>,
    ) -> Self
    where
        SC: StarkGenericConfig<Val = F>,
        C: ChipBehavior<F>,
    {
        let trace = chip.generate_main(chunk, &mut C::Record::default());
        let height = trace.height();
        let preprocessed_trace = pk
            .preprocessed_chip_ordering
            .get(&chip.name())
            .map(|&n| &pk.preprocessed_trace[n]);

        let lookup_filter = |l: &VirtualPairLookup<F>| {
            l.scope == scope && types.map_or(true, |types| types.contains(&l.kind))
        };
        let looking = chip
            .looking
            .iter()
            .filter(|l| lookup_filter(l))
            .zip(repeat(true));
        let looked = chip
            .looked
            .iter()
            .filter(|l| lookup_filter(l))
            .zip(repeat(false));
        // this iterator has elements of kind (num, (lookup, is_looking))
        let lookups = looking.chain(looked).enumerate();

        let mut result = Self::default();
        let empty = [];

        // TODO: our current version of p3-matrix does not have row_slices, which can remove the
        // computation of height
        for row in 0..height {
            let main_row = trace.row_slice(row);
            let preprocessed_row_slice = preprocessed_trace.map(|t| t.row_slice(row));
            // preprocessed_row_slice would get dropped if inlined into the following line,
            // meaning we cannot take a reference to it
            let preprocessed_row = preprocessed_row_slice
                .as_deref()
                .unwrap_or(empty.as_slice());

            for (num, (lookup, is_looking)) in lookups.clone() {
                let mult: F = lookup.mult.apply(preprocessed_row, &main_row);

                // If we use Vec<F>, this allocates an [F; len]
                // Conversion to Rc<[F]> reallocates [strong | weak | [F; len]] and copies the data
                // rather than the pointer, so we collect directly into an Rc<[F]> which will write
                // directly to an Rc allocation, which is a cost already incurred if we write to
                // Vec<F>.
                // Alternatively, we can just use Box<[T]> because these keys are consumed directly
                // in debug_all.
                let values: Box<[F]> = lookup
                    .values
                    .iter()
                    .map(|v| v.apply(preprocessed_row, &main_row))
                    .collect();

                let key = DebugLookupKey {
                    kind: lookup.kind,
                    values,
                };
                let value = LookupData {
                    chip_name: chip.name(),
                    kind: lookup.kind,
                    row,
                    number: num,
                    is_looking,
                    mult,
                };

                let entry = result.lookup_data.entry(key).or_default();

                entry.0.push(value);
                let balance = &mut entry.1;
                if is_looking {
                    *balance += mult;
                } else {
                    *balance -= mult;
                }
            }
        }

        result
    }
}

#[allow(clippy::type_complexity)]
pub struct IncrementalLookupDebugger<'a, SC: StarkGenericConfig> {
    pk: &'a BaseProvingKey<SC>,
    scope: LookupScope,
    types: Option<&'a [LookupType]>,
    lookups: BTreeMap<DebugLookupKey<SC::Val>, (SC::Val, BTreeMap<String, SC::Val>)>,
    messages: Vec<(DebuggerMessageLevel, String)>,
    total: SC::Val,
}

impl<'a, SC: StarkGenericConfig> IncrementalLookupDebugger<'a, SC> {
    pub fn new(
        pk: &'a BaseProvingKey<SC>,
        scope: LookupScope,
        types: Option<&'a [LookupType]>,
    ) -> Self {
        let lookups = BTreeMap::new();
        let messages = vec![];
        let total = SC::Val::ZERO;

        Self {
            pk,
            scope,
            types,
            lookups,
            messages,
            total,
        }
    }

    pub fn print_results(self) -> bool
    where
        SC::Val: PrimeField64,
    {
        let mut success = true;

        info!("\n******** {} Lookups Debugging START ********", self.scope);

        for message in self.messages {
            match message {
                (DebuggerMessageLevel::Info, msg) => log::info!("{}", msg),
                (DebuggerMessageLevel::Debug, msg) => log::debug!("{}", msg),
                (DebuggerMessageLevel::Error, msg) => {
                    eprintln!("{}", msg);
                    success = false;
                }
            }
        }

        info!("Checking for imbalance");
        // checks the imbalance per lookup key
        for (k, (v, cv)) in self.lookups {
            if !v.is_zero() {
                info!("lookup imbalance of {} for {}", field_to_int(v), k);
                success = false;

                // print the detailed per-chip balancing data
                for (c, cv) in cv {
                    info!("  {} balance: {}", c, field_to_int(cv));
                }
            }
        }

        if success {
            info!("Lookups are balanced");
        } else {
            info!("Positive values mean more looking than looked");
            info!("Negative values mean more looked than looking");
            error!("Total imbalance: {}", field_to_int(self.total));
            if self.total.is_zero() {
                error!("Total lookings/lookeds match, but some lookups may have the wrong key");
            }
        }

        info!("\n******** {} Lookups Debugging END ********", self.scope);

        success
    }

    pub fn debug_incremental<C>(&mut self, chips: &[MetaChip<SC::Val, C>], chunks: &[C::Record])
    where
        C: ChipBehavior<SC::Val>
            + for<'b> Air<ProverConstraintFolder<'b, SC>>
            + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
        SC::Val: PrimeField64,
    {
        if self.scope == LookupScope::Regional {
            assert_eq!(
                chunks.len(),
                1,
                "Regional lookups could only be debugged in one chunk",
            );
        }

        // this stores (total balance, chip => local balance) per lookup key
        for chip in chips {
            let mut chip_events = 0;
            for chunk in chunks {
                let data = DebugLookup::debug_lookups(self.pk, chip, chunk, self.scope, self.types)
                    .lookup_data;
                chip_events += data.len();

                // this loop consumes counts and thus the lookup key which allows us to use Box
                // rather than Rc
                for (k, (_, v)) in data {
                    self.total += v;

                    let entry = self.lookups.entry(k).or_default();

                    // total balance
                    entry.0 += v;
                    // keyed balance
                    *entry.1.entry(chip.name()).or_default() += v;
                }
            }

            self.messages.push((
                DebuggerMessageLevel::Debug,
                format!("chip {} experienced {} events", chip.name(), chip_events),
            ));
        }
    }
}

/// Display field elements as signed integers on the range `[-modulus/2, modulus/2]`.
///
/// This presentation is useful when debugging lookups as it makes it clear which lookups
/// are `send` and which are `receive`.
fn field_to_int<F: PrimeField64>(x: F) -> i32 {
    let modulus = F::ORDER_U64;
    let val = x.as_canonical_u64();
    if val > modulus / 2 {
        val as i32 - modulus as i32
    } else {
        val as i32
    }
}
