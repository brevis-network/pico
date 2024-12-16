/*
use super::DebuggerMessageLevel;
use crate::{
    configs::config::StarkGenericConfig,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseProvingKey,
        lookup::LookupType,
    },
};
use alloc::collections::BTreeMap;
use core::{fmt::Display, iter::repeat};
use p3_air::Air;
use p3_field::{Field, PrimeField64};
use p3_matrix::Matrix;
use tracing::error;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LookupData {
    pub chip_name: String,
    pub kind: LookupType,
    pub row: usize,
    pub number: usize,
    pub is_looking: bool,
    pub mult: isize,
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
    pub lookup_data: BTreeMap<DebugLookupKey<F>, (Vec<LookupData>, isize)>,
}

impl<F> DebugLookup<F>
where
    F: Field + PrimeField64,
{
    pub fn debug_lookups<SC, C>(
        chip: &MetaChip<F, C>,
        pkey: &BaseProvingKey<SC>,
        record: &C::Record,
        types: Option<&[LookupType]>,
    ) -> Self
    where
        SC: StarkGenericConfig<Val = F>,
        C: ChipBehavior<F>,
    {
        let trace = chip.generate_main(record, &mut C::Record::default());
        let height = trace.height();
        let preprocessed_trace = pkey
            .preprocessed_chip_ordering
            .get(&chip.name())
            .map(|&n| &pkey.preprocessed_trace[n]);
        let looking = chip.looking.iter().zip(repeat(true));
        let looked = chip.looked.iter().zip(repeat(false));
        let filter = |x| types.map_or(true, |v| v.contains(x));

        // this iterator has elements of kind (num, (lookup, is_looking))
        let lookups = looking
            .chain(looked)
            .enumerate()
            .filter(|x| filter(&x.1 .0.kind));
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

                // convert the upper half of F's range to negative values
                let mult = mult.as_canonical_u64() as isize;

                if mult == 0 {
                    continue;
                }

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

                if mult > (F::ORDER_U64 as isize) >> 1 {
                    error!(
                        "{} encountered large multiplicity for {}: {}",
                        &value.chip_name, &key, mult
                    );
                }

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

pub struct IncrementalLookupDebugger<'a, SC: StarkGenericConfig> {
    messages: Vec<(DebuggerMessageLevel, String)>,
    types: Option<&'a [LookupType]>,
    pk: &'a BaseProvingKey<SC>,
    lookup_map: BTreeMap<DebugLookupKey<SC::Val>, (isize, BTreeMap<String, isize>)>,
    total: isize,
}

impl<'a, SC: StarkGenericConfig> IncrementalLookupDebugger<'a, SC> {
    pub fn new(pk: &'a BaseProvingKey<SC>, types: Option<&'a [LookupType]>) -> Self {
        let messages = vec![(DebuggerMessageLevel::Info, "debugging all lookups".into())];
        Self {
            messages,
            types,
            pk,
            lookup_map: BTreeMap::new(),
            total: 0,
        }
    }

    pub fn print_results(self) -> bool {
        let mut result = false;
        for message in self.messages {
            match message {
                (DebuggerMessageLevel::Info, msg) => log::info!("{}", msg),
                (DebuggerMessageLevel::Debug, msg) => log::debug!("{}", msg),
                (DebuggerMessageLevel::Error, msg) => {
                    eprintln!("{}", msg);
                    result = true;
                }
            }
        }

        tracing::info_span!("debug lookups").in_scope(|| {
            tracing::info!("Checking for imbalance");
            // checks the imbalance per lookup key
            for (k, (v, cv)) in self.lookup_map {
                if v != 0 {
                    tracing::info!("lookup imbalance of {} for {}", v, k);
                    result = false;

                    // print the detailed per-chip balancing data
                    for (c, cv) in cv {
                        tracing::info!("  {} balance: {}", c, cv);
                    }
                }
            }

            // log overall results
            if result {
                tracing::info!("lookups are balanced");
            } else {
                tracing::info!("positive values mean more looking than looked");
                tracing::info!("negative values mean more looked than looking");
                tracing::info!("total imbalance: {}", self.total);
                if self.total == 0 {
                    tracing::info!(
                        "total sends/receives match, but some lookups may have the wrong key"
                    );
                }
            }

            result
        })
    }

    pub fn debug_incremental<C>(&mut self, chips: &[MetaChip<SC::Val, C>], records: &[C::Record])
    where
        C: ChipBehavior<SC::Val>
            + for<'b> Air<ProverConstraintFolder<'b, SC>>
            + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
        SC::Val: PrimeField64,
    {
        // this stores (total balance, chip => local balance) per lookup key
        let chips = chips.into_iter();
        let records = records.into_iter();

        for chip in chips {
            let mut chip_events = 0;
            for record in records.clone() {
                let data =
                    DebugLookup::debug_lookups(chip, self.pk, record, self.types).lookup_data;
                chip_events += data.len();

                // this loop consumes counts and thus the lookup key which allows us to use Box
                // rather than Rc
                for (k, (_, v)) in data {
                    self.total += v;

                    let entry = self.lookup_map.entry(k).or_default();

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
*/
