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
use log::{error, info};
use p3_air::Air;
use p3_field::{Field, PrimeField64};
use p3_matrix::Matrix;

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
        let trace = chip.generate_main(&record, &mut C::Record::default());
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
                let mult: F = lookup.mult.apply(&preprocessed_row, &main_row);

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
                    .map(|v| v.apply(&preprocessed_row, &main_row))
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
                    *balance += mult as isize;
                } else {
                    *balance -= mult as isize;
                }
            }
        }

        result
    }

    pub fn debug_all<'r, 'c, SC, C, CI, R>(
        chips: CI,
        pkey: &BaseProvingKey<SC>,
        records: R,
        types: Option<&[LookupType]>,
    ) -> bool
    where
        SC: StarkGenericConfig<Val = F>,
        C: ChipBehavior<F>
            + for<'a> Air<ProverConstraintFolder<'a, SC>>
            + for<'a> Air<VerifierConstraintFolder<'a, SC>>
            + 'r + 'c,
        CI: IntoIterator<Item = &'c MetaChip<F, C>>,
        R: IntoIterator<Item = &'r C::Record>,
        <R as IntoIterator>::IntoIter: Clone,
        <CI as IntoIterator>::IntoIter: Clone,
    {
        // this stores (total balance, chip => local balance) per lookup key
        let mut lookup_map: BTreeMap<DebugLookupKey<F>, (isize, BTreeMap<&str, isize>)> =
            BTreeMap::new();
        let mut total = 0;
        let chips = chips.into_iter();
        let records = records.into_iter();

        // allocate the name strings exactly once
        // TODO: maybe consider ChipBehavior::name -> &'static str
        let names: Box<[String]> = chips.clone().map(ChipBehavior::name).collect();

        for (chip, name) in chips.zip(names.iter()) {
            let mut chip_events = 0;
            for record in records.clone() {
                let data = Self::debug_lookups(chip, pkey, record, types.clone()).lookup_data;
                chip_events += data.len();

                // this loop consumes counts and thus the lookup key which allows us to use Box
                // rather than Rc
                for (k, (_, v)) in data {
                    total += v;

                    let entry = lookup_map.entry(k).or_default();

                    // total balance
                    entry.0 += v;
                    // keyed balance
                    *entry.1.entry(&name).or_default() += v;
                }
            }

            info!("chip {} experienced {} events", name, chip_events);
        }

        let mut result = true;

        // checks the imbalance per lookup key
        for (k, (v, cv)) in lookup_map {
            if v != 0 {
                info!("lookup imbalance of {} for {}", v, k);
                result = false;

                // print the detailed per-chip balancing data
                for (c, cv) in cv {
                    info!("{} balance: {}", c, cv);
                }
            }
        }

        // log overall results
        if result {
            info!("lookups are balanced");
        } else {
            info!("positive values mean more looking than looked");
            info!("negative values mean more looked than looking");
            info!("total imbalance: {}", total);
            if total == 0 {
                info!("total sends/receives match, but some lookups may have the wrong key");
            }
        }

        result
    }
}
