//! Air with columns
//! | count | fields[..] |
//!
//! Chip will either send or receive the fields with multiplicity count.

use std::{iter, sync::Arc};

use crate::air::any_air::BaseAirWithPublicValues;
use itertools::izip;
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    air::PartitionedAirBuilder,
    builder::LookupBuilder,
    lookup::{LookupScope, LookupType, SymbolicLookup},
    poly::matrix::ColMajorMatrix,
    prover::{
        stacked_pcs::stacked_commit, AirProvingContext, CommittedTraceData,
        ReferenceColMajorBackend,
    },
    AirRef, PartitionedBaseAir, StarkProtocolConfig,
};

pub struct DummyInteractionCols;
impl DummyInteractionCols {
    pub fn count_col() -> usize {
        0
    }
    pub fn field_col(field_idx: usize) -> usize {
        field_idx + 1
    }
}

#[derive(Clone, Copy)]
pub struct DummyInteractionAir {
    field_width: usize,
    /// Send (`looking`) if true. Receive (`looked`) if false.
    pub is_send: bool,
    kind: LookupType,
    /// If true, then | count | and | fields[..] | are in separate main trace partitions.
    pub partition: bool,
}

impl DummyInteractionAir {
    pub fn new(field_width: usize, is_send: bool, kind: LookupType) -> Self {
        Self {
            field_width,
            is_send,
            kind,
            partition: false,
        }
    }

    pub fn partition(self) -> Self {
        Self {
            partition: true,
            ..self
        }
    }

    pub fn field_width(&self) -> usize {
        self.field_width
    }
}

impl<F> BaseAirWithPublicValues<F> for DummyInteractionAir {}
impl<F> PartitionedBaseAir<F> for DummyInteractionAir {
    fn cached_main_widths(&self) -> Vec<usize> {
        if self.partition {
            vec![self.field_width]
        } else {
            vec![]
        }
    }
    fn common_main_width(&self) -> usize {
        if self.partition {
            1
        } else {
            1 + self.field_width
        }
    }
}
impl<F> BaseAir<F> for DummyInteractionAir {
    fn width(&self) -> usize {
        1 + self.field_width
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        None
    }
}

impl<AB: PartitionedAirBuilder + LookupBuilder<SymbolicLookup<AB::Expr>>> Air<AB>
    for DummyInteractionAir
{
    fn eval(&self, builder: &mut AB) {
        let (fields, count) = if self.partition {
            let local_0 = builder.common_main().current_slice();
            let local_1 = builder.cached_mains()[0].current_slice();
            let count = local_0[0];
            let fields = local_1.to_vec();
            (fields, count)
        } else {
            let main = builder.main();
            let local = main.current_slice();
            let count = local[DummyInteractionCols::count_col()];
            let fields: Vec<_> = (0..self.field_width)
                .map(|i| local[DummyInteractionCols::field_col(i)])
                .collect();
            (fields, count)
        };
        let lookup = SymbolicLookup::new(
            fields.into_iter().map(Into::into).collect(),
            count.into(),
            self.kind,
            LookupScope::Regional,
        );
        if self.is_send {
            builder.looking(lookup);
        } else {
            builder.looked(lookup);
        }
    }
}

/// Note: in principle, committing cached trace is out of scope of a chip. But this chip is for
/// testing, so we support it for convenience.
pub struct DummyInteractionChip<SC> {
    config: Option<SC>,
    data: Option<DummyInteractionData>,
    pub air: DummyInteractionAir,
}

#[derive(Debug, Clone)]
pub struct DummyInteractionData {
    pub count: Vec<u32>,
    pub fields: Vec<Vec<u32>>,
}

impl<SC> DummyInteractionChip<SC> {
    pub fn new_without_partition(field_width: usize, is_send: bool, kind: LookupType) -> Self {
        let air = DummyInteractionAir::new(field_width, is_send, kind);
        Self {
            config: None,
            data: None,
            air,
        }
    }
    pub fn new_with_partition(
        config: SC,
        field_width: usize,
        is_send: bool,
        kind: LookupType,
    ) -> Self {
        let air = DummyInteractionAir::new(field_width, is_send, kind).partition();
        Self {
            config: Some(config),
            data: None,
            air,
        }
    }
    pub fn load_data(&mut self, data: DummyInteractionData) {
        let DummyInteractionData { count, fields } = &data;
        let h = count.len();
        assert_eq!(fields.len(), h);
        let w = fields[0].len();
        assert_eq!(self.air.field_width, w);
        assert!(fields.iter().all(|r| r.len() == w));
        self.data = Some(data);
    }
    pub fn air(&self) -> AirRef<SC>
    where
        SC: StarkProtocolConfig,
    {
        Arc::new(self.air)
    }
}

impl<SC: StarkProtocolConfig> DummyInteractionChip<SC> {
    pub fn generate_proving_ctx(&self) -> AirProvingContext<ReferenceColMajorBackend<SC>> {
        assert!(self.data.is_some());
        let data = self.data.clone().unwrap();
        if self.air.partition {
            self.generate_traces_with_partition(data)
        } else {
            let trace = self.generate_traces_without_partition(data);
            AirProvingContext::simple_no_pis(ColMajorMatrix::from_row_major(&trace))
        }
    }
}

impl<SC: StarkProtocolConfig> DummyInteractionChip<SC> {
    pub fn generate_traces_with_partition(
        &self,
        data: DummyInteractionData,
    ) -> AirProvingContext<ReferenceColMajorBackend<SC>> {
        let DummyInteractionData {
            mut count,
            mut fields,
        } = data;
        let h = count.len();
        assert_eq!(fields.len(), h);
        let w = fields[0].len();
        assert_eq!(self.air.field_width, w);
        assert!(fields.iter().all(|r| r.len() == w));
        let h = h.next_power_of_two();
        count.resize(h, 0);
        fields.resize(h, vec![0; w]);
        let common_main_val: Vec<_> = count.into_iter().map(SC::F::from_u32).collect();
        let cached_trace_val: Vec<_> = fields.into_iter().flatten().map(SC::F::from_u32).collect();
        let cached_trace_rm = RowMajorMatrix::new(cached_trace_val, w);
        let cached_trace = ColMajorMatrix::from_row_major(&cached_trace_rm);

        let config = self.config.as_ref().expect("params required for partition");
        let params = config.params();
        let (commit, data) = stacked_commit(
            config.hasher(),
            params.l_skip,
            params.n_stack,
            params.log_blowup,
            params.k_whir(),
            &[&cached_trace],
        )
        .unwrap();

        let common_main_rm = RowMajorMatrix::new(common_main_val, 1);
        AirProvingContext {
            cached_mains: vec![CommittedTraceData {
                commitment: commit,
                trace: cached_trace,
                data: Arc::new(data),
            }],
            common_main: ColMajorMatrix::from_row_major(&common_main_rm),
            public_values: vec![],
        }
    }

    fn generate_traces_without_partition(
        &self,
        data: DummyInteractionData,
    ) -> RowMajorMatrix<SC::F> {
        let DummyInteractionData { count, fields } = data;
        let h = count.len();
        assert_eq!(fields.len(), h);
        let w = fields[0].len();
        assert_eq!(self.air.field_width, w);
        assert!(fields.iter().all(|r| r.len() == w));
        let common_main_val: Vec<_> = izip!(count, fields)
            .flat_map(|(count, fields)| iter::once(count).chain(fields))
            .chain(iter::repeat(0))
            .take((w + 1) * h.next_power_of_two())
            .map(SC::F::from_u32)
            .collect();
        RowMajorMatrix::new(common_main_val, w + 1)
    }
}
