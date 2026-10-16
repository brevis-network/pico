use crate::air::any_air::BaseAirWithPublicValues;
use itertools::{fold, Itertools};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    builder::LookupBuilder,
    lookup::{LookupScope, LookupType, SymbolicLookup},
    poly::matrix::ColMajorMatrix,
    prover::{AirProvingContext, ReferenceColMajorBackend},
    PartitionedBaseAir, StarkProtocolConfig,
};

#[derive(Debug, Clone, Copy)]
pub struct SelfInteractionAir {
    pub width: usize,
    pub kind: LookupType,
}

impl<F> BaseAir<F> for SelfInteractionAir {
    fn width(&self) -> usize {
        self.width
    }
}
impl<F> BaseAirWithPublicValues<F> for SelfInteractionAir {}
impl<F> PartitionedBaseAir<F> for SelfInteractionAir {}

impl<AB: AirBuilder + LookupBuilder<SymbolicLookup<AB::Expr>>> Air<AB> for SelfInteractionAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        let (local, next) = (main.current_slice(), main.next_slice());
        let mut local: Vec<<AB as AirBuilder>::Expr> =
            (*local).iter().map(|v| (*v).into()).collect_vec();
        let mut next: Vec<<AB as AirBuilder>::Expr> =
            (*next).iter().map(|v| (*v).into()).collect_vec();

        let local_sum = fold(&local, AB::Expr::ZERO, |acc, val| acc + val.clone());
        let next_sum = fold(&local, AB::Expr::ZERO, |acc, val| acc + val.clone());

        let lookup = |values: Vec<AB::Expr>, mult: AB::Expr| {
            SymbolicLookup::new(values, mult, self.kind, LookupScope::Regional)
        };

        // Interaction where count is constant
        builder.looking(lookup(local.clone(), AB::Expr::ONE));
        builder.looked(lookup(next.clone(), AB::Expr::ONE));

        // Interaction where count is an expression + common with interaction below
        builder.looking(lookup(local.clone(), local_sum.clone()));
        builder.looked(lookup(next.clone(), next_sum.clone()));

        // Interaction where count == fields[0]
        builder.looking(lookup(local.clone(), local[0].clone()));
        builder.looked(lookup(next.clone(), next[0].clone()));

        local.reverse();
        next.reverse();

        // Interaction where count is an expression + common with interaction above
        builder.looking(lookup(local, local_sum));
        builder.looked(lookup(next, next_sum));
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SelfInteractionChip {
    pub width: usize,
    pub log_height: usize,
}

impl SelfInteractionChip {
    pub fn generate_proving_ctx<SC: StarkProtocolConfig>(
        &self,
    ) -> AirProvingContext<ReferenceColMajorBackend<SC>> {
        assert!(self.width > 0);
        let mut trace = vec![SC::F::ZERO; (1 << self.log_height) * self.width];
        for (row_idx, chunk) in trace.chunks_mut(self.width).enumerate() {
            for (i, val) in chunk.iter_mut().enumerate() {
                *val = SC::F::from_usize((row_idx + i) % self.width);
            }
        }
        let rm = RowMajorMatrix::new(trace, self.width);
        AirProvingContext::simple_no_pis(ColMajorMatrix::from_row_major(&rm))
    }
}
