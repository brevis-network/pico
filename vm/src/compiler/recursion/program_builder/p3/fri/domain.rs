use super::{super::commit::PolynomialSpaceVariable, types::FriConfigVariable};
use crate::compiler::recursion::prelude::*;
use p3_commit::{LagrangeSelectors, TwoAdicMultiplicativeCoset};
use p3_field::{AbstractField, TwoAdicField};

/// Reference: [p3_commit::TwoAdicMultiplicativeCoset]
#[derive(DslVariable, Clone, Copy)]
pub struct TwoAdicMultiplicativeCosetVariable<CF: Config> {
    pub log_n: Var<CF::N>,
    pub size: Var<CF::N>,
    pub shift: Felt<CF::F>,
    pub g: Felt<CF::F>,
}

impl<CF: Config> TwoAdicMultiplicativeCosetVariable<CF> {
    pub const fn size(&self) -> Var<CF::N> {
        self.size
    }

    pub const fn first_point(&self) -> Felt<CF::F> {
        self.shift
    }

    pub const fn gen(&self) -> Felt<CF::F> {
        self.g
    }
}

impl<CF: Config> FromConstant<CF> for TwoAdicMultiplicativeCosetVariable<CF>
where
    CF::F: TwoAdicField,
{
    type Constant = TwoAdicMultiplicativeCoset<CF::F>;

    fn constant(value: Self::Constant, builder: &mut Builder<CF>) -> Self {
        let log_d_val = value.log_n as u32;
        let g_val = CF::F::two_adic_generator(value.log_n);
        TwoAdicMultiplicativeCosetVariable::<CF> {
            log_n: builder.eval::<Var<_>, _>(CF::N::from_canonical_u32(log_d_val)),
            size: builder.eval::<Var<_>, _>(CF::N::from_canonical_u32(1 << (log_d_val))),
            shift: builder.eval(value.shift),
            g: builder.eval(g_val),
        }
    }
}

impl<CF: Config> PolynomialSpaceVariable<CF> for TwoAdicMultiplicativeCosetVariable<CF>
where
    CF::F: TwoAdicField,
{
    type Constant = p3_commit::TwoAdicMultiplicativeCoset<CF::F>;

    fn next_point(
        &self,
        builder: &mut Builder<CF>,
        point: Ext<<CF as Config>::F, <CF as Config>::EF>,
    ) -> Ext<<CF as Config>::F, <CF as Config>::EF> {
        builder.eval(point * self.gen())
    }

    fn selectors_at_point(
        &self,
        builder: &mut Builder<CF>,
        point: Ext<<CF as Config>::F, <CF as Config>::EF>,
    ) -> LagrangeSelectors<Ext<<CF as Config>::F, <CF as Config>::EF>> {
        let unshifted_point: Ext<_, _> = builder.eval(point * self.shift.inverse());
        let z_h_expr = builder
            .exp_power_of_2_v::<Ext<_, _>>(unshifted_point, Usize::Var(self.log_n))
            - CF::EF::one();
        let z_h: Ext<_, _> = builder.eval(z_h_expr);

        LagrangeSelectors {
            is_first_row: builder.eval(z_h / (unshifted_point - CF::EF::one())),
            is_last_row: builder.eval(z_h / (unshifted_point - self.gen().inverse())),
            is_transition: builder.eval(unshifted_point - self.gen().inverse()),
            inv_zeroifier: builder.eval(z_h.inverse()),
        }
    }

    fn zp_at_point(
        &self,
        builder: &mut Builder<CF>,
        point: Ext<<CF as Config>::F, <CF as Config>::EF>,
    ) -> Ext<<CF as Config>::F, <CF as Config>::EF> {
        let unshifted_power = builder
            .exp_power_of_2_v::<Ext<_, _>>(point * self.shift.inverse(), Usize::Var(self.log_n));
        builder.eval(unshifted_power - CF::EF::one())
    }

    fn split_domains(
        &self,
        builder: &mut Builder<CF>,
        log_num_chunks: impl Into<Usize<CF::N>>,
        num_chunks: impl Into<Usize<CF::N>>,
    ) -> Array<CF, Self> {
        let log_num_chunks = log_num_chunks.into();
        let num_chunks = num_chunks.into();
        let log_n: Var<_> = builder.eval(self.log_n - log_num_chunks);
        let size = builder.sll(CF::N::one(), Usize::Var(log_n));

        let g_dom = self.gen();
        let g = builder.exp_power_of_2_v::<Felt<CF::F>>(g_dom, log_num_chunks);

        let domain_power: Felt<_> = builder.eval(CF::F::one());

        let mut domains = builder.dyn_array(num_chunks);

        builder.range(0, num_chunks).for_each(|i, builder| {
            let domain = TwoAdicMultiplicativeCosetVariable {
                log_n,
                size,
                shift: builder.eval(self.shift * domain_power),
                g,
            };
            builder.set(&mut domains, i, domain);
            builder.assign(domain_power, domain_power * g_dom);
        });

        domains
    }

    fn split_domains_const(&self, builder: &mut Builder<CF>, log_num_chunks: usize) -> Vec<Self> {
        let num_chunks = 1 << log_num_chunks;
        let log_n: Var<_> = builder.eval(self.log_n - CF::N::from_canonical_usize(log_num_chunks));
        let size = builder.sll(CF::N::one(), Usize::Var(log_n));

        let g_dom = self.gen();
        let g = builder.exp_power_of_2_v::<Felt<CF::F>>(g_dom, log_num_chunks);

        let domain_power: Felt<_> = builder.eval(CF::F::one());
        let mut domains = vec![];

        for _ in 0..num_chunks {
            domains.push(TwoAdicMultiplicativeCosetVariable {
                log_n,
                size,
                shift: builder.eval(self.shift * domain_power),
                g,
            });
            builder.assign(domain_power, domain_power * g_dom);
        }
        domains
    }

    fn create_disjoint_domain(
        &self,
        builder: &mut Builder<CF>,
        log_degree: Usize<<CF as Config>::N>,
        config: Option<FriConfigVariable<CF>>,
    ) -> Self {
        let domain = config.unwrap().get_subgroup(builder, log_degree);
        builder.assign(domain.shift, self.shift * CF::F::generator());
        domain
    }
}
