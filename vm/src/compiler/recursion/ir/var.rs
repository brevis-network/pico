use super::{Builder, Ptr, Usize};
use crate::configs::config::RecursionGenericConfig;

pub trait Variable<RC: RecursionGenericConfig>: Clone {
    type Expression: From<Self>;

    fn uninit(builder: &mut Builder<RC>) -> Self;

    fn assign(&self, src: Self::Expression, builder: &mut Builder<RC>);

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<RC>,
    );

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<RC>,
    );
}

#[derive(Debug, Clone, Copy)]
pub struct MemIndex<N> {
    pub index: Usize<N>,
    pub offset: usize,
    pub size: usize,
}

pub trait MemVariable<RC: RecursionGenericConfig>: Variable<RC> {
    fn size_of() -> usize;
    /// Loads the variable from the heap.
    fn load(&self, ptr: Ptr<RC::N>, index: MemIndex<RC::N>, builder: &mut Builder<RC>);
    /// Stores the variable to the heap.
    fn store(&self, ptr: Ptr<RC::N>, index: MemIndex<RC::N>, builder: &mut Builder<RC>);
}

pub trait FromConstant<RC: RecursionGenericConfig> {
    type Constant;

    fn constant(value: Self::Constant, builder: &mut Builder<RC>) -> Self;
}
