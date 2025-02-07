use super::{Builder, Ptr, Usize};
use crate::configs::config::FieldGenericConfig;

pub trait Variable<FC: FieldGenericConfig>: Clone {
    type Expression: From<Self>;

    fn uninit(builder: &mut Builder<FC>) -> Self;

    fn assign(&self, src: Self::Expression, builder: &mut Builder<FC>);

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<FC>,
    );

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<FC>,
    );
}

#[derive(Debug, Clone, Copy)]
pub struct MemIndex<N> {
    pub index: Usize<N>,
    pub offset: usize,
    pub size: usize,
}

pub trait MemVariable<FC: FieldGenericConfig>: Variable<FC> {
    fn size_of() -> usize;
    /// Loads the variable from the heap.
    fn load(&self, ptr: Ptr<FC::N>, index: MemIndex<FC::N>, builder: &mut Builder<FC>);
    /// Stores the variable to the heap.
    fn store(&self, ptr: Ptr<FC::N>, index: MemIndex<FC::N>, builder: &mut Builder<FC>);
}

pub trait FromConstant<FC: FieldGenericConfig> {
    type Constant;

    fn constant(value: Self::Constant, builder: &mut Builder<FC>) -> Self;
}
