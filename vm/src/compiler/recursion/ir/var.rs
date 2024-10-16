use super::{Builder, Config, Ptr, Usize};

pub trait Variable<CF: Config>: Clone {
    type Expression: From<Self>;

    fn uninit(builder: &mut Builder<CF>) -> Self;

    fn assign(&self, src: Self::Expression, builder: &mut Builder<CF>);

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<CF>,
    );

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<CF>,
    );
}

#[derive(Debug, Clone, Copy)]
pub struct MemIndex<N> {
    pub index: Usize<N>,
    pub offset: usize,
    pub size: usize,
}

pub trait MemVariable<CF: Config>: Variable<CF> {
    fn size_of() -> usize;
    /// Loads the variable from the heap.
    fn load(&self, ptr: Ptr<CF::N>, index: MemIndex<CF::N>, builder: &mut Builder<CF>);
    /// Stores the variable to the heap.
    fn store(&self, ptr: Ptr<CF::N>, index: MemIndex<CF::N>, builder: &mut Builder<CF>);
}

pub trait FromConstant<CF: Config> {
    type Constant;

    fn constant(value: Self::Constant, builder: &mut Builder<CF>) -> Self;
}
