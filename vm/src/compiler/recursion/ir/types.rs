use super::{
    Builder, DslIr, ExtConst, ExtHandle, FeltHandle, FromConstant, MemIndex, MemVariable, Ptr,
    SymbolicExt, SymbolicFelt, SymbolicUsize, SymbolicVar, VarHandle, Variable,
};
use crate::configs::config::FieldGenericConfig;
use alloc::format;
use p3_field::{ExtensionField, Field, FieldAlgebra, FieldExtensionAlgebra};
use serde::{Deserialize, Serialize};

/// A variable that represents a native field element.
///
/// Used for counters, simple loops, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Var<N> {
    pub idx: u32,
    pub(crate) handle: *mut VarHandle<N>,
}

/// A variable that represents an emulated field element.
///
/// Used to do field arithmetic for recursive verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Felt<F> {
    pub idx: u32,
    pub(crate) handle: *mut FeltHandle<F>,
}

/// A variable that represents an emulated extension field element.
///
/// Used to do extension field arithmetic for recursive verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ext<F, EF> {
    pub idx: u32,
    pub(crate) handle: *mut ExtHandle<F, EF>,
}

unsafe impl<N> Send for Var<N> {}
unsafe impl<F, EF> Send for Ext<F, EF> {}
unsafe impl<F> Send for Felt<F> {}

unsafe impl<N> Sync for Var<N> {}
unsafe impl<F, EF> Sync for Ext<F, EF> {}
unsafe impl<F> Sync for Felt<F> {}

/// A variable that represents either a constant or variable counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Usize<N> {
    Const(usize),
    Var(Var<N>),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Witness<FC: FieldGenericConfig> {
    pub vars: Vec<FC::N>,
    pub felts: Vec<FC::F>,
    pub exts: Vec<FC::EF>,
    pub vkey_hash: FC::N,
    pub committed_values_digest: FC::N,
}

impl<FC: FieldGenericConfig> Witness<FC> {
    pub fn size(&self) -> usize {
        self.vars.len() + self.felts.len() + self.exts.len() + 2
    }

    pub fn write_vkey_hash(&mut self, vkey_hash: FC::N) {
        self.vars.push(vkey_hash);
        self.vkey_hash = vkey_hash;
    }

    pub fn write_committed_values_digest(&mut self, committed_values_digest: FC::N) {
        self.vars.push(committed_values_digest);
        self.committed_values_digest = committed_values_digest
    }
}

impl<N: Field> Usize<N> {
    pub fn value(&self) -> usize {
        match self {
            Usize::Const(c) => *c,
            Usize::Var(_) => panic!("Cannot get the value of a variable"),
        }
    }

    pub fn materialize<FC: FieldGenericConfig<N = N>>(
        &self,
        builder: &mut Builder<FC>,
    ) -> Var<FC::N> {
        match self {
            Usize::Const(c) => builder.eval(FC::N::from_canonical_usize(*c)),
            Usize::Var(v) => *v,
        }
    }
}

impl<N> From<Var<N>> for Usize<N> {
    fn from(v: Var<N>) -> Self {
        Usize::Var(v)
    }
}

impl<N> From<usize> for Usize<N> {
    fn from(c: usize) -> Self {
        Usize::Const(c)
    }
}

impl<N> Var<N> {
    pub const fn new(idx: u32, handle: *mut VarHandle<N>) -> Self {
        Self { idx, handle }
    }

    pub fn id(&self) -> String {
        format!("var{}", self.idx)
    }

    pub fn loc(&self) -> String {
        self.idx.to_string()
    }
}

impl<F> Felt<F> {
    pub const fn new(id: u32, handle: *mut FeltHandle<F>) -> Self {
        Self { idx: id, handle }
    }

    pub fn id(&self) -> String {
        format!("felt{}", self.idx)
    }

    pub fn loc(&self) -> String {
        self.idx.to_string()
    }

    pub fn inverse(&self) -> SymbolicFelt<F>
    where
        F: Field,
    {
        SymbolicFelt::<F>::ONE / *self
    }
}

impl<F, EF> Ext<F, EF> {
    pub const fn new(id: u32, handle: *mut ExtHandle<F, EF>) -> Self {
        Self { idx: id, handle }
    }

    pub fn id(&self) -> String {
        format!("ext{}", self.idx)
    }

    pub fn loc(&self) -> String {
        self.idx.to_string()
    }

    pub fn inverse(&self) -> SymbolicExt<F, EF>
    where
        F: Field,
        EF: ExtensionField<F>,
    {
        SymbolicExt::<F, EF>::ONE / *self
    }
}

impl<FC: FieldGenericConfig> Variable<FC> for Usize<FC::N> {
    type Expression = SymbolicUsize<FC::N>;

    fn uninit(builder: &mut Builder<FC>) -> Self {
        builder.uninit::<Var<FC::N>>().into()
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<FC>) {
        match self {
            Usize::Const(_) => {
                panic!("cannot assign to a constant usize")
            }
            Usize::Var(v) => match src {
                SymbolicUsize::Const(src) => {
                    builder.assign(*v, FC::N::from_canonical_usize(src));
                }
                SymbolicUsize::Var(src) => {
                    builder.assign(*v, src);
                }
            },
        }
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<FC>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicUsize::Const(lhs), SymbolicUsize::Const(rhs)) => {
                assert_eq!(lhs, rhs, "constant usizes do not match");
            }
            (SymbolicUsize::Const(lhs), SymbolicUsize::Var(rhs)) => {
                builder.assert_var_eq(FC::N::from_canonical_usize(lhs), rhs);
            }
            (SymbolicUsize::Var(lhs), SymbolicUsize::Const(rhs)) => {
                builder.assert_var_eq(lhs, FC::N::from_canonical_usize(rhs));
            }
            (SymbolicUsize::Var(lhs), SymbolicUsize::Var(rhs)) => builder.assert_var_eq(lhs, rhs),
        }
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<FC>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicUsize::Const(lhs), SymbolicUsize::Const(rhs)) => {
                assert_ne!(lhs, rhs, "constant usizes do not match");
            }
            (SymbolicUsize::Const(lhs), SymbolicUsize::Var(rhs)) => {
                builder.assert_var_ne(FC::N::from_canonical_usize(lhs), rhs);
            }
            (SymbolicUsize::Var(lhs), SymbolicUsize::Const(rhs)) => {
                builder.assert_var_ne(lhs, FC::N::from_canonical_usize(rhs));
            }
            (SymbolicUsize::Var(lhs), SymbolicUsize::Var(rhs)) => {
                builder.assert_var_ne(lhs, rhs);
            }
        }
    }
}

impl<FC: FieldGenericConfig> Variable<FC> for Var<FC::N> {
    type Expression = SymbolicVar<FC::N>;

    fn uninit(builder: &mut Builder<FC>) -> Self {
        let id = builder.variable_count();
        let var = Var::new(id, builder.var_handle.as_mut());
        builder.inner.get_mut().variable_count += 1;
        var
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<FC>) {
        match src {
            SymbolicVar::Const(src) => {
                builder.push_op(DslIr::ImmV(*self, src));
            }
            SymbolicVar::Val(src) => {
                builder.push_op(DslIr::AddVI(*self, src, FC::N::ZERO));
            }
        }
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<FC>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicVar::Const(lhs), SymbolicVar::Const(rhs)) => {
                assert_eq!(lhs, rhs, "Assertion failed at compile time");
            }
            (SymbolicVar::Const(lhs), SymbolicVar::Val(rhs)) => {
                builder.trace_push(DslIr::AssertEqVI(rhs, lhs));
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Const(rhs)) => {
                builder.trace_push(DslIr::AssertEqVI(lhs, rhs));
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Val(rhs)) => {
                builder.trace_push(DslIr::AssertEqV(lhs, rhs));
            }
        }
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<FC>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicVar::Const(lhs), SymbolicVar::Const(rhs)) => {
                assert_ne!(lhs, rhs, "Assertion failed at compile time");
            }
            (SymbolicVar::Const(lhs), SymbolicVar::Val(rhs)) => {
                builder.trace_push(DslIr::AssertNeVI(rhs, lhs));
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Const(rhs)) => {
                builder.trace_push(DslIr::AssertNeVI(lhs, rhs));
            }
            (SymbolicVar::Val(lhs), SymbolicVar::Val(rhs)) => {
                builder.trace_push(DslIr::AssertNeV(lhs, rhs));
            }
        }
    }
}

impl<FC: FieldGenericConfig> MemVariable<FC> for Var<FC::N> {
    fn size_of() -> usize {
        1
    }

    fn load(&self, ptr: Ptr<FC::N>, index: MemIndex<FC::N>, builder: &mut Builder<FC>) {
        builder.push_op(DslIr::LoadV(*self, ptr, index));
    }

    fn store(
        &self,
        ptr: Ptr<<FC as FieldGenericConfig>::N>,
        index: MemIndex<FC::N>,
        builder: &mut Builder<FC>,
    ) {
        builder.push_op(DslIr::StoreV(*self, ptr, index));
    }
}

impl<FC: FieldGenericConfig> Variable<FC> for Felt<FC::F> {
    type Expression = SymbolicFelt<FC::F>;

    fn uninit(builder: &mut Builder<FC>) -> Self {
        let idx = builder.variable_count();
        let felt = Felt::<FC::F>::new(idx, builder.felt_handle.as_mut());
        builder.inner.get_mut().variable_count += 1;
        felt
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<FC>) {
        match src {
            SymbolicFelt::Const(src) => {
                builder.push_op(DslIr::ImmF(*self, src));
            }
            SymbolicFelt::Val(src) => {
                builder.push_op(DslIr::AddFI(*self, src, FC::F::ZERO));
            }
        }
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<FC>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicFelt::Const(lhs), SymbolicFelt::Const(rhs)) => {
                assert_eq!(lhs, rhs, "Assertion failed at compile time");
            }
            (SymbolicFelt::Const(lhs), SymbolicFelt::Val(rhs)) => {
                builder.trace_push(DslIr::AssertEqFI(rhs, lhs));
            }
            (SymbolicFelt::Val(lhs), SymbolicFelt::Const(rhs)) => {
                builder.trace_push(DslIr::AssertEqFI(lhs, rhs));
            }
            (SymbolicFelt::Val(lhs), SymbolicFelt::Val(rhs)) => {
                builder.trace_push(DslIr::AssertEqF(lhs, rhs));
            }
        }
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<FC>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicFelt::Const(lhs), SymbolicFelt::Const(rhs)) => {
                assert_ne!(lhs, rhs, "Assertion failed at compile time");
            }
            (SymbolicFelt::Const(lhs), SymbolicFelt::Val(rhs)) => {
                builder.trace_push(DslIr::AssertNeFI(rhs, lhs));
            }
            (SymbolicFelt::Val(lhs), SymbolicFelt::Const(rhs)) => {
                builder.trace_push(DslIr::AssertNeFI(lhs, rhs));
            }
            (SymbolicFelt::Val(lhs), SymbolicFelt::Val(rhs)) => {
                builder.trace_push(DslIr::AssertNeF(lhs, rhs));
            }
        }
    }
}

impl<FC: FieldGenericConfig> MemVariable<FC> for Felt<FC::F> {
    fn size_of() -> usize {
        1
    }

    fn load(&self, ptr: Ptr<FC::N>, index: MemIndex<FC::N>, builder: &mut Builder<FC>) {
        builder.push_op(DslIr::LoadF(*self, ptr, index));
    }

    fn store(
        &self,
        ptr: Ptr<<FC as FieldGenericConfig>::N>,
        index: MemIndex<FC::N>,
        builder: &mut Builder<FC>,
    ) {
        builder.push_op(DslIr::StoreF(*self, ptr, index));
    }
}

impl<FC: FieldGenericConfig> Variable<FC> for Ext<FC::F, FC::EF> {
    type Expression = SymbolicExt<FC::F, FC::EF>;

    fn uninit(builder: &mut Builder<FC>) -> Self {
        let idx = builder.variable_count();
        let ext = Ext::<FC::F, FC::EF>::new(idx, builder.ext_handle.as_mut());
        builder.inner.get_mut().variable_count += 1;
        ext
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<FC>) {
        match src {
            SymbolicExt::Const(src) => {
                builder.push_op(DslIr::ImmE(*self, src));
            }
            SymbolicExt::Base(src) => match src {
                SymbolicFelt::Const(src) => {
                    builder.push_op(DslIr::ImmE(*self, FC::EF::from_base(src)));
                }
                SymbolicFelt::Val(src) => {
                    builder.push_op(DslIr::AddEFFI(*self, src, FC::EF::ZERO));
                }
            },
            SymbolicExt::Val(src) => {
                builder.push_op(DslIr::AddEI(*self, src, FC::EF::ZERO));
            }
        }
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<FC>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicExt::Const(lhs), SymbolicExt::Const(rhs)) => {
                assert_eq!(lhs, rhs, "Assertion failed at compile time");
            }
            (SymbolicExt::Const(lhs), SymbolicExt::Val(rhs)) => {
                builder.trace_push(DslIr::AssertEqEI(rhs, lhs));
            }
            (SymbolicExt::Const(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.trace_push(DslIr::AssertEqEI(rhs_value, lhs));
            }
            (SymbolicExt::Val(lhs), SymbolicExt::Const(rhs)) => {
                builder.trace_push(DslIr::AssertEqEI(lhs, rhs));
            }
            (SymbolicExt::Val(lhs), SymbolicExt::Val(rhs)) => {
                builder.trace_push(DslIr::AssertEqE(lhs, rhs));
            }
            (SymbolicExt::Val(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.trace_push(DslIr::AssertEqE(lhs, rhs_value));
            }
            (lhs, rhs) => {
                let lhs_value = Self::uninit(builder);
                lhs_value.assign(lhs, builder);
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.trace_push(DslIr::AssertEqE(lhs_value, rhs_value));
            }
        }
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<FC>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs, rhs) {
            (SymbolicExt::Const(lhs), SymbolicExt::Const(rhs)) => {
                assert_ne!(lhs, rhs, "Assertion failed at compile time");
            }
            (SymbolicExt::Const(lhs), SymbolicExt::Val(rhs)) => {
                builder.trace_push(DslIr::AssertNeEI(rhs, lhs));
            }
            (SymbolicExt::Const(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.trace_push(DslIr::AssertNeEI(rhs_value, lhs));
            }
            (SymbolicExt::Val(lhs), SymbolicExt::Const(rhs)) => {
                builder.trace_push(DslIr::AssertNeEI(lhs, rhs));
            }
            (SymbolicExt::Val(lhs), SymbolicExt::Val(rhs)) => {
                builder.trace_push(DslIr::AssertNeE(lhs, rhs));
            }
            (SymbolicExt::Val(lhs), rhs) => {
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.trace_push(DslIr::AssertNeE(lhs, rhs_value));
            }
            (lhs, rhs) => {
                let lhs_value = Self::uninit(builder);
                lhs_value.assign(lhs, builder);
                let rhs_value = Self::uninit(builder);
                rhs_value.assign(rhs, builder);
                builder.trace_push(DslIr::AssertNeE(lhs_value, rhs_value));
            }
        }
    }
}

impl<FC: FieldGenericConfig> MemVariable<FC> for Ext<FC::F, FC::EF> {
    fn size_of() -> usize {
        1
    }

    fn load(&self, ptr: Ptr<FC::N>, index: MemIndex<FC::N>, builder: &mut Builder<FC>) {
        builder.push_op(DslIr::LoadE(*self, ptr, index));
    }

    fn store(
        &self,
        ptr: Ptr<<FC as FieldGenericConfig>::N>,
        index: MemIndex<FC::N>,
        builder: &mut Builder<FC>,
    ) {
        builder.push_op(DslIr::StoreE(*self, ptr, index));
    }
}

impl<FC: FieldGenericConfig> FromConstant<FC> for Var<FC::N> {
    type Constant = FC::N;

    fn constant(value: Self::Constant, builder: &mut Builder<FC>) -> Self {
        builder.eval(value)
    }
}

impl<FC: FieldGenericConfig> FromConstant<FC> for Felt<FC::F> {
    type Constant = FC::F;

    fn constant(value: Self::Constant, builder: &mut Builder<FC>) -> Self {
        builder.eval(value)
    }
}

impl<FC: FieldGenericConfig> FromConstant<FC> for Ext<FC::F, FC::EF> {
    type Constant = FC::EF;

    fn constant(value: Self::Constant, builder: &mut Builder<FC>) -> Self {
        builder.eval(value.cons())
    }
}
