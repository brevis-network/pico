use backtrace::Backtrace;
use p3_field::PrimeCharacteristicRing;
use std::{cell::UnsafeCell, iter::Zip, ptr, vec::IntoIter};

use super::{
    DslIr, Ext, ExtHandle, ExtOperations, Felt, FeltHandle, FeltOperations, FromConstant,
    SymbolicExt, SymbolicFelt, SymbolicUsize, SymbolicVar, Usize, Var, VarHandle, VarOperations,
    Variable,
};
use crate::{configs::config::FieldGenericConfig, primitives::consts::DIGEST_SIZE};

/// TracedVec is a Vec wrapper that records a trace whenever an element is pushed. When extending
/// from another TracedVec, the traces are copied over.
#[derive(Debug, Clone)]
pub struct TracedVec<T> {
    pub vec: Vec<T>,
    pub traces: Vec<Option<Backtrace>>,
}

impl<T> Default for TracedVec<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> From<Vec<T>> for TracedVec<T> {
    fn from(vec: Vec<T>) -> Self {
        let len = vec.len();
        Self {
            vec,
            traces: vec![None; len],
        }
    }
}

impl<T> TracedVec<T> {
    pub const fn new() -> Self {
        Self {
            vec: Vec::new(),
            traces: Vec::new(),
        }
    }

    pub fn push(&mut self, value: T) {
        self.vec.push(value);
        self.traces.push(None);
    }

    /// Pushes a value to the vector and records a backtrace if PICO_DEBUG is enabled
    pub fn trace_push(&mut self, value: T) {
        self.vec.push(value);
        // TODO: add debug_mode
        self.traces.push(None);
    }

    pub fn extend<I: IntoIterator<Item = (T, Option<Backtrace>)>>(&mut self, iter: I) {
        let iter = iter.into_iter();
        let len = iter.size_hint().0;
        self.vec.reserve(len);
        self.traces.reserve(len);
        for (value, trace) in iter {
            self.vec.push(value);
            self.traces.push(trace);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.vec.is_empty()
    }
}

impl<T> IntoIterator for TracedVec<T> {
    type Item = (T, Option<Backtrace>);
    type IntoIter = Zip<IntoIter<T>, IntoIter<Option<Backtrace>>>;

    fn into_iter(self) -> Self::IntoIter {
        self.vec.into_iter().zip(self.traces)
    }
}

#[derive(Debug, Clone)]
pub struct InnerBuilder<FC: FieldGenericConfig> {
    pub(crate) variable_count: u32,
    pub operations: TracedVec<DslIr<FC>>,
}

/// A builder for the DSL.
///
/// Can compile to both assembly and a set of constraints.
#[derive(Debug)]
pub struct Builder<FC: FieldGenericConfig> {
    pub(crate) inner: Box<UnsafeCell<InnerBuilder<FC>>>,
    pub(crate) nb_public_values: Option<Var<FC::N>>,
    pub(crate) witness_var_count: u32,
    pub(crate) witness_felt_count: u32,
    pub(crate) witness_ext_count: u32,
    pub(crate) var_handle: Box<VarHandle<FC::N>>,
    pub(crate) felt_handle: Box<FeltHandle<FC::F>>,
    pub(crate) ext_handle: Box<ExtHandle<FC::F, FC::EF>>,
    pub(crate) p2_hash_num: Var<FC::N>,
    pub(crate) debug: bool,
    pub(crate) is_sub_builder: bool,
}

impl<FC: FieldGenericConfig> Default for Builder<FC> {
    fn default() -> Self {
        Self::new()
    }
}

impl<FC: FieldGenericConfig> Builder<FC> {
    pub fn new() -> Self {
        // We need to create a temporary placeholder for the p2_hash_num variable.
        let placeholder_p2_hash_num = Var::new(0, ptr::null_mut());

        let mut inner = Box::new(UnsafeCell::new(InnerBuilder {
            variable_count: 0,
            operations: Default::default(),
        }));

        let var_handle = Box::new(VarOperations::var_handle(&mut inner));
        let mut ext_handle = Box::new(ExtOperations::ext_handle(&mut inner));
        let felt_handle = Box::new(FeltOperations::felt_handle(
            &mut inner,
            ext_handle.as_mut() as *mut _ as *mut (),
        ));

        let mut new_builder = Self {
            inner,
            witness_var_count: 0,
            witness_felt_count: 0,
            witness_ext_count: 0,
            nb_public_values: None,
            var_handle,
            felt_handle,
            ext_handle,
            p2_hash_num: placeholder_p2_hash_num,
            debug: false,
            is_sub_builder: false,
        };

        new_builder.p2_hash_num = new_builder.uninit();
        new_builder
    }

    /// Creates a new builder with a given number of counts for each type.
    pub fn new_sub_builder(
        variable_count: u32,
        nb_public_values: Option<Var<FC::N>>,
        p2_hash_num: Var<FC::N>,
        debug: bool,
    ) -> Self {
        let mut builder = Self::new();
        builder.inner.get_mut().variable_count = variable_count;
        builder.nb_public_values = nb_public_values;
        builder.p2_hash_num = p2_hash_num;
        builder.debug = debug;

        builder
    }

    /// Pushes an operation to the builder.
    pub fn push_op(&mut self, op: DslIr<FC>) {
        self.inner.get_mut().operations.push(op);
    }

    pub fn extend_ops(&mut self, ops: impl IntoIterator<Item = (DslIr<FC>, Option<Backtrace>)>) {
        self.inner.get_mut().operations.extend(ops);
    }

    pub fn trace_push(&mut self, op: DslIr<FC>) {
        self.inner.get_mut().operations.trace_push(op);
    }

    pub fn variable_count(&self) -> u32 {
        unsafe { (*self.inner.get()).variable_count }
    }

    pub fn into_operations(self) -> TracedVec<DslIr<FC>> {
        self.inner.into_inner().operations
    }

    /// Creates an uninitialized variable.
    pub fn uninit<V: Variable<FC>>(&mut self) -> V {
        V::uninit(self)
    }

    /// Evaluates an expression and returns a variable.
    pub fn eval<V: Variable<FC>, E: Into<V::Expression>>(&mut self, expr: E) -> V {
        let dst = V::uninit(self);
        dst.assign(expr.into(), self);
        dst
    }

    /// Evaluates a constant expression and returns a variable.
    pub fn constant<V: FromConstant<FC>>(&mut self, value: V::Constant) -> V {
        V::constant(value, self)
    }

    /// Assigns an expression to a variable.
    pub fn assign<V: Variable<FC>, E: Into<V::Expression>>(&mut self, dst: V, expr: E) {
        dst.assign(expr.into(), self);
    }

    /// Asserts that two expressions are equal.
    pub fn assert_eq<V: Variable<FC>>(
        &mut self,
        lhs: impl Into<V::Expression>,
        rhs: impl Into<V::Expression>,
    ) {
        V::assert_eq(lhs, rhs, self);
    }

    /// Asserts that two expressions are not equal.
    pub fn assert_ne<V: Variable<FC>>(
        &mut self,
        lhs: impl Into<V::Expression>,
        rhs: impl Into<V::Expression>,
    ) {
        V::assert_ne(lhs, rhs, self);
    }

    /// Assert that two vars are equal.
    pub fn assert_var_eq<LhsExpr: Into<SymbolicVar<FC::N>>, RhsExpr: Into<SymbolicVar<FC::N>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Var<FC::N>>(lhs, rhs);
    }

    /// Assert that two vars are not equal.
    pub fn assert_var_ne<LhsExpr: Into<SymbolicVar<FC::N>>, RhsExpr: Into<SymbolicVar<FC::N>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_ne::<Var<FC::N>>(lhs, rhs);
    }

    /// Assert that two felts are equal.
    pub fn assert_felt_eq<
        LhsExpr: Into<SymbolicFelt<FC::F>>,
        RhsExpr: Into<SymbolicFelt<FC::F>>,
    >(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Felt<FC::F>>(lhs, rhs);
    }

    /// Assert that two usizes are equal.
    pub fn assert_usize_eq<
        LhsExpr: Into<SymbolicUsize<FC::N>>,
        RhsExpr: Into<SymbolicUsize<FC::N>>,
    >(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Usize<FC::N>>(lhs, rhs);
    }

    /// Assert that two exts are equal.
    pub fn assert_ext_eq<
        LhsExpr: Into<SymbolicExt<FC::F, FC::EF>>,
        RhsExpr: Into<SymbolicExt<FC::F, FC::EF>>,
    >(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Ext<FC::F, FC::EF>>(lhs, rhs);
    }

    pub fn lt(&mut self, lhs: Var<FC::N>, rhs: Var<FC::N>) -> Var<FC::N> {
        let result = self.uninit();
        self.push_op(DslIr::LessThan(result, lhs, rhs));
        result
    }

    /// Evaluate a block of operations over a range from start to end.
    pub fn range(
        &mut self,
        start: impl Into<Usize<FC::N>>,
        end: impl Into<Usize<FC::N>>,
    ) -> RangeBuilder<'_, FC> {
        RangeBuilder {
            start: start.into(),
            end: end.into(),
            builder: self,
            step_size: 1,
        }
    }

    pub fn print_debug(&mut self, val: usize) {
        let constant = self.eval(FC::N::from_usize(val));
        self.print_v(constant);
    }

    /// Print a variable.
    pub fn print_v(&mut self, dst: Var<FC::N>) {
        self.push_op(DslIr::PrintV(dst));
    }

    /// Hint the length of the next vector of variables.
    pub fn hint_len(&mut self) -> Var<FC::N> {
        let len = self.uninit();
        self.push_op(DslIr::HintLen(len));
        len
    }

    pub fn witness_var(&mut self) -> Var<FC::N> {
        assert!(
            !self.is_sub_builder,
            "Cannot create a witness var with a sub builder"
        );
        let witness = self.uninit();
        self.push_op(DslIr::WitnessVar(witness, self.witness_var_count));
        self.witness_var_count += 1;
        witness
    }

    pub fn witness_felt(&mut self) -> Felt<FC::F> {
        assert!(
            !self.is_sub_builder,
            "Cannot create a witness felt with a sub builder"
        );
        let witness = self.uninit();
        self.push_op(DslIr::WitnessFelt(witness, self.witness_felt_count));
        self.witness_felt_count += 1;
        witness
    }

    pub fn witness_ext(&mut self) -> Ext<FC::F, FC::EF> {
        assert!(
            !self.is_sub_builder,
            "Cannot create a witness ext with a sub builder"
        );
        let witness = self.uninit();
        self.push_op(DslIr::WitnessExt(witness, self.witness_ext_count));
        self.witness_ext_count += 1;
        witness
    }

    /// Throws an error.
    pub fn error(&mut self) {
        self.trace_push(DslIr::Error());
    }

    /// Materializes a usize into a variable.
    pub fn materialize(&mut self, num: Usize<FC::N>) -> Var<FC::N> {
        match num {
            Usize::Const(num) => self.eval(FC::N::from_usize(num)),
            Usize::Var(num) => num,
        }
    }

    pub fn commit_vkey_hash_circuit(&mut self, var: Var<FC::N>) {
        self.push_op(DslIr::CircuitCommitVkeyHash(var));
    }

    pub fn commit_committed_values_digest_circuit(&mut self, var: Var<FC::N>) {
        self.push_op(DslIr::CircuitCommitCommittedValuesDigest(var));
    }

    pub fn assert_vk_root_circuit(
        &mut self,
        felts: [Felt<FC::F>; DIGEST_SIZE],
        root: [FC::F; DIGEST_SIZE],
    ) {
        self.push_op(DslIr::CircuitAssertVkRoot(Box::new((felts, root))));
    }

    pub fn felt2var_circuit(&mut self, felt: Felt<FC::F>) -> Var<FC::N> {
        let var = self.uninit();
        self.push_op(DslIr::CircuitFelt2Var(felt, var));
        var
    }

    pub fn cycle_tracker(&mut self, name: &str) {
        self.push_op(DslIr::CycleTracker(name.to_string()));
    }

    pub fn halt(&mut self) {
        self.push_op(DslIr::Halt);
    }
}

/// A builder for the DSL that handles for loops.
pub struct RangeBuilder<'a, FC: FieldGenericConfig> {
    start: Usize<FC::N>,
    end: Usize<FC::N>,
    step_size: usize,
    builder: &'a mut Builder<FC>,
}

impl<FC: FieldGenericConfig> RangeBuilder<'_, FC> {
    pub const fn step_by(mut self, step_size: usize) -> Self {
        self.step_size = step_size;
        self
    }

    pub fn for_each(self, mut f: impl FnMut(Var<FC::N>, &mut Builder<FC>)) {
        let step_size = FC::N::from_usize(self.step_size);
        let loop_variable: Var<FC::N> = self.builder.uninit();
        let mut loop_body_builder = Builder::<FC>::new_sub_builder(
            self.builder.variable_count(),
            self.builder.nb_public_values,
            self.builder.p2_hash_num,
            self.builder.debug,
        );

        f(loop_variable, &mut loop_body_builder);
        self.builder.p2_hash_num = loop_body_builder.p2_hash_num;

        let loop_instructions = loop_body_builder.into_operations();

        let op = DslIr::For(Box::new((
            self.start,
            self.end,
            step_size,
            loop_variable,
            loop_instructions,
        )));
        self.builder.push_op(op);
    }
}
