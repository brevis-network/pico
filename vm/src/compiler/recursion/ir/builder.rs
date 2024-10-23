use super::{
    Array, DslIr, Ext, Felt, FromConstant, SymbolicExt, SymbolicFelt, SymbolicUsize, SymbolicVar,
    Usize, Var, Variable,
};
use crate::{configs::config::FieldGenericConfig, primitives::types::RecursionProgramType};
use backtrace::Backtrace;
use p3_field::AbstractField;
use std::{iter::Zip, vec::IntoIter};

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

    /// Pushes a value to the vector
    pub fn trace_push(&mut self, value: T) {
        self.vec.push(value);
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

/// A builder for the DSL.
///
/// Can compile to both assembly and a set of constraints.
#[derive(Debug, Clone)]
pub struct Builder<RC: FieldGenericConfig> {
    pub(crate) variable_count: u32,
    pub operations: TracedVec<DslIr<RC>>,
    pub(crate) nb_public_values: Option<Var<RC::N>>,
    pub(crate) witness_var_count: u32,
    pub(crate) witness_felt_count: u32,
    pub(crate) witness_ext_count: u32,
    pub(crate) p2_hash_num: Var<RC::N>,
    pub(crate) debug: bool,
    pub(crate) is_sub_builder: bool,
    pub program_type: RecursionProgramType,
}

impl<RC: FieldGenericConfig> Default for Builder<RC> {
    fn default() -> Self {
        Self::new(RecursionProgramType::Riscv)
    }
}

impl<RC: FieldGenericConfig> Builder<RC> {
    pub fn new(program_type: RecursionProgramType) -> Self {
        // We need to create a temporary placeholder for the p2_hash_num variable.
        let placeholder_p2_hash_num = Var::new(0);

        let mut new_builder = Self {
            variable_count: 0,
            witness_var_count: 0,
            witness_felt_count: 0,
            witness_ext_count: 0,
            operations: Default::default(),
            nb_public_values: None,
            p2_hash_num: placeholder_p2_hash_num,
            debug: false,
            is_sub_builder: false,
            program_type,
        };

        new_builder.p2_hash_num = new_builder.uninit();
        new_builder
    }

    /// Creates a new builder with a given number of counts for each type.
    pub fn new_sub_builder(
        variable_count: u32,
        nb_public_values: Option<Var<RC::N>>,
        p2_hash_num: Var<RC::N>,
        debug: bool,
        program_type: RecursionProgramType,
    ) -> Self {
        Self {
            variable_count,
            // Witness counts are only used when the target is a gnark circuit.  And sub-builders
            // are not used when the target is a gnark circuit, so it's fine to set the
            // witness counts to 0.
            witness_var_count: 0,
            witness_felt_count: 0,
            witness_ext_count: 0,
            operations: Default::default(),
            nb_public_values,
            p2_hash_num,
            debug,
            is_sub_builder: true,
            program_type,
        }
    }

    /// Pushes an operation to the builder.
    pub fn push(&mut self, op: DslIr<RC>) {
        self.operations.push(op);
    }

    /// Pushes an operation to the builder.
    pub fn trace_push(&mut self, op: DslIr<RC>) {
        self.operations.trace_push(op);
    }

    /// Creates an uninitialized variable.
    pub fn uninit<V: Variable<RC>>(&mut self) -> V {
        V::uninit(self)
    }

    /// Evaluates an expression and returns a variable.
    pub fn eval<V: Variable<RC>, E: Into<V::Expression>>(&mut self, expr: E) -> V {
        let dst = V::uninit(self);
        dst.assign(expr.into(), self);
        dst
    }

    /// Evaluates a constant expression and returns a variable.
    pub fn constant<V: FromConstant<RC>>(&mut self, value: V::Constant) -> V {
        V::constant(value, self)
    }

    /// Assigns an expression to a variable.
    pub fn assign<V: Variable<RC>, E: Into<V::Expression>>(&mut self, dst: V, expr: E) {
        dst.assign(expr.into(), self);
    }

    /// Asserts that two expressions are equal.
    pub fn assert_eq<V: Variable<RC>>(
        &mut self,
        lhs: impl Into<V::Expression>,
        rhs: impl Into<V::Expression>,
    ) {
        V::assert_eq(lhs, rhs, self);
    }

    /// Asserts that two expressions are not equal.
    pub fn assert_ne<V: Variable<RC>>(
        &mut self,
        lhs: impl Into<V::Expression>,
        rhs: impl Into<V::Expression>,
    ) {
        V::assert_ne(lhs, rhs, self);
    }

    /// Assert that two vars are equal.
    pub fn assert_var_eq<LhsExpr: Into<SymbolicVar<RC::N>>, RhsExpr: Into<SymbolicVar<RC::N>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Var<RC::N>>(lhs, rhs);
    }

    /// Assert that two vars are not equal.
    pub fn assert_var_ne<LhsExpr: Into<SymbolicVar<RC::N>>, RhsExpr: Into<SymbolicVar<RC::N>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_ne::<Var<RC::N>>(lhs, rhs);
    }

    /// Assert that two felts are equal.
    pub fn assert_felt_eq<
        LhsExpr: Into<SymbolicFelt<RC::F>>,
        RhsExpr: Into<SymbolicFelt<RC::F>>,
    >(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Felt<RC::F>>(lhs, rhs);
    }

    /// Assert that two felts are not equal.
    pub fn assert_felt_ne<
        LhsExpr: Into<SymbolicFelt<RC::F>>,
        RhsExpr: Into<SymbolicFelt<RC::F>>,
    >(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_ne::<Felt<RC::F>>(lhs, rhs);
    }

    /// Assert that two usizes are equal.
    pub fn assert_usize_eq<
        LhsExpr: Into<SymbolicUsize<RC::N>>,
        RhsExpr: Into<SymbolicUsize<RC::N>>,
    >(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Usize<RC::N>>(lhs, rhs);
    }

    /// Assert that two usizes are not equal.
    pub fn assert_usize_ne(
        &mut self,
        lhs: impl Into<SymbolicUsize<RC::N>>,
        rhs: impl Into<SymbolicUsize<RC::N>>,
    ) {
        self.assert_ne::<Usize<RC::N>>(lhs, rhs);
    }

    /// Assert that two exts are equal.
    pub fn assert_ext_eq<
        LhsExpr: Into<SymbolicExt<RC::F, RC::EF>>,
        RhsExpr: Into<SymbolicExt<RC::F, RC::EF>>,
    >(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_eq::<Ext<RC::F, RC::EF>>(lhs, rhs);
    }

    /// Assert that two exts are not equal.
    pub fn assert_ext_ne<
        LhsExpr: Into<SymbolicExt<RC::F, RC::EF>>,
        RhsExpr: Into<SymbolicExt<RC::F, RC::EF>>,
    >(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) {
        self.assert_ne::<Ext<RC::F, RC::EF>>(lhs, rhs);
    }

    pub fn lt(&mut self, lhs: Var<RC::N>, rhs: Var<RC::N>) -> Var<RC::N> {
        let result = self.uninit();
        self.operations.push(DslIr::LessThan(result, lhs, rhs));
        result
    }

    /// Evaluate a block of operations if two expressions are equal.
    pub fn if_eq<LhsExpr: Into<SymbolicVar<RC::N>>, RhsExpr: Into<SymbolicVar<RC::N>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) -> IfBuilder<RC> {
        IfBuilder {
            lhs: lhs.into(),
            rhs: rhs.into(),
            is_eq: true,
            builder: self,
        }
    }

    /// Evaluate a block of operations if two expressions are not equal.
    pub fn if_ne<LhsExpr: Into<SymbolicVar<RC::N>>, RhsExpr: Into<SymbolicVar<RC::N>>>(
        &mut self,
        lhs: LhsExpr,
        rhs: RhsExpr,
    ) -> IfBuilder<RC> {
        IfBuilder {
            lhs: lhs.into(),
            rhs: rhs.into(),
            is_eq: false,
            builder: self,
        }
    }

    /// Evaluate a block of operations over a range from start to end.
    pub fn range(
        &mut self,
        start: impl Into<Usize<RC::N>>,
        end: impl Into<Usize<RC::N>>,
    ) -> RangeBuilder<RC> {
        RangeBuilder {
            start: start.into(),
            end: end.into(),
            builder: self,
            step_size: 1,
        }
    }

    /// Break out of a loop.
    pub fn break_loop(&mut self) {
        self.operations.push(DslIr::Break);
    }

    pub fn print_debug(&mut self, val: usize) {
        let constant = self.eval(RC::N::from_canonical_usize(val));
        self.print_v(constant);
    }

    /// Print a variable.
    pub fn print_v(&mut self, dst: Var<RC::N>) {
        self.operations.push(DslIr::PrintV(dst));
    }

    /// Print a felt.
    pub fn print_f(&mut self, dst: Felt<RC::F>) {
        self.operations.push(DslIr::PrintF(dst));
    }

    /// Print an ext.
    pub fn print_e(&mut self, dst: Ext<RC::F, RC::EF>) {
        self.operations.push(DslIr::PrintE(dst));
    }

    /// Hint the length of the next vector of variables.
    pub fn hint_len(&mut self) -> Var<RC::N> {
        let len = self.uninit();
        self.operations.push(DslIr::HintLen(len));
        len
    }

    /// Hint a single variable.
    pub fn hint_var(&mut self) -> Var<RC::N> {
        let len = self.hint_len();
        let arr = self.dyn_array(len);
        self.operations.push(DslIr::HintVars(arr.clone()));
        self.get(&arr, 0)
    }

    /// Hint a single felt.
    pub fn hint_felt(&mut self) -> Felt<RC::F> {
        let len = self.hint_len();
        let arr = self.dyn_array(len);
        self.operations.push(DslIr::HintFelts(arr.clone()));
        self.get(&arr, 0)
    }

    /// Hint a single ext.
    pub fn hint_ext(&mut self) -> Ext<RC::F, RC::EF> {
        let len = self.hint_len();
        let arr = self.dyn_array(len);
        self.operations.push(DslIr::HintExts(arr.clone()));
        self.get(&arr, 0)
    }

    /// Hint a vector of variables.
    pub fn hint_vars(&mut self) -> Array<RC, Var<RC::N>> {
        let len = self.hint_len();
        let arr = self.dyn_array(len);
        self.operations.push(DslIr::HintVars(arr.clone()));
        arr
    }

    /// Hint a vector of felts.
    pub fn hint_felts(&mut self) -> Array<RC, Felt<RC::F>> {
        let len = self.hint_len();
        let arr = self.dyn_array(len);
        self.operations.push(DslIr::HintFelts(arr.clone()));
        arr
    }

    /// Hint a vector of exts.
    pub fn hint_exts(&mut self) -> Array<RC, Ext<RC::F, RC::EF>> {
        let len = self.hint_len();
        let arr = self.dyn_array(len);
        self.operations.push(DslIr::HintExts(arr.clone()));
        arr
    }

    pub fn witness_var(&mut self) -> Var<RC::N> {
        assert!(
            !self.is_sub_builder,
            "Cannot create a witness var with a sub builder"
        );
        let witness = self.uninit();
        self.operations
            .push(DslIr::WitnessVar(witness, self.witness_var_count));
        self.witness_var_count += 1;
        witness
    }

    pub fn witness_felt(&mut self) -> Felt<RC::F> {
        assert!(
            !self.is_sub_builder,
            "Cannot create a witness felt with a sub builder"
        );
        let witness = self.uninit();
        self.operations
            .push(DslIr::WitnessFelt(witness, self.witness_felt_count));
        self.witness_felt_count += 1;
        witness
    }

    pub fn witness_ext(&mut self) -> Ext<RC::F, RC::EF> {
        assert!(
            !self.is_sub_builder,
            "Cannot create a witness ext with a sub builder"
        );
        let witness = self.uninit();
        self.operations
            .push(DslIr::WitnessExt(witness, self.witness_ext_count));
        self.witness_ext_count += 1;
        witness
    }

    /// Throws an error.
    pub fn error(&mut self) {
        self.operations.trace_push(DslIr::Error());
    }

    /// Materializes a usize into a variable.
    pub fn materialize(&mut self, num: Usize<RC::N>) -> Var<RC::N> {
        match num {
            Usize::Const(num) => self.eval(RC::N::from_canonical_usize(num)),
            Usize::Var(num) => num,
        }
    }

    /// Register a felt as public value.  This is append to the proof's public values buffer.
    pub fn register_public_value(&mut self, val: Felt<RC::F>) {
        self.operations.push(DslIr::RegisterPublicValue(val));
    }

    /// Register and commits a felt as public value.  This value will be constrained when verified.
    pub fn commit_public_value(&mut self, val: Felt<RC::F>) {
        assert!(
            !self.is_sub_builder,
            "Cannot commit to a public value with a sub builder"
        );
        if self.nb_public_values.is_none() {
            self.nb_public_values = Some(self.eval(RC::N::zero()));
        }
        let nb_public_values = *self.nb_public_values.as_ref().unwrap();

        self.operations.push(DslIr::Commit(val, nb_public_values));
        self.assign(nb_public_values, nb_public_values + RC::N::one());
    }

    /// Commits an array of felts in public values.
    pub fn commit_public_values(&mut self, vals: &Array<RC, Felt<RC::F>>) {
        assert!(
            !self.is_sub_builder,
            "Cannot commit to public values with a sub builder"
        );
        let len = vals.len();
        self.range(0, len).for_each(|i, builder| {
            let val = builder.get(vals, i);
            builder.commit_public_value(val);
        });
    }

    pub fn commit_vkey_hash_circuit(&mut self, var: Var<RC::N>) {
        self.operations.push(DslIr::CircuitCommitVkeyHash(var));
    }

    pub fn commit_commited_values_digest_circuit(&mut self, var: Var<RC::N>) {
        self.operations
            .push(DslIr::CircuitCommitCommitedValuesDigest(var));
    }

    pub fn reduce_e(&mut self, ext: Ext<RC::F, RC::EF>) {
        self.operations.push(DslIr::ReduceE(ext));
    }

    pub fn felt2var_circuit(&mut self, felt: Felt<RC::F>) -> Var<RC::N> {
        let var = self.uninit();
        self.operations.push(DslIr::CircuitFelt2Var(felt, var));
        var
    }

    pub fn cycle_tracker(&mut self, name: &str) {
        self.operations.push(DslIr::CycleTracker(name.to_string()));
    }

    pub fn halt(&mut self) {
        self.operations.push(DslIr::Halt);
    }
}

/// A builder for the DSL that handles if statements.
pub struct IfBuilder<'a, RC: FieldGenericConfig> {
    lhs: SymbolicVar<RC::N>,
    rhs: SymbolicVar<RC::N>,
    is_eq: bool,
    pub(crate) builder: &'a mut Builder<RC>,
}

/// A set of conditions that if statements can be based on.
enum IfCondition<N> {
    EqConst(N, N),
    NeConst(N, N),
    Eq(Var<N>, Var<N>),
    EqI(Var<N>, N),
    Ne(Var<N>, Var<N>),
    NeI(Var<N>, N),
}

impl<'a, RC: FieldGenericConfig> IfBuilder<'a, RC> {
    pub fn then(mut self, mut f: impl FnMut(&mut Builder<RC>)) {
        // Get the condition reduced from the expressions for lhs and rhs.
        let condition = self.condition();

        // Execute the `then` block and collect the instructions.
        let mut f_builder = Builder::<RC>::new_sub_builder(
            self.builder.variable_count,
            self.builder.nb_public_values,
            self.builder.p2_hash_num,
            self.builder.debug,
            self.builder.program_type,
        );
        f(&mut f_builder);
        self.builder.p2_hash_num = f_builder.p2_hash_num;

        let then_instructions = f_builder.operations;

        // Dispatch instructions to the correct conditional block.
        match condition {
            IfCondition::EqConst(lhs, rhs) => {
                if lhs == rhs {
                    self.builder.operations.extend(then_instructions);
                }
            }
            IfCondition::NeConst(lhs, rhs) => {
                if lhs != rhs {
                    self.builder.operations.extend(then_instructions);
                }
            }
            IfCondition::Eq(lhs, rhs) => {
                let op = DslIr::IfEq(Box::new((lhs, rhs, then_instructions, Default::default())));
                self.builder.operations.push(op);
            }
            IfCondition::EqI(lhs, rhs) => {
                let op = DslIr::IfEqI(Box::new((lhs, rhs, then_instructions, Default::default())));
                self.builder.operations.push(op);
            }
            IfCondition::Ne(lhs, rhs) => {
                let op = DslIr::IfNe(Box::new((lhs, rhs, then_instructions, Default::default())));
                self.builder.operations.push(op);
            }
            IfCondition::NeI(lhs, rhs) => {
                let op = DslIr::IfNeI(Box::new((lhs, rhs, then_instructions, Default::default())));
                self.builder.operations.push(op);
            }
        }
    }

    pub fn then_or_else(
        mut self,
        mut then_f: impl FnMut(&mut Builder<RC>),
        mut else_f: impl FnMut(&mut Builder<RC>),
    ) {
        // Get the condition reduced from the expressions for lhs and rhs.
        let condition = self.condition();
        let mut then_builder = Builder::<RC>::new_sub_builder(
            self.builder.variable_count,
            self.builder.nb_public_values,
            self.builder.p2_hash_num,
            self.builder.debug,
            self.builder.program_type,
        );

        // Execute the `then` and `else_then` blocks and collect the instructions.
        then_f(&mut then_builder);
        self.builder.p2_hash_num = then_builder.p2_hash_num;

        let then_instructions = then_builder.operations;

        let mut else_builder = Builder::<RC>::new_sub_builder(
            self.builder.variable_count,
            self.builder.nb_public_values,
            self.builder.p2_hash_num,
            self.builder.debug,
            self.builder.program_type,
        );
        else_f(&mut else_builder);
        self.builder.p2_hash_num = else_builder.p2_hash_num;

        let else_instructions = else_builder.operations;

        // Dispatch instructions to the correct conditional block.
        match condition {
            IfCondition::EqConst(lhs, rhs) => {
                if lhs == rhs {
                    self.builder.operations.extend(then_instructions);
                } else {
                    self.builder.operations.extend(else_instructions);
                }
            }
            IfCondition::NeConst(lhs, rhs) => {
                if lhs != rhs {
                    self.builder.operations.extend(then_instructions);
                } else {
                    self.builder.operations.extend(else_instructions);
                }
            }
            IfCondition::Eq(lhs, rhs) => {
                let op = DslIr::IfEq(Box::new((lhs, rhs, then_instructions, else_instructions)));
                self.builder.operations.push(op);
            }
            IfCondition::EqI(lhs, rhs) => {
                let op = DslIr::IfEqI(Box::new((lhs, rhs, then_instructions, else_instructions)));
                self.builder.operations.push(op);
            }
            IfCondition::Ne(lhs, rhs) => {
                let op = DslIr::IfNe(Box::new((lhs, rhs, then_instructions, else_instructions)));
                self.builder.operations.push(op);
            }
            IfCondition::NeI(lhs, rhs) => {
                let op = DslIr::IfNeI(Box::new((lhs, rhs, then_instructions, else_instructions)));
                self.builder.operations.push(op);
            }
        }
    }

    fn condition(&mut self) -> IfCondition<RC::N> {
        match (self.lhs.clone(), self.rhs.clone(), self.is_eq) {
            (SymbolicVar::Const(lhs, _), SymbolicVar::Const(rhs, _), true) => {
                IfCondition::EqConst(lhs, rhs)
            }
            (SymbolicVar::Const(lhs, _), SymbolicVar::Const(rhs, _), false) => {
                IfCondition::NeConst(lhs, rhs)
            }
            (SymbolicVar::Const(lhs, _), SymbolicVar::Val(rhs, _), true) => {
                IfCondition::EqI(rhs, lhs)
            }
            (SymbolicVar::Const(lhs, _), SymbolicVar::Val(rhs, _), false) => {
                IfCondition::NeI(rhs, lhs)
            }
            (SymbolicVar::Const(lhs, _), rhs, true) => {
                let rhs: Var<RC::N> = self.builder.eval(rhs);
                IfCondition::EqI(rhs, lhs)
            }
            (SymbolicVar::Const(lhs, _), rhs, false) => {
                let rhs: Var<RC::N> = self.builder.eval(rhs);
                IfCondition::NeI(rhs, lhs)
            }
            (SymbolicVar::Val(lhs, _), SymbolicVar::Const(rhs, _), true) => {
                let lhs: Var<RC::N> = self.builder.eval(lhs);
                IfCondition::EqI(lhs, rhs)
            }
            (SymbolicVar::Val(lhs, _), SymbolicVar::Const(rhs, _), false) => {
                let lhs: Var<RC::N> = self.builder.eval(lhs);
                IfCondition::NeI(lhs, rhs)
            }
            (lhs, SymbolicVar::Const(rhs, _), true) => {
                let lhs: Var<RC::N> = self.builder.eval(lhs);
                IfCondition::EqI(lhs, rhs)
            }
            (lhs, SymbolicVar::Const(rhs, _), false) => {
                let lhs: Var<RC::N> = self.builder.eval(lhs);
                IfCondition::NeI(lhs, rhs)
            }
            (SymbolicVar::Val(lhs, _), SymbolicVar::Val(rhs, _), true) => IfCondition::Eq(lhs, rhs),
            (SymbolicVar::Val(lhs, _), SymbolicVar::Val(rhs, _), false) => {
                IfCondition::Ne(lhs, rhs)
            }
            (SymbolicVar::Val(lhs, _), rhs, true) => {
                let rhs: Var<RC::N> = self.builder.eval(rhs);
                IfCondition::Eq(lhs, rhs)
            }
            (SymbolicVar::Val(lhs, _), rhs, false) => {
                let rhs: Var<RC::N> = self.builder.eval(rhs);
                IfCondition::Ne(lhs, rhs)
            }
            (lhs, SymbolicVar::Val(rhs, _), true) => {
                let lhs: Var<RC::N> = self.builder.eval(lhs);
                IfCondition::Eq(lhs, rhs)
            }
            (lhs, SymbolicVar::Val(rhs, _), false) => {
                let lhs: Var<RC::N> = self.builder.eval(lhs);
                IfCondition::Ne(lhs, rhs)
            }
            (lhs, rhs, true) => {
                let lhs: Var<RC::N> = self.builder.eval(lhs);
                let rhs: Var<RC::N> = self.builder.eval(rhs);
                IfCondition::Eq(lhs, rhs)
            }
            (lhs, rhs, false) => {
                let lhs: Var<RC::N> = self.builder.eval(lhs);
                let rhs: Var<RC::N> = self.builder.eval(rhs);
                IfCondition::Ne(lhs, rhs)
            }
        }
    }
}

/// A builder for the DSL that handles for loops.
pub struct RangeBuilder<'a, RC: FieldGenericConfig> {
    start: Usize<RC::N>,
    end: Usize<RC::N>,
    step_size: usize,
    builder: &'a mut Builder<RC>,
}

impl<'a, RC: FieldGenericConfig> RangeBuilder<'a, RC> {
    pub const fn step_by(mut self, step_size: usize) -> Self {
        self.step_size = step_size;
        self
    }

    pub fn for_each(self, mut f: impl FnMut(Var<RC::N>, &mut Builder<RC>)) {
        let step_size = RC::N::from_canonical_usize(self.step_size);
        let loop_variable: Var<RC::N> = self.builder.uninit();
        let mut loop_body_builder = Builder::<RC>::new_sub_builder(
            self.builder.variable_count,
            self.builder.nb_public_values,
            self.builder.p2_hash_num,
            self.builder.debug,
            self.builder.program_type,
        );

        f(loop_variable, &mut loop_body_builder);
        self.builder.p2_hash_num = loop_body_builder.p2_hash_num;

        let loop_instructions = loop_body_builder.operations;

        let op = DslIr::For(Box::new((
            self.start,
            self.end,
            step_size,
            loop_variable,
            loop_instructions,
        )));
        self.builder.operations.push(op);
    }
}
