use std::sync::{Arc, Mutex};

use p3_air::{AirBuilder, ExtensionBuilder, RowWindow};
use p3_field::PrimeCharacteristicRing;

use super::PartitionedAirBuilder;
use crate::{
    builder::{ChipBuilder, LookupBuilder, ScopedBuilder},
    config::{StarkProtocolConfig, Val},
    lookup::SymbolicLookup,
};

mod check_constraints;
pub use check_constraints::{
    check_constraints, check_logup, debug_constraints_and_interactions, AirProofRawInput,
};

thread_local! {
   pub static USE_DEBUG_BUILDER: Arc<Mutex<bool>> = Arc::new(Mutex::new(true));
}

/// An `AirBuilder` which asserts that each constraint is zero, allowing any failed constraints to
/// be detected early.
pub struct DebugConstraintBuilder<'a, SC: StarkProtocolConfig> {
    pub air_name: &'a str,
    pub row_index: usize,
    pub preprocessed: RowWindow<'a, Val<SC>>,
    pub partitioned_main: Vec<RowWindow<'a, Val<SC>>>,
    pub is_first_row: Val<SC>,
    pub is_last_row: Val<SC>,
    pub is_transition: Val<SC>,
    pub public_values: &'a [Val<SC>],
    pub has_common_main: bool,
}

impl<'a, SC> AirBuilder for DebugConstraintBuilder<'a, SC>
where
    SC: StarkProtocolConfig,
{
    type F = Val<SC>;
    type Expr = Val<SC>;
    type Var = Val<SC>;
    type PreprocessedWindow = RowWindow<'a, Val<SC>>;
    type MainWindow = RowWindow<'a, Val<SC>>;
    type PublicVar = Val<SC>;

    /// It is difficult to horizontally concatenate matrices when the main trace is partitioned, so
    /// we disable this method in that case.
    fn main(&self) -> Self::MainWindow {
        if self.partitioned_main.len() == 1 {
            self.partitioned_main[0]
        } else {
            panic!("Main trace is either empty or partitioned. This function should not be used.")
        }
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed
    }

    fn is_first_row(&self) -> Self::Expr {
        self.is_first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.is_last_row
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == 2 {
            self.is_transition
        } else {
            panic!("only supports a window size of 2")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        assert_eq!(
            x.into(),
            Val::<SC>::ZERO,
            "constraints had nonzero value on air {},row {}",
            self.air_name,
            self.row_index
        );
    }

    fn assert_eq<I1: Into<Self::Expr>, I2: Into<Self::Expr>>(&mut self, x: I1, y: I2) {
        let x = x.into();
        let y = y.into();
        assert_eq!(
            x, y,
            "values didn't match on air {}, row {}: {} != {}",
            self.air_name, self.row_index, x, y
        );
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.public_values
    }
}

impl<SC> ExtensionBuilder for DebugConstraintBuilder<'_, SC>
where
    SC: StarkProtocolConfig,
{
    type EF = SC::EF;
    type ExprEF = SC::EF;
    type VarEF = SC::EF;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        assert_eq!(
            x.into(),
            SC::EF::ZERO,
            "constraints had nonzero value on row {}",
            self.row_index
        );
    }

    fn assert_eq_ext<I1, I2>(&mut self, x: I1, y: I2)
    where
        I1: Into<Self::ExprEF>,
        I2: Into<Self::ExprEF>,
    {
        let x = x.into();
        let y = y.into();
        assert_eq!(
            x, y,
            "values didn't match on air {}, row {}: {} != {}",
            self.air_name, self.row_index, x, y
        );
    }
}

impl<SC> PartitionedAirBuilder for DebugConstraintBuilder<'_, SC>
where
    SC: StarkProtocolConfig,
{
    fn cached_mains(&self) -> &[Self::MainWindow] {
        let mut num_cached_mains = self.partitioned_main.len();
        if self.has_common_main {
            num_cached_mains -= 1;
        }
        &self.partitioned_main[..num_cached_mains]
    }

    fn common_main(&self) -> &Self::MainWindow {
        assert!(self.has_common_main, "AIR doesn't have a common main trace");
        self.partitioned_main.last().unwrap()
    }
}

// ───────────────────────── ChipBuilder trait stack ─────────────────────────
// Lookups are checked separately (`check_logup`), so this builder ignores them.

impl<SC: StarkProtocolConfig> ScopedBuilder for DebugConstraintBuilder<'_, SC> {}

impl<SC: StarkProtocolConfig> LookupBuilder<SymbolicLookup<Val<SC>>>
    for DebugConstraintBuilder<'_, SC>
{
    fn looking(&mut self, _message: SymbolicLookup<Val<SC>>) {}
    fn looked(&mut self, _message: SymbolicLookup<Val<SC>>) {}
}

impl<SC: StarkProtocolConfig> ChipBuilder<Val<SC>> for DebugConstraintBuilder<'_, SC> {}
