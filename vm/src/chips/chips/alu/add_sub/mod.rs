use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod traces;

/// A chip that implements addition for the opcode ADD and SUB.
///
/// SUB is basically an ADD with a re-arrangement of the operands and result.
/// E.g. given the standard ALU op variable name and positioning of `a` = `b` OP `c`,
/// `a` = `b` + `c` should be verified for ADD, and `b` = `a` + `c` (e.g. `a` = `b` - `c`)
/// should be verified for SUB.
#[derive(Default)]
pub struct AddSubChip<F>(PhantomData<F>);
