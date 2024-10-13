use crate::{
    compiler::recursion::asm::AsmConfig,
    configs::bb_poseidon2::{InnerChallenge, InnerVal},
};
pub type InnerConfig = AsmConfig<InnerVal, InnerChallenge>;
