use rand::{
    distr::{Distribution, StandardUniform},
    Rng, RngExt,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum BaseAluOpcode {
    AddF = 0,
    SubF = 1,
    MulF = 2,
    DivF = 3,
}

impl Distribution<BaseAluOpcode> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BaseAluOpcode {
        match rng.random_range(0..4) {
            0 => BaseAluOpcode::AddF,
            1 => BaseAluOpcode::SubF,
            2 => BaseAluOpcode::MulF,
            3 => BaseAluOpcode::DivF,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ExtAluOpcode {
    AddE = 0,
    SubE = 1,
    MulE = 2,
    DivE = 3,
}

impl Distribution<ExtAluOpcode> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ExtAluOpcode {
        match rng.random_range(0..4) {
            0 => ExtAluOpcode::AddE,
            1 => ExtAluOpcode::SubE,
            2 => ExtAluOpcode::MulE,
            3 => ExtAluOpcode::DivE,
            _ => unreachable!(),
        }
    }
}
