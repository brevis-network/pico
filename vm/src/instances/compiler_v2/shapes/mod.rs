pub mod compress_shape;
pub mod riscv_shape;

use crate::instances::compiler_v2::shapes::compress_shape::{
    RecursionVkShape, RiscvRecursionShape,
};
use core::fmt;
use serde::{Deserialize, Serialize};
use std::{cmp::Reverse, collections::BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub struct ProofShape {
    pub chip_information: Vec<(String, usize)>,
}

impl FromIterator<(String, usize)> for ProofShape {
    fn from_iter<T: IntoIterator<Item = (String, usize)>>(iter: T) -> Self {
        let set = iter
            .into_iter()
            .map(|(name, log_degree)| {
                // let priority = name_to_priority.get(&name).copied().unwrap_or(usize::MAX);
                (Reverse(log_degree), name)
            })
            .collect::<BTreeSet<_>>();

        Self {
            chip_information: set
                .into_iter()
                .map(|(Reverse(log_degree), name)| (name, log_degree))
                .collect(),
        }
    }
}

impl IntoIterator for ProofShape {
    type Item = (String, usize);

    type IntoIter = <Vec<(String, usize)> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.chip_information.into_iter()
    }
}

impl fmt::Display for ProofShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Print the proof shapes in a human-readable format
        writeln!(f, "Proofshape:")?;
        for (name, log_degree) in &self.chip_information {
            writeln!(f, "{name}: {}", 1 << log_degree)?;
        }
        Ok(())
    }
}

impl ProofShape {
    pub fn print_chip_information(&self) {
        println!("Chip Information:");
        for (name, value) in &self.chip_information {
            println!("Chip: {}, Value: {}", name, value);
        }
    }
}

// #[derive(Debug, Clone)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PicoRecursionProgramShape {
    Convert(RiscvRecursionShape),
    Combine(RecursionVkShape),
    Compress(RecursionVkShape),
}
