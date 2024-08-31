use hashbrown::HashMap;
use p3_commit::Pcs;
use p3_matrix::{dense::RowMajorMatrix, Dimensions, Matrix};

use pico_configs::config::{StarkGenericConfig, Val, Com};

use crate::keys::{BaseProvingKey, BaseVerifyingKey};
use crate::chip::{BaseChip, ChipBehavior};
use crate::program::Program;

pub struct BaseProver<SC: StarkGenericConfig, C> {
    config: SC,

    chips: Vec<BaseChip<Val<SC>, C>>,
}

impl<SC: StarkGenericConfig, C: ChipBehavior<Val<SC>>> BaseProver<SC, C> {
    pub fn config(&self) -> &SC {
        &self.config
    }

    pub fn chips(&self) -> &[BaseChip<Val<SC>, C>] {
        &self.chips
    }

    pub fn setup(&self) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        let pcs = self.config.pcs();
        let chips_and_preprocessed = self.generate_preprocessed();
        let domains_and_preprocessed = chips_and_preprocessed
            .clone()
            .into_iter()
            .map(|(_, trace)| {
                (
                    pcs.natural_domain_for_degree(trace.height()),
                    trace
                )
            })
            .collect::<Vec<_>>();
        let (commit, _) = pcs.commit(domains_and_preprocessed);

        (
            BaseProvingKey {
                commit: commit.clone(),
                chips_and_traces: chips_and_preprocessed,
            },
            BaseVerifyingKey {
                commit: commit.clone(),
            }
        )
    }

    pub fn generate_preprocessed(&self) -> Vec<(String, RowMajorMatrix<Val<SC>>)> {
        // todo: double check this
        self.chips
            .iter()
            .filter_map(|chip| {
                chip.generate_preprocessed().map(|trace| {
                    (chip.name(), trace)
                })
            })
            .collect::<Vec<_>>()
    }

    pub fn generate_main(&self) -> Vec<(String, RowMajorMatrix<Val<SC>>)> {
        self.chips
            .iter()
            .map(|chip| {
                (chip.name(), chip.generate_main())
            })
            .collect::<Vec<_>>()
    }

    pub fn commit(&self) { //

    }

    pub fn prove(&self) { //

    }
}