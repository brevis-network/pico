use super::{folder::DebugConstraintFolder, lookup::LookupScope};
use crate::{
    configs::config::{Com, PcsProverData, StarkGenericConfig, Val},
    emulator::record::RecordBehavior,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey},
        proof::{BaseProof, MainTraceCommitments, MetaProof},
        prover::BaseProver,
        verifier::BaseVerifier,
        witness::ProvingWitness,
    },
};
use alloc::sync::Arc;
use anyhow::Result;
use itertools::Itertools;
use p3_air::Air;
use p3_challenger::{CanObserve, FieldChallenger};
use p3_field::{Field, FieldAlgebra};
use p3_maybe_rayon::prelude::*;
use std::{array, time::Instant};
use tracing::{debug, info};

/// Functions that each machine instance should implement.
pub trait MachineBehavior<SC, C, I>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    /// Get the name of the machine.
    fn name(&self) -> String;

    /// Get the basemachine
    fn base_machine(&self) -> &BaseMachine<SC, C>;

    /// Get the configuration of the machine.
    fn config(&self) -> Arc<SC> {
        self.base_machine().config()
    }

    /// Get number of public values
    fn num_public_values(&self) -> usize {
        self.base_machine().num_public_values()
    }

    /// Get the chips of the machine.
    fn chips(&self) -> Arc<[MetaChip<SC::Val, C>]> {
        self.base_machine().chips()
    }

    /// Complete the record after emulation.
    fn complement_record(&self, records: &mut [C::Record]) {
        let begin = Instant::now();
        let chips_arc = self.chips();
        let chips = chips_arc.as_ref();
        records.par_iter_mut().for_each(|record| {
            chips.iter().for_each(|chip| {
                if chip.is_active(record) {
                    let mut extra = C::Record::default();
                    chip.extra_record(record, &mut extra);
                    record.append(&mut extra);
                }
            });
            record.register_nonces();
        });
        debug!("complement record in {:?}", begin.elapsed());
    }

    /// setup prover, verifier and keys.
    fn setup_keys(&self, program: &C::Program) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        let begin = Instant::now();

        let (pk, vk) = self.base_machine().setup_keys(program);

        info!(
            "PERF-step=setup_keys-user_time={}",
            begin.elapsed().as_millis(),
        );

        (pk, vk)
    }

    /// Get the prover of the machine.
    fn prove(&self, pk: &BaseProvingKey<SC>, witness: &ProvingWitness<SC, C, I>) -> MetaProof<SC>
    where
        C: for<'a> Air<DebugConstraintFolder<'a, SC::Val, SC::Challenge>>;

    /// Verify the proof.
    fn verify(&self, vk: &BaseVerifyingKey<SC>, proof: &MetaProof<SC>) -> Result<()>;
}

/// A basic machine that includes elemental proving gadgets.
/// Mainly for testing purposes.
pub struct BaseMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    /// Configuration of the machine
    config: Arc<SC>,

    /// Chips of the machine
    chips: Arc<[MetaChip<Val<SC>, C>]>,

    /// Base prover
    prover: BaseProver<SC, C>,

    /// Base verifier
    verifier: BaseVerifier<SC, C>,

    /// Number of public values
    num_public_values: usize,

    /// Contains global scopes.
    has_global: bool,
}

impl<SC, C> Clone for BaseMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    fn clone(&self) -> Self {
        Self {
            has_global: self.has_global,
            config: self.config.clone(),
            chips: self.chips.clone(),
            prover: self.prover.clone(),
            verifier: self.verifier.clone(),
            num_public_values: self.num_public_values,
        }
    }
}

impl<SC, C> BaseMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
{
    /// Name of BaseMachine.
    pub fn name(&self) -> String {
        "BaseMachine".to_string()
    }

    /// Get the configuration of the machine.
    pub fn config(&self) -> Arc<SC> {
        self.config.clone()
    }

    /// Get the chips of the machine.
    pub fn chips(&self) -> Arc<[MetaChip<Val<SC>, C>]> {
        self.chips.clone()
    }

    /// Get the number of public values.
    pub fn num_public_values(&self) -> usize {
        self.num_public_values
    }
}

impl<SC, C> BaseMachine<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    /// Create BaseMachine based on config and chip behavior.
    pub fn new(config: SC, chips: Vec<MetaChip<Val<SC>, C>>, num_public_values: usize) -> Self {
        let has_global = chips
            .iter()
            .any(|chip| chip.lookup_scope() == LookupScope::Global);

        Self {
            config: config.into(),
            chips: chips.into(),
            prover: BaseProver::<SC, C>::new(),
            verifier: BaseVerifier::<SC, C>::new(),
            num_public_values,
            has_global,
        }
    }

    pub fn preprocessed_chip_ids(&self) -> Vec<usize> {
        self.chips()
            .iter()
            .enumerate()
            .filter(|(_, chip)| chip.preprocessed_width() > 0)
            .map(|(i, _)| i)
            .collect()
    }

    /// setup proving and verifying keys.
    pub fn setup_keys(&self, program: &C::Program) -> (BaseProvingKey<SC>, BaseVerifyingKey<SC>) {
        let (pk, vk) = self
            .prover
            .setup_keys(&self.config(), &self.chips(), program);

        (pk, vk)
    }

    pub fn commit(
        &self,
        record: &C::Record,
        lookup_scope: LookupScope,
    ) -> Option<MainTraceCommitments<SC>> {
        self.prover.commit_main(
            &self.config(),
            record,
            self.prover
                .generate_main(&self.chips(), record, lookup_scope),
        )
    }

    /// prove a batch of records
    pub fn prove_ensemble(
        &self,
        pk: &BaseProvingKey<SC>,
        records: &[C::Record],
    ) -> Arc<[BaseProof<SC>]>
    where
        C: for<'c> Air<DebugConstraintFolder<'c, SC::Val, SC::Challenge>>,
    {
        let mut challenger = self.config().challenger();

        // observe preprocessed
        pk.observed_by(&mut challenger);

        // Generate and commit the global traces for each chunk.
        let global_data = records
            .iter()
            .map(|record| {
                if self.has_global {
                    self.commit(record, LookupScope::Global)
                } else {
                    None
                }
            })
            .collect_vec();

        // Observe the challenges for each segment.
        global_data
            .iter()
            .zip_eq(records.iter())
            .for_each(|(global_data, record)| {
                if self.has_global {
                    challenger.observe(
                        global_data
                            .as_ref()
                            .expect("must have a global commitment")
                            .commitment
                            .clone(),
                    );
                }
                challenger
                    .observe_slice(&record.public_values::<SC::Val>()[0..self.num_public_values()]);
            });

        // Obtain the challenges used for the global permutation argument.
        let global_permutation_challenges: [SC::Challenge; 2] = array::from_fn(|_| {
            if self.has_global {
                challenger.sample_ext_element()
            } else {
                SC::Challenge::ZERO
            }
        });

        global_data
            .into_iter()
            .zip_eq(records.iter())
            .enumerate()
            .map(|(i, (global_data, record))| {
                info!("PERF-chunk={}", i + 1);
                let regional_data = self.commit(record, LookupScope::Regional).unwrap();
                self.prover.prove(
                    &self.config(),
                    &self.chips(),
                    pk,
                    regional_data,
                    global_data,
                    &mut challenger.clone(),
                    &global_permutation_challenges,
                    records[i].chunk_index(),
                )
            })
            .collect::<Arc<[_]>>()
    }

    /// Prove assuming that challenger has already observed pk & main commitments and pv's
    pub fn prove_plain(
        &self,
        pk: &BaseProvingKey<SC>,
        challenger: &mut SC::Challenger,
        chunk_index: usize,
        local_commitment: MainTraceCommitments<SC>,
        global_commitment: Option<MainTraceCommitments<SC>>,
    ) -> BaseProof<SC> {
        // Sample for the global permutation challenges.
        // Obtain the challenges used for the global permutation argument.
        let mut global_permutation_challenges: Vec<SC::Challenge> = Vec::new();
        for _ in 0..2 {
            global_permutation_challenges.push(challenger.sample_ext_element());
        }

        self.prover.prove(
            &self.config(),
            &self.chips(),
            pk,
            local_commitment,
            global_commitment,
            challenger,
            &global_permutation_challenges,
            chunk_index,
        )
    }

    /// Verify a batch of BaseProofs e2e
    pub fn verify_ensemble(
        &self,
        vk: &BaseVerifyingKey<SC>,
        proofs: &[BaseProof<SC>],
    ) -> Result<()> {
        assert!(!proofs.is_empty());

        let mut challenger = self.config().challenger();

        // observe all preprocessed and main commits and pv's
        vk.observed_by(&mut challenger);

        proofs.iter().for_each(|proof| {
            if self.has_global {
                challenger.observe(proof.commitments.global_main_commit.clone());
            }
            challenger.observe_slice(&proof.public_values[..self.num_public_values]);
        });

        // Obtain the challenges used for the global permutation argument.
        let global_permutation_challenges: [SC::Challenge; 2] = array::from_fn(|_| {
            if self.has_global {
                challenger.sample_ext_element()
            } else {
                SC::Challenge::ZERO
            }
        });

        // verify all proofs
        for proof in proofs {
            self.verifier.verify(
                &self.config(),
                &self.chips(),
                vk,
                &mut challenger.clone(),
                proof,
                &global_permutation_challenges,
            )?;

            if !proof.regional_cumulative_sum().is_zero() {
                panic!("verify_ensemble: local lookup cumulative sum is not zero");
            }
        }

        let sum = proofs
            .iter()
            .map(|proof| proof.global_cumulative_sum())
            .sum::<SC::Challenge>();

        if !sum.is_zero() {
            panic!("verify_ensemble: global lookup cumulative sum is not zero");
        }

        Ok(())
    }

    /// Verify assuming that challenger has already observed vk & main commitments and pv's
    pub fn verify_plain(
        &self,
        vk: &BaseVerifyingKey<SC>,
        challenger: &mut SC::Challenger,
        proof: &BaseProof<SC>,
    ) -> Result<()> {
        // Obtain the challenges used for the global permutation argument.
        let global_permutation_challenges: [SC::Challenge; 2] = array::from_fn(|_| {
            if self.has_global {
                challenger.sample_ext_element()
            } else {
                SC::Challenge::ZERO
            }
        });

        self.verifier.verify(
            &self.config(),
            &self.chips(),
            vk,
            challenger,
            proof,
            &global_permutation_challenges,
        )
    }
}
