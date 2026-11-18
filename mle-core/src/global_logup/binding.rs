//! What binds a block's global LogUp together, over KoalaBear and Poseidon2.
//!
//! The prover, the native verifier and the recursion circuits must agree on every value here, so
//! each is defined once, in this module:
//!
//! - the heights the committed tables have ([`global_log_height`], [`image_log_heights`]);
//! - the hash chain over the chunks' table commitments ([`chain_root`]), whose root fixes the
//!   ordered list of commitments before any challenge exists;
//! - the challenges `(alpha, beta)`, drawn from a transcript over the parameters, the program and
//!   the chain root, behind a proof of work ([`derive_challenges`], [`check_challenges`]);
//! - the two wraps the recursion uses to carry the challenges and the root along the chain
//!   ([`wrap`], [`wrap_top`]); only the circuits compute them, and the node machines' tests hold
//!   the circuits to these two functions;
//! - the bound on real rows that keeps a multiplicity from wrapping around the field
//!   ([`chunk_count`], [`MAX_COUNT`]).

use std::ops::RangeInclusive;

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};
use p3_maybe_rayon::prelude::*;
use p3_symmetric::Permutation;

use super::{assert_group_vk, group_keygen, group_params, MAX_GROUP_LEN, TABLE_WIDTH};
use crate::{
    config::{
        koala_bear_poseidon2::{
            default_duplex_sponge, poseidon2_perm, Digest, KoalaBearPoseidon2Config, EF, F,
        },
        soundness::{
            admit_production_vk, SoundnessCalculator, UnderBudgetError, VkShape,
            PRODUCTION_SECURITY_BITS,
        },
        SystemParams,
    },
    keygen::types::{MultiStarkProvingKey, MultiStarkVerifyingKey},
    FiatShamirTranscript,
};

type Sc = KoalaBearPoseidon2Config;

// Domain tags: the first element of a preimage, one per family, so that no value of one family
// is also a value of another. Four ASCII characters each, as one field element.
/// `"GLIV"`: the chain's initial value.
pub const TAG_IV: u32 = 0x474C_4956;
/// `"GLLF"`: a chain step.
pub const TAG_LEAF: u32 = 0x474C_4C46;
/// `"GLWR"`: a chain value wrapped with the challenges.
pub const TAG_WRAP: u32 = 0x474C_5752;
/// `"GLTP"`: a chain value wrapped with the chain root.
pub const TAG_TOP: u32 = 0x474C_5450;
/// `"GLCH"`: the challenge transcript.
pub const TAG_CHALLENGE: u32 = 0x474C_4348;
/// `"GLPD"`: the parameter digest.
pub const TAG_PARAMS: u32 = 0x474C_5044;

// The tags differ from one another, each is a canonical field element, and none is a byte.
// The keygen's digests (a key's pre-hash, the constraint digest) take their preimage a byte an
// element, so theirs starts with an element below 256, which no tag here is.
const _: () = {
    let tags = [
        TAG_IV,
        TAG_LEAF,
        TAG_WRAP,
        TAG_TOP,
        TAG_CHALLENGE,
        TAG_PARAMS,
    ];
    let mut i = 0;
    while i < tags.len() {
        assert!(
            tags[i] > 255 && tags[i] < F::ORDER_U32,
            "a domain tag is a byte, or not a canonical field element"
        );
        let mut j = i + 1;
        while j < tags.len() {
            assert!(tags[i] != tags[j], "two domain tags are equal");
            j += 1;
        }
        i += 1;
    }
};

/// The tallest a Global event table gets: `2^22` rows.
pub const MAX_GLOBAL_LOG_HEIGHT: usize = 22;
/// The smallest height tier of the memory image table: `2^16` rows.
pub const MIN_IMAGE_LOG_HEIGHT: usize = 16;
/// The real-row bound is counted in units of `2^10` rows.
pub const LOG_COUNT_UNIT: usize = 10;

/// The log height of every chunk's Global event table under the riscv machine at `riscv`:
/// `min(22, h - 1)` for stacked log height `h`.
///
/// One height per operating point, whatever a chunk's event count: a group proof re-reads the
/// commitment under this height, and a reader that took another would see other columns. At
/// `h - 1` the ten columns fill exactly five stacked columns.
///
/// # Panics
/// If `h < 16`: the smallest image table would not fit the stacked height.
pub fn global_log_height(riscv: &SystemParams) -> usize {
    global_log_height_at(riscv.log_stacked_height())
}

/// [`global_log_height`] from the stacked log height alone, for a reader that holds a layout
/// and not the parameters.
pub fn global_log_height_at(log_stacked_height: usize) -> usize {
    let h = log_stacked_height;
    assert!(
        h >= MIN_IMAGE_LOG_HEIGHT,
        "the global LogUp needs a stacked height of at least 2^{MIN_IMAGE_LOG_HEIGHT}, not 2^{h}"
    );
    MAX_GLOBAL_LOG_HEIGHT.min(h - 1)
}

/// The height tiers a memory image table can take under the riscv machine at `riscv`:
/// `16..=min(22, h)`.
pub fn image_log_heights(riscv: &SystemParams) -> RangeInclusive<usize> {
    let h = riscv.log_stacked_height();
    assert!(
        h >= MIN_IMAGE_LOG_HEIGHT,
        "the global LogUp needs a stacked height of at least 2^{MIN_IMAGE_LOG_HEIGHT}, not 2^{h}"
    );
    MIN_IMAGE_LOG_HEIGHT..=MAX_GLOBAL_LOG_HEIGHT.min(h)
}

/// The tier of an image of `words` words: the smallest that holds it, or `None` when none does.
/// A program has exactly one tier, and it is part of the program's identity.
pub fn image_log_height(riscv: &SystemParams, words: usize) -> Option<usize> {
    image_log_heights(riscv).find(|&log_height| words <= 1 << log_height)
}

/// `H`: the padding-free overwrite sponge over Poseidon2 (rate 8, capacity 8, zero initial
/// state), first eight lanes. Every preimage hashed here has a fixed length and leads with its
/// family's tag.
pub fn hash(elems: &[F]) -> Digest {
    let perm = poseidon2_perm();
    let mut state = [F::ZERO; 16];
    let mut absorbed = 0;
    for &elem in elems {
        state[absorbed] = elem;
        absorbed += 1;
        if absorbed == 8 {
            perm.permute_mut(&mut state);
            absorbed = 0;
        }
    }
    if absorbed != 0 {
        perm.permute_mut(&mut state);
    }
    std::array::from_fn(|i| state[i])
}

/// The chain before any chunk: `H(TAG_IV)`.
pub fn chain_iv() -> Digest {
    hash(&[F::from_u32(TAG_IV)])
}

/// One step of the chain: chunk `index` (from 1) committed its table as `commit`, at
/// `2^log_height` rows of [`TABLE_WIDTH`] columns. The layout is in the preimage so that two
/// readers that disagree on it disagree on the chain.
pub fn chain_step(prev: &Digest, index: u32, log_height: usize, commit: &Digest) -> Digest {
    let mut preimage = Vec::with_capacity(20);
    preimage.push(F::from_u32(TAG_LEAF));
    preimage.extend_from_slice(prev);
    preimage.push(F::from_u32(index));
    preimage.push(F::from_usize(log_height));
    preimage.push(F::from_usize(TABLE_WIDTH));
    preimage.extend_from_slice(commit);
    hash(&preimage)
}

/// The chain over the chunks' table commitments, in chunk order. Under collision resistance the
/// result fixes the ordered list.
pub fn chain_root(log_height: usize, commits: impl IntoIterator<Item = Digest>) -> Digest {
    commits
        .into_iter()
        .zip(1u32..)
        .fold(chain_iv(), |chain, (commit, index)| {
            chain_step(&chain, index, log_height, &commit)
        })
}

/// A chain value bound to the challenges a node used: `H(TAG_WRAP ‖ alpha ‖ beta ‖ x)`.
pub fn wrap(alpha: EF, beta: EF, x: &Digest) -> Digest {
    let mut preimage = Vec::with_capacity(19);
    preimage.push(F::from_u32(TAG_WRAP));
    preimage.extend_from_slice(alpha.as_basis_coefficients_slice());
    preimage.extend_from_slice(beta.as_basis_coefficients_slice());
    preimage.extend_from_slice(x);
    hash(&preimage)
}

/// A chain value bound to the chain root the challenges were derived from:
/// `H(TAG_TOP ‖ root ‖ x)`.
pub fn wrap_top(root: &Digest, x: &Digest) -> Digest {
    let mut preimage = Vec::with_capacity(17);
    preimage.push(F::from_u32(TAG_TOP));
    preimage.extend_from_slice(root);
    preimage.extend_from_slice(x);
    hash(&preimage)
}

/// The group machines that go with one riscv operating point: a key for every group size, and
/// the digest of everything about the operating point a challenge has to depend on.
pub struct GroupMachines {
    config: Sc,
    /// `pks[s - 1]` and `vks[s - 1]` are the keys of the machine for `s` tables.
    pks: Vec<MultiStarkProvingKey<Sc>>,
    vks: Vec<MultiStarkVerifyingKey<Sc>>,
    params_digest: Digest,
}

impl GroupMachines {
    /// Keygen for every group size under [`group_params`] of `riscv`. The machines have no
    /// preprocessed trace, so this is symbolic work only.
    pub fn new(riscv: &SystemParams) -> Self {
        let config = Sc::default_from_params(group_params(riscv));
        let pks: Vec<_> = (1..=MAX_GROUP_LEN)
            .map(|tables| group_keygen(&config, tables))
            .collect();
        let vks: Vec<_> = pks.iter().map(|pk| pk.get_vk()).collect();
        for vk in &vks {
            assert_group_vk(&vk.inner, riscv);
        }
        let pre_hashes: Vec<Digest> = vks.iter().map(|vk| vk.pre_hash).collect();
        let params_digest = params_digest(riscv, &pre_hashes);
        Self {
            config,
            pks,
            vks,
            params_digest,
        }
    }

    /// The config of the group machines, carrying their parameters.
    pub fn config(&self) -> &Sc {
        &self.config
    }

    /// The key of the machine for `tables` tables (`1..=MAX_GROUP_LEN`), or `None` out of range.
    /// The image table's machine is the one for a single table.
    pub fn pk(&self, tables: usize) -> Option<&MultiStarkProvingKey<Sc>> {
        tables.checked_sub(1).and_then(|i| self.pks.get(i))
    }

    /// The verifying key of the machine for `tables` tables, or `None` out of range. A verifier
    /// takes a group's key from here, never from the prover.
    pub fn vk(&self, tables: usize) -> Option<&MultiStarkVerifyingKey<Sc>> {
        tables.checked_sub(1).and_then(|i| self.vks.get(i))
    }

    /// See [`params_digest`].
    pub fn params_digest(&self) -> Digest {
        self.params_digest
    }

    /// The gate a production keygen passes its keys through (`admit_production_vk`), for the
    /// key of every group size and for the round the group proofs share: a key below the
    /// production budget is refused, and so is the round. A group proof's score has no LogUp
    /// round; the round is the block's, scored here under the keys' parameters
    /// ([`SoundnessCalculator::global_logup_bits`]). One line is logged, the largest group's.
    ///
    /// # Panics
    /// If the rows the recursion's root admits in one direction ([`MAX_DIRECTION_ROWS`]) reach
    /// the count the round is scored at.
    pub fn admit_production(&self, backend: &str) -> Result<(), UnderBudgetError> {
        let (largest, rest) = self.vks.split_last().expect("a key per group size");
        for vk in rest {
            let score = SoundnessCalculator::calculate_from_vk(vk);
            if score.total_bits < PRODUCTION_SECURITY_BITS {
                return Err(UnderBudgetError {
                    machine: format!("group ({} tables)", vk.inner.per_air.len()),
                    bits: score.total_bits,
                    pre_hash: format!("{:?}", vk.pre_hash),
                    shape: VkShape::from_vk(vk),
                });
            }
        }
        admit_production_vk("group", backend, largest)?;

        let params = &largest.inner.params;
        assert!(
            MAX_DIRECTION_ROWS < u64::from(params.logup.max_interaction_count),
            "the root admits {MAX_DIRECTION_ROWS} rows in one direction, which the global \
             LogUp's round is not scored for"
        );
        let bits = SoundnessCalculator::global_logup_bits_for::<Sc>(params);
        if bits < PRODUCTION_SECURITY_BITS {
            return Err(UnderBudgetError {
                machine: "global LogUp round's group".into(),
                bits,
                pre_hash: format!("{:?}", largest.pre_hash),
                shape: VkShape::from_vk(largest),
            });
        }
        Ok(())
    }
}

/// The parameter digest: `H(TAG_PARAMS ‖ E ‖ H_G ‖ G ‖ H0_min ‖ H0_max ‖ V_1 ‖ … ‖ V_G)`.
///
/// `E` is the riscv machine's `SystemParams` in postcard, one field element per byte behind a
/// length element; `H_G` the Global table height; `G` the largest group; `H0_min..=H0_max` the
/// image tiers; `V_s` the vk pre-hash of the group machine for `s` tables. A challenge derived
/// over it is a challenge for exactly this operating point and these machines.
pub fn params_digest(riscv: &SystemParams, group_pre_hashes: &[Digest]) -> Digest {
    assert_eq!(group_pre_hashes.len(), MAX_GROUP_LEN);
    let encoded = postcard::to_allocvec(riscv).expect("SystemParams encodes");
    let tiers = image_log_heights(riscv);
    let mut preimage = vec![F::from_u32(TAG_PARAMS), F::from_usize(encoded.len())];
    preimage.extend(encoded.into_iter().map(F::from_u8));
    preimage.extend(
        [
            global_log_height(riscv),
            MAX_GROUP_LEN,
            *tiers.start(),
            *tiers.end(),
        ]
        .map(F::from_usize),
    );
    preimage.extend(group_pre_hashes.iter().flatten().copied());
    hash(&preimage)
}

/// The transcript the challenges come from, up to the proof of work.
fn challenge_transcript(
    params_digest: &Digest,
    vm_vk_digest: &Digest,
    chain_root: &Digest,
) -> impl FiatShamirTranscript<Sc> {
    let mut transcript = default_duplex_sponge();
    FiatShamirTranscript::<Sc>::observe(&mut transcript, F::from_u32(TAG_CHALLENGE));
    FiatShamirTranscript::<Sc>::observe_commit(&mut transcript, *params_digest);
    FiatShamirTranscript::<Sc>::observe_commit(&mut transcript, *vm_vk_digest);
    FiatShamirTranscript::<Sc>::observe_commit(&mut transcript, *chain_root);
    transcript
}

/// Derive a block's LogUp challenges: the proof-of-work witness and `(alpha, beta)`.
///
/// The transcript absorbs the parameter digest, the program's vk digest and the chain root, then
/// a witness that passes `pow_bits` of proof of work, and only then gives the challenges. With
/// the proof of work ahead of the challenges, trying another chain root (one table leaf changed)
/// costs the work again.
///
/// The witness is the least valid one in canonical order, so two provers of the same execution
/// publish the same values. The search takes the candidates a block at a time, in order, each
/// block across the threads.
pub fn derive_challenges(
    params_digest: &Digest,
    vm_vk_digest: &Digest,
    chain_root: &Digest,
    pow_bits: usize,
) -> (F, EF, EF) {
    const BLOCK: u32 = 1 << 16;
    let transcript = challenge_transcript(params_digest, vm_vk_digest, chain_root);
    let witness = (0..F::ORDER_U32)
        .step_by(BLOCK as usize)
        .find_map(|start| {
            (start..start.saturating_add(BLOCK).min(F::ORDER_U32))
                .into_par_iter()
                .filter(|&witness| {
                    transcript
                        .clone()
                        .check_witness(pow_bits, F::from_u32(witness))
                })
                .min()
        })
        .map(F::from_u32)
        .expect("a proof-of-work witness exists");
    let (alpha, beta) =
        check_challenges(params_digest, vm_vk_digest, chain_root, pow_bits, witness)
            .expect("the witness was just found valid");
    (witness, alpha, beta)
}

/// The challenges behind `witness`, or `None` when the witness fails the proof of work.
pub fn check_challenges(
    params_digest: &Digest,
    vm_vk_digest: &Digest,
    chain_root: &Digest,
    pow_bits: usize,
    witness: F,
) -> Option<(EF, EF)> {
    let mut transcript = challenge_transcript(params_digest, vm_vk_digest, chain_root);
    if !transcript.check_witness(pow_bits, witness) {
        return None;
    }
    let alpha = transcript.sample_ext();
    let beta = transcript.sample_ext();
    Some((alpha, beta))
}

/// The sum of two fractions, unreduced: what a parent makes of two children's sums.
pub fn add_fractions((p1, q1): (EF, EF), (p2, q2): (EF, EF)) -> (EF, EF) {
    (p1 * q2 + p2 * q1, q1 * q2)
}

/// A chunk's share of the real-row bound, in units of `2^LOG_COUNT_UNIT` rows.
///
/// `senders` lists, for each AIR of the chunk that sends on the Global bus, how many sends and
/// how many receives one of its rows makes and the AIR's log height. The chunk's table then has
/// at most `sum of sends * height` send rows and as many receive rows by the same count, and no
/// more than the table's own height of either. The share is the larger of the two, rounded up to
/// the unit.
pub fn chunk_count(
    global_log_height: usize,
    senders: impl IntoIterator<Item = (u64, u64, usize)>,
) -> u64 {
    let cap = 1u64 << global_log_height;
    // A height no trace has saturates: the count is then the table's own height, and a caller
    // that reads heights off proofs it has not verified gets a number, not an overflow.
    let rows = |per_row: u64, log_height: usize| {
        if log_height < 32 {
            per_row << log_height
        } else {
            u64::MAX
        }
    };
    let (sends, receives) = senders.into_iter().fold(
        (0u64, 0u64),
        |(s, r), (per_row_s, per_row_r, log_height)| {
            (
                s.saturating_add(rows(per_row_s, log_height)),
                r.saturating_add(rows(per_row_r, log_height)),
            )
        },
    );
    sends
        .min(cap)
        .max(receives.min(cap))
        .div_ceil(1 << LOG_COUNT_UNIT)
}

/// The most a block's chunk shares may add up to: `floor((p - 1 - 2^22) / 2^LOG_COUNT_UNIT)`,
/// which is 2,076,672.
///
/// Within it, the block's send rows (the image table's are all sends, and no image table is
/// taller than `2^22`) and its receive rows each number less than `p`, so a multiplicity that
/// is zero in the field is zero.
///
/// One number at every operating point. A lower stacked height has smaller image tiers and
/// would bear a slightly higher limit; the root programs of the recursion are built from a
/// child's layout, without the riscv parameters, so they all take this one.
pub const MAX_COUNT: u64 =
    (F::ORDER_U32 as u64 - 1 - (1 << MAX_GLOBAL_LOG_HEIGHT)) >> LOG_COUNT_UNIT;

/// The most rows a block within [`MAX_COUNT`] has in one direction: the chunks' rows the count
/// bounds, and the tallest image table on top of the sends. It is below the field's order, and
/// the production gate holds it below the count the global LogUp's round is scored at
/// ([`GroupMachines::admit_production`]).
pub const MAX_DIRECTION_ROWS: u64 = (MAX_COUNT << LOG_COUNT_UNIT) + (1 << MAX_GLOBAL_LOG_HEIGHT);
const _: () = assert!(MAX_DIRECTION_ROWS < F::ORDER_U32 as u64);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::riscv_params_with_128_bits_security, test_utils::test_system_params_small,
    };

    fn digest(seed: u32) -> Digest {
        std::array::from_fn(|i| F::from_u32(seed + i as u32))
    }

    #[test]
    fn heights_follow_the_stacked_height() {
        let production = riscv_params_with_128_bits_security(23);
        assert_eq!(global_log_height(&production), 22);
        assert_eq!(image_log_heights(&production), 16..=22);
        assert_eq!(MAX_COUNT, 2_076_672);
        assert_eq!(MAX_DIRECTION_ROWS, u64::from(F::ORDER_U32) - 1);
        let small = test_system_params_small(2, 16, 3);
        assert_eq!(global_log_height(&small), 17);
        assert_eq!(image_log_heights(&small), 16..=18);
        let smallest = test_system_params_small(2, 14, 3);
        assert_eq!(global_log_height(&smallest), 15);
        assert_eq!(image_log_heights(&smallest), 16..=16);
        assert_eq!(image_log_height(&production, 377_000), Some(19));
        assert_eq!(image_log_height(&production, 1 << 19), Some(19));
        assert_eq!(image_log_height(&production, (1 << 22) + 1), None);
        assert_eq!(image_log_height(&production, 0), Some(16));
    }

    #[test]
    #[should_panic(expected = "stacked height of at least 2^16")]
    fn a_stacked_height_below_two_to_the_sixteen_is_refused() {
        global_log_height(&test_system_params_small(2, 13, 3));
    }

    /// The chain separates order, index, layout and commitment.
    #[test]
    fn the_chain_binds_the_ordered_commitments() {
        let (a, b) = (digest(1), digest(100));
        let root = chain_root(22, [a, b]);
        assert_eq!(
            root,
            chain_step(&chain_step(&chain_iv(), 1, 22, &a), 2, 22, &b)
        );
        assert_ne!(root, chain_root(22, [b, a]));
        assert_ne!(root, chain_root(21, [a, b]));
        assert_ne!(root, chain_root(22, [a]));
        assert_ne!(chain_root(22, []), chain_root(22, [a]));
        assert_eq!(chain_root(22, []), chain_iv());
    }

    /// The witness is the least valid one, and the challenges depend on every input.
    #[test]
    fn challenges_are_deterministic_and_bound_to_their_inputs() {
        let (pd, vd, root) = (digest(1), digest(100), digest(1000));
        let bits = 6;
        let (witness, alpha, beta) = derive_challenges(&pd, &vd, &root, bits);
        assert_eq!(
            derive_challenges(&pd, &vd, &root, bits),
            (witness, alpha, beta)
        );
        assert_eq!(
            check_challenges(&pd, &vd, &root, bits, witness),
            Some((alpha, beta))
        );
        for smaller in 0..witness.as_canonical_u32() {
            assert!(check_challenges(&pd, &vd, &root, bits, F::from_u32(smaller)).is_none());
        }
        assert_ne!(alpha, beta);
        for (pd2, vd2, root2) in [
            (digest(2), vd, root),
            (pd, digest(101), root),
            (pd, vd, digest(1001)),
        ] {
            let (_, alpha2, beta2) = derive_challenges(&pd2, &vd2, &root2, bits);
            assert_ne!((alpha, beta), (alpha2, beta2));
        }
    }

    /// The search by blocks finds the witness a scan in order finds, past the first block too.
    #[test]
    fn the_witness_search_agrees_with_a_scan_in_order() {
        let (pd, vd, bits) = (digest(1), digest(100), 18);
        let mut past_the_first_block = 0;
        for seed in 1000..1003 {
            let root = digest(seed);
            let transcript = challenge_transcript(&pd, &vd, &root);
            let scanned = (0..F::ORDER_U32)
                .map(F::from_u32)
                .find(|&witness| transcript.clone().check_witness(bits, witness))
                .unwrap();
            assert_eq!(derive_challenges(&pd, &vd, &root, bits).0, scanned);
            past_the_first_block += usize::from(scanned.as_canonical_u32() >= 1 << 16);
        }
        assert!(
            past_the_first_block > 0,
            "no witness of these roots lies past the search's first block"
        );
    }

    /// The production gate scores the block's round too: with no proof of work ahead of the
    /// challenges every group key keeps its score, and the round is under the budget.
    #[test]
    fn the_production_gate_scores_the_blocks_round() {
        let production = riscv_params_with_128_bits_security(23);
        GroupMachines::new(&production)
            .admit_production("reference")
            .expect("the production parameters pass");

        let mut no_pow = production;
        no_pow.logup.pow_bits = 0;
        let refused = GroupMachines::new(&no_pow)
            .admit_production("reference")
            .unwrap_err();
        assert!(refused.machine.contains("global LogUp round"));
        assert!(refused.bits < PRODUCTION_SECURITY_BITS);
    }

    /// The round is scored at `max_interaction_count` rows a direction: parameters that count
    /// fewer than the root admits do not pass the gate.
    #[test]
    #[should_panic(expected = "is not scored for")]
    fn the_production_gate_ties_the_row_limit_to_the_scored_count() {
        let mut params = riscv_params_with_128_bits_security(23);
        params.logup.max_interaction_count = 1 << 30;
        let _ = GroupMachines::new(&params).admit_production("reference");
    }

    /// The parameter digest moves with the operating point and with a group key.
    #[test]
    fn the_params_digest_binds_the_operating_point() {
        let riscv = test_system_params_small(2, 16, 3);
        let machines = GroupMachines::new(&riscv);
        assert!(machines.pk(0).is_none());
        assert!(machines.pk(MAX_GROUP_LEN + 1).is_none());
        let pre_hashes: Vec<Digest> = (1..=MAX_GROUP_LEN)
            .map(|s| machines.pk(s).unwrap().vk_pre_hash)
            .collect();
        assert_eq!(machines.params_digest(), params_digest(&riscv, &pre_hashes));
        let other = test_system_params_small(2, 17, 3);
        assert_ne!(
            machines.params_digest(),
            GroupMachines::new(&other).params_digest()
        );
        let mut tampered = pre_hashes.clone();
        tampered[3][0] += F::ONE;
        assert_ne!(machines.params_digest(), params_digest(&riscv, &tampered));
    }

    #[test]
    fn chunk_shares_follow_the_sender_heights() {
        // A CPU chunk: MemoryLocal (4 sends, 4 receives per row) at 2^18, SyscallRiscv (1 send)
        // at 2^16.
        assert_eq!(chunk_count(22, [(4, 4, 18), (1, 0, 16)]), 1_088);
        // The table height caps either direction.
        assert_eq!(chunk_count(22, [(4, 4, 21)]), 4_096);
        assert_eq!(chunk_count(22, [(0, 1, 22)]), 4_096);
        assert_eq!(chunk_count(22, [(1, 0, 4)]), 1);
        assert_eq!(chunk_count(22, []), 0);
    }

    #[test]
    fn fractions_add() {
        let ef = |v: u32| EF::from(F::from_u32(v));
        let sum = add_fractions((ef(1), ef(2)), (ef(1), ef(3)));
        assert_eq!(sum, (ef(5), ef(6)));
        let cancelled = add_fractions((ef(7), ef(4)), (-ef(7), ef(4)));
        assert_eq!(cancelled.0, EF::ZERO);
        assert_ne!(cancelled.1, EF::ZERO);
    }
}
