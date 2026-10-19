use common::{pico_vm, run_proof};
use pico_mle_core::{
    p3_field::{PrimeCharacteristicRing, PrimeField32},
    p3_symmetric::Permutation,
};
use pico_vm::{
    machine::field::FieldSpecificPoseidon2Config,
    mle::machine::riscv::Kb,
    primitives::{consts::PERMUTATION_WIDTH, Poseidon2HashField},
};

const ROUNDS: u32 = 100;

/// The guest's list, repeated, as `sdk/prover/src/tests/poseidon2.rs` also repeats it. Change the
/// three together.
const DIGEST_LENGTHS: [u32; 3] = [0, 8, 20];

fn main() {
    run_proof!(
        [POSEIDON2_PERMUTE],
        commits = expected_commits(ROUNDS),
        ROUNDS
    );
}

/// The guest's commits rebuilt with the machine's host Poseidon2: the loop's `u32`, then each
/// digest's eight words, bincode's fixed little-endian words with no length prefix.
fn expected_commits(rounds: u32) -> Vec<u8> {
    let perm = <Kb as FieldSpecificPoseidon2Config>::permutation();
    let mut inputs = [Kb::ONE; 32];
    for _ in 0..rounds {
        let result = hash_many(&perm, &inputs);
        inputs.fill(result);
    }

    let mut commits = inputs[0].as_canonical_u32().to_le_bytes().to_vec();
    for len in DIGEST_LENGTHS {
        let digest = Kb::poseidon2_hash_iter((1..=len).map(Kb::from_u32).collect());
        commits.extend(
            digest
                .iter()
                .flat_map(|f| f.as_canonical_u32().to_le_bytes()),
        );
    }
    commits
}

/// `pico_sdk::poseidon2_hash::Poseidon2::hash_many`, the guest's loop hash, which is not the
/// machine's sponge: 15 elements absorbed per permutation by addition, one `1` of padding in the
/// next free lane, the first element out.
fn hash_many(perm: &impl Permutation<[Kb; PERMUTATION_WIDTH]>, inputs: &[Kb]) -> Kb {
    let mut state = [Kb::ZERO; PERMUTATION_WIDTH];
    let mut lane = 0;
    for &x in inputs {
        state[lane] += x;
        lane += 1;
        if lane == 15 {
            perm.permute_mut(&mut state);
            lane = 0;
        }
    }
    state[lane] += Kb::ONE;
    perm.permute_mut(&mut state);
    state[0]
}
