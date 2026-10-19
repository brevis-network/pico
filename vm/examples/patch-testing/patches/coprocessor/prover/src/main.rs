use common::{hex, pico_vm, run_proof};
use pico_mle_core::{
    p3_field::{PrimeCharacteristicRing, PrimeField32},
    p3_symmetric::Permutation,
};
use pico_vm::{
    machine::field::FieldSpecificPoseidon2Config, mle::machine::riscv::Kb,
    primitives::consts::PERMUTATION_WIDTH,
};
use sha2::{Digest, Sha256};

/// `receipts.rs`'s `MAX_RECEIPT`: the guest's 64 copies of one receipt, and its leaf count.
const RECEIPTS: usize = 64;

/// The swap amount in each receipt's first field.
const SWAP_AMOUNT: u128 = 0x0001_0d12_bdb1_67e2_01e0;

fn main() {
    run_proof!([POSEIDON2_PERMUTE], commits = expected_commits());
}

/// What reaches the public values: `commit_coprocessor_bytes` writes the receipts' Merkle root and
/// the three dummy commitments, then `syscall_halt` appends the SHA-256 of the coprocessor output
/// stream. `Builder::new()` leaves `chain_id` at 0, which has no dummy of its own, so all three
/// are the zero commitment.
fn expected_commits() -> Vec<u8> {
    let perm = <Kb as FieldSpecificPoseidon2Config>::permutation();
    let leaf = hash(&perm, &receipt_elements());
    let mut level = vec![leaf; RECEIPTS];
    while level.len() > 1 {
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| hash(&perm, &pair.concat()))
            .collect();
    }

    let mut commits: Vec<u8> = level[0]
        .iter()
        .flat_map(|f| f.as_canonical_u32().to_be_bytes())
        .collect();
    commits.extend([0u8; 3 * 32]);

    // The coprocessor output is the guest's `U256` sum of the swap amounts, big-endian.
    commits.extend(Sha256::digest(u256(RECEIPTS as u128 * SWAP_AMOUNT)));
    commits
}

/// `ReceiptData::commit_inputs`'s elements for the receipt `receipts.rs` builds: every byte string
/// packed big-endian three bytes to an element, the last element taking what is left.
fn receipt_elements() -> Vec<Kb> {
    let pool = hex("88e6a0c2ddd26feeb64f039a2c41296fcb3f5640");
    let swap_topic = hex("c42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67");
    let amount = u256(SWAP_AMOUNT);
    let user = hex("0000000000000000000000006a000f20005980200259b80c5102003040001068");

    let mut elements = vec![21_756_846];
    elements.extend(packed(&u256(1_494_611_587)));
    elements.extend([1_738_475_315, 1]);
    // (is_topic, field_index, value): the swap field, then the user field three times.
    let fields = [
        (0, 1, &amount[..]),
        (1, 2, &user),
        (1, 2, &user),
        (1, 2, &user),
    ];
    for (is_topic, field_index, value) in fields {
        elements.extend(packed(&pool));
        elements.extend(packed(&swap_topic[..6]));
        elements.extend([17, is_topic, field_index]);
        elements.extend(packed(value));
    }
    elements.into_iter().map(Kb::from_u32).collect()
}

fn packed(bytes: &[u8]) -> impl Iterator<Item = u32> + '_ {
    bytes
        .chunks(3)
        .map(|chunk| chunk.iter().fold(0, |acc, &b| (acc << 8) | u32::from(b)))
}

fn u256(value: u128) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[16..].copy_from_slice(&value.to_be_bytes());
    bytes
}

/// `coprocessor_sdk::poseidon2_hash::Poseidon2::<8>::hash`, which is not the machine's sponge: 15
/// elements absorbed per permutation by addition, one `1` of padding in the next free lane, the
/// first eight elements out.
fn hash(perm: &impl Permutation<[Kb; PERMUTATION_WIDTH]>, inputs: &[Kb]) -> [Kb; 8] {
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
    core::array::from_fn(|i| state[i])
}
