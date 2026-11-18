//! A proof's WHIR Merkle openings as one multiproof per tree, instead of one full path per query.
//!
//! [`Encode`] writes every query's authentication path in full, so siblings shared between queries
//! are written more than once, and a sibling that another query's path computes is written at
//! all. On the compress proof that is 3,678 digests, about 40% of its bytes. This module writes the
//! same proof with each Merkle tree's openings as a multiproof: the query indices, and only the
//! siblings no queried path yields. It is a wire form only. [`decode_multiproof`] rebuilds the
//! flat paths, so the verifier, the recursion circuits and every key are unchanged, and a proof
//! that round-trips is the same value [`Encode`] would have written.
//!
//! # Format
//!
//! `MULTIPROOF_VERSION` (u32) | the initial round's Merkle depth (u32; each later round's trees are
//! one level shallower than the round before) | the proof's canonical encoding with every Merkle
//! path emptied |
//! per WHIR round, its query indices (u32 each, as many as the round has openings) | per tree, in
//! proof order (the initial round's commitments, then one codeword tree per later round), the
//! siblings no queried path computes, in the order [`prune_tree`] emits them.
//!
//! Nothing here is trusted. The indices and siblings only rebuild candidate paths; the verifier
//! re-derives every index from the transcript and checks every path against its root, so a wrong
//! index or sibling is a rejected proof, never an accepted one.

use std::{
    collections::BTreeMap,
    io::{Error, ErrorKind, Read, Result, Write},
};

use p3_field::BasedVectorSpace;

use crate::{
    codec::{DecodableConfig, Decode, EncodableConfig, Encode},
    config::hasher::MerkleHasher,
    proof::{MerkleProof, Proof},
};

/// Version of the multiproof wire form, ahead of the proof's own `CODEC_VERSION`.
pub const MULTIPROOF_VERSION: u32 = 1;

/// Merkle depth bound on decode. Query indices are u32, so no tree is deeper; anti-DoS only.
const MAX_DEPTH: usize = 32;

fn invalid(msg: impl Into<String>) -> Error {
    Error::new(ErrorKind::InvalidData, msg.into())
}

/// Write `proof` in the multiproof form. `query_indices[r]` are WHIR round `r`'s query indices, as
/// the verifier samples them ([`crate::verifier::TranscriptWalk::whir_query_indices`]).
///
/// Errors, writing nothing useful, if the indices do not fit the proof: a round count or query
/// count that differs from the proof's openings, an index past its tree, or a path of the wrong
/// depth. A proof that verifies with these indices always fits.
pub fn encode_multiproof<SC: EncodableConfig, W: Write>(
    proof: &Proof<SC>,
    query_indices: &[Vec<usize>],
    writer: &mut W,
) -> Result<()> {
    let whir = &proof.whir_proof;
    let trees = trees_of(proof, query_indices)?;
    // The initial round's depth, from the first path the proof has; 0 if it opens nothing.
    let depth0 = match (
        whir.initial_round_merkle_proofs
            .first()
            .and_then(|p| p.first()),
        whir.codeword_merkle_proofs.first().and_then(|p| p.first()),
    ) {
        (Some(path), _) => path.len(),
        (None, Some(path)) => path.len() + 1,
        (None, None) => 0,
    };

    let mut stripped = proof.clone();
    for paths in stripped
        .whir_proof
        .initial_round_merkle_proofs
        .iter_mut()
        .chain(stripped.whir_proof.codeword_merkle_proofs.iter_mut())
    {
        for path in paths {
            path.clear();
        }
    }

    MULTIPROOF_VERSION.encode(writer)?;
    depth0.encode(writer)?;
    stripped.encode(writer)?;
    for round in query_indices {
        for &index in round {
            u32::try_from(index)
                .map_err(|_| invalid("query index does not fit u32"))?
                .encode(writer)?;
        }
    }
    for (paths, round) in whir
        .initial_round_merkle_proofs
        .iter()
        .chain(&whir.codeword_merkle_proofs)
        .zip(trees)
    {
        let depth = depth0
            .checked_sub(round)
            .ok_or_else(|| invalid("Merkle depth underflow"))?;
        for digest in prune_tree(paths, &query_indices[round], depth)? {
            SC::encode_digest(&digest, writer)?;
        }
    }
    Ok(())
}

/// Read a proof written by [`encode_multiproof`] and rebuild its flat Merkle paths with `hasher`,
/// the config's own ([`crate::StarkProtocolConfig::hasher`]): the leaf and node hashes are the
/// verifier's.
///
/// The paths are rebuilt, not checked. Verify the result as any decoded proof.
pub fn decode_multiproof<SC: DecodableConfig, R: Read>(
    hasher: &SC::Hasher,
    reader: &mut R,
) -> Result<Proof<SC>> {
    let version = u32::decode(reader)?;
    if version != MULTIPROOF_VERSION {
        return Err(invalid(format!(
            "multiproof version {version}, expected {MULTIPROOF_VERSION}"
        )));
    }
    let depth0 = usize::decode(reader)?;
    if depth0 > MAX_DEPTH {
        return Err(invalid(format!("Merkle depth {depth0} over {MAX_DEPTH}")));
    }
    let mut proof = Proof::<SC>::decode(reader)?;
    let whir = &proof.whir_proof;
    if whir
        .initial_round_merkle_proofs
        .iter()
        .chain(&whir.codeword_merkle_proofs)
        .flatten()
        .any(|path| !path.is_empty())
    {
        return Err(invalid("multiproof body carries a Merkle path"));
    }

    // Query counts per round, from the openings the proof carries.
    let mut counts = vec![whir.initial_round_opened_rows.first().map_or(0, Vec::len)];
    counts.extend(whir.codeword_opened_values.iter().map(Vec::len));
    let mut query_indices = Vec::with_capacity(counts.len());
    for &n in &counts {
        let mut round = Vec::with_capacity(n.min(1 << 16));
        for _ in 0..n {
            round.push(u32::decode(reader)? as usize);
        }
        query_indices.push(round);
    }

    let leaves = leaf_digests::<SC>(hasher, &proof)?;
    let trees = trees_of(&proof, &query_indices)?;
    let mut rebuilt = Vec::with_capacity(trees.len());
    for (t, &round) in trees.iter().enumerate() {
        let depth = depth0
            .checked_sub(round)
            .ok_or_else(|| invalid("Merkle depth underflow"))?;
        let need = sibling_count(&query_indices[round], depth)?;
        let mut pruned = Vec::with_capacity(need.min(1 << 16));
        for _ in 0..need {
            pruned.push(SC::decode_digest(reader)?);
        }
        rebuilt.push(expand_tree(
            hasher,
            &leaves[t],
            &query_indices[round],
            depth,
            pruned,
        )?);
    }

    let mut rebuilt = rebuilt.into_iter();
    let whir = &mut proof.whir_proof;
    for paths in whir
        .initial_round_merkle_proofs
        .iter_mut()
        .chain(whir.codeword_merkle_proofs.iter_mut())
    {
        *paths = rebuilt.next().expect("one rebuilt tree per tree");
    }
    Ok(proof)
}

/// The WHIR round of each Merkle tree, in proof order: round 0 for each initial commitment, then
/// round `r` for the codeword tree its queries open. Checks the indices against the openings.
fn trees_of<SC: crate::StarkProtocolConfig>(
    proof: &Proof<SC>,
    query_indices: &[Vec<usize>],
) -> Result<Vec<usize>> {
    let whir = &proof.whir_proof;
    if query_indices.len() != whir.codeword_merkle_proofs.len() + 1
        || whir.codeword_opened_values.len() != whir.codeword_merkle_proofs.len()
    {
        return Err(invalid("WHIR round count does not match the query indices"));
    }
    let mut trees = Vec::new();
    for (rows, paths) in whir
        .initial_round_opened_rows
        .iter()
        .zip(&whir.initial_round_merkle_proofs)
    {
        if rows.len() != query_indices[0].len() || paths.len() != query_indices[0].len() {
            return Err(invalid("initial-round query count does not match"));
        }
        trees.push(0);
    }
    if whir.initial_round_opened_rows.len() != whir.initial_round_merkle_proofs.len() {
        return Err(invalid("initial-round commitment count does not match"));
    }
    for (r, (values, paths)) in whir
        .codeword_opened_values
        .iter()
        .zip(&whir.codeword_merkle_proofs)
        .enumerate()
    {
        if values.len() != query_indices[r + 1].len() || paths.len() != query_indices[r + 1].len() {
            return Err(invalid("codeword query count does not match"));
        }
        trees.push(r + 1);
    }
    Ok(trees)
}

/// One leaf digest per query per tree, in proof order, computed as the verifier computes it: each
/// opened row (or extension value, as its basis coefficients) hashed, then the `2^k` row hashes
/// compressed pairwise.
fn leaf_digests<SC: crate::StarkProtocolConfig>(
    hasher: &SC::Hasher,
    proof: &Proof<SC>,
) -> Result<Vec<Vec<SC::Digest>>> {
    fn fold<H: MerkleHasher>(hasher: &H, hashes: Vec<H::Digest>) -> Result<H::Digest> {
        if !hashes.len().is_power_of_two() {
            return Err(invalid("opened rows per query is not a power of two"));
        }
        Ok(hasher.tree_compress(hashes))
    }
    let whir = &proof.whir_proof;
    let mut out = Vec::new();
    for commit in &whir.initial_round_opened_rows {
        out.push(
            commit
                .iter()
                .map(|rows| fold(hasher, rows.iter().map(|r| hasher.hash_slice(r)).collect()))
                .collect::<Result<Vec<_>>>()?,
        );
    }
    for round in &whir.codeword_opened_values {
        out.push(
            round
                .iter()
                .map(|vals| {
                    fold(
                        hasher,
                        vals.iter()
                            .map(|v| hasher.hash_slice(v.as_basis_coefficients_slice()))
                            .collect(),
                    )
                })
                .collect::<Result<Vec<_>>>()?,
        );
    }
    Ok(out)
}

/// The siblings of one tree's queried paths that no queried path computes, bottom level first and
/// by node position within a level. `paths[q]` is query `q`'s flat path, `indices[q]` its leaf.
fn prune_tree<D: Copy>(
    paths: &[MerkleProof<D>],
    indices: &[usize],
    depth: usize,
) -> Result<Vec<D>> {
    if paths.len() != indices.len() || paths.iter().any(|p| p.len() != depth) {
        return Err(invalid(
            "Merkle paths do not match the query count or depth",
        ));
    }
    check_indices(indices, depth)?;
    // Each known node, with one query whose path runs through it.
    let mut level: BTreeMap<usize, usize> = BTreeMap::new();
    for (q, &i) in indices.iter().enumerate() {
        level.entry(i).or_insert(q);
    }
    let mut out = Vec::new();
    // `l` picks a level out of each path the inner loop visits: clippy's suggested iterator over
    // `paths[q]` needs the inner loop's `q`.
    #[allow(clippy::needless_range_loop)]
    for l in 0..depth {
        for (&node, &q) in &level {
            if !level.contains_key(&(node ^ 1)) {
                out.push(paths[q][l]);
            }
        }
        let mut next = BTreeMap::new();
        for (&node, &q) in &level {
            next.entry(node >> 1).or_insert(q);
        }
        level = next;
    }
    Ok(out)
}

/// How many siblings [`prune_tree`] emits for `indices` in a tree of `depth`: it follows from the
/// indices alone.
pub(crate) fn sibling_count(indices: &[usize], depth: usize) -> Result<usize> {
    check_indices(indices, depth)?;
    let mut level: Vec<usize> = indices.to_vec();
    level.sort_unstable();
    level.dedup();
    let mut count = 0;
    for _ in 0..depth {
        count += level
            .iter()
            .filter(|&&n| level.binary_search(&(n ^ 1)).is_err())
            .count();
        level.iter_mut().for_each(|n| *n >>= 1);
        level.dedup();
    }
    Ok(count)
}

/// Rebuild one tree's flat paths from its query leaves and the pruned siblings, in
/// [`prune_tree`]'s order. Queries sharing an index share the first one's leaf.
fn expand_tree<H: MerkleHasher>(
    hasher: &H,
    leaves: &[H::Digest],
    indices: &[usize],
    depth: usize,
    pruned: Vec<H::Digest>,
) -> Result<Vec<MerkleProof<H::Digest>>> {
    if leaves.len() != indices.len() {
        return Err(invalid("leaf count does not match the query count"));
    }
    check_indices(indices, depth)?;
    let mut pruned = pruned.into_iter();
    let mut level: BTreeMap<usize, H::Digest> = BTreeMap::new();
    for (&i, &leaf) in indices.iter().zip(leaves) {
        level.entry(i).or_insert(leaf);
    }
    let mut siblings: Vec<BTreeMap<usize, H::Digest>> = Vec::with_capacity(depth);
    for _ in 0..depth {
        let mut at = BTreeMap::new();
        for &node in level.keys() {
            let sibling = match level.get(&(node ^ 1)) {
                Some(&d) => d,
                None => pruned
                    .next()
                    .ok_or_else(|| invalid("multiproof is short of siblings"))?,
            };
            at.insert(node, sibling);
        }
        let mut next = BTreeMap::new();
        for (&node, &digest) in &level {
            let sibling = at[&node];
            let parent = if node & 1 == 0 {
                hasher.compress(digest, sibling)
            } else {
                hasher.compress(sibling, digest)
            };
            next.entry(node >> 1).or_insert(parent);
        }
        siblings.push(at);
        level = next;
    }
    if pruned.next().is_some() {
        return Err(invalid("multiproof has siblings left over"));
    }
    Ok(indices
        .iter()
        .map(|&i| (0..depth).map(|l| siblings[l][&(i >> l)]).collect())
        .collect())
}

fn check_indices(indices: &[usize], depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(invalid(format!("Merkle depth {depth} over {MAX_DEPTH}")));
    }
    if indices.iter().any(|&i| (i as u64) >> depth != 0) {
        return Err(invalid("query index past its tree"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::koala_bear_poseidon2::{DuplexSpongeRecorder, KoalaBearPoseidon2Config},
        engine::koala_bear_poseidon2::KoalaBearPoseidon2RefEngine,
        keygen::types::MultiStarkVerifyingKey,
        test_utils::{
            test_system_params_small, CachedFixture11, InteractionsFixture11, TestFixture,
        },
        verifier::{replay_transcript, verify},
        StarkEngine, StarkProtocolConfig,
    };

    type Sc = KoalaBearPoseidon2Config;
    type RefEngine = KoalaBearPoseidon2RefEngine<DuplexSpongeRecorder>;

    fn proved<Fx: TestFixture<Sc>>(
        fixture: Fx,
    ) -> (RefEngine, MultiStarkVerifyingKey<Sc>, Proof<Sc>) {
        let engine = RefEngine::new(test_system_params_small(2, 5, 3));
        let (pk, vk) = fixture.keygen(&engine);
        let proof = fixture.prove(&engine, &pk);
        (engine, vk, proof)
    }

    fn indices(
        engine: &RefEngine,
        vk: &MultiStarkVerifyingKey<Sc>,
        proof: &Proof<Sc>,
    ) -> Vec<Vec<usize>> {
        replay_transcript(engine.config(), vk, proof, &mut engine.initial_transcript())
            .expect("replay completes")
            .whir_query_indices()
            .to_vec()
    }

    fn encoded(proof: &Proof<Sc>, indices: &[Vec<usize>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        encode_multiproof(proof, indices, &mut bytes).expect("encodes");
        bytes
    }

    fn decoded(engine: &RefEngine, bytes: &[u8]) -> Result<Proof<Sc>> {
        let mut reader = std::io::Cursor::new(bytes);
        let proof = decode_multiproof::<Sc, _>(engine.config().hasher(), &mut reader)?;
        assert_eq!(reader.position(), bytes.len() as u64, "trailing bytes");
        Ok(proof)
    }

    /// The rebuilt proof is the original value, it verifies, and the multiproof is smaller than
    /// the canonical encoding. Several commitments, so the initial round opens several trees.
    #[test]
    fn round_trips_and_shrinks() {
        for (engine, vk, proof) in [
            proved(CachedFixture11::new(Sc::default_from_params(
                test_system_params_small(2, 5, 3),
            ))),
            proved(InteractionsFixture11),
        ] {
            let idx = indices(&engine, &vk, &proof);
            assert!(idx.iter().any(|r| !r.is_empty()), "vacuous: no queries");
            let bytes = encoded(&proof, &idx);
            let back = decoded(&engine, &bytes).expect("decodes");
            assert_eq!(back, proof, "the multiproof rebuilds the same proof");
            verify(
                engine.config(),
                &vk,
                &back,
                &mut engine.initial_transcript(),
            )
            .expect("the rebuilt proof verifies");
            let flat = proof.encode_to_vec().unwrap().len();
            assert!(
                bytes.len() < flat,
                "multiproof {} B, canonical {flat} B",
                bytes.len()
            );
        }
    }

    /// The indices the walk returns are the ones the verifier samples: with any one changed, the
    /// rebuilt proof no longer verifies (or the encoder refuses it outright).
    #[test]
    fn wrong_indices_do_not_verify() {
        let (engine, vk, proof) = proved(InteractionsFixture11);
        let idx = indices(&engine, &vk, &proof);
        for r in 0..idx.len() {
            if idx[r].is_empty() {
                continue;
            }
            let mut bad = idx.clone();
            bad[r][0] ^= 1;
            let mut bytes = Vec::new();
            if encode_multiproof(&proof, &bad, &mut bytes).is_err() {
                continue;
            }
            if let Ok(back) = decoded(&engine, &bytes) {
                assert!(
                    verify(
                        engine.config(),
                        &vk,
                        &back,
                        &mut engine.initial_transcript()
                    )
                    .is_err(),
                    "round {r}: a proof rebuilt under a wrong index verified"
                );
            }
        }
    }

    /// A flipped byte anywhere in the sibling section is caught by the verifier, never a panic in
    /// the decoder; truncation and trailing bytes are decode errors.
    #[test]
    fn tampered_bytes_are_rejected() {
        let (engine, vk, proof) = proved(InteractionsFixture11);
        let bytes = encoded(&proof, &indices(&engine, &vk, &proof));
        let digest_bytes = 4 * 8;
        let tail = bytes.len() - digest_bytes;
        let mut flipped = bytes.clone();
        flipped[tail] ^= 1;
        let back = decoded(&engine, &flipped).expect("a flipped sibling still decodes");
        assert!(verify(
            engine.config(),
            &vk,
            &back,
            &mut engine.initial_transcript()
        )
        .is_err());
        assert!(decoded(&engine, &bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        let mut reader = std::io::Cursor::new(&longer[..]);
        decode_multiproof::<Sc, _>(engine.config().hasher(), &mut reader).expect("decodes");
        assert_ne!(reader.position(), longer.len() as u64);
        let mut v2 = bytes.clone();
        v2[0] = 2;
        assert!(decoded(&engine, &v2).is_err());
    }

    /// The pruned sibling count is the shared-path count: two queries at sibling leaves need no
    /// leaf-level sibling, and paths agree above the node where they meet.
    #[test]
    fn sibling_count_by_hand() {
        assert_eq!(sibling_count(&[0], 3).unwrap(), 3);
        assert_eq!(sibling_count(&[0, 1], 3).unwrap(), 2);
        assert_eq!(sibling_count(&[0, 0], 3).unwrap(), 3);
        assert_eq!(sibling_count(&[0, 7], 3).unwrap(), 4);
        assert_eq!(sibling_count(&[0, 1, 2, 3, 4, 5, 6, 7], 3).unwrap(), 0);
        assert!(sibling_count(&[8], 3).is_err());
    }
}
