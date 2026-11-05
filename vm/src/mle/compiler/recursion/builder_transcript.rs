//! `Builder` Fiat–Shamir transcript and Poseidon2 hashing: the duplex sponge, absorb/
//! squeeze/observe/sample, witness grinding checks, and Merkle-path verification.

use super::*;

impl<F: PrimeField32 + TwoAdicField + FieldSepticCurve> Builder<F> {
    /// Reset the Fiat-Shamir sponge to its zero state (for verifying N independent proofs).
    pub(super) fn reset_sponge(&mut self) {
        self.sponge = [self.addr_zero; WIDTH];
        self.lane_fresh = [false; WIDTH];
        self.sponge_blocks = [self.addr_zero; PERM_BLOCKS];
        self.sponge_unpacked = [None; PERM_BLOCKS];
        self.absorb_idx = 0;
        self.sample_idx = 0;
    }

    /// Emit Poseidon2Packed over PERM_BLOCKS input block addresses; returns PERM_BLOCKS output
    /// blocks.
    pub(super) fn permute_packed(&mut self, in_blocks: [u32; PERM_BLOCKS]) -> [u32; PERM_BLOCKS] {
        let out: [u32; PERM_BLOCKS] = std::array::from_fn(|_| self.alloc());
        for b in in_blocks {
            self.mark_read(b);
        }
        self.instructions
            .push(Instruction::Poseidon2Packed(Box::new(
                Poseidon2PackedInstr {
                    input_addrs: in_blocks.map(|a| Address(F::from_u32(a))),
                    output_addrs: out.map(|a| Address(F::from_u32(a))),
                    mults: [F::ZERO; PERM_BLOCKS], // backfilled
                },
            )));
        out
    }

    /// Lane addresses of sponge output block j (unpacking lazily on first use).
    pub(super) fn sponge_lane(&mut self, lane: usize) -> u32 {
        let j = lane / PACK_LANES;
        if self.sponge_unpacked[j].is_none() {
            let outs = self.unpack_lanes(self.sponge_blocks[j]);
            self.sponge_unpacked[j] = Some(outs);
        }
        self.sponge_unpacked[j].unwrap()[lane % PACK_LANES]
    }

    /// Build the input block j for the next permutation from fresh lanes and/or
    /// the previous output block (packing only when the block is not intact).
    pub(super) fn build_sponge_block(&mut self, j: usize) -> u32 {
        let fresh: [bool; PACK_LANES] =
            std::array::from_fn(|k| self.lane_fresh[PACK_LANES * j + k]);
        if fresh.iter().all(|&f| !f) {
            return self.sponge_blocks[j];
        }
        let lanes: [u32; PACK_LANES] = std::array::from_fn(|k| {
            if fresh[k] {
                self.sponge[PACK_LANES * j + k]
            } else {
                self.sponge_lane(PACK_LANES * j + k)
            }
        });
        self.pack_block(lanes)
    }

    pub(super) fn do_permute(&mut self) {
        let in_blocks: [u32; PERM_BLOCKS] = std::array::from_fn(|j| self.build_sponge_block(j));
        let out = self.permute_packed(in_blocks);
        self.sponge_blocks = out;
        self.sponge_unpacked = [None; PERM_BLOCKS];
        self.lane_fresh = [false; WIDTH];
        self.absorb_idx = 0;
        self.sample_idx = RATE;
    }

    pub(super) fn absorb_f(&mut self, addr: u32) {
        self.sponge[self.absorb_idx] = addr;
        self.lane_fresh[self.absorb_idx] = true;
        self.absorb_idx += 1;
        if self.absorb_idx == RATE {
            self.do_permute();
        }
    }

    pub(super) fn squeeze_f(&mut self) -> u32 {
        if self.absorb_idx != 0 || self.sample_idx == 0 {
            self.do_permute();
        }
        self.sample_idx -= 1;
        self.sponge_lane(self.sample_idx)
    }

    // ─── Transcript operations ────────────────────────────────────────────────

    /// Observe 1 F value from witness_stream (Hint + absorb).
    pub(super) fn observe_f(&mut self) {
        let addr = self.hint_f();
        self.absorb_f(addr);
    }

    /// Observe 1 EF value and return its EF block address (for chip instructions).
    pub(super) fn observe_ef_for_chip(&mut self) -> u32 {
        let (ef_addr, f_addrs) = self.hint_ef_full();
        for a in f_addrs {
            self.absorb_f(a);
        }
        ef_addr
    }

    /// Observe 8 F constant addresses (Digest from VK, already in memory as Mem(Write)).
    pub(super) fn observe_const_digest(&mut self, addrs: [u32; DIGEST_SIZE]) {
        for a in addrs {
            self.absorb_f(a);
        }
    }

    /// Hint and absorb 8 F values (a digest), returning all 8 addresses.
    pub(super) fn observe_digest_addrs(&mut self) -> [u32; DIGEST_SIZE] {
        std::array::from_fn(|_| self.observe_f_for_chip())
    }

    /// Like observe_digest_for_whir, but also returns all 8 F addresses.
    pub(super) fn observe_digest_for_whir_addrs(&mut self) -> [u32; DIGEST_SIZE] {
        std::array::from_fn(|_| self.observe_f_for_chip())
    }

    /// Observe 1 F value from witness_stream and return its address (for chip instructions).
    pub(super) fn observe_f_for_chip(&mut self) -> u32 {
        let addr = self.hint_f();
        self.absorb_f(addr);
        addr
    }

    /// Squeeze 1 F from the sponge and RETURN the squeezed sponge-lane address. The returned
    /// lane is a Poseidon2-constrained value, i.e. exactly the Fiat-Shamir sample the host
    /// draws at this transcript position. Callers use the returned address to bind the sample
    /// into the circuit (e.g. via the ExpBitsLen chip). See the WHIR query loop and check_witness.
    pub(super) fn sample_f_capture(&mut self) -> u32 {
        self.squeeze_f()
    }

    /// Sample 1 EF from sponge and return its EF block address (for chip instructions).
    pub(super) fn sample_ef_for_chip(&mut self) -> u32 {
        let r: [u32; EXTENSION_DEGREE] = std::array::from_fn(|_| self.squeeze_f());
        self.pack_ef(r)
    }

    /// check_witness(bits, witness): if bits > 0, observe pow_witness then sample 1 F and enforce
    /// that the low `bits` bits of that sample are zero (proof-of-work grinding).
    ///
    /// Soundness fix (proof-of-work grinding was previously not enforced): the host verifier's
    /// `check_witness` observes the witness, draws a
    /// field sample, and requires its low `bits` bits to be zero. We capture the squeezed sample
    /// lane (a Poseidon2-constrained value = the FS sample), canonically decompose it via the
    /// ExpBitsLen chip, and assert `bit[j] == 0` for `j in 0..bits`. `num_bits = 0` is used
    /// because only the exported decomposition bits are needed (the chip's canonicality check runs
    /// regardless of `num_bits`, so the bits are the canonical decomposition); `result` is unused.
    /// The base is an arbitrary nonzero constant (2). Transcript-neutral: no new observe/absorb.
    pub(super) fn check_witness(&mut self, bits: usize) {
        if bits > 0 {
            self.observe_f();
            let sample_lane = self.sample_f_capture();
            let (_result, bit_addrs) = self.exp_bits_len(F::from_u32(2), sample_lane, 0);
            let az = self.addr_zero;
            for &bit in bit_addrs.iter().take(bits) {
                self.assert_f_eq(bit, az);
            }
        }
    }

    /// Hash `elems` (F addresses) with a fresh Poseidon2 sponge.
    /// Returns the digest as `DIGEST_BLOCKS` packed block addresses (`DIGEST_SIZE` felts).
    pub(super) fn hash_poseidon2_fresh(&mut self, elems: &[u32]) -> [u32; DIGEST_BLOCKS] {
        let az = self.addr_zero;
        let mut blocks: [u32; PERM_BLOCKS] = [az; PERM_BLOCKS];
        let mut unpacked: [Option<[u32; PACK_LANES]>; RATE_BLOCKS] = [None; RATE_BLOCKS];
        // absorb index within the current rate window
        let mut idx;
        let mut pending: [u32; RATE] = [az; RATE];
        let mut it = elems.iter().peekable();
        while it.peek().is_some() {
            idx = 0;
            while idx < RATE {
                match it.next() {
                    Some(&a) => {
                        pending[idx] = a;
                        idx += 1;
                    }
                    None => break,
                }
            }
            if idx == 0 {
                break;
            }
            // Build the rate blocks from pending lanes; keep old lanes when partial.
            let mut in_blocks = blocks;
            for j in 0..RATE_BLOCKS {
                let lo = PACK_LANES * j;
                if idx >= lo + PACK_LANES {
                    in_blocks[j] = self.pack_block(std::array::from_fn(|k| pending[lo + k]));
                } else if idx > lo {
                    // partial block: mix fresh lanes with old state lanes
                    let old: [u32; PACK_LANES] = if unpacked[j].is_some() {
                        unpacked[j].unwrap()
                    } else if blocks[j] == az {
                        [az; PACK_LANES]
                    } else {
                        let outs = self.unpack_lanes(blocks[j]);
                        unpacked[j] = Some(outs);
                        outs
                    };
                    let lanes: [u32; PACK_LANES] = std::array::from_fn(|k| {
                        if lo + k < idx {
                            pending[lo + k]
                        } else {
                            old[k]
                        }
                    });
                    in_blocks[j] = self.pack_block(lanes);
                }
                // idx <= lo: block untouched, keep old block addr
            }
            blocks = self.permute_packed(in_blocks);
            unpacked = [None; RATE_BLOCKS];
            if idx < RATE {
                break;
            }
        }
        std::array::from_fn(|j| blocks[j])
    }

    /// Hash `n_values` F values that already live PACKED in `in_blocks` (`PACK_LANES` values per
    /// block, in value order, last block zero-padded) with a fresh Poseidon2 sponge.
    /// Absorbs full blocks directly (zero packing cost); only a partial tail block
    /// mixes fresh lanes with prior state lanes via one unpack + one pack.
    /// Fiat-Shamir semantics are identical to `hash_poseidon2_fresh` over the same
    /// values: a full packed block's VALUE equals the pack_block of its lanes.
    pub(super) fn hash_poseidon2_fresh_packed(
        &mut self,
        in_blocks: &[u32],
        n_values: usize,
    ) -> [u32; DIGEST_BLOCKS] {
        let az = self.addr_zero;
        debug_assert_eq!(in_blocks.len(), n_values.div_ceil(PACK_LANES));
        let full_blocks = n_values / PACK_LANES;
        let tail = n_values % PACK_LANES;
        let mut state: [u32; PERM_BLOCKS] = [az; PERM_BLOCKS];
        let mut bi = 0usize;
        while bi < in_blocks.len() {
            let mut in_state = state;
            let mut absorbed = false;
            for j in 0..RATE_BLOCKS {
                if bi < full_blocks {
                    // Full block: absorb directly (overwrite the rate lane group).
                    in_state[j] = in_blocks[bi];
                    bi += 1;
                    absorbed = true;
                } else if tail > 0 && bi < in_blocks.len() {
                    // Partial tail block: keep old state lanes beyond the tail. This is the one
                    // read of a hinted packed block that does not go through `looked_packed`:
                    // UnpackBlock forwards all its lanes, and its outputs past `PACK_LANES` are
                    // never read. Harmless for the lane rule because the same block is also read
                    // by ExtDotProduct (every opened-row block is), which pins the padding lanes.
                    let fresh = self.unpack_lanes(in_blocks[bi]);
                    let old: [u32; PACK_LANES] = if state[j] == az {
                        [az; PACK_LANES]
                    } else {
                        self.unpack_lanes(state[j])
                    };
                    let lanes: [u32; PACK_LANES] =
                        std::array::from_fn(|k| if k < tail { fresh[k] } else { old[k] });
                    in_state[j] = self.pack_block(lanes);
                    bi += 1;
                    absorbed = true;
                }
            }
            debug_assert!(absorbed);
            state = self.permute_packed(in_state);
        }
        std::array::from_fn(|j| state[j])
    }

    // ─── Merkle/fold helpers ──────────────────────────────────────────────────

    /// Poseidon2 compress on packed digests: permute([left, right]) (`DIGEST_BLOCKS` blocks each)
    /// → the first `DIGEST_BLOCKS` output blocks.
    pub(super) fn compress_poseidon2(
        &mut self,
        left: [u32; DIGEST_BLOCKS],
        right: [u32; DIGEST_BLOCKS],
    ) -> [u32; DIGEST_BLOCKS] {
        let out = self.permute_packed(std::array::from_fn(|i| {
            if i < DIGEST_BLOCKS {
                left[i]
            } else {
                right[i - DIGEST_BLOCKS]
            }
        }));
        std::array::from_fn(|j| out[j])
    }

    /// Binary tree compression: pairwise compress until 1 digest (`DIGEST_BLOCKS` packed blocks).
    pub(super) fn tree_compress_circuit(
        &mut self,
        mut hashes: Vec<[u32; DIGEST_BLOCKS]>,
    ) -> [u32; DIGEST_BLOCKS] {
        while hashes.len() > 1 {
            let mut next = Vec::with_capacity(hashes.len() / 2);
            for pair in hashes.as_chunks::<2>().0 {
                next.push(self.compress_poseidon2(pair[0], pair[1]));
            }
            hashes = next;
        }
        hashes[0]
    }

    /// Digest-wide bit-select via the DigestSelect chip (packed digests):
    /// returns the `DIGEST_BLOCKS` block addrs of (bit == 0 ? h0 : h1) in one instruction.
    pub(super) fn select_digest(
        &mut self,
        bit: u32,
        h0: [u32; DIGEST_BLOCKS],
        h1: [u32; DIGEST_BLOCKS],
    ) -> [u32; DIGEST_BLOCKS] {
        let outs: [u32; DIGEST_BLOCKS] = std::array::from_fn(|_| self.alloc());
        self.mark_read(bit);
        for a in h0 {
            self.mark_read(a);
        }
        for a in h1 {
            self.mark_read(a);
        }
        self.instructions
            .push(Instruction::DigestSelect(Box::new(DigestSelectInstr {
                bit_addr: Address(F::from_u32(bit)),
                in1_addrs: h0.map(|a| Address(F::from_u32(a))),
                in2_addrs: h1.map(|a| Address(F::from_u32(a))),
                out_addrs: outs.map(|a| Address(F::from_u32(a))),
                mults: [F::ZERO; DIGEST_BLOCKS], // backfilled
            })));
        outs
    }

    /// Merkle path verification. Leaf hash + path → verify against root.
    /// index_bits: [n_bits] F addrs each holding 0 or 1.
    /// siblings: n_bits × `DIGEST_BLOCKS` packed block addrs (one hinted digest per level).
    /// root_blocks: the `DIGEST_BLOCKS` packed block addrs of the expected root digest.
    ///
    /// Each level orders the pair with two DigestSelects and compresses once, rather
    /// than compressing both orders and selecting: one Poseidon2Packed row fewer per level for
    /// half a DigestSelect row more. Sound because DigestSelect asserts its bit boolean, so the
    /// pair is (cur, sibling) or (sibling, cur), exactly the two inputs the old form hashed.
    pub(super) fn verify_merkle_path_circuit(
        &mut self,
        leaf_hash: [u32; DIGEST_BLOCKS],
        index_bits: &[u32],
        siblings: &[[u32; DIGEST_BLOCKS]],
        root_blocks: [u32; DIGEST_BLOCKS],
    ) {
        let mut cur = leaf_hash;
        for (&bit_addr, &sibling) in index_bits.iter().zip(siblings.iter()) {
            // (left, right) = bit == 0 ? (cur, sibling) : (sibling, cur).
            let left = self.select_digest(bit_addr, cur, sibling);
            let right = self.select_digest(bit_addr, sibling, cur);
            cur = self.compress_poseidon2(left, right);
        }
        for j in 0..DIGEST_BLOCKS {
            self.assert_ext_eq(cur[j], root_blocks[j]);
        }
    }

    /// Pack a DIGEST_SIZE-lane digest of single-F addresses into DIGEST_BLOCKS block addresses
    /// (done once per digest; reused as Merkle root across all queries).
    pub(super) fn pack_digest(&mut self, addrs: [u32; DIGEST_SIZE]) -> [u32; DIGEST_BLOCKS] {
        std::array::from_fn(|j| self.pack_block(std::array::from_fn(|k| addrs[PACK_LANES * j + k])))
    }
}
