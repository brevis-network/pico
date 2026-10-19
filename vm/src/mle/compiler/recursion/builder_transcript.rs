//! `Builder` Fiat–Shamir transcript and Poseidon2 hashing: the duplex sponge, absorb/
//! squeeze/observe/sample, witness grinding checks, and Merkle-path verification.

use super::*;

impl<F: PrimeField32 + TwoAdicField + FieldSepticCurve> Builder<F> {
    /// Reset the Fiat-Shamir sponge to its zero state (for verifying N independent proofs).
    pub(super) fn reset_sponge(&mut self) {
        self.sponge = [self.addr_zero; WIDTH];
        self.lane_fresh = [false; WIDTH];
        self.sponge_blocks = [self.addr_zero; 4];
        self.sponge_unpacked = [None; 4];
        self.absorb_idx = 0;
        self.sample_idx = 0;
    }

    /// Emit Poseidon2Packed over 4 input block addresses; returns 4 output blocks.
    pub(super) fn permute_packed(&mut self, in_blocks: [u32; 4]) -> [u32; 4] {
        let out: [u32; 4] = std::array::from_fn(|_| self.alloc());
        for b in in_blocks {
            self.mark_read(b);
        }
        self.instructions
            .push(Instruction::Poseidon2Packed(Box::new(
                Poseidon2PackedInstr {
                    input_addrs: in_blocks.map(|a| Address(F::from_u32(a))),
                    output_addrs: out.map(|a| Address(F::from_u32(a))),
                    mults: [F::ZERO; 4], // backfilled
                },
            )));
        out
    }

    /// Lane addresses of sponge output block j (unpacking lazily on first use).
    pub(super) fn sponge_lane(&mut self, lane: usize) -> u32 {
        let j = lane / 4;
        if self.sponge_unpacked[j].is_none() {
            let outs = self.unpack_block(self.sponge_blocks[j]);
            self.sponge_unpacked[j] = Some(outs);
        }
        self.sponge_unpacked[j].unwrap()[lane % 4]
    }

    /// Build the input block j for the next permutation from fresh lanes and/or
    /// the previous output block (packing only when the block is not intact).
    pub(super) fn build_sponge_block(&mut self, j: usize) -> u32 {
        let fresh: [bool; 4] = std::array::from_fn(|k| self.lane_fresh[4 * j + k]);
        if fresh.iter().all(|&f| !f) {
            return self.sponge_blocks[j];
        }
        let lanes: [u32; 4] = std::array::from_fn(|k| {
            if fresh[k] {
                self.sponge[4 * j + k]
            } else {
                self.sponge_lane(4 * j + k)
            }
        });
        self.pack_block(lanes)
    }

    pub(super) fn do_permute(&mut self) {
        let in_blocks: [u32; 4] = std::array::from_fn(|j| self.build_sponge_block(j));
        let out = self.permute_packed(in_blocks);
        self.sponge_blocks = out;
        self.sponge_unpacked = [None; 4];
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
    pub(super) fn observe_const_digest(&mut self, addrs: [u32; 8]) {
        for a in addrs {
            self.absorb_f(a);
        }
    }

    /// Hint and absorb 8 F values (a digest), returning all 8 addresses.
    pub(super) fn observe_digest_addrs(&mut self) -> [u32; 8] {
        std::array::from_fn(|_| self.observe_f_for_chip())
    }

    /// Like observe_digest_for_whir, but also returns all 8 F addresses.
    pub(super) fn observe_digest_for_whir_addrs(&mut self) -> [u32; 8] {
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
    /// Returns the digest as 2 packed block addresses (8 lanes).
    pub(super) fn hash_poseidon2_fresh(&mut self, elems: &[u32]) -> [u32; 2] {
        let az = self.addr_zero;
        let mut blocks: [u32; 4] = [az; 4];
        let mut unpacked: [Option<[u32; 4]>; 2] = [None; 2];
        // absorb index within the current rate window
        let mut idx;
        let mut pending: [u32; 8] = [az; 8];
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
            // Build rate blocks 0..2 from pending lanes; keep old lanes when partial.
            let mut in_blocks = blocks;
            for j in 0..2 {
                let lo = 4 * j;
                if idx >= lo + 4 {
                    in_blocks[j] = self.pack_block([
                        pending[lo],
                        pending[lo + 1],
                        pending[lo + 2],
                        pending[lo + 3],
                    ]);
                } else if idx > lo {
                    // partial block: mix fresh lanes with old state lanes
                    let old: [u32; 4] = if unpacked[j].is_some() {
                        unpacked[j].unwrap()
                    } else if blocks[j] == az {
                        [az; 4]
                    } else {
                        let outs = self.unpack_block(blocks[j]);
                        unpacked[j] = Some(outs);
                        outs
                    };
                    let lanes: [u32; 4] = std::array::from_fn(|k| {
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
            unpacked = [None; 2];
            if idx < RATE {
                break;
            }
        }
        [blocks[0], blocks[1]]
    }

    /// Hash `n_values` F values that already live PACKED in `in_blocks` (4 lanes per
    /// block, in value order, last block zero-padded) with a fresh Poseidon2 sponge.
    /// Absorbs full blocks directly (zero packing cost); only a partial tail block
    /// mixes fresh lanes with prior state lanes via one unpack + one pack.
    /// Fiat-Shamir semantics are identical to `hash_poseidon2_fresh` over the same
    /// values: a full packed block's VALUE equals the pack_block of its lanes.
    pub(super) fn hash_poseidon2_fresh_packed(
        &mut self,
        in_blocks: &[u32],
        n_values: usize,
    ) -> [u32; 2] {
        let az = self.addr_zero;
        debug_assert_eq!(in_blocks.len(), n_values.div_ceil(4));
        let full_blocks = n_values / 4;
        let tail = n_values % 4;
        let mut state: [u32; 4] = [az; 4];
        let mut bi = 0usize;
        while bi < in_blocks.len() {
            let mut in_state = state;
            let mut absorbed = false;
            for j in 0..2 {
                if bi < full_blocks {
                    // Full block: absorb directly (overwrite the rate lane group).
                    in_state[j] = in_blocks[bi];
                    bi += 1;
                    absorbed = true;
                } else if tail > 0 && bi < in_blocks.len() {
                    // Partial tail block: keep old state lanes beyond the tail.
                    let fresh = self.unpack_block(in_blocks[bi]);
                    let old: [u32; 4] = if state[j] == az {
                        [az; 4]
                    } else {
                        self.unpack_block(state[j])
                    };
                    let lanes: [u32; 4] =
                        std::array::from_fn(|k| if k < tail { fresh[k] } else { old[k] });
                    in_state[j] = self.pack_block(lanes);
                    bi += 1;
                    absorbed = true;
                }
            }
            debug_assert!(absorbed);
            state = self.permute_packed(in_state);
        }
        [state[0], state[1]]
    }

    // ─── Merkle/fold helpers ──────────────────────────────────────────────────

    /// Poseidon2 compress on packed digests: permute([left(2 blocks), right(2 blocks)])
    /// → first 2 output blocks.
    pub(super) fn compress_poseidon2(&mut self, left: [u32; 2], right: [u32; 2]) -> [u32; 2] {
        let out = self.permute_packed([left[0], left[1], right[0], right[1]]);
        [out[0], out[1]]
    }

    /// Binary tree compression: pairwise compress until 1 digest (2 packed blocks).
    pub(super) fn tree_compress_circuit(&mut self, mut hashes: Vec<[u32; 2]>) -> [u32; 2] {
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
    /// returns 2 block addrs of (bit == 0 ? h0 : h1) in one instruction.
    pub(super) fn select_digest(&mut self, bit: u32, h0: [u32; 2], h1: [u32; 2]) -> [u32; 2] {
        let outs: [u32; 2] = std::array::from_fn(|_| self.alloc());
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
                mults: [F::ZERO; 2], // backfilled
            })));
        outs
    }

    /// Merkle path verification. Leaf hash + path → verify against root.
    /// index_bits: [n_bits] F addrs each holding 0 or 1.
    /// siblings: [n_bits] × 8 F addrs.
    /// root_addrs: [8] F addrs of the expected root digest.
    pub(super) fn verify_merkle_path_circuit(
        &mut self,
        leaf_hash: [u32; 2],
        index_bits: &[u32],
        siblings: &[[u32; 2]],
        root_blocks: [u32; 2],
    ) {
        let mut cur = leaf_hash;
        for (&bit_addr, &sibling) in index_bits.iter().zip(siblings.iter()) {
            let h0 = self.compress_poseidon2(cur, sibling);
            let h1 = self.compress_poseidon2(sibling, cur);
            // cur = bit == 0 ? h0 : h1, one DigestSelect instruction for both blocks.
            cur = self.select_digest(bit_addr, h0, h1);
        }
        for j in 0..2 {
            self.assert_ext_eq(cur[j], root_blocks[j]);
        }
    }

    /// Pack an 8-lane digest of single-F addresses into 2 block addresses
    /// (done once per digest; reused as Merkle root across all queries).
    pub(super) fn pack_digest(&mut self, addrs: [u32; 8]) -> [u32; 2] {
        [
            self.pack_block([addrs[0], addrs[1], addrs[2], addrs[3]]),
            self.pack_block([addrs[4], addrs[5], addrs[6], addrs[7]]),
        ]
    }
}
