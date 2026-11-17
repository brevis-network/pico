//! The global LogUp in the recursion tree: the chain over the chunks' Global table commitments,
//! its two wrapped forms, the fractional sum, and what a complete root asserts about them.
//!
//! Every function here is the in-circuit twin of one in `pico_mle_core::global_logup` (the
//! binding the prover and the native verifier compute with), over the same preimages.

use super::*;
use crate::emulator::recursion::public_values::GLOBAL_SUM_LEN;

impl<F: PrimeField32 + TwoAdicField> Builder<F> {
    /// `H(elems)` as [`DIGEST_SIZE`] field elements.
    pub(super) fn hash_to_felts(&mut self, elems: &[u32]) -> [u32; DIGEST_SIZE] {
        let blocks = self.hash_poseidon2_fresh(elems);
        let lo = self.unpack_lanes(blocks[0]);
        let hi = self.unpack_lanes(blocks[1]);
        std::array::from_fn(|i| {
            if i < PACK_LANES {
                lo[i]
            } else {
                hi[i - PACK_LANES]
            }
        })
    }

    /// The chain before any chunk, as constants.
    pub(super) fn global_chain_iv(&mut self) -> [u32; DIGEST_SIZE] {
        global_logup::chain_iv().map(|x| self.const_f(x.as_canonical_u32()))
    }

    /// One step of the chain: `H(TAG_LEAF ‖ prev ‖ index ‖ log_height ‖ width ‖ commit)`.
    /// `index` is an address; the table's layout is the caller's baked constant.
    pub(super) fn global_chain_step(
        &mut self,
        prev: [u32; DIGEST_SIZE],
        index: u32,
        log_height: usize,
        commit: [u32; DIGEST_SIZE],
    ) -> [u32; DIGEST_SIZE] {
        let mut preimage = Vec::with_capacity(20);
        preimage.push(self.const_f(global_logup::TAG_LEAF));
        preimage.extend_from_slice(&prev);
        preimage.push(index);
        preimage.push(self.const_f(log_height as u32));
        preimage.push(self.const_f(global_logup::TABLE_WIDTH as u32));
        preimage.extend_from_slice(&commit);
        self.hash_to_felts(&preimage)
    }

    /// A chain value bound to the challenges a node used: `H(TAG_WRAP ‖ alpha ‖ beta ‖ x)`,
    /// the challenges as their base-field coefficients.
    pub(super) fn wrap_chain(
        &mut self,
        alpha: [u32; EXTENSION_DEGREE],
        beta: [u32; EXTENSION_DEGREE],
        x: [u32; DIGEST_SIZE],
    ) -> [u32; DIGEST_SIZE] {
        let mut preimage = Vec::with_capacity(19);
        preimage.push(self.const_f(global_logup::TAG_WRAP));
        preimage.extend_from_slice(&alpha);
        preimage.extend_from_slice(&beta);
        preimage.extend_from_slice(&x);
        self.hash_to_felts(&preimage)
    }

    /// A chain value bound to the root the challenges were derived from:
    /// `H(TAG_TOP ‖ root ‖ x)`.
    pub(super) fn wrap_chain_top(
        &mut self,
        root: [u32; DIGEST_SIZE],
        x: [u32; DIGEST_SIZE],
    ) -> [u32; DIGEST_SIZE] {
        let mut preimage = Vec::with_capacity(17);
        preimage.push(self.const_f(global_logup::TAG_TOP));
        preimage.extend_from_slice(&root);
        preimage.extend_from_slice(&x);
        self.hash_to_felts(&preimage)
    }

    /// The fraction `(0, 1)`: a subtree without a group proof.
    pub(super) fn zero_global_sum(&self) -> [u32; GLOBAL_SUM_LEN] {
        let mut frac = [self.addr_zero; GLOBAL_SUM_LEN];
        frac[EXTENSION_DEGREE] = self.addr_one;
        frac
    }

    /// `(p, q) = (p_a q_b + p_b q_a, q_a q_b)` over two fractions held as public-value slots.
    pub(super) fn add_global_sums(
        &mut self,
        a: [u32; GLOBAL_SUM_LEN],
        b: [u32; GLOBAL_SUM_LEN],
    ) -> [u32; GLOBAL_SUM_LEN] {
        let halves =
            |x: [u32; GLOBAL_SUM_LEN]| -> ([u32; EXTENSION_DEGREE], [u32; EXTENSION_DEGREE]) {
                (
                    std::array::from_fn(|i| x[i]),
                    std::array::from_fn(|i| x[EXTENSION_DEGREE + i]),
                )
            };
        let ((p_a, q_a), (p_b, q_b)) = (halves(a), halves(b));
        let (p_a, q_a) = (self.pack_ef(p_a), self.pack_ef(q_a));
        let (p_b, q_b) = (self.pack_ef(p_b), self.pack_ef(q_b));
        let (p, q) = self.frac_fold(p_a, q_a, p_b, q_b);
        let (p, q) = (self.unpack_block(p), self.unpack_block(q));
        std::array::from_fn(|i| {
            if i < EXTENSION_DEGREE {
                p[i]
            } else {
                q[i - EXTENSION_DEGREE]
            }
        })
    }

    /// What a complete root asserts about the global LogUp, over its public values `pv_arr`.
    ///
    /// 1. The chain closes: `start == H(TAG_TOP ‖ end ‖ end)`. Only an image node produces such
    ///    a value, from the chain root it derived the challenges from; so the tree has the
    ///    second phase, proved under challenges that come after every chunk's table commitment.
    ///    A tree of chunks alone starts at `IV` and fails here, and nowhere else.
    /// 2. The sum is zero over a non-zero denominator: `p == 0` and `q · q⁻¹ == 1`.
    /// 3. The chunks' real-row count is at most `max_count`, so that a multiplicity that is
    ///    zero in the field is zero.
    ///
    /// Hints, in order: `q⁻¹` ([`EXTENSION_DEGREE`] elements), then the 21 bits of
    /// `max_count − count`, low bit first.
    pub(super) fn assert_global_logup_closed(&mut self, pv_arr: &[u32], max_count: u64) {
        const COUNT_BITS: usize = 21;
        const _: () = assert!(global_logup::MAX_COUNT < 1 << COUNT_BITS);
        // What a tree's count stays below: a convert leaf range-checks its chunk index to
        // `MAX_LOG_NUMBER_OF_CHUNKS` bits, and writes a share of one unit per `2^LOG_COUNT_UNIT`
        // rows of a table of at most `2^MAX_GLOBAL_LOG_HEIGHT`. The decomposition below takes
        // `max_count − count` for small only if a count past the limit cannot wrap around to
        // within `2^COUNT_BITS` under it.
        const TREE_COUNT_BOUND: u64 = 1
            << (crate::primitives::consts::MAX_LOG_NUMBER_OF_CHUNKS
                + global_logup::MAX_GLOBAL_LOG_HEIGHT
                - global_logup::LOG_COUNT_UNIT);
        assert!(
            TREE_COUNT_BOUND + (1 << COUNT_BITS) < u64::from(F::ORDER_U32),
            "a tree's real-row count could wrap around the field"
        );
        assert!(
            max_count <= global_logup::MAX_COUNT,
            "a real-row limit of {max_count} is above the sound one, {}",
            global_logup::MAX_COUNT
        );
        let col = RECURSION_PUBLIC_VALUES_COL_MAP;
        let (addr_zero, addr_one) = (self.addr_zero, self.addr_one);

        let end: [u32; DIGEST_SIZE] = col.global_chain_end.map(|i| pv_arr[i]);
        let closed = self.wrap_chain_top(end, end);
        for j in 0..DIGEST_SIZE {
            self.assert_f_eq(pv_arr[col.global_chain_start[j]], closed[j]);
        }

        for j in 0..EXTENSION_DEGREE {
            self.assert_f_eq(pv_arr[col.global_sum[j]], addr_zero);
        }
        let q = self.pack_ef(std::array::from_fn(|j| {
            pv_arr[col.global_sum[EXTENSION_DEGREE + j]]
        }));
        let q_inv: [u32; EXTENSION_DEGREE] = std::array::from_fn(|_| self.hint_f());
        let q_inv = self.pack_ef(q_inv);
        let product = self.ext_mul(q, q_inv);
        self.assert_ext_eq(product, addr_one);

        // `count` is below `TREE_COUNT_BOUND`, 2^28 (at most 2^16 chunks of at most 2^12 units
        // each), so `max_count − count` fits 21 bits exactly when `count <= max_count`.
        let max = self.const_f(max_count as u32);
        let slack = self.base_sub(max, pv_arr[col.global_row_count]);
        let two = self.const_f(2);
        let mut acc = addr_zero;
        let mut pow = addr_one;
        for i in 0..COUNT_BITS {
            let bit = self.hint_f();
            let one_minus = self.base_sub(addr_one, bit);
            let bb = self.base_mul(bit, one_minus);
            self.assert_f_eq(bb, addr_zero);
            let term = self.base_mul(bit, pow);
            acc = self.base_add(acc, term);
            if i + 1 < COUNT_BITS {
                pow = self.base_mul(pow, two);
            }
        }
        self.assert_f_eq(acc, slack);
    }
}
