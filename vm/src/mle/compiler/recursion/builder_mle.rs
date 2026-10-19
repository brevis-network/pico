//! `Builder` multilinear / eq-polynomial circuit evaluators: Lagrange interpolation, GKR
//! sumcheck rounds, fraction & univariate folding, constraint-DAG evaluation, and WHIR binary folding.

use super::*;

impl<F: PrimeField32 + TwoAdicField + FieldSepticCurve> Builder<F> {
    /// One degree-2 sumcheck round via the LagrangeEvalD2 precompile chip.
    /// Reads the running `claim`, the prover evaluations s(1)=`s1`, s(2)=`s2`, and the
    /// challenge `r`; returns the addr of next_claim = p(r), where p is the unique
    /// quadratic with p(0) = claim - s1 (the round sum check, enforced by construction),
    /// p(1) = s1, p(2) = s2. Replaces a 16-instruction ExtAlu/AssertZeroExt chain
    /// (s0 derivation + trivial sum re-check + 12-op Lagrange interpolation).
    pub(super) fn lagrange_eval_d2(&mut self, claim: u32, s1: u32, s2: u32, r: u32) -> u32 {
        let next_claim = self.alloc();
        self.mark_read(claim);
        self.mark_read(s1);
        self.mark_read(s2);
        self.mark_read(r);
        self.instructions
            .push(Instruction::LagrangeEvalD2(LagrangeEvalD2Instr {
                claim_addr: Address(F::from_u32(claim)),
                s1_addr: Address(F::from_u32(s1)),
                s2_addr: Address(F::from_u32(s2)),
                r_addr: Address(F::from_u32(r)),
                next_claim_addr: Address(F::from_u32(next_claim)),
                mult: F::ZERO, // backfilled
            }));
        next_claim
    }

    /// One GKR cubic sumcheck sub-round via the GkrSumcheckRound precompile chip.
    /// Reads the running `claim`, prover evaluations s(1)=`s1`, s(2)=`s2`, s(3)=`s3`,
    /// the challenge `r`, the previous round's point coordinate `xi` and the running
    /// eq product `eq_in`. Returns (next_claim, eq_out) where next_claim = p(r) for
    /// the unique cubic with p(0) = claim - s1 (the round sum check, enforced by
    /// construction), p(i) = s_i, and eq_out = eq_in * eq_factor(xi, r).
    /// Replaces a ~43-instruction ExtAlu/Mem/AssertZeroExt chain per sub-round.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn gkr_sumcheck_round(
        &mut self,
        claim: u32,
        s1: u32,
        s2: u32,
        s3: u32,
        r: u32,
        xi: u32,
        eq_in: u32,
    ) -> (u32, u32) {
        let next_claim = self.alloc();
        let eq_out = self.alloc();
        for a in [claim, s1, s2, s3, r, xi, eq_in] {
            self.mark_read(a);
        }
        self.instructions
            .push(Instruction::GkrSumcheckRound(Box::new(
                GkrSumcheckRoundInstr {
                    claim_addr: Address(F::from_u32(claim)),
                    s1_addr: Address(F::from_u32(s1)),
                    s2_addr: Address(F::from_u32(s2)),
                    s3_addr: Address(F::from_u32(s3)),
                    r_addr: Address(F::from_u32(r)),
                    xi_addr: Address(F::from_u32(xi)),
                    eq_in_addr: Address(F::from_u32(eq_in)),
                    next_claim_addr: Address(F::from_u32(next_claim)),
                    eq_out_addr: Address(F::from_u32(eq_out)),
                    mult_next: F::ZERO, // backfilled
                    mult_eq: F::ZERO,   // backfilled
                },
            )));
        (next_claim, eq_out)
    }

    /// General Lagrange interpolation at integer nodes {0, 1, ..., n-1}.
    /// Given `evals[i]` = address of p(i) and `r` = address of challenge, returns p(r).
    /// Uses prefix-suffix products: O(3n) ExtAlu muls + O(n) adds total.
    pub(super) fn lagrange_eval_generic(&mut self, evals: &[u32], r: u32) -> u32 {
        let n = evals.len();
        if n == 0 {
            return self.addr_zero;
        }
        if n == 1 {
            return evals[0];
        }
        // Write integer constants 0, 1, ..., n-1 as EF block constants.
        let node_addrs: Vec<u32> = (0..n)
            .map(|j| self.write_const(Block([F::from_u32(j as u32), F::ZERO, F::ZERO, F::ZERO])))
            .collect();
        // diffs[j] = r - j.
        let diffs: Vec<u32> = (0..n).map(|j| self.ext_sub(r, node_addrs[j])).collect();
        // Prefix products: prefix[i] = prod_{k<i} diffs[k], prefix[0] = 1.
        let mut prefix = vec![self.addr_one];
        for i in 1..n {
            let p = self.ext_mul(prefix[i - 1], diffs[i - 1]);
            prefix.push(p);
        }
        // Suffix products: suffix[i] = prod_{k>i} diffs[k], suffix[n-1] = 1.
        let mut suffix = vec![self.addr_zero; n];
        suffix[n - 1] = self.addr_one;
        for i in (0..n - 1).rev() {
            let s = self.ext_mul(suffix[i + 1], diffs[i + 1]);
            suffix[i] = s;
        }
        // result = sum_i evals[i] * prefix[i] * suffix[i] * denom_inv[i].
        let mut result = self.addr_zero;
        for i in 0..n {
            let denom_inv = lagrange_basis_denom_inv(n, i);
            let addr_inv = self.write_const(Block([denom_inv, F::ZERO, F::ZERO, F::ZERO]));
            let num = self.ext_mul(prefix[i], suffix[i]);
            let term = self.ext_mul(evals[i], num);
            let term = self.ext_mul(term, addr_inv);
            result = if i == 0 {
                term
            } else {
                self.ext_add(result, term)
            };
        }
        result
    }

    /// Linear interpolation: a + r*(b - a) via 3 ExtAlu ops.
    pub(super) fn interp_linear(&mut self, a: u32, b: u32, r: u32) -> u32 {
        let diff = self.ext_sub(b, a);
        let rd = self.ext_mul(r, diff);
        self.ext_add(a, rd)
    }

    // ─── Chip instruction builders ────────────────────────────────────────────

    /// Emit FracFold: (out_p, out_q) = (p1·q2 + p2·q1, q1·q2).
    pub(super) fn frac_fold(&mut self, p1: u32, q1: u32, p2: u32, q2: u32) -> (u32, u32) {
        let out_p = self.alloc();
        let out_q = self.alloc();
        self.mark_read(p1);
        self.mark_read(q1);
        self.mark_read(p2);
        self.mark_read(q2);
        self.instructions.push(Instruction::FracFold(FracFoldInstr {
            in_p1_addr: Address(F::from_u32(p1)),
            in_q1_addr: Address(F::from_u32(q1)),
            in_p2_addr: Address(F::from_u32(p2)),
            in_q2_addr: Address(F::from_u32(q2)),
            out_p_addr: Address(F::from_u32(out_p)),
            out_q_addr: Address(F::from_u32(out_q)),
            mult: F::ZERO, // backfilled
        }));
        (out_p, out_q)
    }

    /// Emit UnivariateFold.
    pub(super) fn univariate_fold(&mut self, coeffs: Vec<u32>, claimed_sum: u32, r: u32) -> u32 {
        let next_sum = self.alloc();
        for &c in &coeffs {
            self.mark_read(c);
        }
        // Unused coeff slots in the chip trace are filled with addr_zero (Block([0,0,0,0])).
        // MemoryConst must account for those reads so the bus interaction balances.
        let az = self.addr_zero;
        let num_unused = MAX_COEFFS.saturating_sub(coeffs.len());
        for _ in 0..num_unused {
            self.mark_read(az);
        }
        self.mark_read(claimed_sum);
        self.mark_read(r);
        self.instructions
            .push(Instruction::UnivariateFold(Box::new(UnivariateFoldInstr {
                coeffs_addrs: coeffs
                    .into_iter()
                    .map(|a| Address(F::from_u32(a)))
                    .collect(),
                claimed_sum_addr: Address(F::from_u32(claimed_sum)),
                r_addr: Address(F::from_u32(r)),
                next_sum_addr: Address(F::from_u32(next_sum)),
                mult: F::ZERO, // backfilled
            })));
        next_sum
    }

    /// Emit ExpBitsLen: canonically bit-decompose the field element at `bit_src_addr` (LSB-first)
    /// and compute `result = base^(canonical(bit_src) mod 2^num_bits)`.
    ///
    /// `base`/`num_bits` are program-fixed constants baked into the chip's preprocessed trace (not
    /// memory operands). Returns `(result_addr, bit_addrs)` where `bit_addrs` holds the 31
    /// decomposition-bit addresses (KoalaBear is a 31-bit field; bit j = the j-th canonical bit).
    /// The chip reads `bit_src` once, so we `mark_read` it here (the producer's write mult then
    /// backfills correctly). The `result` and per-bit writes are emitted with mult 0 and their
    /// write mults are backfilled from `read_counts` in `finish()`, so any consumer that reads
    /// `result` or a bit MUST `mark_read` it (e.g. via `assert_f_eq`, which reads both operands).
    pub(super) fn exp_bits_len(
        &mut self,
        base: F,
        bit_src_addr: u32,
        num_bits: usize,
    ) -> (u32, Vec<u32>) {
        let result_addr = self.alloc();
        // Rows 0..30 export the 31 LSB-first decomposition bits; row 31 is the terminal row.
        let bit_addrs: Vec<u32> = (0..NUM_BITS_MAX_PLUS_ONE - 1)
            .map(|_| self.alloc())
            .collect();
        self.mark_read(bit_src_addr);
        self.instructions
            .push(Instruction::ExpBitsLen(Box::new(ExpBitsLenInstr {
                base,
                num_bits: num_bits as u32,
                bit_src_in_addr: Address(F::from_u32(bit_src_addr)),
                result_out_addr: Address(F::from_u32(result_addr)),
                result_mult: F::ZERO, // backfilled
                bit_outs_addrs_mults: bit_addrs
                    .iter()
                    .map(|&a| (Address(F::from_u32(a)), F::ZERO)) // backfilled
                    .collect(),
            })));
        (result_addr, bit_addrs)
    }

    /// Emit ExtDotProduct over PACKED value groups: each group is
    /// (packed value block addr, [mu addr; EXTENSION_DEGREE]) and contributes
    /// sum_k val.lane_k * mu_k. Padding lanes must use the zero address for mu
    /// (their contribution is then 0 regardless of the lane value).
    /// Returns the accumulator address.
    pub(super) fn ext_dot_product_packed(
        &mut self,
        groups: &[(u32, [u32; EXTENSION_DEGREE])],
    ) -> u32 {
        if groups.is_empty() {
            return self.addr_zero;
        }
        let acc = self.alloc();
        for &(val, mus) in groups {
            self.mark_read(val);
            for m in mus {
                self.mark_read(m);
            }
        }
        // Pad to a whole number of rows with zero-address groups; the padded
        // groups read the zero block and contribute 0 to the sum. MemoryConst
        // must account those reads so the memory bus balances.
        let az = self.addr_zero;
        let gp = crate::primitives::consts::EXT_DOT_PRODUCT_GROUPS;
        let pad = (gp - groups.len() % gp) % gp;
        for _ in 0..pad {
            self.mark_read(az);
            for _ in 0..EXTENSION_DEGREE {
                self.mark_read(az);
            }
        }
        let val_addrs: Vec<Address<F>> = groups
            .iter()
            .map(|&(val, _)| val)
            .chain(std::iter::repeat_n(az, pad))
            .map(|a| Address(F::from_u32(a)))
            .collect();
        let mu_addrs: Vec<Address<F>> = groups
            .iter()
            .flat_map(|&(_, mus)| mus)
            .chain(std::iter::repeat_n(az, pad * EXTENSION_DEGREE))
            .map(|a| Address(F::from_u32(a)))
            .collect();
        self.instructions
            .push(Instruction::ExtDotProduct(Box::new(ExtDotProductInstr {
                mu_addrs,
                val_addrs,
                acc_addr: Address(F::from_u32(acc)),
                mult: F::ZERO, // backfilled
            })));
        acc
    }

    /// eq(xi, r) = xi*r + (1-xi)*(1-r) = 2*xi*r - xi - r + 1.
    pub(super) fn eq_factor(&mut self, xi: u32, r: u32) -> u32 {
        let xi_r = self.ext_mul(xi, r);
        let two_xir = self.ext_add(xi_r, xi_r);
        let xi_plus_r = self.ext_add(xi, r);
        let t = self.ext_sub(two_xir, xi_plus_r);
        self.ext_add(t, self.addr_one)
    }

    /// Evaluate the multilinear extension of `addrs` at point `x`.
    /// Consumes `addrs` (folds in place). Returns address of result.
    pub(super) fn eval_mle_circuit(&mut self, mut addrs: Vec<u32>, x: &[u32]) -> u32 {
        let mut len = addrs.len();
        for &xj in x.iter().rev() {
            len >>= 1;
            for i in 0..len {
                let lo = addrs[i];
                let hi = addrs[len + i];
                let diff = self.ext_sub(hi, lo);
                let t = self.ext_mul(xj, diff);
                addrs[i] = self.ext_add(lo, t);
            }
        }
        addrs[0]
    }

    /// eval_mobius_eq_mle: ∏_i ((1 - 2*u_i)*(1 - alpha_i) + u_i*alpha_i).
    pub(super) fn eval_mobius_eq_circuit(&mut self, u: &[u32], alpha: &[u32]) -> u32 {
        let mut acc = self.addr_one;
        for (&ui, &ai) in u.iter().zip(alpha.iter()) {
            let two_ui = self.ext_add(ui, ui);
            let w0 = self.ext_sub(self.addr_one, two_ui);
            let one_minus_ai = self.ext_sub(self.addr_one, ai);
            let t0 = self.ext_mul(w0, one_minus_ai);
            let t1 = self.ext_mul(ui, ai);
            let factor = self.ext_add(t0, t1);
            acc = self.ext_mul(acc, factor);
        }
        acc
    }

    /// Compute eval_eq_uni(l, x, y) in the circuit.
    /// Formula: res = 1; for i in 0..l { res = (x+y)*res + (x-1)*(y-1); x=x^2; y=y^2 }; res *= 2^{-l}.
    pub(super) fn eval_eq_uni_circuit(&mut self, l: usize, x: u32, y: u32) -> u32 {
        if l == 0 {
            return self.addr_one;
        }
        let mut res = self.addr_one;
        let mut x_cur = x;
        let mut y_cur = y;
        for _ in 0..l {
            let xy_sum = self.ext_add(x_cur, y_cur);
            let t1 = self.ext_mul(xy_sum, res);
            let x1 = self.ext_sub(x_cur, self.addr_one);
            let y1 = self.ext_sub(y_cur, self.addr_one);
            let t2 = self.ext_mul(x1, y1);
            res = self.ext_add(t1, t2);
            x_cur = self.ext_mul(x_cur, x_cur);
            y_cur = self.ext_mul(y_cur, y_cur);
        }
        // Multiply by 2^{-l} in the base field.
        let inv2l = inv_2_pow::<F>(l as u64);
        let c = self.write_const(Block([F::from_u32(inv2l), F::ZERO, F::ZERO, F::ZERO]));
        self.ext_mul(res, c)
    }

    /// Compute eval_in_uni(l_skip, n, u0) in the circuit.
    /// If n >= 0: returns 1. If n < 0: eval_eq_uni_at_one(|n|, u0^{2^{l_skip - |n|}}).
    pub(super) fn eval_in_uni_circuit(&mut self, l_skip: usize, n: isize, u0: u32) -> u32 {
        if n >= 0 {
            return self.addr_one;
        }
        let abs_n = (-n) as usize;
        // z = u0^{2^{l_skip - abs_n}}
        let mut z = u0;
        for _ in 0..l_skip.saturating_sub(abs_n) {
            z = self.ext_mul(z, z);
        }
        // eval_eq_uni_at_one(abs_n, z) = prod_{i=0}^{abs_n-1} (z^{2^i} + 1) * 2^{-abs_n}
        let mut acc = self.addr_one;
        let mut z_cur = z;
        for _ in 0..abs_n {
            let t = self.ext_add(z_cur, self.addr_one);
            acc = self.ext_mul(acc, t);
            z_cur = self.ext_mul(z_cur, z_cur);
        }
        let inv2n = inv_2_pow::<F>(abs_n as u64);
        let c = self.write_const(Block([F::from_u32(inv2n), F::ZERO, F::ZERO, F::ZERO]));
        self.ext_mul(acc, c)
    }

    /// Compute eval_eq_uni_at_one(l, x) = prod_{k=0}^{l-1}(x^{2^k}+1) * 2^{-l} in the circuit.
    pub(super) fn eval_eq_uni_at_one_circuit(&mut self, l: usize, x: u32) -> u32 {
        if l == 0 {
            return self.addr_one;
        }
        let mut acc = self.addr_one;
        let mut x_cur = x;
        for _ in 0..l {
            let t = self.ext_add(x_cur, self.addr_one);
            acc = self.ext_mul(acc, t);
            x_cur = self.ext_mul(x_cur, x_cur);
        }
        let inv2l = inv_2_pow::<F>(l as u64);
        let c = self.write_const(Block([F::from_u32(inv2l), F::ZERO, F::ZERO, F::ZERO]));
        self.ext_mul(acc, c)
    }

    /// Compute progression_exp2(m, l) = prod_{j=0}^{l-1}(1 + m^{2^j}) in the circuit.
    pub(super) fn progression_exp2_circuit(&mut self, m: u32, l: usize) -> u32 {
        if l == 0 {
            return self.addr_one;
        }
        let mut pow = m;
        let mut sum = self.addr_one;
        for _ in 0..l {
            let one_plus_pow = self.ext_add(self.addr_one, pow);
            sum = self.ext_mul(sum, one_plus_pow);
            pow = self.ext_mul(pow, pow);
        }
        sum
    }

    /// Compute eval_eq_uni(l, x, omega_pow) where omega_pow is a base-field constant.
    /// x is an EF address; omega_pow_seq[j] = omega^{2^j} (build-time constants).
    pub(super) fn eval_eq_uni_const_y_circuit(&mut self, x: u32, omega_pow_seq: &[F]) -> u32 {
        let l = omega_pow_seq.len();
        if l == 0 {
            return self.addr_one;
        }
        let mut res = self.addr_one;
        let mut x_pow = x;
        let mut omega_cur = omega_pow_seq[0];
        for j in 0..l {
            if j > 0 {
                omega_cur = omega_pow_seq[j];
            }
            let omega_addr = self.write_const(Block([omega_cur, F::ZERO, F::ZERO, F::ZERO]));
            let xpo = self.ext_add(x_pow, omega_addr);
            let a = self.ext_mul(xpo, res);
            let x_m1 = self.ext_sub(x_pow, self.addr_one);
            // (omega_cur - 1) as a field constant (base-field arithmetic at build time)
            let omega_m1_val = omega_cur - F::ONE;
            let om1_addr = self.write_const(Block([omega_m1_val, F::ZERO, F::ZERO, F::ZERO]));
            let b = self.ext_mul(x_m1, om1_addr);
            res = self.ext_add(a, b);
            x_pow = self.ext_mul(x_pow, x_pow);
        }
        let inv2l = inv_2_pow::<F>(l as u64);
        let c = self.write_const(Block([F::from_u32(inv2l), F::ZERO, F::ZERO, F::ZERO]));
        self.ext_mul(res, c)
    }

    /// Compute eval_eq_mle for a single variable: 1 - x - y + 2*x*y.
    pub(super) fn eval_eq_mle_1_circuit(&mut self, x: u32, y: u32) -> u32 {
        let xpy = self.ext_add(x, y);
        let one_m_xpy = self.ext_sub(self.addr_one, xpy);
        let xy = self.ext_mul(x, y);
        let two_xy = self.ext_add(xy, xy);
        self.ext_add(one_m_xpy, two_xy)
    }

    /// Compute the 2^n hypercube evaluations of the multilinear extension at xi_addrs.
    /// evals_eq_hypercube_serial equivalent in circuit: returns 2^n EF addresses.
    pub(super) fn evals_eq_hypercube_circuit(&mut self, xi_addrs: &[u32]) -> Vec<u32> {
        let n = xi_addrs.len();
        let mut out = vec![self.addr_zero; 1 << n];
        out[0] = self.addr_one;
        for (i, &xi_j) in xi_addrs.iter().enumerate() {
            let one_m_xi = self.ext_sub(self.addr_one, xi_j);
            for k in 0..(1usize << i) {
                let lo = out[k];
                let hi = self.ext_mul(lo, xi_j);
                let lo_new = self.ext_mul(lo, one_m_xi);
                out[k + (1 << i)] = hi;
                out[k] = lo_new;
            }
        }
        out
    }

    /// Compute eval_eq_sharp_uni(omega_skip_pows, xi[0..l_skip], z) in the circuit.
    /// omega_skip_pows: [omega^0, omega^1, ..., omega^{2^l-1}] as base-field constants.
    pub(super) fn eval_eq_sharp_uni_circuit(
        &mut self,
        xi_l_addrs: &[u32],
        z: u32,
        omega_skip_pows: &[F],
    ) -> u32 {
        let l_skip = xi_l_addrs.len();
        let n_pts = 1 << l_skip;
        debug_assert_eq!(omega_skip_pows.len(), n_pts);
        // eq_xi_evals[k] = MLE of indicator at hypercube point k, evaluated at xi_l_addrs.
        let eq_xi_evals = self.evals_eq_hypercube_circuit(xi_l_addrs);
        let mut result = self.addr_zero;
        for k in 0..n_pts {
            // omega_pow_seq[j] = omega_k^{2^j} where omega_k = omega^k
            let mut omega_pow_seq = vec![F::ZERO; l_skip];
            let mut op = omega_skip_pows[k];
            for j in 0..l_skip {
                omega_pow_seq[j] = op;
                op = op * op;
            }
            let eval_k = self.eval_eq_uni_const_y_circuit(z, &omega_pow_seq);
            let term = self.ext_mul(eval_k, eq_xi_evals[k]);
            result = self.ext_add(result, term);
        }
        result
    }

    /// Evaluate all EvalDag nodes and return their circuit addresses.
    /// partitioned_main: [cached_0, cached_1, ..., common_main] — Vec of (claim, claim_rot) pairs.
    /// preprocessed: optional Vec of (claim, claim_rot) pairs.
    /// pv_addrs: per-air public value addresses (F elements stored as EF with upper zeros).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn eval_dag_nodes_circuit(
        &mut self,
        dag: &EvalDag,
        is_first_row: u32,
        is_last_row: u32,
        is_transition: u32,
        partitioned_main: &[Vec<(u32, u32)>],
        preprocessed: Option<&Vec<(u32, u32)>>,
        pv_addrs: &[u32],
    ) -> Vec<u32> {
        let addr_zero = self.addr_zero;
        let mut vals: Vec<u32> = Vec::with_capacity(dag.nodes.len());
        for node in &dag.nodes {
            let val = match node {
                EvalNode::Variable { entry, index } => {
                    let (claim, claim_rot) = match entry {
                        EvalEntry::Main {
                            part_index,
                            offset: _,
                        } => {
                            let part = partitioned_main
                                .get(*part_index)
                                .and_then(|p| p.get(*index));
                            part.copied().unwrap_or((addr_zero, addr_zero))
                        }
                        EvalEntry::Preprocessed { offset: _ } => preprocessed
                            .and_then(|p| p.get(*index))
                            .copied()
                            .unwrap_or((addr_zero, addr_zero)),
                        EvalEntry::Public => {
                            let pv_addr = pv_addrs.get(*index).copied().unwrap_or(addr_zero);
                            (pv_addr, addr_zero)
                        }
                    };
                    let offset = match entry {
                        EvalEntry::Main { offset, .. } | EvalEntry::Preprocessed { offset } => {
                            *offset
                        }
                        EvalEntry::Public => 0,
                    };
                    if offset == 0 {
                        claim
                    } else {
                        claim_rot
                    }
                }
                EvalNode::IsFirstRow => is_first_row,
                EvalNode::IsLastRow => is_last_row,
                EvalNode::IsTransition => is_transition,
                EvalNode::Constant(c) => {
                    self.write_const(Block([F::from_u32(*c), F::ZERO, F::ZERO, F::ZERO]))
                }
                EvalNode::Add(l, r) => {
                    let lv = vals[*l];
                    let rv = vals[*r];
                    self.ext_add(lv, rv)
                }
                EvalNode::Sub(l, r) => {
                    let lv = vals[*l];
                    let rv = vals[*r];
                    self.ext_sub(lv, rv)
                }
                EvalNode::Neg(i) => {
                    let iv = vals[*i];
                    self.ext_sub(addr_zero, iv)
                }
                EvalNode::Mul(l, r) => {
                    let lv = vals[*l];
                    let rv = vals[*r];
                    self.ext_mul(lv, rv)
                }
            };
            vals.push(val);
        }
        vals
    }

    /// Compute is_first_row and is_last_row for a trace with given rs_n and l in circuit.
    /// omega: two_adic_generator(l) as base-field constant.
    /// rs_n: [r0, r1, ..., r_{n_lift}] — circuit EF addresses.
    pub(super) fn compute_is_first_last_row_circuit(
        &mut self,
        l: usize,
        omega: F,
        rs_n: &[u32],
    ) -> (u32, u32) {
        debug_assert!(!rs_n.is_empty());
        let r0 = rs_n[0];
        // Inverse of 2^l as base-field constant.
        let inv2l = inv_2_pow::<F>(l as u64);
        let inv_l_addr = self.write_const(Block([F::from_u32(inv2l), F::ZERO, F::ZERO, F::ZERO]));
        // progression_exp2(r0, l)
        let pexp_r0 = self.progression_exp2_circuit(r0, l);
        // r0 * omega (omega is an F constant; stored as EF [omega, 0, 0, 0])
        let omega_addr = self.write_const(Block([omega, F::ZERO, F::ZERO, F::ZERO]));
        let r0_omega = self.ext_mul(r0, omega_addr);
        let pexp_r0_omega = self.progression_exp2_circuit(r0_omega, l);
        // Products over rs_n[1..]
        let mut prod_1mr = self.addr_one;
        let mut prod_r = self.addr_one;
        for &ri in &rs_n[1..] {
            let one_m_ri = self.ext_sub(self.addr_one, ri);
            prod_1mr = self.ext_mul(prod_1mr, one_m_ri);
            prod_r = self.ext_mul(prod_r, ri);
        }
        let ifr_unnorm = self.ext_mul(pexp_r0, prod_1mr);
        let is_first_row = self.ext_mul(ifr_unnorm, inv_l_addr);
        let ilr_unnorm = self.ext_mul(pexp_r0_omega, prod_r);
        let is_last_row = self.ext_mul(ilr_unnorm, inv_l_addr);
        (is_first_row, is_last_row)
    }

    /// Compute eq_3b for a single interaction: product over bits of b_int
    /// selecting xi or (1-xi) at positions [l_skip+n_lift, l_skip+n_logup).
    pub(super) fn eq_3b_for_interaction_circuit(
        &mut self,
        b_int: usize,
        n_lift: usize,
        n_logup: usize,
        l_skip: usize,
        xi_addrs: &[u32],
    ) -> u32 {
        if n_logup <= n_lift {
            return self.addr_one;
        }
        let dim = n_logup - n_lift;
        let mut result = self.addr_one;
        for k in 0..dim {
            let xi_k = xi_addrs[l_skip + n_lift + k];
            let factor = if (b_int >> k) & 1 == 1 {
                xi_k
            } else {
                self.ext_sub(self.addr_one, xi_k)
            };
            result = self.ext_mul(result, factor);
        }
        result
    }

    /// Compute (eq_ns, eq_sharp_ns) arrays of length n_max+1 in circuit.
    /// xi_addrs: all xi values [xi_0, xi_1, ..., xi_{l_skip+n_global-1}].
    /// r0_bc: first BC challenge.
    /// bc_r_challenges: subsequent BC sumcheck challenges [r_1, ..., r_{n_max}].
    /// omega_skip_pows: [omega^0, ..., omega^{2^l_skip-1}] as base-field constants.
    pub(super) fn compute_eq_ns_circuit(
        &mut self,
        l_skip: usize,
        n_max: usize,
        xi_addrs: &[u32],
        r0_bc: u32,
        bc_r_challenges: &[u32],
        omega_skip_pows: &[F],
    ) -> (Vec<u32>, Vec<u32>) {
        let mut eq_ns = vec![self.addr_zero; n_max + 1];
        let mut eq_sharp_ns = vec![self.addr_zero; n_max + 1];
        // Base values at index 0.
        eq_ns[0] = self.eval_eq_uni_circuit(l_skip, xi_addrs[0], r0_bc);
        eq_sharp_ns[0] =
            self.eval_eq_sharp_uni_circuit(&xi_addrs[..l_skip], r0_bc, omega_skip_pows);
        // Incremental eq_mle factors.
        for i in 1..=n_max {
            let xi_i = xi_addrs[l_skip + i - 1];
            let r_i = bc_r_challenges[i - 1];
            let eq_mle = self.eval_eq_mle_1_circuit(xi_i, r_i);
            eq_ns[i] = self.ext_mul(eq_ns[i - 1], eq_mle);
            eq_sharp_ns[i] = self.ext_mul(eq_sharp_ns[i - 1], eq_mle);
        }
        // Reverse-product correction (front-loaded batch sumcheck).
        // r_rev_prod starts at rs[n_max] = bc_r_challenges[n_max-1] (or r0_bc if n_max=0).
        if n_max > 0 {
            let mut r_rev_prod = bc_r_challenges[n_max - 1];
            for i in (0..n_max).rev() {
                let tmp_ns = self.ext_mul(eq_ns[i], r_rev_prod);
                eq_ns[i] = tmp_ns;
                let tmp_sn = self.ext_mul(eq_sharp_ns[i], r_rev_prod);
                eq_sharp_ns[i] = tmp_sn;
                // rs[i] = r0_bc if i==0, bc_r_challenges[i-1] otherwise.
                let rs_i = if i == 0 {
                    r0_bc
                } else {
                    bc_r_challenges[i - 1]
                };
                r_rev_prod = self.ext_mul(r_rev_prod, rs_i);
            }
        }
        (eq_ns, eq_sharp_ns)
    }

    /// Compute (interaction_num, interaction_denom) EF sums for a single trace.
    /// eq_3bs: per-interaction eq_3b values.
    /// node_vals: evaluated EvalDag node addresses.
    /// interactions: from EvalDag.
    /// beta_logup_addr: EF address of beta_logup challenge.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn compute_trace_interaction_evals_circuit(
        &mut self,
        eq_3bs: &[u32],
        node_vals: &[u32],
        interactions: &[EvalInteraction],
        beta_logup_addr: u32,
        _n_lift: usize,
        n: isize,
        eq_sharp_ns_n_lift: u32,
        _r0_bc: u32,
        _bc_r_challenges: &[u32],
    ) -> (u32, u32) {
        if interactions.is_empty() {
            return (self.addr_zero, self.addr_zero);
        }
        let addr_zero = self.addr_zero;
        // norm_factor: 1 for n >= 0, else 1/2^|n|.
        let norm_factor_addr = if n >= 0 {
            self.addr_one
        } else {
            let abs_n = n.unsigned_abs() as u32;
            let inv_norm = inv_2_pow::<F>(abs_n as u64);
            self.write_const(Block([F::from_u32(inv_norm), F::ZERO, F::ZERO, F::ZERO]))
        };
        // Compute beta powers: beta^0, beta^1, ..., beta^{max_msg_len}.
        let max_msg_len = interactions
            .iter()
            .map(|ia| ia.message.len())
            .max()
            .unwrap_or(0);
        let mut beta_pows: Vec<u32> = Vec::with_capacity(max_msg_len + 2);
        beta_pows.push(self.addr_one); // beta^0 = 1
        let mut cur_beta = self.addr_one;
        for _ in 0..=max_msg_len {
            cur_beta = self.ext_mul(cur_beta, beta_logup_addr);
            beta_pows.push(cur_beta);
        }
        let mut sum_num = addr_zero;
        let mut sum_denom = addr_zero;
        for (ia, &eq_3b) in interactions.iter().zip(eq_3bs.iter()) {
            // num = node_vals[count]
            let num_i = node_vals[ia.count];
            // denom = sum_j(node_vals[msg[j]] * beta^j) + (bus_index+1) * beta^|msg|
            let mut denom_i = addr_zero;
            for (j, &msg_idx) in ia.message.iter().enumerate() {
                let msg_val = node_vals[msg_idx];
                let term = self.ext_mul(msg_val, beta_pows[j]);
                denom_i = self.ext_add(denom_i, term);
            }
            // (bus_index + 1) as base-field constant
            let bus_p1_val = F::from_u32(ia.bus_index as u32 + 1);
            let bus_p1_addr = self.write_const(Block([bus_p1_val, F::ZERO, F::ZERO, F::ZERO]));
            let bus_term = self.ext_mul(bus_p1_addr, beta_pows[ia.message.len()]);
            denom_i = self.ext_add(denom_i, bus_term);
            // Weight by eq_3b
            let weighted_num = self.ext_mul(eq_3b, num_i);
            let weighted_denom = self.ext_mul(eq_3b, denom_i);
            sum_num = self.ext_add(sum_num, weighted_num);
            sum_denom = self.ext_add(sum_denom, weighted_denom);
        }
        // interaction_num = norm_factor * eq_sharp_ns[n_lift] * sum_num
        let num_scaled = self.ext_mul(norm_factor_addr, sum_num);
        let interaction_num = self.ext_mul(num_scaled, eq_sharp_ns_n_lift);
        // interaction_denom = eq_sharp_ns[n_lift] * sum_denom
        let interaction_denom = self.ext_mul(eq_sharp_ns_n_lift, sum_denom);
        (interaction_num, interaction_denom)
    }

    /// Compute (interaction_num, interaction_denom, constraint_eval) for a single trace t.
    /// Returns (num, denom, c_eval) where:
    ///   interactions_evals += [num, denom] and constraints_evals += [c_eval].
    #[allow(clippy::too_many_arguments)]
    pub(super) fn compute_bc_final_for_trace(
        &mut self,
        vk: &RecursionVkLayout,
        trace_idx: usize,
        xi_addrs: &[u32],
        r0_bc: u32,
        bc_r_challenges: &[u32],
        eq_ns: &[u32],
        eq_sharp_ns: &[u32],
        per_trace_common: &[Vec<(u32, u32)>],
        per_trace_preproc: &[Option<Vec<(u32, u32)>>],
        per_trace_cached: &[Vec<Vec<(u32, u32)>>],
        per_air_pv_addrs: &[Vec<u32>],
        beta_logup_addr: u32,
        lambda_bc: u32,
        stacked_idx_ref: &mut usize,
    ) -> (u32, u32, u32) {
        let air_idx = vk.trace_ordering[trace_idx];
        let air = &vk.per_air[air_idx];
        let n = vk.n_per_trace[trace_idx];
        let n_lift = n.max(0) as usize;
        let l_skip = vk.l_skip;
        let n_logup = vk.n_logup;
        let addr_zero = self.addr_zero;

        // Compute rs_n and l for this trace.
        let (l, rs_n): (usize, Vec<u32>) = if n.is_negative() {
            let abs_n = n.unsigned_abs();
            // rs_n = [r0_bc^{2^abs_n}]
            let mut r0_pow = r0_bc;
            for _ in 0..abs_n {
                r0_pow = self.ext_mul(r0_pow, r0_pow);
            }
            (l_skip.wrapping_add_signed(n), vec![r0_pow])
        } else {
            // rs_n = [r0_bc, bc_r_challenges[0..n_lift]]
            let mut rs = vec![r0_bc];
            rs.extend_from_slice(&bc_r_challenges[..n_lift]);
            (l_skip, rs)
        };

        // omega for this trace: two_adic_generator(l).
        let omega: F = F::two_adic_generator(l);

        // Compute is_first_row and is_last_row.
        let (is_first_row, is_last_row) = self.compute_is_first_last_row_circuit(l, omega, &rs_n);
        let is_transition = self.ext_sub(self.addr_one, is_last_row);

        // Build partitioned_main: [cached_0, ..., common_main].
        let mut partitioned_main: Vec<Vec<(u32, u32)>> = per_trace_cached[trace_idx].clone();
        partitioned_main.push(per_trace_common[trace_idx].clone());

        let preprocessed = per_trace_preproc[trace_idx].as_ref();
        let pv_addrs = &per_air_pv_addrs[air_idx];

        // Evaluate all DAG nodes.
        let node_vals = self.eval_dag_nodes_circuit(
            &air.eval_dag,
            is_first_row,
            is_last_row,
            is_transition,
            &partitioned_main,
            preprocessed,
            pv_addrs,
        );

        // Constraint evaluation: sum(lambda_bc^i * node_vals[constraint_idx[i]]).
        let mut constraint_eval = addr_zero;
        let mut lambda_pow = self.addr_one;
        for &cidx in &air.eval_dag.constraint_idx {
            let term = self.ext_mul(lambda_pow, node_vals[cidx]);
            constraint_eval = self.ext_add(constraint_eval, term);
            lambda_pow = self.ext_mul(lambda_pow, lambda_bc);
        }
        // constraints_eval = eq_ns[n_lift] * constraint_eval
        let c_eval = self.ext_mul(eq_ns[n_lift], constraint_eval);

        // Interaction evaluation.
        // Compute eq_3b per interaction (global stacked_idx tracking).
        let stacked_idx_start = *stacked_idx_ref;
        let eq_3bs: Vec<u32> = air
            .eval_dag
            .interactions
            .iter()
            .map(|_| {
                let b_int = *stacked_idx_ref >> (l_skip + n_lift);
                *stacked_idx_ref += 1 << (l_skip + n_lift);
                self.eq_3b_for_interaction_circuit(b_int, n_lift, n_logup, l_skip, xi_addrs)
            })
            .collect();
        let _ = stacked_idx_start;

        let (interaction_num, interaction_denom) = self.compute_trace_interaction_evals_circuit(
            &eq_3bs,
            &node_vals,
            &air.eval_dag.interactions,
            beta_logup_addr,
            n_lift,
            n,
            eq_sharp_ns[n_lift],
            r0_bc,
            bc_r_challenges,
        );

        (interaction_num, interaction_denom, c_eval)
    }

    /// Compute (eq, rot) = eval_eq_rot_cube(x, y) in the circuit.
    /// Matches poly_common::eval_eq_rot_cube: iterates i in (0..n).rev().
    pub(super) fn eval_eq_rot_cube_circuit(&mut self, x: &[u32], y: &[u32]) -> (u32, u32) {
        debug_assert_eq!(x.len(), y.len());
        let mut rot = self.addr_one;
        let mut eq = self.addr_one;
        for i in (0..x.len()).rev() {
            let xi = x[i];
            let yi = y[i];
            // new_eq = x[i]*y[i] + (1-x[i])*(1-y[i])
            let new_eq = self.eq_factor(xi, yi);
            // new_rot = x[i]*(1-y[i])*eq + (1-x[i])*y[i]*rot
            let one_m_yi = self.ext_sub(self.addr_one, yi);
            let x_1my = self.ext_mul(xi, one_m_yi);
            let term1 = self.ext_mul(x_1my, eq);
            let one_m_xi = self.ext_sub(self.addr_one, xi);
            let omx_y = self.ext_mul(one_m_xi, yi);
            let term2 = self.ext_mul(omx_y, rot);
            let new_rot = self.ext_add(term1, term2);
            eq = self.ext_mul(eq, new_eq);
            rot = new_rot;
        }
        (eq, rot)
    }

    /// Compute eval_rot_kernel_prism(l, x, y) in the circuit.
    /// Matches poly_common::eval_rot_kernel_prism.
    pub(super) fn eval_rot_kernel_prism_circuit(&mut self, l: usize, x: &[u32], y: &[u32]) -> u32 {
        debug_assert_eq!(x.len(), y.len());
        // omega = two_adic_generator(l) — compile-time constant
        let omega = F::two_adic_generator(l);
        let omega_addr = self.write_const(Block([omega, F::ZERO, F::ZERO, F::ZERO]));
        // y0_omega = y[0] * omega
        let y0_omega = self.ext_mul(y[0], omega_addr);
        // (eq_cube, rot_cube) = eval_eq_rot_cube(x[1..], y[1..])
        let (eq_cube, rot_cube) = self.eval_eq_rot_cube_circuit(&x[1..], &y[1..]);
        // a = eval_eq_uni(l, x[0], y0_omega) * eq_cube
        let eq_uni = self.eval_eq_uni_circuit(l, x[0], y0_omega);
        let a = self.ext_mul(eq_uni, eq_cube);
        // b = eval_eq_uni_at_one(l, x[0]) * eval_eq_uni_at_one(l, y0_omega) * (rot_cube - eq_cube)
        let eqat1_x = self.eval_eq_uni_at_one_circuit(l, x[0]);
        let eqat1_y = self.eval_eq_uni_at_one_circuit(l, y0_omega);
        let rot_m_eq = self.ext_sub(rot_cube, eq_cube);
        let eqat1_prod = self.ext_mul(eqat1_y, rot_m_eq);
        let b = self.ext_mul(eqat1_x, eqat1_prod);
        self.ext_add(a, b)
    }

    /// Compute eval_eq_mle(x, y) = prod_i eq_factor(x[i], y[i]) in the circuit.
    pub(super) fn eval_eq_mle_circuit(&mut self, x: &[u32], y: &[u32]) -> u32 {
        debug_assert_eq!(x.len(), y.len());
        let mut acc = self.addr_one;
        for (&xi, &yi) in x.iter().zip(y.iter()) {
            let f = self.eq_factor(xi, yi);
            acc = self.ext_mul(acc, f);
        }
        acc
    }

    /// Evaluate univariate poly P(x) = Σ_i coeffs[i]*x^i via the HornerEval
    /// precompile chip (one instruction, one chip row per coefficient).
    /// `coeffs` in ascending-degree order; `x` can be an F or EF address.
    /// Replaces a 2-ExtAlu-per-coefficient Horner chain.
    pub(super) fn horner_eval_circuit(&mut self, coeffs: &[u32], x: u32) -> u32 {
        if coeffs.is_empty() {
            return self.addr_zero;
        }
        let out = self.alloc();
        for &c in coeffs {
            self.mark_read(c);
        }
        self.mark_read(x);
        // Evaluation order (highest degree first), FRONT-padded with zero addresses
        // to a DATAPAR multiple: leading zero coefficients do not change P(x).
        // MemoryConst must account those reads so the memory bus balances.
        let az = self.addr_zero;
        let dp = crate::primitives::consts::HORNER_EVAL_DATAPAR;
        let pad = (dp - coeffs.len() % dp) % dp;
        for _ in 0..pad {
            self.mark_read(az);
        }
        let coeff_addrs: Vec<Address<F>> = std::iter::repeat_n(az, pad)
            .chain(coeffs.iter().rev().copied())
            .map(|a| Address(F::from_u32(a)))
            .collect();
        self.instructions
            .push(Instruction::HornerEval(Box::new(HornerEvalInstr {
                coeff_addrs,
                x_addr: Address(F::from_u32(x)),
                out_addr: Address(F::from_u32(out)),
                mult: F::ZERO, // backfilled
            })));
        out
    }

    /// Compute [x, x^2, x^4, ..., x^{2^{n-1}}] using ext_mul (EF squaring).
    /// Returns (last_pow, left_pows) where last_pow = x^{2^{n-1}} and
    /// left_pows = [x, x^2, ..., x^{2^{n-2}}] (length n-1, empty when n=1).
    pub(super) fn pow_sequence_ext(&mut self, x: u32, n: usize) -> (u32, Vec<u32>) {
        let mut pows: Vec<u32> = Vec::with_capacity(n.saturating_sub(1));
        let mut cur = x;
        for _ in 0..n.saturating_sub(1) {
            pows.push(cur);
            cur = self.ext_mul(cur, cur);
        }
        (cur, pows)
    }

    /// Compute [x, x^2, x^4, ..., x^{2^{n-1}}] using base_mul (F squaring).
    /// Returns (last_pow, left_pows) — same structure as pow_sequence_ext.
    pub(super) fn pow_sequence_base(&mut self, x: u32, n: usize) -> (u32, Vec<u32>) {
        let mut pows: Vec<u32> = Vec::with_capacity(n.saturating_sub(1));
        let mut cur = x;
        for _ in 0..n.saturating_sub(1) {
            pows.push(cur);
            cur = self.base_mul(cur, cur);
        }
        (cur, pows)
    }

    /// General binary k-fold: implements `binary_k_fold(values, alphas, x)` from the WHIR verifier.
    ///
    /// `vals`: 2^k EF circuit addresses (consumed; only vals[0] is the result).
    /// `alphas`: k EF circuit addresses (one per fold stage).
    /// `zi_root_f`: F addr of x = zi_root = omega^{query_index}.
    /// `zi_root_inv_f`: F addr of x^{-1} = zi_root_inv (the circuit computes halving internally).
    ///
    /// Matches the WHIR verifier's `binary_k_fold` reference implementation.
    pub(super) fn binary_k_fold_circuit(
        &mut self,
        mut vals: Vec<u32>,
        alphas: &[u32],
        zi_root_f: u32,
        zi_root_inv_f: u32,
    ) -> u32 {
        let k = alphas.len();
        let n = vals.len();
        debug_assert_eq!(n, 1 << k);

        // Twist constants omega_k^i and omega_k^{-i} for i = 0..2^{k-1}.
        // Cached by value across calls (they only depend on k, which is fixed),
        // so each constant's Mem(Write) is emitted once per program, not per query.
        let omega_k = F::two_adic_generator(k);
        let omega_k_inv = Field::inverse(&omega_k);
        let half = 1usize << (k - 1);

        let mut tw_val = F::ONE;
        let mut inv_tw_val = F::ONE;
        let mut tw_addrs = Vec::with_capacity(half);
        let mut inv_tw_addrs = Vec::with_capacity(half);
        for _ in 0..half {
            tw_addrs.push(self.const_f(tw_val.as_canonical_u32()));
            inv_tw_addrs.push(self.const_f(inv_tw_val.as_canonical_u32()));
            tw_val *= omega_k;
            inv_tw_val *= omega_k_inv;
        }

        // Successive squarings of zi_root and zi_root_inv.
        // xi_pows[j] = zi_root^{2^j}, xi_inv_pows[j] = zi_root_inv^{2^j}.
        let mut xi_pows = Vec::with_capacity(k);
        let mut xi_inv_pows = Vec::with_capacity(k);
        let mut xi = zi_root_f;
        let mut xi_inv = zi_root_inv_f;
        for _ in 0..k {
            xi_pows.push(xi);
            xi_inv_pows.push(xi_inv);
            xi = self.base_mul(xi, xi);
            xi_inv = self.base_mul(xi_inv, xi_inv);
        }

        for j in 0..k {
            let m = n >> (j + 1);
            for i in 0..m {
                let tw_idx = i << j;
                // One BinaryFoldStep instruction per butterfly:
                //   vals[i] += (alpha_j - tw*xi_j) * (vals[i] - vals[i+m])
                //              * (inv_tw * xi_inv_j / 2)
                vals[i] = self.binary_fold_step(
                    tw_addrs[tw_idx],
                    xi_pows[j],
                    inv_tw_addrs[tw_idx],
                    xi_inv_pows[j],
                    alphas[j],
                    vals[i],
                    vals[i + m],
                );
            }
            // Only vals[0..m] are needed for subsequent stages.
        }

        vals[0]
    }

    /// Emit one BinaryFoldStep instruction (see BinaryFoldStepChip). Returns the
    /// address of out = v_lo + (alpha - tw*xi) * (v_lo - v_hi) * (inv_tw*xi_inv/2).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn binary_fold_step(
        &mut self,
        tw: u32,
        xi: u32,
        inv_tw: u32,
        xi_inv: u32,
        alpha: u32,
        v_lo: u32,
        v_hi: u32,
    ) -> u32 {
        let out = self.alloc();
        for a in [tw, xi, inv_tw, xi_inv, alpha, v_lo, v_hi] {
            self.mark_read(a);
        }
        self.instructions
            .push(Instruction::BinaryFoldStep(Box::new(BinaryFoldStepInstr {
                tw_addr: Address(F::from_u32(tw)),
                xi_addr: Address(F::from_u32(xi)),
                inv_tw_addr: Address(F::from_u32(inv_tw)),
                xi_inv_addr: Address(F::from_u32(xi_inv)),
                alpha_addr: Address(F::from_u32(alpha)),
                v_lo_addr: Address(F::from_u32(v_lo)),
                v_hi_addr: Address(F::from_u32(v_hi)),
                out_addr: Address(F::from_u32(out)),
                mult: F::ZERO, // backfilled
            })));
        out
    }
}
