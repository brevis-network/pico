//! Convert verifier-circuit lowering: `Builder::verify_one` (the per-proof orchestration) and
//! `Builder::finish`, plus the public `ConvertVerifierCircuit` entry points that assemble the program.

use super::*;

impl<F: PrimeField32 + TwoAdicField> Builder<F> {
    // ─── verify_one: verify a single STARK proof (no Deferred (PVs) / finish) ─────────────

    pub(super) fn verify_one(&mut self, vk: &RecursionVkLayout) -> ProofPvAddrs {
        self.verify_one_in_mode(vk, None, false).0
    }

    /// [`Self::verify_one`] for a recursion child of a parent in whitelist mode: the child's vk
    /// pre-hash is a baked constant, the one every key at the layout's heights has
    /// (`extract_recursion_vk_layout_from_heights`), where `verify_one` takes it as a witness.
    ///
    /// The parent reads the child under one row's layout and checks its key against the
    /// whitelist, whose leaf is hashed from the pre-hash and the merged commitment
    /// (`assert_children_whitelisted`). With the pre-hash a witness, a key of any row is a member,
    /// and nothing but the Merkle hash of its commitment's rows keeps it from being read under
    /// this row's layout, which does not hold between rows whose commitments are equally wide or
    /// both at most a sponge block wide. With it baked, the leaf is that of a key of this row or
    /// the membership check fails.
    pub(super) fn verify_one_of_row(&mut self, vk: &RecursionVkLayout) -> ProofPvAddrs {
        assert!(
            vk.merged_preprocessed_commit.is_some(),
            "a row is what a merged-preprocessed (recursion) key is padded to"
        );
        self.verify_one_in_mode(vk, None, true).0
    }

    /// [`Self::verify_one`] for a child in the external LogUp challenge mode: a group proof of
    /// the global LogUp. The challenges `alpha` and `beta` are the caller's, as base-field
    /// coefficients; the verifier absorbs them where an internal-mode child grinds and samples.
    /// Returns the proof's fractional sum `(p, q)` beside the addresses, as coefficients: the
    /// numerator the proof claims, which the GKR root is held to, and the denominator.
    ///
    /// The child's vk pre-hash is a baked constant here, where `verify_one` takes it as a
    /// witness: a group proof has no whitelist membership to pin its key, and the key is what
    /// says the table's rows are summed and nothing else.
    pub(super) fn verify_one_external(
        &mut self,
        vk: &RecursionVkLayout,
        alpha: [u32; EXTENSION_DEGREE],
        beta: [u32; EXTENSION_DEGREE],
    ) -> (ProofPvAddrs, GlobalSum) {
        let (pvs, sum) = self.verify_one_in_mode(vk, Some((alpha, beta)), true);
        (pvs, sum.expect("an external-mode child hands back its sum"))
    }

    /// `baked_pre_hash`: the child's vk pre-hash is the layout's, a constant of the program
    /// (an external-mode child's always; an internal-mode one's under [`Self::verify_one_of_row`]),
    /// instead of a witness.
    fn verify_one_in_mode(
        &mut self,
        vk: &RecursionVkLayout,
        external: Option<([u32; EXTENSION_DEGREE], [u32; EXTENSION_DEGREE])>,
        baked_pre_hash: bool,
    ) -> (ProofPvAddrs, Option<GlobalSum>) {
        assert!(
            baked_pre_hash || external.is_none(),
            "an external-mode child's pre-hash is baked"
        );
        assert_eq!(
            external.is_some(),
            vk.external_logup,
            "the child's LogUp challenge mode and the verifier's entry point disagree"
        );
        let addr_zero = self.addr_zero;
        let addr_one = self.addr_one;

        // Write preprocessed-commit constants per AIR — EXCEPT app-identity preprocessed tables
        // (the RISC-V program table), whose commit is WITNESSED in the per-air loop below (so the
        // program stays out of the baked circuit → app-independent). App-prep entries are `None`
        // here and filled into `app_prep_commit_addrs` at observe time.
        let preproc_const_addrs: Vec<Option<[u32; 8]>> = vk
            .per_air
            .iter()
            .map(|air| {
                if air.app_preprocessed {
                    return None;
                }
                air.preprocessed_commit.map(|commit| {
                    std::array::from_fn(|i| self.write_const(Block::from(F::from_u32(commit[i]))))
                })
            })
            .collect();
        // Witnessed app-preprocessed commits (RISC-V program table), filled at observe time.
        let mut app_prep_commit_addrs: Vec<Option<[u32; 8]>> = vec![None; vk.per_air.len()];

        // Merged-preprocessed mode: the machine's single multi-matrix prep commitment is a
        // layout constant, observed once right after common_main_commit (host order); each
        // prep AIR then observes its log_height in the per-air loop like a non-prep AIR
        // (per-air `preprocessed_commit` is `None` for every AIR in this mode).
        //
        // Intentional mechanism difference from the host: the host reads each air's presence
        // and log_height off the proof and pins merged prep heights to the vk
        // (`PreprocessedTraceHeightMismatch`); here both are baked at build time (n_per_trace /
        // stacking layout / the merged commit constant) and absorbed as constants, so the
        // transcript names the layout that reads the child. Witnessing them instead would let
        // one child transcript be valid under every layout with the same present chips and
        // stacked widths, and a cheater could pick the layout after seeing the LogUp
        // challenges.
        // Ordering contract: this circuit observes column openings and assembles the stacking
        // t_claims in ONE pass (per trace: prep then cached). The host arranges t_claims per
        // COMMIT (merged mode: all prep traces consecutively as commit 1, cached after). The
        // two orders coincide exactly when no AIR carries cached mains — true for the
        // recursion machines that use merged preprocessing. Fail loudly if that ever changes.
        if vk.merged_preprocessed_commit.is_some() {
            assert!(
                vk.per_air.iter().all(|a| a.num_cached_mains == 0),
                "merged-preprocessed verify_one assumes no cached mains (t_claims ordering)"
            );
        }

        // ── Phase 1: observe VK hash + common_main_commit ─────────────────────
        // The vk pre-hash seeds the Fiat-Shamir transcript exactly as on the host. It covers
        // machine + shape only (see `compute_vk_pre_hash`), so it is no application anchor.
        // Application identity travels separately: the witnessed program-table commitment feeds
        // the `riscv_vk_digest` exe anchor (convert layer).
        //
        // Where the caller asks, it is baked: an external-mode child's (`verify_one_external`),
        // and a recursion child's in whitelist mode (`verify_one_of_row`), whose whitelist leaf
        // is hashed from these addresses. Otherwise it travels on the witness stream, and the
        // program takes what it is given: the layout's heights and constraints are baked
        // either way.
        let vk_pre_hash_addrs = if baked_pre_hash {
            let baked = vk.vk_pre_hash.map(|limb| self.const_f(limb));
            self.observe_const_digest(baked);
            baked
        } else {
            self.observe_digest_addrs() // vk_pre_hash from witness
        };
        let common_main_commit_addrs = self.observe_digest_addrs(); // common_main_commit
                                                                    // Merged-preprocessed commitment (the recursion child's program identity): WITNESSED
                                                                    // (hint + absorb) at the same transcript position the host observes it, with the same
                                                                    // value — transcript-neutral, same move as the app-prep commit above. This makes the
                                                                    // parent circuit independent of the child's identity (the combine collapse); the child
                                                                    // proof still verifies against the witnessed value (it is the prep stacking root).
                                                                    //
                                                                    // BINDING CONTRACT: in whitelist mode (vk_verification), the witnessed commitment is
                                                                    // pinned in-circuit by the VK-whitelist membership check below (its leaf hashes this
                                                                    // value and the vk pre-hash, which that mode bakes: the key is a member, and of this
                                                                    // layout's row); with vk_verification OFF it is NOT pinned — a parent then attests "some
                                                                    // child verified under some merged commitment" (fail-open dev mode), and only the
                                                                    // apex's verify-under-the-honest-root-VK covers the root node itself.
        let merged_prep_addrs: Option<[u32; 8]> = vk
            .merged_preprocessed_commit
            .is_some()
            .then(|| self.observe_digest_addrs());

        // ── Phase 2: per-AIR preamble ─────────────────────────────────────────
        let mut riscv_pv_f_addrs: Option<Vec<u32>> = None;
        let mut per_air_cached_commit_addrs: Vec<Vec<[u32; 8]>> = vec![vec![]; vk.per_air.len()];
        // per_air_pv_addrs[air_idx]: F-element addresses for this AIR's public values.
        // Saved for all present AIRs that use public values in their EvalDag constraints.
        let mut per_air_pv_addrs: Vec<Vec<u32>> = vec![vec![]; vk.per_air.len()];
        // Trace-height LogUp overflow bound (host verifier: per bus,
        // Σ_air 2^lifted_log_height * count_weight below the base-field order, guarding the
        // LogUp fractional sum against mod-p wraparound): NOT re-evaluated in-circuit, and it
        // does not need to be — child heights are BAKED into this program (absorbed below as
        // constants, fixed by the layout; a proof of different heights does not verify), and
        // every layout is rejected at creation if its baked heights violate the bound (the
        // unconditional assert in `extract_recursion_vk_layout_from_heights`, which the
        // whitelist builder routes the entire vk universe through). If heights ever become
        // witnessed, the bound must move in-circuit — see the enforcement-point comment in
        // layout.rs.
        for (air_idx, air) in vk.per_air.iter().enumerate() {
            if !air.is_required {
                // is_air_present: 0 = absent, 1 = present, at the host's transcript position.
                self.absorb_f(if air.is_present { addr_one } else { addr_zero });
            }
            if air.is_present {
                if air.app_preprocessed {
                    // App-identity preprocessed table (program): witness the commit (hint +
                    // absorb) at the SAME transcript position a baked const would occupy — the
                    // absorbed value is identical (the real program commit), so the transcript is
                    // unchanged; only the source (const → witness) differs. Captured for the
                    // WHIR stacking root below.
                    let addrs = self.observe_digest_addrs();
                    app_prep_commit_addrs[air_idx] = Some(addrs);
                } else if let Some(preproc_addrs) = preproc_const_addrs[air_idx] {
                    self.observe_const_digest(preproc_addrs);
                } else {
                    let log_height = air.log_height.expect("a present AIR has a log_height");
                    let h = self.const_f(log_height as u32);
                    self.absorb_f(h); // log_height
                }
                for _ in 0..air.num_cached_mains {
                    let caddrs = self.observe_digest_addrs();
                    per_air_cached_commit_addrs[air_idx].push(caddrs);
                }
                // Save PV addresses: for Deferred (PVs) (recursion children's pvs), for the
                // RISCV→recursion PV translation, and for BC final assertion.
                let save_for_bc = air.uses_public_values;
                let save_for_d6 =
                    air.num_public_values == RECURSION_NUM_PVS && riscv_pv_f_addrs.is_none();
                // A RISCV child's Global air (present in EVERY chunk — unlike CPU / MemInit,
                // absent in memory-only or precompile-table chunks) carries the riscv
                // PublicValues copy, and the carrier binding ties it to the Cpu / Ecall /
                // MemInit / MemFinal pv slices — always capture all of their addresses,
                // independent of whether their constraints read pvs. Which air is which is the
                // caller's to say, by air id: Global, MemInit and MemFinal carry the same number
                // of public values.
                let save_for_tie =
                    air.num_public_values == RISCV_NUM_PVS || air.num_public_values == MAX_NUM_PVS;
                if save_for_d6 || save_for_bc || save_for_tie {
                    let addrs: Vec<u32> = (0..air.num_public_values)
                        .map(|_| self.observe_f_for_chip())
                        .collect();
                    if save_for_d6 {
                        riscv_pv_f_addrs = Some(addrs.clone());
                    }
                    per_air_pv_addrs[air_idx] = addrs;
                } else {
                    for _ in 0..air.num_public_values {
                        self.observe_f();
                    }
                }
            }
        }

        // Build stacking commit roots (packed into DIGEST_BLOCKS blocks each, reused across all
        // queries) in trace_id order for WHIR query phase Merkle verify.
        let mut stacking_commit_blocks: Vec<[u32; DIGEST_BLOCKS]> = Vec::new();
        stacking_commit_blocks.push(self.pack_digest(common_main_commit_addrs));
        // Merged-preprocessed mode: the merged commitment is stacking commit 1; per-trace
        // commits below then carry cached mains only (per-air preproc consts are all None).
        if let Some(addrs) = merged_prep_addrs {
            stacking_commit_blocks.push(self.pack_digest(addrs));
        }
        // The roots are matched to `vk.stacking_widths` by position where the queries are
        // checked, and that list has the present AIRs' commitments only. An absent AIR's baked
        // root is packed here all the same, so each has to come after the
        // last root of a present AIR: `trace_ordering` puts the absent AIRs last.
        let mut matched_roots = stacking_commit_blocks.len();
        let mut past_the_present = false;
        for &air_id in &vk.trace_ordering {
            let before = stacking_commit_blocks.len();
            // Preprocessed stacking root: baked const for machine tables (byte), witnessed addrs
            // for the app-identity table (program). Exactly one of the two is Some per AIR.
            if let Some(preproc) = preproc_const_addrs[air_id] {
                stacking_commit_blocks.push(self.pack_digest(preproc));
            } else if let Some(app_preproc) = app_prep_commit_addrs[air_id] {
                stacking_commit_blocks.push(self.pack_digest(app_preproc));
            }
            for &caddrs in &per_air_cached_commit_addrs[air_id] {
                stacking_commit_blocks.push(self.pack_digest(caddrs));
            }
            let roots = stacking_commit_blocks.len() - before;
            if vk.per_air[air_id].is_present {
                assert!(
                    !past_the_present || roots == 0,
                    "AIR {air_id}'s stacked commitment follows an absent AIR's: it would be \
                     checked against another commitment's width"
                );
                matched_roots += roots;
            } else {
                past_the_present |= roots > 0;
            }
        }
        assert_eq!(
            matched_roots,
            vk.stacking_widths.len(),
            "the stacked commitments of the present AIRs are not the ones the layout sized"
        );

        // ── Phase 3: GKR (fractional sumcheck) ───────────────────────────────
        let n_logup = vk.n_logup;
        let total_gkr_rounds = vk.l_skip + n_logup;

        // alpha_logup is saved for the GKR final-claim consistency check, beta_logup for the BC
        // final assertion (interaction denominators). Internal mode: grind, then sample both.
        // External mode: absorb the caller's, at the same transcript position.
        let (alpha_logup_addr, beta_logup_addr) = match external {
            None => {
                self.check_witness(vk.logup_pow_bits);
                let alpha = self.sample_ef_for_chip();
                let beta = self.sample_ef_for_chip();
                (alpha, beta)
            }
            Some((alpha, beta)) => {
                for lane in alpha.into_iter().chain(beta) {
                    self.absorb_f(lane);
                }
                (self.pack_ef(alpha), self.pack_ef(beta))
            }
        };
        // The fractional sum an external-mode child hands back.
        let mut logup_sum: Option<GlobalSum> = None;
        assert!(
            external.is_none() || n_logup > 0,
            "an external-mode child without interactions has no sum to hand back"
        );

        // Deferred (GKR/BC): hold GKR final claims until after Phase 4.
        let mut gkr_numer: Option<u32> = None;
        let mut gkr_denom: Option<u32> = None;

        // xi_addrs: GKR multilinear evaluation point, length l_skip + n_logup (then extended).
        let mut xi_addrs: Vec<u32> = Vec::new();

        if n_logup > 0 {
            // Round 0: observe q0_claim + layer_claims[0], FracFold, sample mu. An external-mode
            // proof carries its numerator claim too, ahead of q0_claim.
            let p0_claim = external.map(|_| self.observe_ef_full_for_chip());
            let (q0_claim_addr, q0_claim_lanes) = self.observe_ef_full_for_chip();

            let p0 = self.observe_ef_for_chip();
            let q0 = self.observe_ef_for_chip();
            let p1 = self.observe_ef_for_chip();
            let q1 = self.observe_ef_for_chip();
            let (out_p0, out_q0) = self.frac_fold(p0, q0, p1, q1);

            // (a) Numerator product: zero (the LogUp zero-sum check), or in external mode the
            // claim the proof hands back for its caller to add up.
            match p0_claim {
                None => self.assert_ext_eq(out_p0, addr_zero),
                Some((p0_claim_addr, p0_claim_lanes)) => {
                    self.assert_ext_eq(out_p0, p0_claim_addr);
                    logup_sum = Some((p0_claim_lanes, q0_claim_lanes));
                }
            }
            // (b) Denominator product must equal q0_claim.
            self.assert_ext_eq(out_q0, q0_claim_addr);

            let mu0 = self.sample_ef_for_chip();
            let mut numer_claim = self.interp_linear(p0, p1, mu0);
            let mut denom_claim = self.interp_linear(q0, q1, mu0);

            let mut prev_gkr_r: Vec<u32> = vec![mu0];

            for round in 1..total_gkr_rounds {
                let lambda = self.sample_ef_for_chip();
                let lambda_dc = self.ext_mul(lambda, denom_claim);
                let mut claim = self.ext_add(numer_claim, lambda_dc);

                let mut curr_round_r: Vec<u32> = Vec::with_capacity(round);
                let mut eq = self.addr_one;

                for k in 0..round {
                    let s1 = self.observe_ef_for_chip();
                    let s2 = self.observe_ef_for_chip();
                    let s3 = self.observe_ef_for_chip();
                    let r = self.sample_ef_for_chip();
                    let xi_k = prev_gkr_r[k];
                    // Precompile round: derives s0 = claim - s1 (sum check by
                    // construction), folds the cubic to p(r) and accumulates the
                    // eq product, all in one instruction.
                    let (new_claim, new_eq) =
                        self.gkr_sumcheck_round(claim, s1, s2, s3, r, xi_k, eq);
                    claim = new_claim;
                    eq = new_eq;
                    curr_round_r.push(r);
                }

                let lp0 = self.observe_ef_for_chip();
                let lq0 = self.observe_ef_for_chip();
                let lp1 = self.observe_ef_for_chip();
                let lq1 = self.observe_ef_for_chip();
                let (out_pi, out_qi) = self.frac_fold(lp0, lq0, lp1, lq1);

                let mu = self.sample_ef_for_chip();

                // Consistency check: (out_p + lambda * out_q) * eq == claim.
                let lambda_oq = self.ext_mul(lambda, out_qi);
                let combined = self.ext_add(out_pi, lambda_oq);
                let expected = self.ext_mul(combined, eq);
                self.assert_ext_eq(expected, claim);

                numer_claim = self.interp_linear(lp0, lp1, mu);
                denom_claim = self.interp_linear(lq0, lq1, mu);

                prev_gkr_r = std::iter::once(mu).chain(curr_round_r).collect();
            }
            gkr_numer = Some(numer_claim);
            gkr_denom = Some(denom_claim);
            xi_addrs = prev_gkr_r;
        }

        // Extra xi samples: fill up to l_skip + max(n_max, n_logup) total.
        let n_max = vk.n_max;
        let n_global = n_max.max(n_logup);
        let xi_so_far = if n_logup > 0 { total_gkr_rounds } else { 0 };
        let xi_target = vk.l_skip + n_global;
        for _ in xi_so_far..xi_target {
            xi_addrs.push(self.sample_ef_for_chip());
        }

        // lambda (batch constraint)
        let lambda_bc = self.sample_ef_for_chip();

        // ── Phase 4: BatchConstraint ──────────────────────────────────────────

        // BC terms: only PRESENT AIRs contribute to the RISCV verifier's Fiat-Shamir transcript.
        // Absent optional AIRs have no BC terms in the proof; they use addr_zero (= EF zero).
        // Reading hints only for present AIRs keeps the transcript consistent with the RISCV verifier.
        let mut num_term_addrs: Vec<u32> = Vec::with_capacity(vk.trace_ordering.len());
        let mut denom_term_addrs: Vec<u32> = Vec::with_capacity(vk.trace_ordering.len());
        for &air_idx in &vk.trace_ordering {
            let air = &vk.per_air[air_idx];
            if air.is_present {
                num_term_addrs.push(self.observe_ef_for_chip()); // 1 hint, absorb
                denom_term_addrs.push(self.observe_ef_for_chip()); // 1 hint, absorb
            } else {
                num_term_addrs.push(self.addr_zero); // 0 hints, zero EF value
                denom_term_addrs.push(self.addr_zero); // 0 hints, zero EF value
            }
        }

        // Deferred (GKR/BC): assert GKR final claims are consistent with per-AIR BC terms.
        if let (Some(numer_claim), Some(denom_claim)) = (gkr_numer, gkr_denom) {
            let mut sum_n = addr_zero;
            for &na in &num_term_addrs {
                sum_n = self.ext_add(sum_n, na);
            }
            self.assert_ext_eq(numer_claim, sum_n);
            let mut sum_d = addr_zero;
            for &da in &denom_term_addrs {
                sum_d = self.ext_add(sum_d, da);
            }
            let alpha_plus_sum_d = self.ext_add(alpha_logup_addr, sum_d);
            self.assert_ext_eq(denom_claim, alpha_plus_sum_d);
        }

        // sample mu (batch constraint)
        let mu_bc = self.sample_ef_for_chip();

        // Observe univariate_round_coeffs.
        let s_deg = vk.max_constraint_degree + 1;
        let univar_len = s_deg * ((1usize << vk.l_skip) - 1) + 1;
        let mut bc_univar_coeffs: Vec<u32> = Vec::with_capacity(univar_len);
        for _ in 0..univar_len {
            bc_univar_coeffs.push(self.observe_ef_for_chip());
        }
        // sample r_0 (batch constraint) — saved for Deferred (stacking) stacking check.
        let r0_bc = self.sample_ef_for_chip();

        // Check 1: sum_claim == sum_univ_domain_s_0.
        // sum_claim = mu-hash of interleaved (num_term, denom_term) pairs.
        // IMPORTANT: only PRESENT AIRs contribute — do NOT advance cur_mu_pow for absent AIRs.
        // With fixed trace_ordering=[0..num_airs], absent AIRs may interleave with present AIRs.
        // Advancing cur_mu_pow for absent AIRs would give present AIRs higher mu^powers than the
        // RISCV verifier (which only iterates present traces with consecutive mu^0, mu^2, ...).
        let mut sum_claim = addr_zero;
        let mut cur_mu_pow = self.addr_one;
        for (&air_idx, (&na, &da)) in vk
            .trace_ordering
            .iter()
            .zip(num_term_addrs.iter().zip(denom_term_addrs.iter()))
        {
            if !vk.per_air[air_idx].is_present {
                continue; // absent AIR: zero contribution, must NOT advance cur_mu_pow
            }
            let term_n = self.ext_mul(na, cur_mu_pow);
            sum_claim = self.ext_add(sum_claim, term_n);
            cur_mu_pow = self.ext_mul(cur_mu_pow, mu_bc);
            let term_d = self.ext_mul(da, cur_mu_pow);
            sum_claim = self.ext_add(sum_claim, term_d);
            cur_mu_pow = self.ext_mul(cur_mu_pow, mu_bc);
        }
        // sum_univ_domain_s_0 = (sum of bc_univar_coeffs at step 1<<l_skip) * step
        let step = 1usize << vk.l_skip;
        let mut sum_univ = addr_zero;
        let mut idx = 0usize;
        while idx < bc_univar_coeffs.len() {
            sum_univ = self.ext_add(sum_univ, bc_univar_coeffs[idx]);
            idx += step;
        }
        let step_const = self.write_const(Block::from(F::from_u32(step as u32)));
        let sum_univ_scaled = self.ext_mul(sum_univ, step_const);
        self.assert_ext_eq(sum_claim, sum_univ_scaled);

        // Initial bc_claim = s_0(r_0) via Horner evaluation of bc_univar_coeffs
        // (HornerEval precompile; returns addr_zero when empty).
        let mut bc_claim: u32 = self.horner_eval_circuit(&bc_univar_coeffs, r0_bc);
        let mut bc_r_challenges: Vec<u32> = Vec::with_capacity(n_max);
        for _ in 0..n_max {
            let evals: Vec<u32> = (0..s_deg).map(|_| self.observe_ef_for_chip()).collect();
            let p0 = self.ext_sub(bc_claim, evals[0]);
            let sum = self.ext_add(p0, evals[0]);
            self.assert_ext_eq(sum, bc_claim);
            let r = self.sample_ef_for_chip();
            bc_r_challenges.push(r);
            let mut all_evals = Vec::with_capacity(s_deg + 1);
            all_evals.push(p0);
            all_evals.extend_from_slice(&evals);
            bc_claim = self.lagrange_eval_generic(&all_evals, r);
        }
        // bc_claim is asserted against evaluated_claim in the BC final assertion below;
        // lambda_bc feeds the stacking evaluation.

        // Column openings.
        // t_claim_addrs[i] = claim address for the i-th stacked column term.
        // t_claim_rot_addrs[i] = claim_rot address (addr_zero when need_rot=false, actual when true).
        let mut t_claim_addrs: Vec<u32> = Vec::new();
        let mut t_claim_rot_addrs: Vec<u32> = Vec::new();
        // Per-trace opening pairs (claim_addr, claim_rot_addr) for BC final assertion.
        let mut per_trace_common: Vec<Vec<(u32, u32)>> = vec![Vec::new(); vk.trace_ordering.len()];
        let mut per_trace_preproc: Vec<Option<Vec<(u32, u32)>>> =
            vec![None; vk.trace_ordering.len()];
        let mut per_trace_cached: Vec<Vec<Vec<(u32, u32)>>> =
            vec![Vec::new(); vk.trace_ordering.len()];

        // Phase 4a: common main columns, trace_id order.
        // For PRESENT AIRs: observe_ef_for_chip() reads hint and absorbs into transcript.
        // For ABSENT AIRs: no stream read and no absorb (uses addr_zero) — matches the RISCV
        //   verifier, which skips absent-AIR column openings entirely.
        for (trace_idx, &air_idx) in vk.trace_ordering.iter().enumerate() {
            let air = &vk.per_air[air_idx];
            for col_id in 0..air.num_common_main_cols {
                // Absent optional AIRs: skip entirely (no hint read, no absorb).
                // The RISCV verifier only absorbs column openings for present AIRs.
                // Using addr_zero (= EF zero) without reading from the stream keeps
                // the transcript and hint count consistent with the RISCV verifier.
                if !air.is_present {
                    // Absent AIR: no stream read, no absorb, no mle_open, no t_claim entry.
                    // Absent AIRs have no stacking contribution (stacking_col_layout excludes them).
                    // Adding addr_zero to t_claim_addrs would inflate stk_s0 computation unnecessarily.
                    per_trace_common[trace_idx].push((addr_zero, addr_zero));
                    // Do NOT push to t_claim_addrs / t_claim_rot_addrs for absent AIRs.
                    continue;
                }
                let claim_addr = self.observe_ef_for_chip();
                // RISCV verifier always observes claim_rot (via column_openings_by_rot):
                //   need_rot=True:  claim_rot = actual rotated value (from stream)
                //   need_rot=False: claim_rot = EF::ZERO (absorb EXTENSION_DEGREE zeros, no
                //   stream read)
                let claim_rot_addr = if air.need_rot {
                    self.observe_ef_for_chip()
                } else {
                    for _ in 0..EXTENSION_DEGREE {
                        self.absorb_f(addr_zero);
                    }
                    addr_zero
                };
                self.mle_open(air_idx, col_id, claim_addr);
                per_trace_common[trace_idx].push((claim_addr, claim_rot_addr));
                t_claim_addrs.push(claim_addr);
                t_claim_rot_addrs.push(claim_rot_addr);
            }
        }

        // Phase 4b: preprocessed + cached columns, trace_id order.
        // Absent AIRs: skip entirely (addr_zero, no stream reads, no absorb).
        // Present AIRs with need_rot=False: absorb claim only (NOT claim_rot zeros).
        //   The RISCV verifier does not observe claim_rot for need_rot=False AIRs.
        for (trace_idx, &air_idx) in vk.trace_ordering.iter().enumerate() {
            let air = &vk.per_air[air_idx];
            if air.has_preprocessed {
                let mut preproc_cols: Vec<(u32, u32)> = Vec::new();
                for col_id in 0..air.num_preprocessed_cols {
                    let (claim_addr, claim_rot_addr) = if air.is_present {
                        let claim_addr = self.observe_ef_for_chip();
                        let claim_rot_addr = if air.need_rot {
                            self.observe_ef_for_chip()
                        } else {
                            for _ in 0..EXTENSION_DEGREE {
                                self.absorb_f(addr_zero);
                            }
                            addr_zero
                        };
                        (claim_addr, claim_rot_addr)
                    } else {
                        // Absent AIR: no stream read, no absorb, no mle_open, no t_claim entry.
                        preproc_cols.push((addr_zero, addr_zero));
                        continue; // skip t_claim_addrs push for absent AIRs
                    };
                    self.mle_open(air_idx, col_id, claim_addr);
                    preproc_cols.push((claim_addr, claim_rot_addr));
                    t_claim_addrs.push(claim_addr);
                    t_claim_rot_addrs.push(claim_rot_addr);
                }
                per_trace_preproc[trace_idx] = Some(preproc_cols);
            }
            let mut cached_cols: Vec<Vec<(u32, u32)>> = Vec::new();
            for (cached_idx, &w) in air.cached_main_widths.iter().enumerate() {
                let mut one_cache: Vec<(u32, u32)> = Vec::new();
                for col_id in 0..w {
                    let (claim_addr, claim_rot_addr) = if air.is_present {
                        let claim_addr = self.observe_ef_for_chip();
                        let claim_rot_addr = if air.need_rot {
                            self.observe_ef_for_chip()
                        } else {
                            for _ in 0..EXTENSION_DEGREE {
                                self.absorb_f(addr_zero);
                            }
                            addr_zero
                        };
                        (claim_addr, claim_rot_addr)
                    } else {
                        // Absent AIR: no stream read, no absorb, no mle_open, no t_claim entry.
                        one_cache.push((addr_zero, addr_zero));
                        continue; // skip t_claim_addrs push for absent AIRs
                    };
                    self.mle_open(air_idx, cached_idx * 1000 + col_id, claim_addr);
                    one_cache.push((claim_addr, claim_rot_addr));
                    t_claim_addrs.push(claim_addr);
                    t_claim_rot_addrs.push(claim_rot_addr);
                }
                cached_cols.push(one_cache);
            }
            per_trace_cached[trace_idx] = cached_cols;
        }

        // ── BC final assertion: bc_claim == evaluated_claim ──────────────────
        {
            // omega_skip_pows: [omega^0, ..., omega^{2^l_skip - 1}] (build-time constants).
            let omega_skip = F::two_adic_generator(vk.l_skip);
            let omega_skip_pows: Vec<F> = {
                let mut pows = Vec::with_capacity(1 << vk.l_skip);
                let mut cur = F::ONE;
                for _ in 0..(1usize << vk.l_skip) {
                    pows.push(cur);
                    cur *= omega_skip;
                }
                pows
            };
            let (eq_ns, eq_sharp_ns) = self.compute_eq_ns_circuit(
                vk.l_skip,
                n_max,
                &xi_addrs,
                r0_bc,
                &bc_r_challenges,
                &omega_skip_pows,
            );

            // interactions_evals: [num_0, denom_0, num_1, denom_1, ...]
            // constraints_evals:  [c_0, c_1, ...]
            let mut interactions_evals: Vec<u32> = Vec::new();
            let mut constraints_evals: Vec<u32> = Vec::new();
            let mut stacked_idx: usize = 0;
            for trace_idx in 0..vk.trace_ordering.len() {
                let air_idx = vk.trace_ordering[trace_idx];
                let air = &vk.per_air[air_idx];
                if !air.is_present {
                    // Absent AIR: skip entirely — no contribution to the batch constraint evaluation.
                    // The RISCV verifier only includes present AIRs in the bc sum.
                    // Skipping absent AIRs ensures cur_mu_pow uses the same exponents as the RISCV verifier.
                    continue;
                }
                let (interaction_num, interaction_denom, c_eval) = self.compute_bc_final_for_trace(
                    vk,
                    trace_idx,
                    &xi_addrs,
                    r0_bc,
                    &bc_r_challenges,
                    &eq_ns,
                    &eq_sharp_ns,
                    &per_trace_common,
                    &per_trace_preproc,
                    &per_trace_cached,
                    &per_air_pv_addrs,
                    beta_logup_addr,
                    lambda_bc,
                    &mut stacked_idx,
                );
                interactions_evals.push(interaction_num);
                interactions_evals.push(interaction_denom);
                constraints_evals.push(c_eval);
            }

            // evaluated_claim = sum_i evals[i] * mu_bc^i
            // (interactions first, then constraints — matching batch_constraints.rs ordering).
            let mut evaluated_claim = addr_zero;
            let mut cur_mu_pow = self.addr_one;
            for &eval in interactions_evals.iter().chain(constraints_evals.iter()) {
                let term = self.ext_mul(eval, cur_mu_pow);
                evaluated_claim = self.ext_add(evaluated_claim, term);
                cur_mu_pow = self.ext_mul(cur_mu_pow, mu_bc);
            }
            self.assert_ext_eq(bc_claim, evaluated_claim);
        }

        // ── Phase 5: Stacking ─────────────────────────────────────────────────

        let lambda_stk = self.sample_ef_for_chip();

        // stk_s0 = sum_i (claim_i + claim_rot_i * lambda_stk) * lambda_sqr^i
        // Matches the stacked_reduction verifier: s_0 = sum_i (t_i.0 + t_i.1 * lambda) * lambda_sqr^i
        let stk_s0 = if t_claim_addrs.is_empty() {
            addr_zero
        } else {
            let lambda_sqr = self.ext_mul(lambda_stk, lambda_stk);
            let mut pow = addr_one;
            let first_rot = t_claim_rot_addrs[0];
            let first_term = if first_rot == addr_zero {
                t_claim_addrs[0]
            } else {
                let rot_part = self.ext_mul(first_rot, lambda_stk);
                self.ext_add(t_claim_addrs[0], rot_part)
            };
            let mut acc = self.ext_mul(first_term, pow);
            for i in 1..t_claim_addrs.len() {
                pow = self.ext_mul(pow, lambda_sqr);
                let claim_rot = t_claim_rot_addrs[i];
                let term = if claim_rot == addr_zero {
                    t_claim_addrs[i]
                } else {
                    let rot_part = self.ext_mul(claim_rot, lambda_stk);
                    self.ext_add(t_claim_addrs[i], rot_part)
                };
                let t = self.ext_mul(term, pow);
                acc = self.ext_add(acc, t);
            }
            acc
        };

        let stk_univar_len = 2 * ((1usize << vk.l_skip) - 1) + 1;
        // GUARD: UnivariateFoldChip hardcodes its coefficient capacity and domain-sum order to
        // MAX_COEFFS (= 31, sized for l_skip = 4, giving order MAX_COEFFS.div_ceil(2) = 16 =
        // 2^l_skip). The stacking round-0 univariate has `stk_univar_len` coefficients; a config
        // with a different l_skip would diverge from the chip's fixed sizing and silently break
        // the domain-sum check. Fail loudly until the chip is generalized to l_skip.
        assert_eq!(
            stk_univar_len, MAX_COEFFS,
            "UnivariateFoldChip is sized for l_skip=4 (MAX_COEFFS={MAX_COEFFS}); l_skip={} would \
             need MAX_COEFFS={stk_univar_len}. Generalize the chip's omega_order before changing \
             l_skip.",
            vk.l_skip,
        );
        let mut stk_coeffs: Vec<u32> = Vec::with_capacity(stk_univar_len);
        for _ in 0..stk_univar_len {
            stk_coeffs.push(self.observe_ef_for_chip());
        }
        let stk_u0 = self.sample_ef_for_chip();

        let mut stk_claim = self.univariate_fold(stk_coeffs, stk_s0, stk_u0);

        let mut stk_u_challenges: Vec<u32> = Vec::with_capacity(vk.n_stack);
        for _ in 0..vk.n_stack {
            let s1 = self.observe_ef_for_chip();
            let s2 = self.observe_ef_for_chip();
            let u = self.sample_ef_for_chip();
            stk_u_challenges.push(u);
            // Precompile round: derives s0 = stk_claim - s1 (sum check by construction)
            // and folds to p(u) in one instruction.
            stk_claim = self.lagrange_eval_d2(stk_claim, s1, s2, u);
        }

        let mut stk_open_addrs: Vec<u32> = Vec::new();
        for (commit_idx, &width) in vk.stacking_widths.iter().enumerate() {
            for col_id in 0..width {
                let val_addr = self.observe_ef_for_chip();
                self.mle_open(commit_idx, col_id, val_addr);
                stk_open_addrs.push(val_addr);
            }
        }

        // Deferred (stacking): stk_claim == sum_j (q_coeff_j * stk_open_j).
        {
            let l_skip = vk.l_skip;
            let n_stack = vk.n_stack;
            let mut u_all: Vec<u32> = Vec::with_capacity(n_stack + 1);
            u_all.push(stk_u0);
            u_all.extend_from_slice(&stk_u_challenges);
            let mut r_all: Vec<u32> = Vec::with_capacity(n_max + 1);
            r_all.push(r0_bc);
            r_all.extend_from_slice(&bc_r_challenges);

            let lambda_sqr = self.ext_mul(lambda_stk, lambda_stk);
            let mut lambda_pow = addr_one;
            let mut final_sum = addr_zero;
            let mut commit_offset = 0usize;

            for (layout, &commit_width) in
                vk.stacking_col_layout.iter().zip(vk.stacking_widths.iter())
            {
                for &(n, row_idx, stacked_col_idx, need_rot_entry) in layout {
                    let stk_open = stk_open_addrs[commit_offset + stacked_col_idx];
                    let n_lift = n.max(0) as usize;

                    let in_uni = self.eval_in_uni_circuit(l_skip, n, stk_u0);

                    let eq_upper = if n_lift >= n_stack {
                        addr_one
                    } else {
                        let mut acc = addr_one;
                        for j in 0..(n_stack - n_lift) {
                            let bit = (row_idx >> (l_skip + n_lift + j)) & 1;
                            let u_j = u_all[n_lift + 1 + j];
                            let factor = if bit == 1 {
                                u_j
                            } else {
                                self.ext_sub(addr_one, u_j)
                            };
                            acc = self.ext_mul(acc, factor);
                        }
                        acc
                    };

                    let eq_prism = if n < 0 {
                        let abs_n = (-n) as usize;
                        let l = l_skip.saturating_sub(abs_n);
                        let mut rs_0 = r_all[0];
                        for _ in 0..abs_n {
                            rs_0 = self.ext_mul(rs_0, rs_0);
                        }
                        self.eval_eq_uni_circuit(l, u_all[0], rs_0)
                    } else {
                        let eq_uni = self.eval_eq_uni_circuit(l_skip, u_all[0], r_all[0]);
                        if n_lift == 0 {
                            eq_uni
                        } else {
                            let eq_mle =
                                self.eval_eq_mle_circuit(&u_all[1..=n_lift], &r_all[1..=n_lift]);
                            self.ext_mul(eq_uni, eq_mle)
                        }
                    };

                    // Matches verifier: batched = lambda_sqr^idx * (eq_prism + lambda * rot_kernel_prism)
                    let batched_prism = if need_rot_entry {
                        let rot_kp = if n < 0 {
                            let abs_n = (-n) as usize;
                            let l = l_skip.saturating_sub(abs_n);
                            let mut rs_0 = r_all[0];
                            for _ in 0..abs_n {
                                rs_0 = self.ext_mul(rs_0, rs_0);
                            }
                            self.eval_rot_kernel_prism_circuit(l, &[u_all[0]], &[rs_0])
                        } else {
                            self.eval_rot_kernel_prism_circuit(
                                l_skip,
                                &u_all[..=n_lift],
                                &r_all[..=n_lift],
                            )
                        };
                        let lambda_rot_kp = self.ext_mul(lambda_stk, rot_kp);
                        self.ext_add(eq_prism, lambda_rot_kp)
                    } else {
                        eq_prism
                    };

                    let q = self.ext_mul(lambda_pow, in_uni);
                    let q = self.ext_mul(q, eq_upper);
                    let q = self.ext_mul(q, batched_prism);
                    let term = self.ext_mul(q, stk_open);
                    final_sum = self.ext_add(final_sum, term);

                    lambda_pow = self.ext_mul(lambda_pow, lambda_sqr);
                }
                commit_offset += commit_width;
            }
            self.assert_ext_eq(stk_claim, final_sum);
        }

        // ── Phase 6: WHIR ─────────────────────────────────────────────────────
        // Counts hint BLOCKS (multi-output batched hints count once per output).
        let pre_phase6_hint_count = self
            .instructions
            .iter()
            .map(|i| match i {
                crate::compiler::recursion::instruction::Instruction::Hint(h) => {
                    h.output_addrs_mults.len()
                }
                _ => 0,
            })
            .sum::<usize>();

        let mut u_cube: Vec<u32> = Vec::with_capacity(vk.l_skip + vk.n_stack);
        {
            let mut pow = stk_u0;
            for _ in 0..vk.l_skip {
                u_cube.push(pow);
                pow = self.ext_mul(pow, pow);
            }
        }
        for &u_i in &stk_u_challenges {
            u_cube.push(u_i);
        }

        let mut alphas_whir: Vec<u32> = Vec::new();

        self.check_witness(vk.mu_pow_bits);
        let mu = self.sample_ef_for_chip();

        let total_width: usize = vk.stacking_widths.iter().sum();
        let mut mu_pows: Vec<u32> = Vec::with_capacity(total_width.max(1));
        {
            let mut p = self.addr_one;
            for _ in 0..total_width {
                mu_pows.push(p);
                p = self.ext_mul(p, mu);
            }
        }

        let mut whir_claim = addr_zero;
        for (&open_addr, &mu_pow) in stk_open_addrs.iter().zip(mu_pows.iter()) {
            let term = self.ext_mul(open_addr, mu_pow);
            whir_claim = self.ext_add(whir_claim, term);
        }

        let mut codeword_commit_blocks: Vec<[u32; DIGEST_BLOCKS]> = Vec::new();

        let mut gammas: Vec<u32> = Vec::with_capacity(vk.num_whir_rounds);
        let mut z0_addrs: Vec<u32> = Vec::new();
        let mut zi_root_per_round: Vec<Vec<u32>> = Vec::with_capacity(vk.num_whir_rounds);
        let mut final_poly_addrs: Vec<u32> = Vec::new();

        for whir_round in 0..vk.num_whir_rounds {
            let is_final = whir_round == vk.num_whir_rounds - 1;

            for _ in 0..vk.k_whir {
                let ev1 = self.observe_ef_for_chip();
                let ev2 = self.observe_ef_for_chip();
                self.check_witness(vk.folding_pow_bits);
                let alpha = self.sample_ef_for_chip();
                alphas_whir.push(alpha);
                // Precompile round: derives ev0 = whir_claim - ev1 (sum check by
                // construction) and folds to p(alpha) in one instruction.
                whir_claim = self.lagrange_eval_d2(whir_claim, ev1, ev2, alpha);
            }

            let ood_val_opt: Option<u32>;
            if is_final {
                let final_len = 1usize << vk.log_final_poly_len;
                final_poly_addrs = (0..final_len).map(|_| self.observe_ef_for_chip()).collect();
                ood_val_opt = None;
            } else {
                let commit_addrs = self.observe_digest_for_whir_addrs();
                let packed = self.pack_digest(commit_addrs);
                codeword_commit_blocks.push(packed);
                let z0 = self.sample_ef_for_chip();
                z0_addrs.push(z0);
                let ood_val = self.observe_ef_for_chip();
                ood_val_opt = Some(ood_val);
            }

            self.check_witness(vk.query_phase_pow_bits);

            let n_bits = vk.log_rs_domain_size - vk.k_whir - whir_round;
            let num_queries = vk
                .num_queries_per_whir_round
                .get(whir_round)
                .copied()
                .unwrap_or(0);

            let alphas_slice: Vec<u32> = (0..vk.k_whir)
                .map(|j| alphas_whir[whir_round * vk.k_whir + j])
                .collect();

            let mut yi_addrs: Vec<u32> = Vec::with_capacity(num_queries);
            let mut zi_roots_this_round: Vec<u32> = Vec::with_capacity(num_queries);
            for _ in 0..num_queries {
                // Capture the Fiat-Shamir sample lane for this query (a Poseidon2-constrained
                // value). The host derives the query index as `sample_bits(n_bits)` = the low
                // n_bits of this same sample, sets `zi_root = omega^index`, and opens the Merkle
                // path at that index.
                let sample_lane = self.sample_f_capture();

                // Batched hint: zi_root, zi_root_inv, index_bits[0..n_bits]
                // (pushed consecutively in that order by the witness-stream builder).
                let header = self.hint_fs(2 + n_bits);
                let zi_root_f = header[0];
                zi_roots_this_round.push(zi_root_f);
                let zi_root_inv_f = header[1];
                let index_bits: Vec<u32> = header[2..].to_vec();

                // Soundness fix (the query position was previously unconstrained): bind the
                // hinted query point / direction bits to the
                // Fiat-Shamir sample. omega_round is the per-round generator the host uses for
                // `zi_root = omega^index`: two_adic_generator(log_rs_domain_size - whir_round)
                // (see machine/recursion/witness.rs `omega_full`). The ExpBitsLen chip canonically
                // decomposes the sample and computes `omega_round^(canonical(sample) mod 2^n_bits)
                // = omega_round^query_index = zi_root`, exporting the low bits (= index_bits).
                // Asserting equality pins zi_root_f and index_bits[j] to the transcript. This is
                // transcript-neutral (the hints were never absorbed). zi_root_inv_f is pinned
                // just below; downstream fold/Merkle/final-poly are left unchanged.
                let omega_round = F::two_adic_generator(vk.log_rs_domain_size - whir_round);
                let (res, bits) = self.exp_bits_len(omega_round, sample_lane, n_bits);
                self.assert_f_eq(zi_root_f, res);
                for j in 0..n_bits {
                    self.assert_f_eq(index_bits[j], bits[j]);
                }

                // Soundness fix (pin the hinted fold inverse): with zi_root_f transcript-bound
                // above, `zi_root_f * zi_root_inv_f == 1` forces zi_root_inv_f = 1/zi_root_f,
                // the value binary_k_fold_circuit consumes downstream.
                let inv_check = self.base_mul(zi_root_f, zi_root_inv_f);
                self.assert_f_eq(inv_check, self.addr_one);

                let yi = if whir_round == 0 {
                    let fold_size = 1usize << vk.k_whir;
                    // Per-j packed (value block, [mu; PACK_LANES]) groups collected across all
                    // commits; each codeword value is then one ExtDotProduct instruction.
                    let mut mu_val_groups: Vec<Vec<(u32, [u32; PACK_LANES])>> =
                        vec![Vec::new(); fold_size];
                    let mut mu_pow_idx = 0usize;
                    let az = self.addr_zero;

                    for (commit_root, &width) in
                        stacking_commit_blocks.iter().zip(vk.stacking_widths.iter())
                    {
                        let blocks_per_row = width.div_ceil(PACK_LANES);
                        // Batched hint: fold_size rows x ceil(width/PACK_LANES) PACKED value
                        // blocks (PACK_LANES row values per block, tail zero-padded), row-major
                        // (matches the witness-stream builder's push order).
                        let flat_blocks = self.hint_fs(fold_size * blocks_per_row);
                        let row_blocks: Vec<&[u32]> = flat_blocks.chunks(blocks_per_row).collect();
                        let leaf_hashes: Vec<[u32; DIGEST_BLOCKS]> = row_blocks
                            .iter()
                            .map(|blocks| self.hash_poseidon2_fresh_packed(blocks, width))
                            .collect();
                        let query_digest = self.tree_compress_circuit(leaf_hashes);
                        // Batched hint: n_bits x DIGEST_BLOCKS packed sibling digest blocks.
                        let flat_sibs = self.hint_fs(n_bits * DIGEST_BLOCKS);
                        let siblings: Vec<[u32; DIGEST_BLOCKS]> = flat_sibs
                            .chunks(DIGEST_BLOCKS)
                            .map(|c| c.try_into().unwrap())
                            .collect();
                        self.verify_merkle_path_circuit(
                            query_digest,
                            &index_bits,
                            &siblings,
                            *commit_root,
                        );
                        for (j, groups) in mu_val_groups.iter_mut().enumerate() {
                            for (b, &blk) in row_blocks[j].iter().enumerate() {
                                // Padding lanes (beyond width) take the zero address
                                // for mu, so they contribute 0 to the dot product.
                                let mus: [u32; PACK_LANES] = std::array::from_fn(|k| {
                                    let c = PACK_LANES * b + k;
                                    if c < width {
                                        mu_pows[mu_pow_idx + c]
                                    } else {
                                        az
                                    }
                                });
                                groups.push((blk, mus));
                            }
                        }
                        mu_pow_idx += width;
                    }

                    // codeword_vals[j] = sum_c mu_pow[c] * opened_row[j][c] over all
                    // commits, one ExtDotProduct instruction per j.
                    let codeword_vals: Vec<u32> = mu_val_groups
                        .iter()
                        .map(|groups| self.ext_dot_product_packed(groups))
                        .collect();

                    self.binary_k_fold_circuit(
                        codeword_vals,
                        &alphas_slice,
                        zi_root_f,
                        zi_root_inv_f,
                    )
                } else {
                    let fold_size = 1usize << vk.k_whir;
                    let mut opened_ef_addrs: Vec<u32> = Vec::with_capacity(fold_size);
                    let mut leaf_hashes: Vec<[u32; DIGEST_BLOCKS]> = Vec::with_capacity(fold_size);

                    for _ in 0..fold_size {
                        let (ef_addr, f_addrs) = self.hint_ef_full();
                        let leaf = self.hash_poseidon2_fresh(&f_addrs);
                        opened_ef_addrs.push(ef_addr);
                        leaf_hashes.push(leaf);
                    }
                    let query_digest = self.tree_compress_circuit(leaf_hashes);
                    let commit_root = codeword_commit_blocks[whir_round - 1];
                    // Batched hint: n_bits x DIGEST_BLOCKS packed sibling digest blocks.
                    let flat_sibs = self.hint_fs(n_bits * DIGEST_BLOCKS);
                    let siblings: Vec<[u32; DIGEST_BLOCKS]> = flat_sibs
                        .chunks(DIGEST_BLOCKS)
                        .map(|c| c.try_into().unwrap())
                        .collect();
                    self.verify_merkle_path_circuit(
                        query_digest,
                        &index_bits,
                        &siblings,
                        commit_root,
                    );
                    self.binary_k_fold_circuit(
                        opened_ef_addrs,
                        &alphas_slice,
                        zi_root_f,
                        zi_root_inv_f,
                    )
                };

                yi_addrs.push(yi);
            }
            zi_root_per_round.push(zi_roots_this_round);

            let gamma = self.sample_ef_for_chip();
            gammas.push(gamma);

            if let Some(y0) = ood_val_opt {
                let term = self.ext_mul(y0, gamma);
                whir_claim = self.ext_add(whir_claim, term);
            }

            let mut gamma_pow = self.ext_mul(gamma, gamma);
            for &yi in &yi_addrs {
                let term = self.ext_mul(yi, gamma_pow);
                whir_claim = self.ext_add(whir_claim, term);
                gamma_pow = self.ext_mul(gamma_pow, gamma);
            }
        }

        // ── Deferred (WHIR): WHIR final poly assertion ────────────────────────────────
        {
            let t = vk.k_whir * vk.num_whir_rounds;
            let suffix_sum = self.eval_mle_circuit(final_poly_addrs.clone(), &u_cube[t..]);
            let prefix = self.eval_mobius_eq_circuit(&u_cube[..t], &alphas_whir);
            let mut acc = self.ext_mul(prefix, suffix_sum);

            let mut j = vk.k_whir;
            for i in 0..vk.num_whir_rounds {
                let slc_len = (t - j) + 1;
                let alpha_slc: Vec<u32> = alphas_whir[j..t].to_vec();
                let gamma_i = gammas[i];

                if i < vk.num_whir_rounds - 1 {
                    let z0 = z0_addrs[i];
                    let (z0_pow_max, z0_pow_left) = self.pow_sequence_ext(z0, slc_len);
                    let eq_z0 = self.eval_eq_mle_circuit(&alpha_slc, &z0_pow_left);
                    let h_z0 = self.horner_eval_circuit(&final_poly_addrs, z0_pow_max);
                    let t1 = self.ext_mul(gamma_i, eq_z0);
                    let contrib_z0 = self.ext_mul(t1, h_z0);
                    acc = self.ext_add(acc, contrib_z0);
                }

                let mut gamma_pow = self.ext_mul(gamma_i, gamma_i);
                for &zi_root in &zi_root_per_round[i] {
                    let mut zi = zi_root;
                    for _ in 0..vk.k_whir {
                        zi = self.base_mul(zi, zi);
                    }
                    let (zi_pow_max, zi_pow_left) = self.pow_sequence_base(zi, slc_len);
                    let eq_zi = self.eval_eq_mle_circuit(&alpha_slc, &zi_pow_left);
                    let h_zi = self.horner_eval_circuit(&final_poly_addrs, zi_pow_max);
                    let t1 = self.ext_mul(gamma_pow, eq_zi);
                    let contrib_zi = self.ext_mul(t1, h_zi);
                    acc = self.ext_add(acc, contrib_zi);
                    gamma_pow = self.ext_mul(gamma_pow, gamma_i);
                }

                j += vk.k_whir;
            }

            self.assert_ext_eq(acc, whir_claim);
        }

        // Diagnostic: log Phase6 circuit hint count (in blocks, not instructions).
        let post_phase6_hint_count = self
            .instructions
            .iter()
            .map(|i| match i {
                crate::compiler::recursion::instruction::Instruction::Hint(h) => {
                    h.output_addrs_mults.len()
                }
                _ => 0,
            })
            .sum::<usize>();
        tracing::debug!(
            "CIRCUIT Phase6 hints: {} (pre={} post={}) Phase1to5={}",
            post_phase6_hint_count - pre_phase6_hint_count,
            pre_phase6_hint_count,
            post_phase6_hint_count,
            pre_phase6_hint_count,
        );

        // The witnessed app-identity (program-table) commitment, if any — at most one AIR is
        // app_preprocessed (the program table). This becomes the `riscv_vk_digest` PV.
        let app_prep_commit = app_prep_commit_addrs.into_iter().flatten().next();

        // Return ProofPvAddrs (Deferred (PVs) is done by the caller).
        let pvs = ProofPvAddrs {
            pv: riscv_pv_f_addrs.unwrap_or_else(|| vec![self.addr_zero; RECURSION_NUM_PVS]),
            app_prep_commit,
            vk_pre_hash: vk_pre_hash_addrs,
            merged_commit: merged_prep_addrs,
            per_air_pv: per_air_pv_addrs,
            cached_commits: per_air_cached_commit_addrs,
        };
        (pvs, logup_sum)
    }

    // ─── Aggregation primitives (used by build_verify_n_program_multi) ──────────
    //
    // These operate on the per-child `ProofPvAddrs` returned by `verify_one` and on the
    // node's public-value address array `pv_arr`. They are the backend-independent
    // aggregation logic (continuity / merge / completeness); the STARK verification itself is
    // `verify_one`. The global LogUp's part of it is in `builder_global_logup`.

    /// Cross-child continuity: each `proof[i]`'s exit values must equal `proof[i+1]`'s entry
    /// values (next_pc→start_pc, next_chunk→start_chunk, last_*_addr→previous_*_addr,
    /// end_reconstruct→start_reconstruct), and all children must share one `riscv_vk_digest`.
    /// No-op for a single child.
    pub(super) fn assert_child_continuity(&mut self, all_pvs: &[ProofPvAddrs]) {
        let col = RECURSION_PUBLIC_VALUES_COL_MAP;
        for i in 0..all_pvs.len().saturating_sub(1) {
            // next_pc == proof[i+1].start_pc (3 F elements)
            for j in 0..3 {
                self.assert_f_eq(
                    all_pvs[i].pv[col.next_pc[j]],
                    all_pvs[i + 1].pv[col.start_pc[j]],
                );
            }
            // next_chunk == proof[i+1].start_chunk
            self.assert_f_eq(
                all_pvs[i].pv[col.next_chunk],
                all_pvs[i + 1].pv[col.start_chunk],
            );
            // last_*_addr_limbs == proof[i+1].previous_*_addr_limbs
            for j in 0..ADDR_NUM_LIMBS {
                self.assert_f_eq(
                    all_pvs[i].pv[col.last_init_addr_limbs[j]],
                    all_pvs[i + 1].pv[col.previous_init_addr_limbs[j]],
                );
                self.assert_f_eq(
                    all_pvs[i].pv[col.last_finalize_addr_limbs[j]],
                    all_pvs[i + 1].pv[col.previous_finalize_addr_limbs[j]],
                );
            }
            // Reconstruct-deferred-digest continuity (FRI combine parity): each child's end
            // digest must equal the next child's start digest, so the chain the root closes
            // (start_reconstruct == 0, end_reconstruct == deferred_proofs_digest) actually
            // telescopes across the whole tree. This is the link that carries it: leaves are
            // transparent segments, so without it a prover could set an interior child's end
            // digest freely and the root would still see a chain that closed.
            for j in 0..DIGEST_SIZE {
                self.assert_f_eq(
                    all_pvs[i].pv[col.end_reconstruct_deferred_digest[j]],
                    all_pvs[i + 1].pv[col.start_reconstruct_deferred_digest[j]],
                );
            }
            // The global LogUp's chain: each child ends where the next one starts. Chunk leaves
            // carry the chain over the Global table commitments; the group and image nodes ahead
            // of chunk 1 carry wrapped values of it, so this is also the link that holds them to
            // one set of challenges and to the chunks they cover (`assert_global_logup_closed`).
            for j in 0..DIGEST_SIZE {
                self.assert_f_eq(
                    all_pvs[i].pv[col.global_chain_end[j]],
                    all_pvs[i + 1].pv[col.global_chain_start[j]],
                );
            }
            // riscv_vk_digest must be consistent across all proofs
            for j in 0..DIGEST_SIZE {
                self.assert_f_eq(
                    all_pvs[i].pv[col.riscv_vk_digest[j]],
                    all_pvs[i + 1].pv[col.riscv_vk_digest[j]],
                );
            }
        }
    }

    /// Whitelist mode: witness the whitelist root (8 hints) into this node's `pv[vk_root]`.
    pub(super) fn witness_vk_root(&mut self, pv_arr: &mut [u32]) -> [u32; 8] {
        let col = RECURSION_PUBLIC_VALUES_COL_MAP;
        let vk_root_w: [u32; 8] = std::array::from_fn(|_| self.hint_f());
        for (i, &idx) in col.vk_root.iter().enumerate() {
            pv_arr[idx] = vk_root_w[i];
        }
        vk_root_w
    }

    /// Whitelist mode: for each recursion child, (a) pin its `pv[vk_root]` to `vk_root_w` — one
    /// tree, one whitelist — and (b) Merkle-verify its VK identity leaf
    /// `H(LEAF_DOMAIN ‖ vk_pre_hash ‖ merged_commit)` against that root. Hints, per child in
    /// order: `DEPTH × (index bit, sibling (8))`.
    pub(super) fn assert_children_whitelisted(
        &mut self,
        vk_root_w: [u32; 8],
        children: &[&ProofPvAddrs],
    ) {
        let col = RECURSION_PUBLIC_VALUES_COL_MAP;
        let addr_zero = self.addr_zero;
        let root_packed = self.pack_digest(vk_root_w);
        let leaf_dom = self.write_const(Block::from(F::from_u32(VK_MAP_LEAF_DOMAIN)));
        for child in children {
            for (i, &idx) in col.vk_root.iter().enumerate() {
                self.assert_f_eq(child.pv[idx], vk_root_w[i]);
            }
            let merged = child
                .merged_commit
                .expect("whitelisted children are recursion (merged-preprocessed) proofs");
            let mut elems = Vec::with_capacity(17);
            elems.push(leaf_dom);
            elems.extend_from_slice(&child.vk_pre_hash);
            elems.extend_from_slice(&merged);
            let leaf = self.hash_poseidon2_fresh(&elems);
            let mut bits = Vec::with_capacity(MLE_VK_MERKLE_DEPTH);
            let mut siblings = Vec::with_capacity(MLE_VK_MERKLE_DEPTH);
            for _ in 0..MLE_VK_MERKLE_DEPTH {
                // Hinted index bit, boolean-constrained: bit·(1 − bit) == 0.
                let bit = self.hint_f();
                let one_minus = self.base_sub(self.addr_one, bit);
                let bb = self.base_mul(bit, one_minus);
                self.assert_f_eq(bb, addr_zero);
                bits.push(bit);
                let sib: [u32; 8] = std::array::from_fn(|_| self.hint_f());
                siblings.push(self.pack_digest(sib));
            }
            self.verify_merkle_path_circuit(leaf, &bits, &siblings, root_packed);
        }
    }

    /// Combine-layer only (children carry recursion PVs) — FRI parity: re-hash each child's
    /// public values and assert equality with its `digest` PV slots. The aggregation itself
    /// never consumes a child's digest (each node recomputes its own — see the invariant note
    /// on `finalize_pv_digest_and_commit`); this maintains the interface guarantee that EVERY
    /// proof in the tree carries a truthful digest, so a downstream consumer may read any
    /// node's digest as a stand-in for its public values.
    pub(super) fn assert_child_pv_digests(&mut self, all_pvs: &[ProofPvAddrs]) {
        let col = RECURSION_PUBLIC_VALUES_COL_MAP;
        for child in all_pvs {
            let blocks = self.hash_poseidon2_fresh(&child.pv[..NUM_PV_ELMS_TO_HASH]);
            let d_lo = self.unpack_lanes(blocks[0]);
            let d_hi = self.unpack_lanes(blocks[1]);
            for (i, &idx) in col.digest.iter().enumerate() {
                let expected = if i < PACK_LANES {
                    d_lo[i]
                } else {
                    d_hi[i - PACK_LANES]
                };
                self.assert_f_eq(child.pv[idx], expected);
            }
        }
    }

    /// Convert-layer only: translate a verified RISCV child's public values (carried in the
    /// Global air's riscv `PublicValues` copy) into the `RecursionPublicValues` layout the whole
    /// tree speaks. Ties the unconstrained Global carrier to each present constrained pv air
    /// (Cpu / Ecall / MemInit / MemFinal) so it inherits their trace bindings; freezes pc / addr
    /// cursors on chunks lacking the relevant air; asserts `exit_code == 0` per chunk, a nonzero
    /// pc limb SUM on CPU chunks, `chunk != 1` on non-CPU chunks and the chunk range check (both
    /// FRI convert parity); makes the leaf a transparent segment of the deferred-proof chain; and
    /// copies the derived recursion fields (next_chunk, next_execution_chunk, …). The global
    /// LogUp's fields are the caller's to write. Returns the freshly-built recursion `pv_arr`.
    pub(super) fn translate_riscv_child_pvs(
        &mut self,
        vk: &RecursionVkLayout,
        pvs: &ProofPvAddrs,
    ) -> Vec<u32> {
        let addr_zero = self.addr_zero;
        // Source: the riscv `PublicValues` copy carried by the Global air (present in EVERY
        // chunk). Whether the chunk actually EXECUTED (vs a memory-only or precompile-table
        // chunk) is a layout fact: Cpu and Ecall are the two RISCV_NUM_PVS-pv airs, and both are
        // present exactly in execution chunks.
        let has_cpu = vk
            .per_air
            .iter()
            .any(|a| a.is_present && a.num_public_values == RISCV_NUM_PVS);
        // The carrier is the Global air's, named by its air id: MemInit and MemFinal carry as
        // many public values, so the count does not tell the three apart.
        let global = &vk.per_air[air_id::GLOBAL];
        assert!(
            global.is_required && global.is_present && global.num_public_values == MAX_NUM_PVS,
            "RISCV child: the Global air must be required and carry the riscv PublicValues copy"
        );
        let src = &pvs.per_air_pv[air_id::GLOBAL];
        assert_eq!(src.len(), MAX_NUM_PVS, "Global pv slice not captured");
        let riscv: &RiscvPublicValues<Word<u32>, u32> = src[..RISCV_NUM_PVS].borrow();
        let mut arr = vec![addr_zero; RECURSION_NUM_PVS];
        let next_chunk_addr = self.base_add(riscv.chunk, self.addr_one);
        // Execution-chunk counters advance only in chunks that RUN the CPU; a memory-only
        // chunk passes them through unchanged.
        let next_exec_addr = if has_cpu {
            self.base_add(riscv.execution_chunk, self.addr_one)
        } else {
            riscv.execution_chunk
        };

        // Carrier binding: the Global-air copy is an unconstrained carrier; TIE it to every
        // present constrained pv air so it inherits their trace bindings (Cpu: execution chunk
        // and pc ends; Ecall: exit_code and both commit digests; MemInit/Final: addr-limb
        // cursors). Without this, a prover could satisfy those airs with honest slices while
        // feeding the recursion a fictional chain.
        //
        // Cpu and Ecall each get their OWN public-value vector in the proof, which the verifier
        // observes separately and never equates, and they pin disjoint fields — so both are tied.
        //
        // Ecall pins its fields only on its HALT / COMMIT rows, so in every other chunk they are
        // free: exit_code is pinned to zero on every chunk below, and each commit digest is taken
        // only from the chunk that committed all eight of its words, below.
        let riscv_pv_airs: Vec<usize> = vk
            .per_air
            .iter()
            .enumerate()
            .filter(|(_, a)| a.num_public_values == RISCV_NUM_PVS)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            riscv_pv_airs.len(),
            2,
            "riscv machine must declare exactly Cpu + Ecall with RISCV_NUM_PVS pvs"
        );
        // Both run on exactly the chunks that execute instructions. A layout with one and not the
        // other would count as executing (`has_cpu`) while leaving the other's fields untied.
        assert_eq!(
            vk.per_air[riscv_pv_airs[0]].is_present, vk.per_air[riscv_pv_airs[1]].is_present,
            "Cpu and Ecall must be present together"
        );
        for idx in riscv_pv_airs {
            if vk.per_air[idx].is_present {
                let slice = &pvs.per_air_pv[idx];
                assert_eq!(slice.len(), RISCV_NUM_PVS, "riscv pv slice not captured");
                for (i, &addr) in slice.iter().enumerate() {
                    self.assert_f_eq(addr, src[i]);
                }
            }
        }
        // MemInit / MemFinal, by air id: with the Global carrier they are the three
        // MAX_NUM_PVS-pv airs.
        let mem_idxs = [air_id::MEM_INIT, air_id::MEM_FINAL];
        let max_pv_airs: Vec<usize> = vk
            .per_air
            .iter()
            .enumerate()
            .filter(|(_, a)| a.num_public_values == MAX_NUM_PVS)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            max_pv_airs,
            [air_id::MEM_INIT, air_id::MEM_FINAL, air_id::GLOBAL],
            "riscv machine must declare exactly MemInit, MemFinal and Global with MAX_NUM_PVS pvs"
        );
        let has_init = vk.per_air[mem_idxs[0]].is_present;
        let has_final = vk.per_air[mem_idxs[1]].is_present;
        for (present, idx) in [(has_init, mem_idxs[0]), (has_final, mem_idxs[1])] {
            if present {
                let slice = &pvs.per_air_pv[idx];
                assert_eq!(slice.len(), MAX_NUM_PVS, "Mem pv slice not captured");
                for (i, &addr) in slice.iter().enumerate() {
                    self.assert_f_eq(addr, src[i]);
                }
            }
        }
        // A complete proof attests a SUCCESSFUL execution: exit_code == 0 on EVERY chunk. On an
        // execution chunk the carrier is tied (above) to the trace-constrained exit_code (which
        // the Ecall air pins on the halt row), so this rejects a failed program at convert time;
        // on any other chunk it pins the otherwise-free carrier to 0. Without a per-chunk
        // assert, the root completeness `exit_code == 0` reads only the last leaf — a
        // memory-finalize chunk whose exit_code carrier is free — so a failed execution (halt
        // with a non-zero code on an interior chunk) could be certified complete. Honest chunks
        // all carry 0.
        self.assert_f_eq(riscv.exit_code, addr_zero);

        // Each commit digest is bound only on its own COMMIT / COMMIT_DEFERRED_PROOFS rows, a word
        // on its row, so a leaf takes it only from the chunk that ran all eight of its words, once
        // each -- the tally Ecall publishes, tied to the carrier above -- and contributes zero from
        // every other chunk, whatever its copy says. The merge sums the contributions, and the
        // root closes on the sum. A chunk that ran some of a digest's words but not all of them
        // does not prove: the emulator keeps each run in one chunk. A chunk without Ecall
        // publishes no tally.
        //
        // An honest tally is `count = 8·(c + d)`, `mask = 0xFF00·c + 0xFF·d`, with `c` and `d`
        // whether the chunk ran the output and the deferred digest. Both are linear in the pair,
        // `c = (mask/255 - count/8)/255` and `d = count/8 - c`, so asserting them boolean admits
        // exactly those four pairs. Then count is 0, 8 or 16 rows, each adding a power of two
        // below 2^16, so the mask cannot wrap; and `count` powers of two summing to a mask with
        // `count` bits set are those bits once each: COMMIT words 0..7 when `c`, and
        // COMMIT_DEFERRED_PROOFS words 0..7 when `d`.
        let (leaf_cvd, leaf_deferred): ([Word<u32>; PV_DIGEST_NUM_WORDS], [u32; DIGEST_SIZE]) =
            if has_cpu {
                let eighth = self.write_const(Block::from(F::from_u32(8).inverse()));
                let inv255 = self.write_const(Block::from(F::from_u32(255).inverse()));
                let runs = self.base_mul(riscv.commits, eighth);
                let weighted = self.base_mul(riscv.commit_mask, inv255);
                let c_255 = self.base_sub(weighted, runs);
                let c = self.base_mul(c_255, inv255);
                let d = self.base_sub(runs, c);
                for flag in [c, d] {
                    let flag_minus_one = self.base_sub(flag, self.addr_one);
                    let both = self.base_mul(flag, flag_minus_one);
                    self.assert_f_eq(both, addr_zero);
                }
                let cvd = std::array::from_fn(|w| {
                    Word(std::array::from_fn(|b| {
                        self.base_mul(c, riscv.committed_value_digest[w].0[b])
                    }))
                });
                let deferred =
                    std::array::from_fn(|j| self.base_mul(d, riscv.deferred_proofs_digest[j]));
                (cvd, deferred)
            } else {
                (
                    [Word([addr_zero; WORD_SIZE]); PV_DIGEST_NUM_WORDS],
                    [addr_zero; DIGEST_SIZE],
                )
            };

        // A CPU chunk cannot start at pc == 0 (the halted sentinel). Assert the WHOLE pc is
        // nonzero — sum the three limbs and hint the inverse of the sum. That is an "is the pc
        // zero" test only because every limb is canonical (in `[0, 2^16)`), which keeps
        // Σ limbs < 3·2^16 ≪ p so the sum cannot cancel. Since X12 the Cpu air carries no
        // per-limb U16 range check on `pc`; the canonicity reaches this carrier over two hops
        // instead:
        //   1. `vm/src/chips/chips/riscv_cpu/public_values/constraints.rs:31` pins
        //      `PV.start_pc` element-wise to row 0's `pc` with `when_first_row().assert_pc_eq` (and
        //      pins the third public-value limb to zero),
        //      and row 0 is forced real by `eval_is_real`
        //      (`vm/src/chips/chips/riscv_cpu/constraints.rs:183-184`);
        //   2. the Program lookup (`vm/src/chips/chips/riscv_cpu/constraints.rs:40-46`), whose
        //      count is exactly `is_real`, pins that row's whole tuple — both `pc` limbs
        //      included — to a row of the preprocessed table, and that table is built as
        //      `Pc::try_from(pc_base + 4i)`
        //      (`vm/src/chips/chips/riscv_program/traces.rs:65-65`), whose limbs are canonical by
        //      construction.
        // Both hops are named in the load-bearing list in `riscv_cpu/constraints.rs`; weakening
        // either one silently turns this assert back into a partial test.
        // (Matches the FRI convert guard.) NOTE: an earlier `start_pc[0] != 0` form was
        // wrong — it spuriously failed (host inverse-of-zero panic) whenever a chunk began at a
        // 0x10000-aligned pc (limb0 == 0, pc != 0), the exact bug the FRI path fixed. This stops
        // a "halt then resume from pc 0" chain where an interior chunk reaches next_pc == 0 and
        // the next CPU chunk is forced to start_pc == 0 by continuity. Only meaningful on CPU
        // chunks; the host pushes the inverse iff has_cpu.
        if has_cpu {
            let sum01 = self.base_add(riscv.start_pc[0], riscv.start_pc[1]);
            let pc_sum = self.base_add(sum01, riscv.start_pc[2]);
            let inv = self.hint_f();
            let prod = self.base_mul(pc_sum, inv);
            self.assert_f_eq(prod, self.addr_one);
        }

        // A chunk that does not RUN the CPU cannot be chunk 1 (FRI convert parity,
        // defense-in-depth: the root already asserts start_execution_chunk == 1, which makes
        // chunk 1 an execution chunk — this states the same fact locally). Assert chunk != 1
        // via a hinted inverse of (chunk − 1); the host pushes it iff !has_cpu.
        if !has_cpu {
            let diff = self.base_sub(riscv.chunk, self.addr_one);
            let inv = self.hint_f();
            let prod = self.base_mul(diff, inv);
            self.assert_f_eq(prod, self.addr_one);
        }

        // chunk fits in MAX_LOG_NUMBER_OF_CHUNKS bits. With `start_chunk == 1` and
        // `next_chunk = chunk + 1` continuity this bounds the number of leaves of a tree, and
        // the root's real-row assertion relies on it: the tree's count, a share per leaf, has to
        // stay clear of the field's order (`assert_global_logup_closed`). Hint the bits LSB-first,
        // boolean-constrain each, assert the recomposition equals the carrier's chunk.
        {
            let two = self.write_const(Block::from(F::from_u32(2)));
            let max_bits = crate::primitives::consts::MAX_LOG_NUMBER_OF_CHUNKS;
            let mut acc = addr_zero;
            let mut pow = self.addr_one;
            for i in 0..max_bits {
                let bit = self.hint_f();
                let one_minus = self.base_sub(self.addr_one, bit);
                let bb = self.base_mul(bit, one_minus);
                self.assert_f_eq(bb, addr_zero);
                let term = self.base_mul(bit, pow);
                acc = self.base_add(acc, term);
                if i + 1 < max_bits {
                    pow = self.base_mul(pow, two);
                }
            }
            self.assert_f_eq(acc, riscv.chunk);
        }

        // The chain value this leaf passes through. Free here on purpose: continuity forces every
        // leaf in the tree to the same one, and the root closes both ends of the chain around it.
        let deferred_digest: [u32; DIGEST_SIZE] = std::array::from_fn(|_| self.hint_f());

        // A chunk that does not RUN the CPU cannot move the pc: freeze it. (With the carrier
        // tie + continuity, neighbors' trace-bound values pin the carrier.)
        if !has_cpu {
            for j in 0..3 {
                self.assert_f_eq(riscv.start_pc[j], riscv.next_pc[j]);
            }
        }
        // A chunk without MemInit (resp. MemFinal) cannot move the memory init (resp. finalize)
        // address cursor: freeze it.
        if !has_init {
            for j in 0..ADDR_NUM_LIMBS {
                self.assert_f_eq(
                    riscv.previous_init_addr_limbs[j],
                    riscv.last_init_addr_limbs[j],
                );
            }
        }
        if !has_final {
            for j in 0..ADDR_NUM_LIMBS {
                self.assert_f_eq(
                    riscv.previous_finalize_addr_limbs[j],
                    riscv.last_finalize_addr_limbs[j],
                );
            }
        }
        {
            let rec: &mut RecursionPublicValues<u32> = arr.as_mut_slice().borrow_mut();
            rec.committed_value_digest = leaf_cvd;
            rec.deferred_proofs_digest = leaf_deferred;
            rec.start_pc = riscv.start_pc;
            rec.next_pc = riscv.next_pc;
            rec.start_chunk = riscv.chunk;
            rec.next_chunk = next_chunk_addr;
            rec.start_execution_chunk = riscv.execution_chunk;
            rec.next_execution_chunk = next_exec_addr;
            rec.contains_execution_chunk = if has_cpu { self.addr_one } else { addr_zero };
            rec.previous_init_addr_limbs = riscv.previous_init_addr_limbs;
            rec.last_init_addr_limbs = riscv.last_init_addr_limbs;
            rec.previous_finalize_addr_limbs = riscv.previous_finalize_addr_limbs;
            rec.last_finalize_addr_limbs = riscv.last_finalize_addr_limbs;
            rec.exit_code = riscv.exit_code;
            // A leaf is TRANSPARENT in the chain: it starts and ends at the same witnessed value,
            // so it neither creates nor consumes a step. Cross-child continuity forces every leaf
            // to the same value, the root pins the chain's left end to zero and its right end to
            // the guest's `deferred_proofs_digest`; between them sit the deferred nodes, each
            // advancing the digest by one verified proof.
            //
            // Not `riscv.deferred_proofs_digest`: the guest commits that just before halting, so
            // chunks before the halting one carry zero and the rest hold the committed value —
            // using it here would break continuity at that boundary.
            rec.start_reconstruct_deferred_digest = deferred_digest;
            rec.end_reconstruct_deferred_digest = deferred_digest;
            // vk_root / sponge fields stay zero; riscv_vk_digest and the global LogUp's fields
            // are written by the caller; flag_complete and digest are set later.
        }
        arr
    }

    /// Merge the children's public values into `pv_arr` (which starts as a copy of child 0):
    /// end-of-tree values from the last child; contains_execution_chunk OR (with a per-child
    /// boolean assert); a running-counter merge of start/next_execution_chunk that also asserts
    /// execution-chunk continuity; the sums of the children's committed_value_digest and
    /// deferred_proofs_digest; the global LogUp's chain end, fractional sum and real-row count;
    /// and all children agree on vk_root.
    pub(super) fn merge_child_pvs(&mut self, pv_arr: &mut [u32], all_pvs: &[ProofPvAddrs]) {
        let col = RECURSION_PUBLIC_VALUES_COL_MAP;
        let addr_zero = self.addr_zero;
        let n = all_pvs.len();
        // PV merge using last proof's "end" values.
        let last = &all_pvs[n - 1];

        // next_pc, next_chunk from last proof
        for j in 0..3 {
            pv_arr[col.next_pc[j]] = last.pv[col.next_pc[j]];
        }
        pv_arr[col.next_chunk] = last.pv[col.next_chunk];

        // address limbs: previous_* from proof[0], last_* from last proof
        for j in 0..ADDR_NUM_LIMBS {
            pv_arr[col.last_init_addr_limbs[j]] = last.pv[col.last_init_addr_limbs[j]];
            pv_arr[col.last_finalize_addr_limbs[j]] = last.pv[col.last_finalize_addr_limbs[j]];
        }

        // exit_code from last proof
        pv_arr[col.exit_code] = last.pv[col.exit_code];

        // end_reconstruct_deferred_digest from last proof
        for j in 0..DIGEST_SIZE {
            pv_arr[col.end_reconstruct_deferred_digest[j]] =
                last.pv[col.end_reconstruct_deferred_digest[j]];
        }

        // The global LogUp: the chain ends where the last child's does (its start is child 0's,
        // already in `pv_arr`); the fractional sums add as fractions; the real-row counts add.
        for j in 0..DIGEST_SIZE {
            pv_arr[col.global_chain_end[j]] = last.pv[col.global_chain_end[j]];
        }
        let mut frac = col.global_sum.map(|i| all_pvs[0].pv[i]);
        let mut count = all_pvs[0].pv[col.global_row_count];
        for child in &all_pvs[1..] {
            frac = self.add_global_sums(frac, col.global_sum.map(|i| child.pv[i]));
            count = self.base_add(count, child.pv[col.global_row_count]);
        }
        for (slot, addr) in col.global_sum.into_iter().zip(frac) {
            pv_arr[slot] = addr;
        }
        pv_arr[col.global_row_count] = count;

        // Each child's contains_execution_chunk is boolean (FRI combine parity); the OR
        // recurrence and the running-counter selects below assume it.
        for pv in all_pvs.iter() {
            let c = pv.pv[col.contains_execution_chunk];
            let one_minus_c = self.base_sub(self.addr_one, c);
            let prod = self.base_mul(c, one_minus_c);
            self.assert_f_eq(prod, addr_zero);
        }

        // contains_execution_chunk = OR across all proofs: a + b*(1-a)
        let mut contains = pv_arr[col.contains_execution_chunk];
        for pv in all_pvs.iter().skip(1) {
            let b_val = pv.pv[col.contains_execution_chunk];
            let one_minus_a = self.base_sub(self.addr_one, contains);
            let b_times_one_minus_a = self.base_mul(b_val, one_minus_a);
            contains = self.base_add(contains, b_times_one_minus_a);
        }
        pv_arr[col.contains_execution_chunk] = contains;

        // deferred_proofs_digest: the sum of the children's. Every leaf contributes zero or the
        // digest of the one chunk that committed it, so the sum is that digest.
        for j in 0..DIGEST_SIZE {
            let mut acc = pv_arr[col.deferred_proofs_digest[j]];
            for pv in all_pvs.iter().skip(1) {
                acc = self.base_add(acc, pv.pv[col.deferred_proofs_digest[j]]);
            }
            pv_arr[col.deferred_proofs_digest[j]] = acc;
        }

        // start_execution_chunk / next_execution_chunk + execution-chunk continuity (FRI combine
        // parity). Running counter `current_exec` = the next expected execution-chunk number:
        // initialized to the first executing child's start_execution_chunk, advanced to each
        // executing child's next_execution_chunk, and each executing child asserted to START
        // where the running counter is (contiguous execution-chunk numbering across children).
        // `seen` tracks whether an executing child has appeared yet. Works for any arity.
        let mut seen = addr_zero;
        let mut start_exec = pv_arr[col.start_execution_chunk];
        let mut current_exec = start_exec;
        for pv in all_pvs.iter() {
            let cur_contains = pv.pv[col.contains_execution_chunk];
            let cur_start = pv.pv[col.start_execution_chunk];
            let cur_next = pv.pv[col.next_execution_chunk];
            let one_minus_seen = self.base_sub(self.addr_one, seen);
            // is_first = cur_contains && !seen
            let is_first = self.base_mul(cur_contains, one_minus_seen);
            let one_minus_first = self.base_sub(self.addr_one, is_first);
            // On the first executing child, latch start_exec / current_exec to its start.
            let se_new = self.base_mul(cur_start, is_first);
            let se_keep = self.base_mul(start_exec, one_minus_first);
            start_exec = self.base_add(se_new, se_keep);
            let ce_new = self.base_mul(cur_start, is_first);
            let ce_keep = self.base_mul(current_exec, one_minus_first);
            current_exec = self.base_add(ce_new, ce_keep);
            // Continuity: an executing child must start at the running counter.
            let diff = self.base_sub(current_exec, cur_start);
            let chk = self.base_mul(cur_contains, diff);
            self.assert_f_eq(chk, addr_zero);
            // Advance the running counter past this child if it executed.
            let one_minus_contains = self.base_sub(self.addr_one, cur_contains);
            let adv = self.base_mul(cur_next, cur_contains);
            let hold = self.base_mul(current_exec, one_minus_contains);
            current_exec = self.base_add(adv, hold);
            // seen := seen || cur_contains
            let seen_add = self.base_mul(cur_contains, one_minus_seen);
            seen = self.base_add(seen, seen_add);
        }
        pv_arr[col.start_execution_chunk] = start_exec;
        pv_arr[col.next_execution_chunk] = current_exec;

        // committed_value_digest: the sum of the children's, as for deferred_proofs_digest above.
        for word in col.committed_value_digest.iter() {
            for &idx in word.0.iter() {
                let mut acc = pv_arr[idx];
                for pv in all_pvs.iter().skip(1) {
                    acc = self.base_add(acc, pv.pv[idx]);
                }
                pv_arr[idx] = acc;
            }
        }

        // vk_root: all proofs must agree.
        for i in 0..(n - 1) {
            for j in 0..DIGEST_SIZE {
                self.assert_f_eq(
                    all_pvs[i].pv[col.vk_root[j]],
                    all_pvs[i + 1].pv[col.vk_root[j]],
                );
            }
        }
    }

    /// Root-only completeness assertions, all against UNIVERSAL constants so the root circuit
    /// stays program-agnostic: the tree covers a full, successful execution — next_pc==0,
    /// start_chunk==1, memory cursors==0, exit_code==0, at-least-one execution chunk starting at 1,
    /// non-empty tree, deferred digest chain, and the global LogUp closed over all of its chunks
    /// (`assert_global_logup_closed`, with `max_global_row_count` as the real-row limit). Emitted only for the
    /// aggregation tree root.
    ///
    /// The program-specific facts are bound WITHOUT baking per-program constants (which would
    /// make the root VK per-program): the guest entry pc via the convert layer's chunk-1 gate
    /// (`start_chunk == 1 ⇒ start_pc == witnessed pc_start`), and the initial memory via the
    /// image node, which opens the image table whose commitment and tier it hashes into the
    /// identity it publishes. The witnessed identity itself is pinned by the apex through the
    /// in-circuit `riscv_vk_digest = H(program_commit ‖ pc_start ‖ image_commit ‖ image_tier)`
    /// anchor. The circuit therefore stays app-agnostic (its VK depends only on the node shape),
    /// hence VK-allowlist-able.
    ///
    /// Hints, in order: `inv(next_chunk − 1)`, then those of `assert_global_logup_closed`.
    pub(super) fn assert_root_complete(&mut self, pv_arr: &[u32], max_global_row_count: u64) {
        let col = RECURSION_PUBLIC_VALUES_COL_MAP;
        let addr_zero = self.addr_zero;
        // Program execution finished: next_pc == 0.
        for j in 0..3 {
            self.assert_f_eq(pv_arr[col.next_pc[j]], addr_zero);
        }
        // The tree covers the execution from the first chunk: start_chunk == 1.
        self.assert_f_eq(pv_arr[col.start_chunk], self.addr_one);
        // The memory init/finalize address cursors start at zero.
        for j in 0..ADDR_NUM_LIMBS {
            self.assert_f_eq(pv_arr[col.previous_init_addr_limbs[j]], addr_zero);
            self.assert_f_eq(pv_arr[col.previous_finalize_addr_limbs[j]], addr_zero);
        }
        // The program exited successfully: a complete proof attests a successful execution.
        self.assert_f_eq(pv_arr[col.exit_code], addr_zero);
        // At least one execution chunk, starting at chunk 1.
        self.assert_f_eq(pv_arr[col.contains_execution_chunk], self.addr_one);
        self.assert_f_eq(pv_arr[col.start_execution_chunk], self.addr_one);
        // next_chunk != 1 (defense in depth vs an empty tree): witness the inverse of
        // (next_chunk - 1) and assert (next_chunk - 1) * inv == 1. The prover pushes the inverse
        // wherever this block is emitted — last in a root program, but a deferred node runs the
        // same block over its CHILD's public values with more hints after it.
        {
            let diff = self.base_sub(pv_arr[col.next_chunk], self.addr_one);
            let inv = self.hint_f();
            let prod = self.base_mul(diff, inv);
            self.assert_f_eq(prod, self.addr_one);
        }
        // Deferred-proof digest chain: starts at zero, ends at the accumulated digest.
        for j in 0..DIGEST_SIZE {
            self.assert_f_eq(pv_arr[col.start_reconstruct_deferred_digest[j]], addr_zero);
            self.assert_f_eq(
                pv_arr[col.end_reconstruct_deferred_digest[j]],
                pv_arr[col.deferred_proofs_digest[j]],
            );
        }
        // Cross-chunk consistency: the global LogUp, closed over every chunk of the tree.
        self.assert_global_logup_closed(pv_arr, max_global_row_count);
    }

    /// Compute the public-values Poseidon2 digest over `pv_arr[..NUM_PV_ELMS_TO_HASH]`, write it
    /// into the digest slots, and emit the `commit_public_values` instruction for this node.
    ///
    /// Recompute THIS node's PV digest and commit. The FRI path also re-hashes every child's
    /// public values and asserts equality with the child's committed `digest` field; this path
    /// does the same — see `assert_child_pv_digests`, called for every combine child in
    /// `build_verify_n_program_multi`. The aggregation itself consumes only the child's
    /// SUBSTANTIVE fields (start_pc, next_pc, chunk, committed_value_digest, …), each bound
    /// to the child proof by `verify_one`, and never a child's `digest`; the `digest` slot
    /// inherited when `pv_arr` is cloned from child 0 is overwritten here with this node's fresh
    /// recompute, and the root's digest is re-checked host-side in `CombineMachine::verify` /
    /// the apex. With the per-child check in place, EVERY proof in the tree carries a truthful
    /// digest, so a downstream consumer may read any node's digest as a stand-in for its PVs.
    pub(super) fn finalize_pv_digest_and_commit(&mut self, pv_arr: &mut [u32]) {
        let col = RECURSION_PUBLIC_VALUES_COL_MAP;
        // Compute digest = Poseidon2_fresh(pv_arr[..NUM_PV_ELMS_TO_HASH]).
        let pv_arr_refs: Vec<u32> = pv_arr.to_vec();
        let digest_blocks = self.hash_poseidon2_fresh(&pv_arr_refs[..NUM_PV_ELMS_TO_HASH]);
        let d_lo = self.unpack_lanes(digest_blocks[0]);
        let d_hi = self.unpack_lanes(digest_blocks[1]);
        let digest_addrs: [u32; 8] = std::array::from_fn(|i| {
            if i < PACK_LANES {
                d_lo[i]
            } else {
                d_hi[i - PACK_LANES]
            }
        });
        for (i, &idx) in col.digest.iter().enumerate() {
            pv_arr[idx] = digest_addrs[i];
        }

        // Build RecursionPublicValues<u32> and commit.
        let pv_addrs: &RecursionPublicValues<u32> = (*pv_arr).borrow();
        let pv_addrs = *pv_addrs;
        for &addr in &pv_addrs.digest {
            self.mark_read(addr);
        }
        self.instructions.push(commit_public_values::<F>(&pv_addrs));
    }

    // ─── Finalize ─────────────────────────────────────────────────────────────

    pub(super) fn finish(self) -> RecursionProgram<F> {
        let Builder {
            mut instructions,
            read_counts,
            next_addr,
            ..
        } = self;

        for instr in &mut instructions {
            match instr {
                Instruction::Mem(mi) if mi.kind == MemAccessKind::Write => {
                    let addr = mi.addrs.inner.as_usize() as u32;
                    mi.mult = F::from_u32(read_counts.get(&addr).copied().unwrap_or(0));
                }
                Instruction::Poseidon2(pi) => {
                    for i in 0..WIDTH {
                        let addr = pi.addrs.output[i].as_usize() as u32;
                        pi.mults[i] = F::from_u32(read_counts.get(&addr).copied().unwrap_or(0));
                    }
                }
                Instruction::Hint(hi) => {
                    for (addr, mult) in &mut hi.output_addrs_mults {
                        let a = addr.as_usize() as u32;
                        *mult = F::from_u32(read_counts.get(&a).copied().unwrap_or(0));
                    }
                }
                Instruction::HintExt2Felts(hi) => {
                    for (addr, mult) in &mut hi.output_addrs_mults {
                        let a = addr.as_usize() as u32;
                        *mult = F::from_u32(read_counts.get(&a).copied().unwrap_or(0));
                    }
                }
                Instruction::ExtAlu(ei) => {
                    let addr = ei.addrs.out.as_usize() as u32;
                    ei.mult = F::from_u32(read_counts.get(&addr).copied().unwrap_or(0));
                }
                Instruction::BaseAlu(bi) => {
                    let addr = bi.addrs.out.as_usize() as u32;
                    bi.mult = F::from_u32(read_counts.get(&addr).copied().unwrap_or(0));
                }
                Instruction::FracFold(fi) => {
                    let p_addr = fi.out_p_addr.as_usize() as u32;
                    let q_addr = fi.out_q_addr.as_usize() as u32;
                    let p_cnt = read_counts.get(&p_addr).copied().unwrap_or(0);
                    let q_cnt = read_counts.get(&q_addr).copied().unwrap_or(0);
                    // out_p and out_q are always consumed together as a (numerator,
                    // denominator) pair, so their read counts must match; the single
                    // `mult` field then equals both. If they ever diverge, sending both
                    // addresses on the memory bus with a max() mult would over-send the
                    // lesser-read address and unbalance the global lookup — fail loudly.
                    assert_eq!(
                        p_cnt, q_cnt,
                        "FracFold out_p/out_q read counts diverge (out_p={p_cnt}, out_q={q_cnt}); \
                         the memory bus would be unbalanced"
                    );
                    fi.mult = F::from_u32(p_cnt);
                }
                Instruction::UnivariateFold(ui) => {
                    let addr = ui.next_sum_addr.as_usize() as u32;
                    ui.mult = F::from_u32(read_counts.get(&addr).copied().unwrap_or(0));
                }
                Instruction::LagrangeEvalD2(li) => {
                    let addr = li.next_claim_addr.as_usize() as u32;
                    li.mult = F::from_u32(read_counts.get(&addr).copied().unwrap_or(0));
                }
                Instruction::GkrSumcheckRound(gi) => {
                    let next_addr = gi.next_claim_addr.as_usize() as u32;
                    let eq_addr = gi.eq_out_addr.as_usize() as u32;
                    gi.mult_next = F::from_u32(read_counts.get(&next_addr).copied().unwrap_or(0));
                    gi.mult_eq = F::from_u32(read_counts.get(&eq_addr).copied().unwrap_or(0));
                }
                Instruction::Select(si) => {
                    let out1_addr = si.addrs.out1.as_usize() as u32;
                    let out2_addr = si.addrs.out2.as_usize() as u32;
                    si.mult1 = F::from_u32(read_counts.get(&out1_addr).copied().unwrap_or(0));
                    si.mult2 = F::from_u32(read_counts.get(&out2_addr).copied().unwrap_or(0));
                }
                Instruction::ExtDotProduct(di) => {
                    let addr = di.acc_addr.as_usize() as u32;
                    di.mult = F::from_u32(read_counts.get(&addr).copied().unwrap_or(0));
                }
                Instruction::HornerEval(hi) => {
                    let addr = hi.out_addr.as_usize() as u32;
                    hi.mult = F::from_u32(read_counts.get(&addr).copied().unwrap_or(0));
                }
                Instruction::DigestSelect(di) => {
                    for i in 0..DIGEST_BLOCKS {
                        let addr = di.out_addrs[i].as_usize() as u32;
                        di.mults[i] = F::from_u32(read_counts.get(&addr).copied().unwrap_or(0));
                    }
                }
                Instruction::PackBlock(pi) => {
                    let addr = pi.out_addr.as_usize() as u32;
                    pi.mult = F::from_u32(read_counts.get(&addr).copied().unwrap_or(0));
                }
                Instruction::UnpackBlock(ui) => {
                    for i in 0..EXTENSION_DEGREE {
                        let addr = ui.out_addrs[i].as_usize() as u32;
                        ui.mults[i] = F::from_u32(read_counts.get(&addr).copied().unwrap_or(0));
                    }
                }
                Instruction::Poseidon2Packed(pi) => {
                    for i in 0..PERM_BLOCKS {
                        let addr = pi.output_addrs[i].as_usize() as u32;
                        pi.mults[i] = F::from_u32(read_counts.get(&addr).copied().unwrap_or(0));
                    }
                }
                Instruction::BinaryFoldStep(bi) => {
                    let addr = bi.out_addr.as_usize() as u32;
                    bi.mult = F::from_u32(read_counts.get(&addr).copied().unwrap_or(0));
                }
                Instruction::ExpBitsLen(ei) => {
                    // Backfill the result write mult and the per-bit write mults from read_counts,
                    // mirroring the Hint/UnpackBlock arms. Bits that no consumer reads keep mult 0
                    // (a lazy no-op message, like padding).
                    let addr = ei.result_out_addr.as_usize() as u32;
                    ei.result_mult = F::from_u32(read_counts.get(&addr).copied().unwrap_or(0));
                    for (addr, mult) in &mut ei.bit_outs_addrs_mults {
                        let a = addr.as_usize() as u32;
                        *mult = F::from_u32(read_counts.get(&a).copied().unwrap_or(0));
                    }
                }
                _ => {}
            }
        }

        RecursionProgram {
            instructions,
            total_memory: next_addr as usize,
            ..Default::default()
        }
    }
}

// ─── Main program builder ─────────────────────────────────────────────────────

impl ConvertVerifierCircuit {
    /// Build the verification program for N STARK proofs, each child `i` verified under its OWN
    /// RecursionVkLayout `vks[i]`. `build_verify_program` calls this with n=1 (convert); the
    /// n>1 path IS the Combine layer (per-node, possibly DIFFERENT shapes).
    ///
    /// `is_convert_layer`: true when verifying RISCV proofs (convert layer) — `riscv_vk_digest`
    /// is SET to the in-circuit exe-identity digest `H(DOMAIN ‖ program_commit ‖ pc_start ‖
    /// image_commit ‖ image_tier)` over the witnessed identity. false for the combine layer
    /// (verifying recursion proofs) — `riscv_vk_digest` is PROPAGATED from the child's PV
    /// unchanged.
    ///
    /// `is_complete`: true ONLY for the aggregation tree root. The root program sets
    /// `flag_complete = 1` in its public values and emits the completeness assertions — all
    /// against UNIVERSAL constants (next_pc == 0, start_chunk == 1, cursors-start-at-zero,
    /// exit_code == 0, execution start/end conditions, deferred chain, and the global LogUp
    /// closed over the tree's chunks); non-root programs set 0 and emit none. No per-program
    /// constant is ever baked, so every node VK depends only on the node shape (app-agnostic,
    /// hence VK-allowlist-able). The program-specific facts are bound instead by the convert
    /// layer's chunk-1 gate (entry pc) and by the image node (initial memory: it opens the
    /// image table whose commitment and tier it hashes into `riscv_vk_digest`), each pinned to
    /// trusted values through the apex's single `riscv_vk_digest` comparison.
    pub fn build_verify_n_program_multi<F: PrimeField32 + TwoAdicField>(
        vks: &[&RecursionVkLayout],
        is_convert_layer: bool,
        is_complete: bool,
        vk_verification: bool,
    ) -> RecursionProgram<F> {
        Self::build_verify_n_program_multi_within(
            vks,
            is_convert_layer,
            is_complete,
            vk_verification,
            global_logup::MAX_COUNT,
        )
    }

    /// [`Self::build_verify_n_program_multi`] with the real-row limit a complete root asserts
    /// as a parameter. The limit is `MAX_COUNT`; a smaller one is still sound, and lets a
    /// negative test put it below a block's count.
    #[doc(hidden)]
    pub fn build_verify_n_program_multi_within<F: PrimeField32 + TwoAdicField>(
        vks: &[&RecursionVkLayout],
        is_convert_layer: bool,
        is_complete: bool,
        vk_verification: bool,
        max_global_row_count: u64,
    ) -> RecursionProgram<F> {
        let n = vks.len();
        assert!(n >= 1);
        // The convert layer's RISCV->recursion translation only builds a merged pv_arr from
        // child 0; the n>1 merge/continuity below reads all_pvs[i>0].pv, which for a RISCV
        // child is the zero-vector fallback. A multi-child convert call would make those
        // continuity asserts vacuous (0 == 0), so restrict the convert layer to single-child.
        assert!(
            !is_convert_layer || n == 1,
            "convert layer verifies exactly one RISCV child (is_convert_layer implies n == 1)"
        );
        let mut b = Builder::<F>::new();
        b.addr_zero = b.init_constants();
        let addr_zero = b.addr_zero;

        let mut all_pvs: Vec<ProofPvAddrs> = Vec::with_capacity(n);
        // Where each child's verify begins and ends, for `RecursionProgram::child_spans`. Taken
        // from the instruction count around the call, which is stable: `finish` only backfills
        // `mult` in place, and the merge tail's `commit_public_values` is pushed after this loop.
        let mut child_spans: Vec<(usize, usize)> = Vec::with_capacity(n);
        for i in 0..n {
            if i > 0 {
                b.reset_sponge();
            }
            let start = b.instructions.len();
            // In whitelist mode a recursion child's key is held to the row of its layout. A
            // RISC-V child has no row: its layout bakes its constraints and heights, and its
            // program travels in the exe identity.
            let pvs = if vk_verification && !is_convert_layer {
                b.verify_one_of_row(vks[i])
            } else {
                b.verify_one(vks[i])
            };
            child_spans.push((start, b.instructions.len()));
            all_pvs.push(pvs);
        }

        // Cross-child continuity (no-op for n == 1).
        b.assert_child_continuity(&all_pvs);
        // Per-child PV-digest validity (combine children only — a RISCV child's recursion pv
        // array is synthesized by translation below, not carried by the proof).
        if !is_convert_layer {
            b.assert_child_pv_digests(&all_pvs);
        }

        // Deferred (PVs): commit public values.
        {
            let col = RECURSION_PUBLIC_VALUES_COL_MAP;
            // Build the merged pv_arr. Start from proof[0]'s PVs.
            // Convert layer (child = RISCV proof): TRANSLATE the child's RISCV `PublicValues`
            // layout into the `RecursionPublicValues` layout — the whole tree above speaks
            // recursion offsets (continuity, merge, completeness asserts all index them).
            // Combine layer (child = recursion proof): the child pvs are already in recursion
            // layout — start from a copy.
            let mut pv_arr: Vec<u32> = if is_convert_layer {
                b.translate_riscv_child_pvs(vks[0], &all_pvs[0])
            } else {
                all_pvs[0].pv.clone()
            };
            // riscv_vk_digest: convert layer (child = RISCV proof) computes the VM-layer exe
            // identity anchor IN-CIRCUIT (mirroring the FRI convert's hash of its RiscvVmVk):
            //
            //   riscv_vk_digest = H(DOMAIN ‖ program_commit ‖ pc_start ‖ image_commit ‖ image_tier)
            //
            // program_commit is the witnessed program-table commitment (Merkle-hard-bound as the
            // program table's WHIR stacking root — see `verify_one`); pc_start (3), the image
            // table's commitment (8) and its height tier (1) are raw witness hints (not
            // absorbed — they are not part of the child's STARK transcript). The hash is the
            // exact in-circuit mirror of `RiscvVmVk::digest` (same padding-free rate-8 overwrite
            // sponge, same 21-element preimage order), so the apex compares this PV against the
            // trusted `RiscvVmVk::digest()` — a single self-attested anchor.
            //
            // Binding of the hinted fields:
            //   - chunk-1 gating: is_first = (start_chunk == 1) ⇒ start_pc == pc_start;
            //   - the image commitment and tier only enter the hash here. The image node opens
            //     the table under that commitment at that tier and publishes the same digest,
            //     and continuity holds every node of the tree to one digest.
            // start_chunk itself is chain-bound: continuity links every child's next_chunk to
            // its sibling's start_chunk and the root asserts start_chunk == 1, so exactly the
            // leftmost leaf gates on. `assert_child_continuity` forces every sibling to carry
            // the same digest, so one tree = one (program, pc, image) triple.
            //
            // Combine layer (child = recursion proof) PROPAGATES the child's
            // pv[riscv_vk_digest] (already in pv_arr from clone) unchanged.
            if is_convert_layer {
                let child = vks[0];
                let program_commit = all_pvs[0]
                    .app_prep_commit
                    .expect("convert layer verifies a RISCV proof, which has a program table");
                // Witness the chain value before this chunk (8), then the VM-layer identity:
                // pc_start (3 limbs), the image table's commitment (8) and its height tier (1).
                let chain_in: [u32; DIGEST_SIZE] = std::array::from_fn(|_| b.hint_f());
                let pc_w: [u32; 3] = std::array::from_fn(|_| b.hint_f());
                let image_w: [u32; DIGEST_SIZE] = std::array::from_fn(|_| b.hint_f());
                let tier_w = b.hint_f();
                let mut preimage = Vec::with_capacity(21);
                preimage.push(b.const_f(RISCV_VK_DIGEST_DOMAIN));
                preimage.extend_from_slice(&program_commit);
                preimage.extend_from_slice(&pc_w);
                preimage.extend_from_slice(&image_w);
                preimage.push(tier_w);
                let digest = b.hash_to_felts(&preimage);
                for (slot, addr) in col.riscv_vk_digest.into_iter().zip(digest) {
                    pv_arr[slot] = addr;
                }

                // ── chunk-1 gating: is_first = (start_chunk == 1) ──
                // From a hinted inverse: diff = start_chunk − 1; is_first = 1 − diff·inv;
                // assert is_first·diff == 0. diff ≠ 0 forces is_first = 0 (regardless of the
                // hint); diff == 0 gives is_first = 1 identically — the exact indicator, with
                // no boolean assumption on the hint.
                let one = b.addr_one;
                let diff = b.base_sub(pv_arr[col.start_chunk], one);
                let inv = b.hint_f();
                let prod = b.base_mul(diff, inv);
                let is_first = b.base_sub(one, prod);
                let gate_check = b.base_mul(is_first, diff);
                b.assert_f_eq(gate_check, addr_zero);
                // Gated entry-pc binding: the first chunk's trace-bound start_pc must equal the
                // witnessed pc_start (limb-wise); non-first chunks are unconstrained here.
                for j in 0..3 {
                    let d = b.base_sub(pv_arr[col.start_pc[j]], pc_w[j]);
                    let g = b.base_mul(is_first, d);
                    b.assert_f_eq(g, addr_zero);
                }

                // ── The global LogUp: this chunk's step of the chain, and its row count ──
                // The Global air's event table is the one cached main `verify_one` opened, at
                // the one height this layout bakes. A reader at another height would see other
                // columns under the same commitment, so the height is asserted here and goes
                // into the chain with the width.
                let global = &child.per_air[air_id::GLOBAL];
                let log_height = global.log_height.expect("the Global air is present");
                assert!(
                    global.cached_main_widths == [global_logup::TABLE_WIDTH]
                        && log_height
                            == global_logup::global_log_height_at(child.l_skip + child.n_stack),
                    "RISCV child: the Global air must commit one event table of {} columns at \
                     the operating point's height",
                    global_logup::TABLE_WIDTH
                );
                let commit = match all_pvs[0].cached_commits[air_id::GLOBAL][..] {
                    [commit] => commit,
                    _ => unreachable!("one cached main, one commitment"),
                };
                // The chain starts at IV before chunk 1; before any other chunk it is a free
                // witness, which continuity ties to the chunk on the left.
                let iv = b.global_chain_iv();
                for j in 0..DIGEST_SIZE {
                    let d = b.base_sub(chain_in[j], iv[j]);
                    let g = b.base_mul(is_first, d);
                    b.assert_f_eq(g, addr_zero);
                }
                let chain_out =
                    b.global_chain_step(chain_in, pv_arr[col.start_chunk], log_height, commit);
                // The chunk's share of the real-row bound: a constant of the layout, from the
                // heights of the airs that send on the Global bus.
                let count = global_logup::chunk_count(
                    log_height,
                    GLOBAL_SENDERS.iter().filter_map(|&(air, sends, receives)| {
                        let air = &child.per_air[air];
                        air.is_present.then(|| {
                            let log_height = air.log_height.expect("a present air has a height");
                            (sends, receives, log_height)
                        })
                    }),
                );
                let count = b.const_f(u32::try_from(count).expect("a chunk's share is small"));
                let frac = b.zero_global_sum();
                {
                    let rec: &mut RecursionPublicValues<u32> = pv_arr.as_mut_slice().borrow_mut();
                    rec.global_chain_start = chain_in;
                    rec.global_chain_end = chain_out;
                    rec.global_sum = frac;
                    rec.global_row_count = count;
                }
            }

            if n > 1 {
                b.merge_child_pvs(&mut pv_arr, &all_pvs);
            }

            // ── VK whitelist (vk_verification mode) ──
            // Every node witnesses `vk_root` (the whitelist Merkle root) into its public
            // values. Combine nodes additionally (a) pin each child's pv[vk_root] to their own
            // witnessed root — one tree, one whitelist — and (b) Merkle-verify each child VK's
            // identity leaf H(LEAF_DOMAIN ‖ vk_pre_hash ‖ merged_commit) against it, closing
            // the witnessed-identity binding: a child only counts if its VK is whitelisted.
            // Convert leaves carry the root unchecked (their child is a RISC-V proof, anchored
            // by the exe digest); the apex pins the root PV against the trusted constant.
            // With vk_verification off, pv[vk_root] stays zero (dev mode, fail-open).
            if vk_verification {
                let vk_root_w = b.witness_vk_root(&mut pv_arr);
                if !is_convert_layer {
                    let children: Vec<&ProofPvAddrs> = all_pvs.iter().collect();
                    b.assert_children_whitelisted(vk_root_w, &children);
                }
            }

            // flag_complete: baked from `is_complete` (build parameter), for ALL n — including
            // the n=1 root of a single-chunk program. Children always carry 0 here (propagating
            // the child flag instead would mean the root's completeness could never arm).
            pv_arr[col.flag_complete] = if is_complete { b.addr_one } else { addr_zero };

            // Completeness assertions — emitted at BUILD time only for the tree root
            // (`is_complete` is a baked constant, so no in-circuit flag gating is needed:
            // root programs get the universal asserts, non-root programs get nothing). All
            // asserts are against universal constants — including the closure of the global
            // LogUp (see assert_root_complete) — keeping this circuit app-agnostic.
            if is_complete {
                b.assert_root_complete(&pv_arr, max_global_row_count);
            }

            // digest + commit.
            b.finalize_pv_digest_and_commit(&mut pv_arr);
        }

        let mut program = b.finish();
        program.child_spans = child_spans;
        program
    }

    /// Build the verification program for a single proof (wrapper around
    /// build_verify_n_program_multi with n=1).
    pub fn build_verify_program<F: PrimeField32 + TwoAdicField>(
        input: &ConvertProgramInput,
    ) -> RecursionProgram<F> {
        // Convert layer: child is a RISCV proof, so riscv_vk_digest is set to the in-circuit
        // exe-identity digest (is_convert_layer = true). Convert proofs are never complete roots.
        Self::build_verify_n_program_multi::<F>(&[&input.vk], true, false, input.vk_verification)
    }

    /// Build the deferred-verifier program: verify ONE complete root of a *sub-program* and
    /// advance the deferred-proof hash chain by a single step,
    /// `end = H(start ‖ child.riscv_vk_digest ‖ child.committed_value_digest)` — the same
    /// preimage and sponge the guest's `hash_deferred_proof` uses, which is what makes the
    /// guest's claimed digest and this chain comparable at the root.
    ///
    /// The node it emits is transparent in every dimension the tree chains EXCEPT that digest:
    /// chunk and execution-chunk cursors sit at 1, it contains no execution chunk, the global
    /// LogUp passes through it, and its pc is the witnessed entry pc of the MAIN program. Chunk
    /// continuity then admits it only as a tree PREFIX: a riscv leaf sets `next_chunk = chunk + 1`,
    /// and since the root pins `start_chunk == 1` and continuity numbers the leaves up from there,
    /// no leaf in a tree that can close leaves the cursor at 1 for a node to follow.
    ///
    /// One consequence worth knowing before touching the continuity links: with such a node
    /// leading the tree, the root's `start_chunk == 1` and `previous_*_addr == 0` read ITS baked
    /// constants rather than a leaf's trace-bound values, so those asserts become tautologies and
    /// the real binding moves onto continuity — `next_chunk`/`last_*_addr` welding the node to the
    /// chunk-1 leaf. The property survives, but continuity is then the only thing holding it.
    ///
    /// Note the two roles `riscv_vk_digest` plays here: the value this node PUBLISHES is the
    /// main program's (continuity forces it to agree with the execution leaves), while the
    /// value that enters the hash is the CHILD's — the sub-program's identity is carried by the
    /// chain, not by this node's public values.
    ///
    /// Witness contract, after `verify_one`'s own hints and in this order:
    ///   1. the hints of the child's completeness block (`assert_root_complete`):
    ///      `inv(child.next_chunk − 1)`, the inverse of the child's global-LogUp denominator
    ///      (5), the 21 bits of the child's slack under the real-row limit;
    ///   2. the start digest (8) — where this step's chain segment begins;
    ///   3. the global LogUp's chain value (8) this node passes through;
    ///   4. `riscv_vk_digest` (8) and `end_pc` (3) — the MAIN program's exe identity and entry pc;
    ///   5. whitelist mode only: `vk_root` (8), then the child's `DEPTH × (bit, sibling (8))`.
    pub fn build_deferred_program<F: PrimeField32 + TwoAdicField>(
        child: &RecursionVkLayout,
        vk_verification: bool,
    ) -> RecursionProgram<F> {
        Self::deferred_program(child, vk_verification, true, false)
    }

    /// Negative tests only: [`Self::build_deferred_program`] without the requirement that the
    /// child's own deferred digest is zero. A node built from it is the control that shows a
    /// sub-proof which defers is refused by that requirement and by nothing else.
    #[doc(hidden)]
    pub fn build_deferred_program_admitting_nested_for_testing<F: PrimeField32 + TwoAdicField>(
        child: &RecursionVkLayout,
        vk_verification: bool,
    ) -> RecursionProgram<F> {
        Self::deferred_program(child, vk_verification, false, false)
    }

    /// Negative tests only: [`Self::build_deferred_program`] with the node's own fraction of the
    /// global LogUp at `(0, 0)` instead of `(0, 1)`. Added into a tree's sum it takes the
    /// numerator to zero whatever the groups add up to; the root's assertion that the
    /// denominator has an inverse is what has to refuse the tree.
    #[doc(hidden)]
    pub fn build_deferred_program_with_zero_denominator_for_testing<
        F: PrimeField32 + TwoAdicField,
    >(
        child: &RecursionVkLayout,
        vk_verification: bool,
    ) -> RecursionProgram<F> {
        Self::deferred_program(child, vk_verification, true, true)
    }

    fn deferred_program<F: PrimeField32 + TwoAdicField>(
        child: &RecursionVkLayout,
        vk_verification: bool,
        refuse_nested: bool,
        zero_denominator: bool,
    ) -> RecursionProgram<F> {
        // Every check below reads the child's recursion public values; without that air
        // `verify_one` hands back a zero vector and the checks turn into assertions about
        // nothing. `flag_complete == 1` would still reject it, but as an opaque constraint
        // failure at prove time rather than a sentence at build time.
        assert!(
            child.merged_preprocessed_commit.is_some()
                && child
                    .per_air
                    .iter()
                    .any(|air| air.is_present && air.num_public_values == RECURSION_NUM_PVS),
            "deferred child is not a recursion proof carrying recursion public values"
        );
        let col = RECURSION_PUBLIC_VALUES_COL_MAP;
        let mut b = Builder::<F>::new();
        b.addr_zero = b.init_constants();
        let addr_zero = b.addr_zero;
        let addr_one = b.addr_one;

        let span_start = b.instructions.len();
        // The sub-proof is a complete root, a key of the combine tier: in whitelist mode it is
        // held to that row, as a node's children are.
        let child_pvs = if vk_verification {
            b.verify_one_of_row(child)
        } else {
            b.verify_one(child)
        };
        let child_spans = vec![(span_start, b.instructions.len())];

        // ── The child must be a COMPLETE root of its own program ──
        // Its flag says the child's own circuit ran the completeness block; re-running the
        // relations here is what actually binds them, since they are relations over public
        // values `verify_one` has already tied to the verified proof.
        b.assert_f_eq(child_pvs.pv[col.flag_complete], addr_one);
        b.assert_root_complete(&child_pvs.pv, global_logup::MAX_COUNT);
        // No nested deferred proofs: a sub-proof that itself defers would ride its own unverified
        // claims into this chain, and nothing below would ever check them.
        if refuse_nested {
            for j in 0..DIGEST_SIZE {
                b.assert_f_eq(child_pvs.pv[col.deferred_proofs_digest[j]], addr_zero);
            }
        }
        // Keep the tree-wide guarantee that every proof's `digest` PV is truthful.
        b.assert_child_pv_digests(std::slice::from_ref(&child_pvs));

        // ── One step of the deferred chain ──
        let start_digest: [u32; DIGEST_SIZE] = std::array::from_fn(|_| b.hint_f());
        let mut preimage = Vec::with_capacity(2 * DIGEST_SIZE + 32);
        preimage.extend_from_slice(&start_digest);
        for j in 0..DIGEST_SIZE {
            preimage.push(child_pvs.pv[col.riscv_vk_digest[j]]);
        }
        for word in col.committed_value_digest.iter() {
            for &idx in word.0.iter() {
                preimage.push(child_pvs.pv[idx]);
            }
        }
        let digest_blocks = b.hash_poseidon2_fresh(&preimage);
        let d_lo = b.unpack_lanes(digest_blocks[0]);
        let d_hi = b.unpack_lanes(digest_blocks[1]);
        let end_digest: [u32; DIGEST_SIZE] = std::array::from_fn(|i| {
            if i < PACK_LANES {
                d_lo[i]
            } else {
                d_hi[i - PACK_LANES]
            }
        });

        // ── This node's own public values ──
        // All free witnesses here and pinned by cross-child continuity: the global LogUp's
        // chain value against the neighbours', the digest against the execution leaves'
        // in-circuit exe anchor, the pc against the chunk-1 leaf's trace-bound `start_pc`.
        let global_chain: [u32; DIGEST_SIZE] = std::array::from_fn(|_| b.hint_f());
        let riscv_vk_digest: [u32; DIGEST_SIZE] = std::array::from_fn(|_| b.hint_f());
        let end_pc: [u32; 3] = std::array::from_fn(|_| b.hint_f());
        let global_sum = b
            .zero_global_sum()
            .map(|slot| if zero_denominator { addr_zero } else { slot });
        let mut pv_arr = vec![addr_zero; RECURSION_NUM_PVS];
        {
            let rec: &mut RecursionPublicValues<u32> = pv_arr.as_mut_slice().borrow_mut();
            rec.start_reconstruct_deferred_digest = start_digest;
            rec.end_reconstruct_deferred_digest = end_digest;
            rec.start_pc = end_pc;
            rec.next_pc = end_pc;
            rec.start_chunk = addr_one;
            rec.next_chunk = addr_one;
            rec.start_execution_chunk = addr_one;
            rec.next_execution_chunk = addr_one;
            rec.riscv_vk_digest = riscv_vk_digest;
            // Transparent in the global LogUp: the chain passes through, the fraction is
            // `(0, 1)`, which adds nothing, and the node has no rows to count.
            rec.global_chain_start = global_chain;
            rec.global_chain_end = global_chain;
            rec.global_sum = global_sum;
            // Left at zero: committed_value_digest and deferred_proofs_digest (this node makes no
            // claim about either, and the merge sums both, so a zero adds nothing), the
            // four address cursors, exit_code, global_row_count, flag_complete (a deferred node can
            // never be a complete root) and contains_execution_chunk.
        }
        // ── Whitelist mode: the child is a whitelisted complete root under this tree's root ──
        // Same check combine runs on its children. Membership plus `flag_complete == 1` above
        // leaves only the complete-root combine shapes: every other recursion program bakes the
        // flag to 0. The parent's `vk_root` agreement then holds the sub-proof to the trusted
        // root the apex pins. Dev mode leaves `vk_root` at zero, as every node does.
        if vk_verification {
            let vk_root_w = b.witness_vk_root(&mut pv_arr);
            b.assert_children_whitelisted(vk_root_w, &[&child_pvs]);
        }
        b.finalize_pv_digest_and_commit(&mut pv_arr);

        let mut program = b.finish();
        program.child_spans = child_spans;
        program
    }
}
