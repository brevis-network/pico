//! The two programs that bring the global LogUp's second phase into the recursion tree.
//!
//! A **group node** verifies one group proof: up to `MAX_GROUP_LEN` chunks' Global event
//! tables, re-opened under the block's challenges, summed. An **image node** verifies the group
//! proof over the program's memory image table, and is the one place the challenges are
//! derived. Both are leaves that lead the tree, ahead of chunk 1, the way deferred nodes do:
//! chunk and execution-chunk cursors at 1, no execution chunk, nothing committed.
//!
//! What ties them to the chunks is the chain (`builder_global_logup`): the convert leaves fold their
//! table commitments into it from left to right, and these nodes carry wrapped values of it
//! from right to left, so that continuity and the root's closure admit exactly one arrangement,
//! `[image][group m] … [group 1][chunk 1 … chunk n]`, under one pair of challenges derived from
//! the chain over all `n` commitments.

use super::*;

impl<F: PrimeField32 + TwoAdicField> Builder<F> {
    /// The public values of a node that leads the tree and covers no chunk: transparent in
    /// every chained dimension but the global LogUp's.
    ///
    /// `pc` and `riscv_vk_digest` are the main program's, `deferred` the deferred chain's value
    /// at the node, which passes through.
    fn prefix_node_pvs(
        &mut self,
        pc: [u32; 3],
        riscv_vk_digest: [u32; DIGEST_SIZE],
        deferred: [u32; DIGEST_SIZE],
        chain_start: [u32; DIGEST_SIZE],
        chain_end: [u32; DIGEST_SIZE],
        sum: GlobalSum,
    ) -> Vec<u32> {
        let (addr_zero, addr_one) = (self.addr_zero, self.addr_one);
        let mut pv_arr = vec![addr_zero; RECURSION_NUM_PVS];
        let rec: &mut RecursionPublicValues<u32> = pv_arr.as_mut_slice().borrow_mut();
        rec.start_reconstruct_deferred_digest = deferred;
        rec.end_reconstruct_deferred_digest = deferred;
        rec.start_pc = pc;
        rec.next_pc = pc;
        rec.start_chunk = addr_one;
        rec.next_chunk = addr_one;
        rec.start_execution_chunk = addr_one;
        rec.next_execution_chunk = addr_one;
        rec.riscv_vk_digest = riscv_vk_digest;
        rec.global_chain_start = chain_start;
        rec.global_chain_end = chain_end;
        rec.global_sum[..EXTENSION_DEGREE].copy_from_slice(&sum.0);
        rec.global_sum[EXTENSION_DEGREE..].copy_from_slice(&sum.1);
        // Left at zero: committed_value_digest, deferred_proofs_digest, the four address
        // cursors, exit_code, global_row_count (the node has no chunk rows to count), flag_complete and
        // contains_execution_chunk.
        pv_arr
    }

    /// The Global tables a group or image proof opens, one per AIR: each AIR is required and
    /// present, with one cached main of the table's width, at `2^log_height` rows. Returns the
    /// commitments in AIR order.
    fn group_table_commits(
        child: &RecursionVkLayout,
        pvs: &ProofPvAddrs,
        log_height: usize,
    ) -> Vec<[u32; DIGEST_SIZE]> {
        assert!(
            child.external_logup && child.merged_preprocessed_commit.is_none(),
            "a group proof is in the external LogUp challenge mode, without preprocessing"
        );
        child
            .per_air
            .iter()
            .zip(&pvs.cached_commits)
            .map(|(air, commits)| {
                assert!(
                    air.is_required
                        && air.is_present
                        && air.cached_main_widths == [global_logup::TABLE_WIDTH]
                        && air.log_height == Some(log_height)
                        && air.num_public_values == 0,
                    "a group proof opens one {}-column table per AIR at 2^{log_height} rows",
                    global_logup::TABLE_WIDTH
                );
                // What the program evaluates is this layout's constraints: a table's rows
                // summed and nothing else, as the group machine's key has it
                // (`pico_mle_core::global_logup::assert_group_vk`).
                let dag = &air.eval_dag;
                let table_column = |node: usize| match dag.nodes.get(node) {
                    Some(EvalNode::Variable {
                        entry:
                            EvalEntry::Main {
                                part_index: 0,
                                offset: 0,
                            },
                        index,
                    }) => Some(*index),
                    _ => None,
                };
                let [interaction] = dag.interactions.as_slice() else {
                    panic!("a group AIR has one interaction");
                };
                assert!(
                    dag.constraint_idx.is_empty()
                        && interaction.bus_index
                            == pico_mle_core::lookup::LookupType::GlobalLogUp as u16
                        && interaction.count_weight == 1
                        && interaction
                            .message
                            .iter()
                            .map(|&node| table_column(node))
                            .eq((0..global_logup::MESSAGE_LEN).map(Some))
                        && table_column(interaction.count) == Some(global_logup::MULTIPLICITY_COL),
                    "a group AIR sends its table's columns in order on the group bus, and has \
                     no constraint"
                );
                match commits[..] {
                    [commit] => commit,
                    _ => unreachable!("one cached main, one commitment"),
                }
            })
            .collect()
    }
}

impl ConvertVerifierCircuit {
    /// Build the group node's program for `child`, the layout of a group proof over `s` chunk
    /// tables (`s` is the layout's AIR count).
    ///
    /// The node covers chunks `a ..= a + s − 1`, with `a` a witness. It verifies the group
    /// proof under witnessed challenges, folds the `s` commitments the proof opens into the
    /// chain from a witnessed value before chunk `a`, and publishes the proof's fractional sum.
    /// Its chain fields run against the chunks' direction and carry the challenges:
    ///
    /// - start: `W(alpha ‖ beta, chain after chunk a + s − 1)`;
    /// - end: `W(alpha ‖ beta, chain before chunk a)`, or the chain's initial value itself when
    ///   `a == 1`, which is what chunk 1's leaf starts at.
    ///
    /// The node derives no challenge and checks no proof of work: continuity equates its start
    /// with the end of the node on its left, down from the image node's, and a wrapped value
    /// determines both the challenges and the chain value under it. `a` needs no range check
    /// for the same reason: the chain value fixes the list of commitments before it.
    ///
    /// The tables' height is the layout's, held to the operating point's (`log_stacked_height`
    /// is the riscv machine's); the caller holds the layout's key to the group machine's
    /// (`pico_mle_core::global_logup::assert_group_vk`).
    ///
    /// Witness contract, in this order: the challenges (5 + 5); `verify_one`'s own hints, without
    /// the vk pre-hash, which is baked; `a`, `inv(a − 1)` (anything when `a == 1`), the chain
    /// value before chunk `a` (8); the main program's `riscv_vk_digest` (8) and entry pc (3);
    /// the deferred chain's value (8); in whitelist mode `vk_root` (8).
    pub fn build_group_node_program<F: PrimeField32 + TwoAdicField>(
        child: &RecursionVkLayout,
        log_stacked_height: usize,
        vk_verification: bool,
    ) -> RecursionProgram<F> {
        let tables = child.per_air.len();
        assert!(
            (1..=global_logup::MAX_GROUP_LEN).contains(&tables),
            "a group holds 1 to {} tables, not {tables}",
            global_logup::MAX_GROUP_LEN
        );
        assert_eq!(
            log_stacked_height,
            child.l_skip + child.n_stack,
            "a group proof is made at the riscv machine's stacked height"
        );
        let log_height = global_logup::global_log_height_at(log_stacked_height);
        let mut b = Builder::<F>::new();
        b.addr_zero = b.init_constants();
        let (addr_zero, addr_one) = (b.addr_zero, b.addr_one);

        let alpha: [u32; EXTENSION_DEGREE] = std::array::from_fn(|_| b.hint_f());
        let beta: [u32; EXTENSION_DEGREE] = std::array::from_fn(|_| b.hint_f());
        let span_start = b.instructions.len();
        let (child_pvs, sum) = b.verify_one_external(child, alpha, beta);
        let child_spans = vec![(span_start, b.instructions.len())];
        let commits = Builder::<F>::group_table_commits(child, &child_pvs, log_height);

        // is_first = (a == 1), the exact indicator, as the convert leaf computes its own.
        let first = b.hint_f();
        let diff = b.base_sub(first, addr_one);
        let inv = b.hint_f();
        let prod = b.base_mul(diff, inv);
        let is_first = b.base_sub(addr_one, prod);
        let gate_check = b.base_mul(is_first, diff);
        b.assert_f_eq(gate_check, addr_zero);
        // The chain before chunk `a`: the initial value when `a == 1`, and otherwise whatever
        // makes the folded value the one the node on the left ends with.
        let chain_before: [u32; DIGEST_SIZE] = std::array::from_fn(|_| b.hint_f());
        let iv = b.global_chain_iv();
        for j in 0..DIGEST_SIZE {
            let d = b.base_sub(chain_before[j], iv[j]);
            let g = b.base_mul(is_first, d);
            b.assert_f_eq(g, addr_zero);
        }
        let mut chain = chain_before;
        for (j, commit) in commits.into_iter().enumerate() {
            let offset = b.const_f(j as u32);
            let index = b.base_add(first, offset);
            chain = b.global_chain_step(chain, index, log_height, commit);
        }
        let chain_start = b.wrap_chain(alpha, beta, chain);
        // `a == 1`: hand chunk 1 the initial value itself, which `chain_before` then is.
        let wrapped_before = b.wrap_chain(alpha, beta, chain_before);
        let chain_end: [u32; DIGEST_SIZE] = std::array::from_fn(|j| {
            let d = b.base_sub(chain_before[j], wrapped_before[j]);
            let g = b.base_mul(is_first, d);
            b.base_add(wrapped_before[j], g)
        });

        // Free witnesses, pinned by cross-child continuity as a deferred node's are.
        let riscv_vk_digest: [u32; DIGEST_SIZE] = std::array::from_fn(|_| b.hint_f());
        let pc: [u32; 3] = std::array::from_fn(|_| b.hint_f());
        let deferred: [u32; DIGEST_SIZE] = std::array::from_fn(|_| b.hint_f());
        let mut pv_arr =
            b.prefix_node_pvs(pc, riscv_vk_digest, deferred, chain_start, chain_end, sum);
        if vk_verification {
            b.witness_vk_root(&mut pv_arr);
        }
        b.finalize_pv_digest_and_commit(&mut pv_arr);

        let mut program = b.finish();
        program.child_spans = child_spans;
        program
    }

    /// Build the image node's program for `child`, the layout of a group proof over one memory
    /// image table; the table's height in the layout is the node's tier.
    ///
    /// The node is where the block's challenges come from. It derives them in the circuit from
    /// `params_digest` (a constant: the operating point and the group machines), a witnessed
    /// program identity digest and a witnessed chain root, behind the proof of work; verifies
    /// the image group proof under them; and recomputes the identity digest from the image
    /// commitment that proof opened and its own tier, so that the image summed is the program's
    /// and is read at the program's tier. Its chain fields:
    ///
    /// - start: `H(TAG_TOP ‖ root ‖ y)`, the form the root's closure asks for, which holds
    ///   `root` and `y` to the chain over every chunk;
    /// - end: `W(alpha ‖ beta, y)`, which hands the challenges to the first group node.
    ///
    /// Witness contract, in this order: the identity digest (8), the chain root (8), the
    /// proof-of-work witness; `verify_one`'s own hints, without the vk pre-hash, which is baked;
    /// the program-table commitment (8) and the entry pc (3); `y` (8); the deferred chain's
    /// value (8); in whitelist mode `vk_root` (8).
    pub fn build_image_node_program<F: PrimeField32 + TwoAdicField>(
        child: &RecursionVkLayout,
        params_digest: [u32; DIGEST_SIZE],
        vk_verification: bool,
    ) -> RecursionProgram<F> {
        assert_eq!(child.per_air.len(), 1, "the image group has one table");
        let log_height = child.per_air[0]
            .log_height
            .expect("the image table is present");
        assert!(
            (global_logup::MIN_IMAGE_LOG_HEIGHT
                ..=global_logup::MAX_GLOBAL_LOG_HEIGHT.min(child.l_skip + child.n_stack))
                .contains(&log_height),
            "2^{log_height} rows is no tier of the image table at this stacked height"
        );
        let mut b = Builder::<F>::new();
        b.addr_zero = b.init_constants();

        // The challenges: a transcript of its own over (TAG_CHALLENGE, params digest, identity
        // digest, chain root), then the proof of work, then alpha and beta.
        b.reset_sponge();
        let riscv_vk_digest: [u32; DIGEST_SIZE] = std::array::from_fn(|_| b.hint_f());
        let root: [u32; DIGEST_SIZE] = std::array::from_fn(|_| b.hint_f());
        let tag = b.const_f(global_logup::TAG_CHALLENGE);
        b.absorb_f(tag);
        let params_digest = params_digest.map(|limb| b.const_f(limb));
        b.observe_const_digest(params_digest);
        b.observe_const_digest(riscv_vk_digest);
        b.observe_const_digest(root);
        assert!(
            child.logup_pow_bits > 0,
            "the challenges of the global LogUp sit behind a proof of work"
        );
        b.check_witness(child.logup_pow_bits);
        let alpha: [u32; EXTENSION_DEGREE] = std::array::from_fn(|_| b.squeeze_f());
        let beta: [u32; EXTENSION_DEGREE] = std::array::from_fn(|_| b.squeeze_f());

        b.reset_sponge();
        let span_start = b.instructions.len();
        let (child_pvs, sum) = b.verify_one_external(child, alpha, beta);
        let child_spans = vec![(span_start, b.instructions.len())];
        let image_commit = match Builder::<F>::group_table_commits(child, &child_pvs, log_height)[..]
        {
            [commit] => commit,
            _ => unreachable!("one table"),
        };

        // The identity digest over the image this proof opened, at this program's tier.
        let program_commit: [u32; DIGEST_SIZE] = std::array::from_fn(|_| b.hint_f());
        let pc: [u32; 3] = std::array::from_fn(|_| b.hint_f());
        let mut preimage = Vec::with_capacity(21);
        preimage.push(b.const_f(RISCV_VK_DIGEST_DOMAIN));
        preimage.extend_from_slice(&program_commit);
        preimage.extend_from_slice(&pc);
        preimage.extend_from_slice(&image_commit);
        preimage.push(b.const_f(log_height as u32));
        let digest = b.hash_to_felts(&preimage);
        for j in 0..DIGEST_SIZE {
            b.assert_f_eq(digest[j], riscv_vk_digest[j]);
        }

        let y: [u32; DIGEST_SIZE] = std::array::from_fn(|_| b.hint_f());
        let chain_start = b.wrap_chain_top(root, y);
        let chain_end = b.wrap_chain(alpha, beta, y);

        let deferred: [u32; DIGEST_SIZE] = std::array::from_fn(|_| b.hint_f());
        let mut pv_arr =
            b.prefix_node_pvs(pc, riscv_vk_digest, deferred, chain_start, chain_end, sum);
        if vk_verification {
            b.witness_vk_root(&mut pv_arr);
        }
        b.finalize_pv_digest_and_commit(&mut pv_arr);

        let mut program = b.finish();
        program.child_spans = child_spans;
        program
    }

    /// Tests only: a program that holds the given constants as a root's global LogUp fields and
    /// makes the root's assertions about them (`assert_global_logup_closed`), and nothing else. Its hints
    /// are that function's: the inverse of the denominator, then the bits of the slack under
    /// `max_count`.
    #[doc(hidden)]
    pub fn build_global_logup_closure_program_for_testing<F: PrimeField32 + TwoAdicField>(
        chain_start: [u32; DIGEST_SIZE],
        chain_end: [u32; DIGEST_SIZE],
        frac: [u32; crate::emulator::recursion::public_values::GLOBAL_SUM_LEN],
        count: u32,
        max_count: u64,
    ) -> RecursionProgram<F> {
        let mut b = Builder::<F>::new();
        b.addr_zero = b.init_constants();
        let mut pv_arr = vec![b.addr_zero; RECURSION_NUM_PVS];
        {
            let chain_start = chain_start.map(|x| b.const_f(x));
            let chain_end = chain_end.map(|x| b.const_f(x));
            let frac = frac.map(|x| b.const_f(x));
            let count = b.const_f(count);
            let rec: &mut RecursionPublicValues<u32> = pv_arr.as_mut_slice().borrow_mut();
            rec.global_chain_start = chain_start;
            rec.global_chain_end = chain_end;
            rec.global_sum = frac;
            rec.global_row_count = count;
        }
        b.assert_global_logup_closed(&pv_arr, max_count);
        b.finalize_pv_digest_and_commit(&mut pv_arr);
        b.finish()
    }

    /// Tests only: a program that wraps the given constants with the challenges (`wrap_chain`) and
    /// asserts the result is `expected`, and nothing else. It takes no hints.
    #[doc(hidden)]
    pub fn build_chain_wrap_program_for_testing<F: PrimeField32 + TwoAdicField>(
        alpha: [u32; EXTENSION_DEGREE],
        beta: [u32; EXTENSION_DEGREE],
        x: [u32; DIGEST_SIZE],
        expected: [u32; DIGEST_SIZE],
    ) -> RecursionProgram<F> {
        let mut b = Builder::<F>::new();
        b.addr_zero = b.init_constants();
        let mut pv_arr = vec![b.addr_zero; RECURSION_NUM_PVS];
        let alpha = alpha.map(|c| b.const_f(c));
        let beta = beta.map(|c| b.const_f(c));
        let x = x.map(|c| b.const_f(c));
        let wrapped = b.wrap_chain(alpha, beta, x);
        for (wrapped, expected) in wrapped.into_iter().zip(expected) {
            let expected = b.const_f(expected);
            b.assert_f_eq(wrapped, expected);
        }
        b.finalize_pv_digest_and_commit(&mut pv_arr);
        b.finish()
    }
}
