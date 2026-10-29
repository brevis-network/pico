//! MLE/WHIR-backend end-to-end recursion proving from a real ELF.
//!
//! Runs the proving pipeline up to the requested `--step`:
//!   riscv   → prove + verify each RISCV chunk
//!   convert → wrap each RISCV proof in a recursion (Convert) proof and verify it
//!   combine → tree-reduce the convert proofs to one complete root proof and verify it
//!   embed   → re-prove that root under the outer BN254-Poseidon2 config and verify it
//!   wrap    → embed, then emit the gnark circuit + witness for it, and the verifier's inputs
//!             (both require the default `multi-field-transcript` feature)
//! (compress arrives in a later phase.)
//!
//! Usage:
//!   cargo run --release -p pico-vm --example test_mle_e2e -- --elf fib --n 10 --field kb --step combine
//!
//! Operating point: `log_stacked_height` 23 and a chunk of 2^23 derived from it, i.e. what
//! `mle-single-node` ships. `MLE_LOG_STACKED_HEIGHT` moves both. The whitelist is OFF by
//! default (`VK_VERIFICATION`), again matching the prover; turning it on needs a bucket table
//! that reaches the chosen height.
//!
//! Cross-build check (env vars):
//!   MLE_DUMP_ROOT=<path>   after the root verifies, write it plus its VK and child layouts there
//!   MLE_VERIFY_ROOT=<path> verify such a dump and exit — no emulation, no proving, and `--step`
//!                          is ignored. The program identity is re-derived from the ELF given on
//!                          the command line, so pass the same one the dump was made from.
//!
//! Negative-test hooks (env vars; each run MUST fail — a zero exit is a fail-open bug):
//!   N1_INCOMPLETE=1   combine a strict prefix of the chunks under a complete root
//!                     (fails at next_pc == 0; needs >= 3 chunks — use e.g. --n 3000000)
//!   N1_BAD_GCS=1      bake a wrong global-cumulative-sum target (fails at GCS == E,
//!                     isolating the cross-chunk closure; any chunk count)
//!   N2_TAMPER_CHILD=1 corrupt one opened value of a convert child (in a release build witness
//!                     generation goes through and the root's STARK verify rejects it on the
//!                     in-circuit WHIR checks; with debug assertions the recursion runtime's
//!                     `AssertZeroExt` panics first; any chunk count)
//!   N3_BAD_ENTRY=1    wrong TRUSTED entry pc (fails at the apex exe anchor; any count)
//!   N4_WRONG_PROGRAM=1 wrong TRUSTED program commitment (fails at the apex exe anchor)
//!   N5_BAD_PC_WITNESS=1 wrong PROVER-side pc_start witness (the chunk-1 convert's gated
//!                     in-circuit assert start_pc == pc_start is unsatisfiable)
//!   N6_BAD_GCS_WITNESS=1 wrong PROVER-side initial_gcs witness (the root's in-circuit GCS
//!                     closure to the zero point is unsatisfiable)
//!   N7_BAD_VK_ROOT=1  hand a different whitelist than the tree was proven against (host-side,
//!                     at `CombineMachine::verify`'s vk_root check; forces whitelist mode on)
//!   N9_WRONG_PINNED_ROOT=1 pin a root that is not the whitelist's (the deployment constant
//!                     disagrees with the artifact) — the apex MUST refuse at construction
//!   N8_FORGED_MEMBERSHIP=1 corrupt every whitelist Merkle path, entries + root intact —
//!                     witness generation succeeds, so the IN-CIRCUIT membership constraint
//!                     itself must reject (root STARK verify fails)
//!   N10_UNLISTED_SHAPE=1 remove this run's own convert VKs from the whitelist and re-root it,
//!                     so the shapes the chunks select are not members — the host-side lookup
//!                     fails closed at combine witness generation, before any recursion proof

use p3_field::PrimeCharacteristicRing;
use pico_mle_core::{
    config::{recursion_params_with_100_bits_security, riscv_params_with_100_bits_security},
    StarkEngine,
};
use pico_vm::{
    compiler::{
        program::ProgramBehavior,
        riscv::compiler::{Compiler, SourceType},
    },
    configs::stark_config::KoalaBearPoseidon2,
    machine::{logger::setup_logger, septic::SepticDigest},
    mle::machine::{
        combine::CombineMachine,
        convert::ConvertMachine,
        exe::RiscvVmVk,
        recursion::Kb,
        riscv,
        vk_map::{vk_identity, MleVkMap},
    },
};
use tracing::info;

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    setup_logger();
    let (elf, stdin, args) = parse_args::parse_args::<KoalaBearPoseidon2>();
    // kb-only by design: the MLE backend ships only a KoalaBear engine.
    assert_eq!(
        args.field, "kb",
        "test_mle_e2e is KoalaBear-only by design; got --field {}",
        args.field
    );

    let compiler = Compiler::new(SourceType::RISCV, elf).expect("failed to parse ELF");
    let program = compiler.compile();

    // Verify-only: accept a root proved by another build (CPU or `cuda`). Nothing is
    // emulated or proved here. The program identity is derived locally from the same ELF rather
    // than taken from the dump — that is the half of the claim worth checking.
    if let Ok(path) = std::env::var("MLE_VERIFY_ROOT") {
        let bytes = std::fs::read(&path).expect("root dump read");
        #[allow(clippy::type_complexity)]
        let (proof_bytes, root_vk, layouts, dumped_height, dumped_whitelist): (
            Vec<u8>,
            pico_mle_core::keygen::types::MultiStarkVerifyingKey<riscv::Sc>,
            Vec<pico_vm::mle::compiler::recursion::RecursionVkLayout>,
            usize,
            bool,
        ) = bincode::deserialize(&bytes).expect("root dump decode");
        // Through the versioned codec, so a wire-format divergence fails here rather than
        // surfacing as an unexplained verification error later.
        use pico_mle_core::codec::Decode;
        let proof =
            pico_mle_core::protocol::proof::Proof::<riscv::Sc>::decode_from_bytes(&proof_bytes)
                .expect("root proof decode");
        // The whitelist arm needs a vk map that this path has no way to reconstruct, and
        // `verify` refuses without one. Say so here rather than failing later against an API the
        // caller never touched — cross-build checking is scoped to the whitelist-off mode.
        assert!(
            !dumped_whitelist,
            "this root was proved with the whitelist on; cross-build checking only covers \
             VK_VERIFICATION=false"
        );
        // Rebuilt at the dump's operating point, not this run's: the shape has to be the one the
        // proof was made against.
        let engine: riscv::Engine =
            StarkEngine::new(riscv_params_with_100_bits_security(dumped_height));
        let airs = riscv::mle_riscv_air_refs(program.clone(), dumped_whitelist);
        let (_, riscv_vk) = engine.keygen_with_app_prep(&airs, riscv::RISCV_APP_PREP_AIR_IDS);
        let trusted = RiscvVmVk::from_program_and_vk(&program, &riscv_vk);
        let mut combine = CombineMachine::new(
            recursion_params_with_100_bits_security(),
            trusted,
            dumped_whitelist,
        );
        combine
            .preregister_root_shape(&layouts)
            .unwrap_or_else(|e| panic!("{e}"));
        // `verify` selects the honest VK on two digests. Most divergences move
        // `merged_preprocessed_commit` and so fail one line up, in the lookup; this catches the
        // rest — anything the two digests happen to agree on.
        let honest = combine
            .honest_root_vk(&root_vk)
            .expect("no honestly keygen'd complete shape matches the dumped root vk");
        if bincode::serialize(honest).expect("honest vk encode")
            != bincode::serialize(&root_vk).expect("dumped vk encode")
        {
            // Not `assert_eq!`: the two operands are megabyte blobs, and a failure here is this
            // gate's whole product — the reader needs a sentence, not two hex dumps.
            panic!("the dumped root vk differs from the one this build keygens for the same shape");
        }
        combine
            .verify(&(proof, std::sync::Arc::new(root_vk)))
            .expect("cross-build root verify failed");
        info!(
            "cross-build root verify ✓ ({path}, height {dumped_height}, whitelist {dumped_whitelist})"
        );
        return;
    }

    // Only reached once this run is going to prove. The GPU prover allocates from the shared pico
    // pool and refuses to run without it; the single-node driver is what normally sets it up per
    // card. (A verify-only run still touches the device when it builds the engine — what it skips
    // is the pool, not the card.)
    #[cfg(feature = "cuda")]
    riscv::init_mle_gpu_pool(riscv::MLE_GPU_DEVICE);

    let log_stacked_height: usize = riscv::log_stacked_height_from_env();
    info!("log_stacked_height = {log_stacked_height}");

    // A chunk holds one CPU row per instruction, so the stacked height is its natural capacity;
    // `CHUNK_SIZE` can take it lower to split a program into more chunks.
    let chunk_size = riscv::chunk_size_from_env(log_stacked_height);
    info!("chunk_size = {chunk_size}");
    let (records, committed) =
        riscv::emulate_with_committed_bytes(program.clone(), stdin, Some(chunk_size));
    info!(
        "emulated {} chunk(s), {} committed byte(s)",
        records.len(),
        committed.len()
    );

    // Off = natural heights and dynamic per-shape keygen, which is how the MLE prover runs; on =
    // bucketed shapes and a finite whitelist. Shape bucketing is linked to this flag, and the
    // bucket tables are sized for a stacked height of 22.
    //
    // Same `VK_VERIFICATION` the FRI stack reads, parsed the same way, but defaulting off here
    // where that stack defaults on.
    //
    // The whitelist-tampering hooks force it on: without the whitelist they would trip the
    // `assert!(vk_verification, …)` below, and that non-zero exit reads as a pass to a harness
    // that scores "the run failed" as "the tamper was caught".
    let whitelist_hook = std::env::var("N7_BAD_VK_ROOT").is_ok()
        || std::env::var("N8_FORGED_MEMBERSHIP").is_ok()
        || std::env::var("N9_WRONG_PINNED_ROOT").is_ok()
        || std::env::var("N10_UNLISTED_SHAPE").is_ok();
    let requested = std::env::var("VK_VERIFICATION").map(|v| v.eq_ignore_ascii_case("true"));
    let vk_verification = requested.clone().unwrap_or(false) || whitelist_hook;
    if whitelist_hook && requested == Ok(false) {
        tracing::warn!(
            "VK_VERIFICATION=false overridden: N7/N8 only mean anything with the whitelist"
        );
    }
    // Log the resolved mode, as the FRI stack does — the two differ in what they cover, and a run
    // that does not say which one it took is hard to read back.
    info!(
        "vk_verification = {vk_verification} ({})",
        if vk_verification {
            "bucketed shapes, finite whitelist"
        } else {
            "natural heights, dynamic per-shape keygen"
        }
    );
    // ── Phase 1: RISCV ──────────────────────────────────────────────────────
    let bundle = riscv::prove_riscv(
        program.clone(),
        &records,
        log_stacked_height,
        vk_verification,
    )
    .expect("riscv prove failed");
    let initial_gcs = program.initial_global_cumulative_sum();
    // Test convenience: the "trusted" pre-hash and program commitment are taken from the
    // bundle's own keygen (same trust stance for both; a real consumer supplies both from an
    // independent trusted source). The lean pre-hash covers machine+shape only, so the program
    // commitment must be pinned explicitly.
    riscv::verify_riscv(
        &bundle,
        bundle.vk.pre_hash,
        &[(
            riscv::air_id::PROGRAM,
            riscv::riscv_program_commit(&bundle.vk),
        )],
        initial_gcs,
    )
    .expect("riscv verify failed");
    let (riscv_vk, riscv_proofs) = bundle.into_parts();
    info!(
        "RISCV: {} chunk proof(s) proved + verified ✓",
        riscv_proofs.len()
    );
    if args.step == "riscv" {
        return;
    }

    // ── Phase 2: Convert ────────────────────────────────────────────────────
    // VM-layer exe identity (program_commit, pc_start, initial_gcs): witnessed into every
    // convert proof (prover side) and pinned at the apex (trusted side).
    let riscv_vm_vk = RiscvVmVk::from_program_and_vk(&program, &riscv_vk);
    // Negative-test hooks N5/N6 perturb the PROVER-side witness (the trusted identity below
    // stays honest), so the in-circuit bindings themselves must reject:
    //   N5_BAD_PC_WITNESS → the chunk-1 convert's gated assert is_first·(start_pc − pc_w) == 0
    //     is unsatisfiable → that convert proof MUST fail;
    //   N6_BAD_GCS_WITNESS → a wrong point is injected at the chunk-1 leaf → the root's
    //     in-circuit closure (GCS == zero point) is unsatisfiable → the root MUST fail.
    let mut prover_vm_vk = riscv_vm_vk.clone();
    if std::env::var("N5_BAD_PC_WITNESS").is_ok() {
        tracing::warn!("N5_BAD_PC_WITNESS: wrong pc_start witness — MUST FAIL (chunk-1 gate)");
        prover_vm_vk.pc_start[0] += Kb::ONE;
    }
    if std::env::var("N6_BAD_GCS_WITNESS").is_ok() {
        tracing::warn!("N6_BAD_GCS_WITNESS: wrong initial_gcs witness — MUST FAIL (root closure)");
        prover_vm_vk.initial_gcs = SepticDigest(prover_vm_vk.initial_gcs.0.double());
    }
    // The TRUSTED exe identity handed to the apex. Negative hooks N3/N1/N4 perturb one of its
    // fields; the honest proof's in-circuit riscv_vk_digest then cannot match the trusted
    // RiscvVmVk::digest(), so the apex MUST reject.
    let mut trusted_vm_vk = riscv_vm_vk.clone();
    if std::env::var("N3_BAD_ENTRY").is_ok() {
        tracing::warn!(
            "N3_BAD_ENTRY: wrong trusted entry pc — this run MUST FAIL (at the apex exe anchor)"
        );
        trusted_vm_vk.pc_start[0] += Kb::ONE;
    }
    if std::env::var("N1_BAD_GCS").is_ok() {
        tracing::warn!(
            "N1_BAD_GCS: wrong trusted initial GCS — this run MUST FAIL (at the apex exe anchor)"
        );
        trusted_vm_vk.initial_gcs = SepticDigest(trusted_vm_vk.initial_gcs.0.double());
    }
    if std::env::var("N4_WRONG_PROGRAM").is_ok() {
        tracing::warn!(
            "N4_WRONG_PROGRAM: wrong trusted program commit — MUST FAIL (at the apex exe anchor)"
        );
        trusted_vm_vk.program_commit[0] += Kb::ONE;
    }
    let t_new = std::time::Instant::now();
    let mut convert = ConvertMachine::new(
        riscv_vk,
        prover_vm_vk,
        &riscv_proofs,
        recursion_params_with_100_bits_security(),
        vk_verification,
    )
    .expect("convert machine build failed");
    let new_ms = t_new.elapsed().as_millis();
    // The whitelist must exist before ANY recursion proving (every proof witnesses vk_root):
    // build it from this run's own VKs — the convert VKs plus the three collapsed combine node
    // VKs (eagerly keygen'd from the uniform bucketed child layout). The combine machine is
    // therefore constructed here, before the convert proofs.
    let trusted_vm_vk_for_apex = trusted_vm_vk.clone();
    let mut combine = CombineMachine::new(
        recursion_params_with_100_bits_security(),
        trusted_vm_vk,
        vk_verification,
    );
    let vk_map = if vk_verification {
        // The node PKs must exist before proving regardless of the map's source.
        let combine_vks = combine
            .preregister_standard_shapes(&convert.pks[0].3)
            .unwrap_or_else(|e| panic!("{e}"));
        let map = if let Ok(path) = std::env::var("MLE_VK_MAP") {
            // GLOBAL whitelist artifact (the offline mle_build_vk_map deliverable): this run's
            // VKs must already be members — a drift fails fail-closed at witness generation.
            let map = std::sync::Arc::new(MleVkMap::load(&path));
            info!(
                "vk map: GLOBAL artifact `{path}`, {} entries, root = {:?}",
                map.entries.len(),
                map.root()
            );
            map
        } else {
            // Self-map: whitelist this run's own VKs (exercises the machinery without the
            // artifact; the trusted root is then only as trustworthy as this run).
            let mut ids: Vec<pico_vm::mle::machine::vk_map::VkIdentity> = convert
                .pks
                .iter()
                .map(|entry| vk_identity(&entry.3))
                .collect();
            ids.extend(combine_vks.iter().map(|v| vk_identity(v)));
            let map = std::sync::Arc::new(MleVkMap::build(ids));
            info!(
                "vk map: self, {} entries, root = {:?}",
                map.entries.len(),
                map.root()
            );
            map
        };
        // Negative-test hook N10_UNLISTED_SHAPE: drop this run's own convert VKs from the
        // whitelist and re-root it, so the shapes the chunks select are not members. The
        // host-side lookup MUST fail closed at combine witness generation (the pinned root and
        // the apex are never reached).
        let map = if std::env::var("N10_UNLISTED_SHAPE").is_ok() {
            tracing::warn!(
                "N10_UNLISTED_SHAPE: this run's convert VKs removed from the whitelist — MUST \
                 FAIL (combine witness generation)"
            );
            let mine: Vec<pico_vm::mle::machine::vk_map::VkIdentity> = convert
                .pks
                .iter()
                .map(|entry| vk_identity(&entry.3))
                .collect();
            let mut ids = map.entries.clone();
            let before = ids.len();
            ids.retain(|id| !mine.contains(id));
            assert!(
                ids.len() < before,
                "N10: this run's convert VKs were not whitelist members to begin with"
            );
            std::sync::Arc::new(MleVkMap::build(ids))
        } else {
            map
        };
        convert.set_vk_root(map.root()).expect("set vk root");
        combine.set_vk_map(map.clone());
        Some(map)
    } else {
        None
    };
    let t_prove_all = std::time::Instant::now();
    let convert_proofs = convert
        .prove_with_vks(&riscv_proofs)
        .expect("convert prove failed");
    let prove_all_ms = t_prove_all.elapsed().as_millis();
    let t_verify_all = std::time::Instant::now();
    for (proof, vk) in &convert_proofs {
        convert
            .engine
            .verify(&**vk, proof)
            .expect("convert verify failed");
    }
    info!(
        "convert_timing phase: new_ms = {new_ms}, prove_all_ms = {prove_all_ms}, \
         verify_all_ms = {}",
        t_verify_all.elapsed().as_millis()
    );
    info!(
        "Convert: {} proof(s) proved + verified on the MLE/WHIR backend ✓",
        convert_proofs.len()
    );
    if args.step == "convert" {
        return;
    }

    // ── Phase 3: Combine (the machine + whitelist were built before convert proving) ──
    // Negative-test hook N1_INCOMPLETE: combine only a strict PREFIX of the chunks while
    // still baking a complete root. The completeness block is armed, so proving MUST fail —
    // but note the FIRST unsatisfiable assertion is next_pc == 0 (the prefix's last chunk is
    // non-final). This proves the completeness block is WIRED, but does not isolate the GCS
    // closure; use N6_BAD_GCS_WITNESS for that.
    let mut children = convert_proofs;
    if std::env::var("N1_INCOMPLETE").is_ok() {
        assert!(
            children.len() >= 3,
            "N1_INCOMPLETE needs >= 3 chunks (use --elf fib with a large --n)"
        );
        children.truncate(2);
        tracing::warn!(
            "N1_INCOMPLETE: combining only the first 2 chunks — this run MUST FAIL (at next_pc==0)"
        );
    }
    // Negative-test hook N2_TAMPER_CHILD: corrupt one opened value of a convert child proof.
    // The combine pipeline MUST reject it: witness generation goes through, and the root's
    // STARK verify fails on the in-circuit WHIR checks (measured; the host transcript replay
    // does not re-verify the child) — this run MUST FAIL.
    if std::env::var("N2_TAMPER_CHILD").is_ok() {
        tracing::warn!("N2_TAMPER_CHILD: corrupting one convert-child opened value — MUST FAIL");
        children[0].0.whir_proof.initial_round_opened_rows[0][0][0][0] += Kb::ONE;
    }
    // Negative-test hook N8_FORGED_MEMBERSHIP: corrupt every whitelist path (entries + root
    // intact, so host-side lookups succeed and witness generation proceeds) BEFORE proving —
    // the in-circuit membership constraint is the only thing left to notice the forgery.
    if std::env::var("N8_FORGED_MEMBERSHIP").is_ok() {
        assert!(vk_verification, "N8 requires whitelist mode");
        tracing::warn!(
            "N8_FORGED_MEMBERSHIP: corrupting whitelist paths — MUST FAIL (in-circuit membership)"
        );
        let mut bad = (**vk_map.as_ref().unwrap()).clone();
        bad.corrupt_paths_for_testing();
        combine.set_vk_map(std::sync::Arc::new(bad));
    }
    let root = combine
        .prove_tree(children)
        .expect("combine prove_tree failed");
    // Negative-test hook N7_BAD_VK_ROOT: hand the apex a DIFFERENT whitelist than the one the
    // tree was proven against. The root's witnessed vk_root PV cannot match the new trusted
    // root — the apex whitelist check MUST reject.
    if std::env::var("N7_BAD_VK_ROOT").is_ok() {
        assert!(vk_verification, "N7 requires whitelist mode");
        tracing::warn!("N7_BAD_VK_ROOT: wrong trusted whitelist — MUST FAIL (apex vk_root)");
        let mut ids = vk_map.as_ref().unwrap().entries.clone();
        ids.swap(0, 1); // different leaf order → different root, same members
        combine.set_vk_map(std::sync::Arc::new(MleVkMap::build(ids)));
    }
    combine.verify(&root).expect("combine root verify failed");
    // Standalone apex (FRI parity): re-accept the root from artifacts only — no machine. It
    // requires the whitelist (its trust story), so it runs in whitelist mode only; hooks that
    // perturb the trusted identity apply to it identically.
    if let Some(map) = &vk_map {
        // The pinned root is the deployment's constant (`MLE_VK_ROOT`); a self-map run has none
        // and pins its own. N9 pins a wrong one: the apex MUST refuse it at construction.
        let mut trusted_root =
            pico_vm::mle::machine::vk_map::pinned_root_from_env().unwrap_or_else(|| map.root());
        if std::env::var("N9_WRONG_PINNED_ROOT").is_ok() {
            tracing::warn!("N9_WRONG_PINNED_ROOT: pinning a wrong root — MUST FAIL (apex)");
            trusted_root[0] += pico_vm::mle::machine::riscv::Kb::ONE;
        }
        let apex = pico_vm::mle::machine::apex::MleApexVerifier::new(
            recursion_params_with_100_bits_security(),
            std::sync::Arc::clone(map),
            trusted_vm_vk_for_apex.clone(),
            trusted_root,
        );
        apex.verify(&root).expect("standalone apex verify failed");
        info!("standalone apex verify ✓");
    }
    // Cross-build check: hand the root to the other build (CPU or `cuda`) and have it verify. What
    // this covers is the two builds' keygen, constraint set and wire format. What it does NOT
    // cover: this example drives the CPU `CombineMachine`, while production `cuda` builds
    // recursion-prove through `GpuCombineMachine` — that prover is outside the gate. The child
    // layouts travel with the proof because the verifying side has no children to derive the
    // root's shape from.
    if let Ok(path) = std::env::var("MLE_DUMP_ROOT") {
        let layouts = combine
            .root_child_layouts(&root.1)
            .expect("no complete shape matches the root vk")
            .to_vec();
        // The proof travels in its own versioned wire codec, not bincode: that codec is what a
        // real consumer decodes with, so routing the dump through it makes this gate cover the
        // wire format too. The vk and layouts have no such codec and go through serde.
        use pico_mle_core::codec::Encode;
        // The operating point and the whitelist mode ride along: they change the keygen'd shape,
        // so a verifier that guessed them from its own environment would fail with a digest
        // mismatch rather than a mismatch it can name.
        let blob = (
            root.0.encode_to_vec().expect("root proof encode"),
            &*root.1,
            &layouts,
            log_stacked_height,
            vk_verification,
        );
        std::fs::write(&path, bincode::serialize(&blob).expect("root dump encode"))
            .expect("root dump write");
        info!("root dumped to {path} ({} child layout(s))", layouts.len());
    }
    info!(
        "Combine: root proved + verified (complete, {} distinct shape(s)) ✓",
        combine.num_distinct_shapes()
    );
    // Root proof size + per-field attribution. Shared with the GPU driver so the field
    // list exists once (`recursion::log_proof_size`); measures the proof only — the vk is a
    // fixed, separately known artifact.
    pico_vm::mle::machine::recursion::log_proof_size("Combine: root", &root.0);
    if args.step == "combine" {
        return;
    }

    // ── embed: re-prove the complete root under the outer BN254-hashed config ────────────────
    //
    // The step the on-chain path needs: same program family as the root it wraps, but its Merkle
    // paths and transcript are BN254-native, so a gnark circuit can verify them with `Permute`
    // opcodes instead of a few hundred emulated Poseidon2-KoalaBear permutations per hash.
    if args.step == "embed" || args.step == "wrap" {
        let emit_wrap = args.step == "wrap";
        run_embed_step(
            root,
            trusted_vm_vk_for_apex,
            vk_verification,
            vk_map,
            emit_wrap.then_some(committed.as_slice()),
        );
        return;
    }

    // compress: later phase.
    info!(
        "step `{}` not yet implemented on the MLE backend",
        args.step
    );
}

/// Re-prove the complete root under the outer BN254-Poseidon2 config, verify it, and report its
/// size; with `wrap_committed`, also build the wrap circuit for it. Only compiled with the feature
/// that brings the outer config into existence.
#[cfg(feature = "multi-field-transcript")]
fn run_embed_step(
    root: pico_vm::mle::machine::convert::ProofWithVk,
    trusted_vm_vk: RiscvVmVk,
    vk_verification: bool,
    vk_map: Option<std::sync::Arc<MleVkMap>>,
    wrap_committed: Option<&[u8]>,
) {
    use pico_mle_core::codec::Encode;
    use pico_vm::mle::machine::embed::EmbedMachine;

    let mut embed = EmbedMachine::new(
        pico_mle_core::config::embed_params_with_100_bits_security(),
        trusted_vm_vk,
        vk_verification,
    );
    if let Some(map) = &vk_map {
        embed.set_vk_map(map.clone());
    }
    let t_prove = std::time::Instant::now();
    let embed_proof = embed.prove(root).expect("embed prove failed");
    let prove_ms = t_prove.elapsed().as_millis();
    let t_verify = std::time::Instant::now();
    embed.verify(&embed_proof).expect("embed verify failed");
    info!(
        "Embed: proved + verified under the outer BN254 config ({} shape(s)) ✓ \
         prove_ms={prove_ms} verify_ms={}",
        embed.num_distinct_shapes(),
        t_verify.elapsed().as_millis(),
    );
    let embed_bytes = embed_proof
        .0
        .encode_to_vec()
        .expect("encode embed proof")
        .len();
    info!(
        "Embed: proof serialized size = {} bytes ({:.2} KiB)",
        embed_bytes,
        embed_bytes as f64 / 1024.0
    );
    fn sz<T: serde::Serialize>(v: &T) -> usize {
        postcard::to_allocvec(v).map(|b| b.len()).unwrap_or(0)
    }
    let p = &embed_proof.0;
    info!(
        "embed proof size breakdown: common_main_commit={} trace_vdata={} public_values={} \
         gkr={} batch_constraint={} stacking={} whir={}",
        sz(&p.common_main_commit),
        sz(&p.trace_vdata),
        sz(&p.public_values),
        sz(&p.gkr_proof),
        sz(&p.batch_constraint_proof),
        sz(&p.stacking_proof),
        sz(&p.whir_proof),
    );

    let Some(committed) = wrap_committed else {
        return;
    };

    // ── wrap: the embed-proof verifier as a gnark circuit ───────────────────────────────────
    //
    // WRAP_TAMPER selects a negative test: the opcode stream stays honest and exactly one witness
    // value is perturbed. Every witness value is supposed to be bound by some constraint, so gnark
    // solve MUST then fail — one that still solves is an under-constrained value.
    let tamper_kind = std::env::var("WRAP_TAMPER").ok();
    if let Some(kind) = &tamper_kind {
        tracing::warn!("WRAP_TAMPER={kind}: perturbing one witness value — gnark solve MUST FAIL");
    }
    let t_wrap = std::time::Instant::now();
    // Whitelist mode pins its root; whitelist-off is a dev run and says so explicitly.
    let vk_root_pin = match vk_map.as_ref() {
        Some(m) => pico_vm::mle::machine::wrap::VkRootPin::Trusted(m.root()),
        None => pico_vm::mle::machine::wrap::VkRootPin::DevUnpinned,
    };
    let artifacts = pico_vm::mle::machine::wrap::build_wrap_artifacts_with(
        &embed_proof,
        vk_root_pin,
        |w, squeezes| {
            let Some(kind) = tamper_kind.as_deref() else {
                return;
            };
            let one_f = Kb::ONE;
            let one_n = <pico_vm::configs::field_config::KoalaBearBn254 as
                pico_vm::configs::config::FieldGenericConfig>::N::ONE;
            let one_ef = <pico_vm::configs::field_config::KoalaBearBn254 as
                pico_vm::configs::config::FieldGenericConfig>::EF::ONE;
            match kind {
                // vars: commitments (head) and transcript remainders (tail)
                "var_first" => w.vars[0] += one_n,
                "var_mid" => {
                    let i = w.vars.len() / 2;
                    w.vars[i] += one_n
                }
                "var_last" => {
                    let i = w.vars.len() - 1;
                    w.vars[i] += one_n
                }
                // felts: public values (head), opened WHIR rows (middle), transcript digits
                // (tail)
                "felt_first" => w.felts[0] += one_f,
                "felt_mid" => {
                    let i = w.felts.len() / 2;
                    w.felts[i] += one_f
                }
                "felt_last" => {
                    let i = w.felts.len() - 1;
                    w.felts[i] += one_f
                }
                // exts: gkr claims (head), sumcheck/stacking (middle), whir final poly (tail)
                "ext_first" => w.exts[0] += one_ef,
                "ext_mid" => {
                    let i = w.exts.len() / 2;
                    w.exts[i] += one_ef
                }
                "ext_last" => {
                    let i = w.exts.len() - 1;
                    w.exts[i] += one_ef
                }
                // The three public inputs.
                "vkey_hash" => w.vkey_hash += one_n,
                "cvd" => w.committed_values_digest += one_n,
                // The remainder of the FIRST squeeze, pushed past the canonical bound: this is the
                // value the outer circuit's canonical-remainder check exists to reject.
                "rem_over_bound" => {
                    let idx = w.vars.len() - squeezes;
                    w.vars[idx] =
                        pico_vm::compiler::recursion::circuit::outer_bn254::canonical_rem_max()
                            + one_n;
                }
                other => panic!("unknown WRAP_TAMPER kind `{other}`"),
            }
        },
    )
    .expect("wrap artifact build failed");
    info!(
        "wrap: built in {} ms — {} gnark opcodes; witness vars={} felts={} exts={}; \
         {} extraction squeezes",
        t_wrap.elapsed().as_millis(),
        artifacts.constraints.len(),
        artifacts.num_vars,
        artifacts.num_felts,
        artifacts.num_exts,
        artifacts.num_extraction_squeezes,
    );
    info!(
        "wrap public inputs: vkey_hash={} committed_values_digest={} \
         (vk_root is baked into the circuit, not a public input)",
        artifacts.vkey_hash, artifacts.committed_values_digest,
    );
    artifacts
        .save("wrap_constraints.json", "wrap_groth16_witness.json")
        .expect("write wrap artifacts");
    info!("wrap: wrote wrap_constraints.json + wrap_groth16_witness.json ✓");

    // What the verifier contract is called with, apart from the proof gnark has yet to make:
    // `contracts/`'s `verifyPicoProof(riscvVKey, publicValues, proof)`. The digest is the one
    // input the contract computes itself, from `publicValues`, so the bytes written here must hash
    // to the proof's — checked rather than assumed.
    let word = |n: &<pico_vm::configs::field_config::KoalaBearBn254 as
        pico_vm::configs::config::FieldGenericConfig>::N| {
        use p3_field::PrimeField;
        let be = n.as_canonical_biguint().to_bytes_be();
        assert!(be.len() <= 32, "a BN254 scalar is at most 32 bytes");
        let mut out = [0u8; 32];
        out[32 - be.len()..].copy_from_slice(&be);
        out
    };
    let mut digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(committed).into();
    // `hashPublicValues`: the top three bits cleared, so the digest fits one BN254 scalar.
    digest[0] &= 0x1f;
    let cvd = word(&artifacts.committed_values_digest);
    assert_eq!(
        digest, cvd,
        "the committed bytes do not hash to the proof's committed_values_digest"
    );
    // The fields of main's `inputs.json` (`cargo pico prove --evm`), in its order, less the
    // proof: `jq` appends that once gnark has made it (see `gnark/README.md`).
    #[derive(serde::Serialize)]
    struct WrapInputs {
        #[serde(rename = "riscvVKey")]
        riscv_vkey: String,
        #[serde(rename = "publicValues")]
        public_values: String,
        #[serde(rename = "committedValuesDigest")]
        committed_values_digest: String,
    }
    let inputs = WrapInputs {
        riscv_vkey: format!("0x{}", hex::encode(word(&artifacts.vkey_hash))),
        public_values: format!("0x{}", hex::encode(committed)),
        committed_values_digest: format!("0x{}", hex::encode(cvd)),
    };
    std::fs::write(
        "wrap_inputs.json",
        serde_json::to_string_pretty(&inputs).expect("inputs serialize") + "\n",
    )
    .expect("write wrap_inputs.json");
    info!("wrap: wrote wrap_inputs.json (the verifier's inputs, less the proof) ✓");
}

#[cfg(not(feature = "multi-field-transcript"))]
fn run_embed_step(
    _root: pico_vm::mle::machine::convert::ProofWithVk,
    _trusted_vm_vk: RiscvVmVk,
    _vk_verification: bool,
    _vk_map: Option<std::sync::Arc<MleVkMap>>,
    wrap_committed: Option<&[u8]>,
) {
    panic!(
        "`--step {}` needs the outer BN254 config: rebuild without --no-default-features, or \
         with --features multi-field-transcript",
        if wrap_committed.is_some() {
            "wrap"
        } else {
            "embed"
        }
    );
}
