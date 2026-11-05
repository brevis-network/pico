//! MLE/WHIR-backend end-to-end recursion proving from a real ELF.
//!
//! Runs the proving pipeline up to the requested `--step`:
//!   riscv    → prove + verify each RISCV chunk
//!   convert  → wrap each RISCV proof in a recursion (Convert) proof and verify it
//!   combine  → tree-reduce the convert proofs to one complete root proof and verify it
//!   compress → re-prove that root under the inner config at the compress preset and verify it:
//!              the final compression layer, the proof that is handed out
//!   embed    → compress, then re-prove the compress proof under the outer BN254-Poseidon2 config
//!              and verify it
//!   wrap     → embed, then emit the gnark circuit + witness for it, and the verifier's inputs
//!              (both require the default `multi-field-transcript` feature)
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
//!   MLE_DUMP_COMPRESS=<path> / MLE_VERIFY_COMPRESS=<path>  the same pair for the compress proof
//!                          (`--step compress / embed / wrap`): the dump carries the proof, its VK
//!                          and the root's layout; the verifier re-keygens compress for that
//!                          layout and compares (`--step` is ignored, as with MLE_VERIFY_ROOT).
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
//!   N11_TAMPER_PACKED_LANE=1 set the padding lane (lane PACK_LANES of a `Block::packed`) of the
//!                     first packed opened-row block of every WHIR round-0 (query, commit) pair
//!                     to one, in every recursion witness (`recursion/witness.rs`); the packed
//!                     consumers read that lane as the constant zero, so the memory bus cannot
//!                     balance — the FIRST proof built on such a witness, a convert proof,
//!                     MUST FAIL in its prover with `LogupZerocheck(NonZeroRootSum)`
//!   N10_UNLISTED_SHAPE=1 remove this run's own convert VKs from the whitelist and re-root it,
//!                     so the shapes the chunks select are not members — the host-side lookup
//!                     fails closed at combine witness generation, before any recursion proof
//!   N12_TAMPER_COMPRESS=1 (with --step compress / embed / wrap) corrupt one opened value of the
//!                     compress proof after proving; the compress verify MUST reject it (the
//!                     reason is logged), and under the whitelist artifact so must the apex's
//!                     `verify_compress`
//!   N13_COMPRESS_INCOMPLETE=1 (with --step compress) hand the first chunk's convert proof to
//!                     the compress machine in place of the complete root: the compress program
//!                     is built with `is_complete = true`, so a non-final child (flag_complete 0,
//!                     next_pc ≠ 0) MUST FAIL — in a release build witness generation goes
//!                     through and the STARK verify rejects (`SumClaimMismatch`, measured); with
//!                     debug assertions the recursion runtime's `AssertZeroExt` is expected to
//!                     panic first. Needs >= 2 chunks (fib with a large --n)
//!   N14_TAMPER_EMBED_CHILD=1 (with --step embed / wrap) corrupt one opened value of the compress
//!                     proof after it verified, then hand it to embed: embed's prove or verify
//!                     MUST reject it (in a release build witness generation goes through and the
//!                     embed STARK verify rejects; with debug assertions `AssertZeroExt` is
//!                     expected to panic first)
//!   N15_TAMPER_EMBED=1 (with --step embed / wrap) corrupt one opened value of the embed proof
//!                     after proving; the embed verify MUST reject it
//!   N16_FORGED_EMBED_MEMBERSHIP=1 (with --step embed / wrap; forces whitelist mode) hand embed a
//!                     whitelist whose paths are corrupted, entries + root intact: witness
//!                     generation succeeds, so embed's IN-CIRCUIT membership check of the compress
//!                     key must reject (the embed proof's STARK verify fails, measured in a
//!                     release build); an error at prove time means the in-circuit check was not
//!                     reached and is logged as not exercised, with a zero exit (a failed host-side
//!                     whitelist lookup panics in witness generation instead)
//!   N17_EMBED_GETS_ROOT=1 (with --step embed / wrap) hand the combine root to embed in place of
//!                     the compress proof: embed's child guard MUST refuse it with an error before
//!                     keygen, not at the tier assertion when padding to the embed row; an error
//!                     from anything else is logged as the guard not having run, with a zero exit
//!   N14–N17 are armed by `=1` and act only under `--step embed / wrap` in a build with the
//!   `multi-field-transcript` feature; anywhere else a run that sets one logs that it was not
//!   exercised and exits zero (an unexercised hook is no pass). Without the feature,
//!   `--step embed / wrap` stop before proving.

use p3_field::PrimeCharacteristicRing;
use pico_mle_core::{
    codec::{Decode, Encode},
    config::{
        compress_params_with_128_bits_security, recursion_params_with_128_bits_security,
        riscv_params_with_128_bits_security,
    },
    StarkEngine,
};
#[cfg(feature = "cuda")]
use pico_vm::mle::machine::compress::GpuCompressMachine;
use pico_vm::{
    compiler::{
        program::ProgramBehavior,
        riscv::compiler::{Compiler, SourceType},
    },
    configs::stark_config::KoalaBearPoseidon2,
    machine::{logger::setup_logger, septic::SepticDigest},
    mle::machine::{
        combine::CombineMachine,
        compress::CompressMachine,
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
            StarkEngine::new(riscv_params_with_128_bits_security(dumped_height));
        let airs = riscv::mle_riscv_air_refs(program.clone(), dumped_whitelist);
        let (_, riscv_vk) = engine.keygen_with_app_prep(&airs, riscv::RISCV_APP_PREP_AIR_IDS);
        let trusted = RiscvVmVk::from_program_and_vk(&program, &riscv_vk);
        let mut combine = CombineMachine::new(
            recursion_params_with_128_bits_security(),
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
    // Same gate for the compress proof: the dump carries the root's layout, which is what the
    // compress key is a function of, and the verifying side re-keygens compress for it.
    if let Ok(path) = std::env::var("MLE_VERIFY_COMPRESS") {
        let bytes = std::fs::read(&path).expect("compress dump read");
        #[allow(clippy::type_complexity)]
        let (proof_bytes, compress_vk, root_layout, dumped_height, dumped_whitelist): (
            Vec<u8>,
            pico_mle_core::keygen::types::MultiStarkVerifyingKey<riscv::Sc>,
            pico_vm::mle::compiler::recursion::RecursionVkLayout,
            usize,
            bool,
        ) = bincode::deserialize(&bytes).expect("compress dump decode");
        let proof =
            pico_mle_core::protocol::proof::Proof::<riscv::Sc>::decode_from_bytes(&proof_bytes)
                .expect("compress proof decode");
        assert!(
            !dumped_whitelist,
            "this compress proof was made with the whitelist on; cross-build checking only covers \
             VK_VERIFICATION=false"
        );
        let engine: riscv::Engine =
            StarkEngine::new(riscv_params_with_128_bits_security(dumped_height));
        let airs = riscv::mle_riscv_air_refs(program.clone(), dumped_whitelist);
        let (_, riscv_vk) = engine.keygen_with_app_prep(&airs, riscv::RISCV_APP_PREP_AIR_IDS);
        let trusted = RiscvVmVk::from_program_and_vk(&program, &riscv_vk);
        let mut compress = CompressMachine::new(
            compress_params_with_128_bits_security(),
            trusted,
            dumped_whitelist,
        );
        compress
            .preregister(&root_layout)
            .unwrap_or_else(|e| panic!("{e}"));
        let honest = compress
            .honest_compress_vk(&compress_vk)
            .expect("no honestly keygen'd compress shape matches the dumped vk");
        if bincode::serialize(honest).expect("honest vk encode")
            != bincode::serialize(&compress_vk).expect("dumped vk encode")
        {
            panic!(
                "the dumped compress vk differs from the one this build keygens for the same root \
                 layout"
            );
        }
        compress
            .verify(&(proof, std::sync::Arc::new(compress_vk)))
            .expect("cross-build compress verify failed");
        info!(
            "cross-build compress verify ✓ ({path}, height {dumped_height}, whitelist \
             {dumped_whitelist})"
        );
        return;
    }

    // The embed hooks act only where embed runs: `--step embed / wrap`, in a build with the outer
    // BN254 config. Anywhere else a run that sets one says so before proving anything and exits
    // zero, since a hook that is never reached must not read as "the tamper was caught" to an
    // exit-code harness. Without the outer config an embed / wrap step stops here too, before the
    // riscv proof rather than after compress.
    let armed: Vec<&str> = EMBED_HOOKS.into_iter().filter(|h| hook(h)).collect();
    let embed_runs =
        cfg!(feature = "multi-field-transcript") && matches!(args.step.as_str(), "embed" | "wrap");
    if !armed.is_empty() && !embed_runs {
        info!(
            "{}: not exercised — needs `--step embed / wrap` and the multi-field-transcript \
             feature (zero exit: an unexercised hook is no pass)",
            armed.join(" + ")
        );
        return;
    }
    #[cfg(not(feature = "multi-field-transcript"))]
    {
        assert!(
            !matches!(args.step.as_str(), "embed" | "wrap"),
            "`--step {}` needs the outer BN254 config: rebuild without --no-default-features, or \
             with --features multi-field-transcript",
            args.step
        );
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
        || std::env::var("N10_UNLISTED_SHAPE").is_ok()
        || hook("N16_FORGED_EMBED_MEMBERSHIP");
    let requested = std::env::var("VK_VERIFICATION").map(|v| v.eq_ignore_ascii_case("true"));
    let vk_verification = requested.clone().unwrap_or(false) || whitelist_hook;
    if whitelist_hook && requested == Ok(false) {
        info!(
            "VK_VERIFICATION=false overridden: N7–N10 and N16 only mean anything with the whitelist"
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
        recursion_params_with_128_bits_security(),
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
        recursion_params_with_128_bits_security(),
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
            // The compress key, over the combine-tier child every complete root takes in
            // whitelist mode: embed checks it in-circuit, so a self-map run that goes on to
            // embed needs it, as the shipped whitelist has it (its last leaf). This couples every
            // self-map run to the compress row, `--step convert / combine` included: one more
            // keygen (`prove_compress_node` keygens again on its own machine), and a stale compress
            // row stops the run here at the tier assertion.
            let combine_tier = combine
                .combine_tier_child_layout(&convert.pks[0].3)
                .unwrap_or_else(|e| panic!("{e}"));
            let compress_vk = CompressMachine::new(
                compress_params_with_128_bits_security(),
                trusted_vm_vk_for_apex.clone(),
                true,
            )
            .preregister(&combine_tier)
            .unwrap_or_else(|e| panic!("{e}"));
            ids.push(vk_identity(&compress_vk));
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
    // Negative-test hook N11_TAMPER_PACKED_LANE: read by the recursion witness builder
    // (`recursion/witness.rs`), which corrupts the padding lane of packed opened-row blocks;
    // the first convert prove below MUST FAIL. Logged here, before the failure, at info level
    // (the forest logger prints only INFO events).
    if std::env::var("N11_TAMPER_PACKED_LANE").is_ok_and(|v| v == "1") {
        tracing::info!(
            "N11_TAMPER_PACKED_LANE: a packed block's padding lane is non-zero — the convert \
             prove MUST FAIL"
        );
    }
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
    // Negative-test hook N13_COMPRESS_INCOMPLETE: a non-final chunk's convert proof in place of the
    // complete root. The compress program's completeness block is armed (`is_complete = true`), so
    // this MUST FAIL: in a release build witness generation goes through and the STARK verify
    // rejects (`SumClaimMismatch`, measured); with debug assertions the runtime's `AssertZeroExt`
    // is expected to panic first. A zero exit here is the fail-open signal (see the head).
    if std::env::var("N13_COMPRESS_INCOMPLETE").is_ok_and(|v| v == "1") {
        assert!(
            convert_proofs.len() >= 2,
            "N13_COMPRESS_INCOMPLETE needs >= 2 chunks (use --elf fib with a large --n)"
        );
        info!(
            "N13_COMPRESS_INCOMPLETE: handing the first chunk's convert proof to compress — this \
             run MUST FAIL"
        );
        let child = convert_proofs[0].clone();
        let _ = run_compress_step(
            child,
            trusted_vm_vk_for_apex,
            vk_verification,
            vk_map,
            log_stacked_height,
        );
        info!(
            "N13_COMPRESS_INCOMPLETE: compress accepted a non-final convert proof — FAIL-OPEN \
             (zero exit)"
        );
        return;
    }
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
            recursion_params_with_128_bits_security(),
            compress_params_with_128_bits_security(),
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

    // ── compress: re-prove the complete root under the inner config at the compress preset ───
    //
    // The final compression layer: the proof that is handed out, 123 WHIR queries at
    // log_blowup 4 in place of the root's 383 at log_blowup 2. `--step embed / wrap` go on from it.
    if matches!(args.step.as_str(), "compress" | "embed" | "wrap") {
        // Negative-test hook N17_EMBED_GETS_ROOT (with --step embed / wrap, checked at the start):
        // the combine root handed to embed in place of the compress proof; embed's child guard MUST
        // refuse it.
        if hook("N17_EMBED_GETS_ROOT") {
            n17_embed_gets_root(root, trusted_vm_vk_for_apex, vk_verification, vk_map);
            return;
        }
        let compress_proof = run_compress_step(
            root,
            trusted_vm_vk_for_apex.clone(),
            vk_verification,
            vk_map.clone(),
            log_stacked_height,
        );
        if args.step == "compress" {
            return;
        }

        // ── embed: re-prove the compress proof under the outer BN254-hashed config ───────────
        //
        // The step the on-chain path needs: same program family as the compress proof it wraps,
        // but its Merkle paths and transcript are BN254-native, so a gnark circuit can verify them
        // with `Permute` opcodes instead of a few hundred emulated Poseidon2-KoalaBear permutations
        // per hash.
        let emit_wrap = args.step == "wrap";
        run_embed_step(
            compress_proof,
            trusted_vm_vk_for_apex,
            vk_verification,
            vk_map,
            emit_wrap.then_some(committed.as_slice()),
        );
        return;
    }

    info!(
        "step `{}` not yet implemented on the MLE backend",
        args.step
    );
}

/// A negative-test hook is armed by `<NAME>=1`.
fn hook(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| v == "1")
}

/// The hooks that act only where embed runs (`--step embed / wrap`, `multi-field-transcript`).
const EMBED_HOOKS: [&str; 4] = [
    "N14_TAMPER_EMBED_CHILD",
    "N15_TAMPER_EMBED",
    "N16_FORGED_EMBED_MEMBERSHIP",
    "N17_EMBED_GETS_ROOT",
];

/// Prove the compress node over `root` and return the machine, the proof (not yet verified), the
/// root's layout and the prove time. The compress key is keygen'd first, so the prove time excludes
/// keygen, except on a `cuda` build: there the GPU prover keygens its own device key inside
/// the prove, so `prove_ms` includes that keygen and its warm-up (`gpu_compress_timing` breaks it
/// down). Under the GLOBAL artifact (`MLE_VK_MAP`) the key must be a whitelist member, the last
/// leaf: asserted before proving, as the SDK refuses it.
fn prove_compress_node(
    root: pico_vm::mle::machine::convert::ProofWithVk,
    trusted_vm_vk: RiscvVmVk,
    vk_verification: bool,
    vk_map: &Option<std::sync::Arc<MleVkMap>>,
) -> (
    CompressMachine,
    pico_vm::mle::machine::compress::CompressProofWithVk,
    pico_vm::mle::compiler::recursion::RecursionVkLayout,
    u128,
) {
    let mut compress = CompressMachine::new(
        compress_params_with_128_bits_security(),
        trusted_vm_vk,
        vk_verification,
    );
    if let Some(map) = vk_map {
        compress.set_vk_map(map.clone());
    }
    // The root's layout is what the compress key is a function of; a dump carries it because the
    // verifying side has no root to derive it from.
    let root_layout =
        pico_vm::mle::machine::recursion::extract_recursion_vk_layout(&root.1, Some(&root.0));
    let t_keygen = std::time::Instant::now();
    let vk = compress.preregister(&root_layout).expect("compress keygen");
    info!("Compress: keygen_ms={}", t_keygen.elapsed().as_millis());
    if let Some(map) = vk_map
        .as_ref()
        .filter(|_| std::env::var("MLE_VK_MAP").is_ok())
    {
        let index = map.find(&vk_identity(&vk)).expect(
            "the compress key is not a whitelist member: the artifact predates this binary's \
             compress machinery",
        );
        info!(
            "compress key is whitelist leaf {index} of {}",
            map.entries.len()
        );
    }
    let t_prove = std::time::Instant::now();
    // GPU build: the production prover (`GpuCompressMachine`, device keygen + trace-gen) proves,
    // and the CPU machine keygens the same layout's key and accepts — as combine's root is.
    #[cfg(feature = "cuda")]
    let proof = {
        let mut gpu =
            GpuCompressMachine::new(compress_params_with_128_bits_security(), vk_verification);
        if let Some(map) = vk_map {
            gpu.set_vk_map(map.clone());
        }
        let proved = gpu.prove(&root).expect("gpu compress prove failed");
        compress
            .preregister(&proved.root_layout)
            .unwrap_or_else(|e| panic!("{e}"));
        proved.proof
    };
    #[cfg(not(feature = "cuda"))]
    let proof = compress.prove(root).expect("compress prove failed");
    (compress, proof, root_layout, t_prove.elapsed().as_millis())
}

/// Prove the compress node over the complete root (`prove_compress_node`), verify it, report its
/// size and stacked width, and serve the hooks of this step: `MLE_DUMP_COMPRESS`,
/// `N12_TAMPER_COMPRESS`. Returns the verified compress proof, which `--step embed / wrap` hand on
/// to embed.
fn run_compress_step(
    root: pico_vm::mle::machine::convert::ProofWithVk,
    trusted_vm_vk: RiscvVmVk,
    vk_verification: bool,
    vk_map: Option<std::sync::Arc<MleVkMap>>,
    log_stacked_height: usize,
) -> pico_vm::mle::machine::compress::CompressProofWithVk {
    let tamper = std::env::var("N12_TAMPER_COMPRESS").is_ok_and(|v| v == "1");
    let (compress, mut compress_proof, root_layout, prove_ms) =
        prove_compress_node(root, trusted_vm_vk.clone(), vk_verification, &vk_map);
    if tamper {
        info!(
            "N12_TAMPER_COMPRESS: corrupting one opened value of the compress proof — verify MUST \
             FAIL"
        );
        compress_proof.0.whir_proof.initial_round_opened_rows[0][0][0][0] += Kb::ONE;
        // A zero exit is the fail-open signal of this example's negative tests (see the head), so
        // an accepted tamper logs FAIL-OPEN (at info, which the forest logger prints) and exits 0;
        // the rejection panics, as required.
        let mut fail_open = false;
        match compress.verify(&compress_proof) {
            Err(e) => info!("N12_TAMPER_COMPRESS: compress verify rejected ✓: {e:#}"),
            Ok(()) => {
                info!(
                    "N12_TAMPER_COMPRESS: compress verify ACCEPTED the tampered proof — FAIL-OPEN"
                );
                fail_open = true;
            }
        }
        // The same tamper through the apex, the verifier a consumer runs.
        if let Some(apex) = compress_apex(&vk_map, &trusted_vm_vk) {
            match apex.verify_compress(&compress_proof) {
                Err(e) => info!("N12_TAMPER_COMPRESS: apex verify_compress rejected ✓: {e:#}"),
                Ok(()) => {
                    info!(
                        "N12_TAMPER_COMPRESS: apex verify_compress ACCEPTED the tampered proof — \
                         FAIL-OPEN"
                    );
                    fail_open = true;
                }
            }
        }
        if fail_open {
            std::process::exit(0);
        }
        panic!("N12_TAMPER_COMPRESS: rejected as required — this run MUST FAIL");
    }

    let t_verify = std::time::Instant::now();
    compress
        .verify(&compress_proof)
        .expect("compress verify failed");
    info!(
        "Compress: proved + verified under the inner config ({} shape(s)) ✓ \
         prove_ms={prove_ms} verify_ms={}",
        compress.num_distinct_shapes(),
        t_verify.elapsed().as_millis(),
    );
    pico_vm::mle::machine::recursion::log_proof_size("Compress:", &compress_proof.0);
    // Standalone apex (as for the root above): the compress key authenticated by membership, then
    // the six checks under the compress engine.
    if let Some(apex) = compress_apex(&vk_map, &trusted_vm_vk) {
        apex.verify_compress(&compress_proof)
            .expect("standalone apex verify of the compress proof failed");
        info!("standalone apex verify (compress) ✓");
    }

    if let Ok(path) = std::env::var("MLE_DUMP_COMPRESS") {
        let blob = (
            compress_proof
                .0
                .encode_to_vec()
                .expect("compress proof encode"),
            &*compress_proof.1,
            &root_layout,
            log_stacked_height,
            vk_verification,
        );
        std::fs::write(
            &path,
            bincode::serialize(&blob).expect("compress dump encode"),
        )
        .expect("compress dump write");
        info!("compress proof dumped to {path}");
    }
    compress_proof
}

/// The apex a consumer verifies a compress proof with, under the GLOBAL whitelist artifact
/// (`MLE_VK_MAP`, pinned by `MLE_VK_ROOT`): the deployment's case, and the only one wired up. A
/// self-map run holds the compress leaf too (added where its map is built) and could run it as the
/// root's apex does, pinning its own root; it does not, so this is `None` there and the machine's
/// verify is the only check.
fn compress_apex(
    vk_map: &Option<std::sync::Arc<MleVkMap>>,
    trusted_vm_vk: &RiscvVmVk,
) -> Option<pico_vm::mle::machine::apex::MleApexVerifier> {
    let map = vk_map
        .as_ref()
        .filter(|_| std::env::var("MLE_VK_MAP").is_ok())?;
    let trusted_root =
        pico_vm::mle::machine::vk_map::pinned_root_from_env().unwrap_or_else(|| map.root());
    Some(pico_vm::mle::machine::apex::MleApexVerifier::new(
        recursion_params_with_128_bits_security(),
        compress_params_with_128_bits_security(),
        map.clone(),
        trusted_vm_vk.clone(),
        trusted_root,
    ))
}

/// The stacked width of every commit the WHIR initial round opens, and their sum, for a proof of
/// any config (the inner config's proofs get this line from `log_proof_size`).
#[cfg(feature = "multi-field-transcript")]
fn log_stacked_widths<SC: pico_mle_core::StarkProtocolConfig>(
    label: &str,
    proof: &pico_mle_core::proof::Proof<SC>,
) {
    let widths: Vec<usize> = proof
        .whir_proof
        .initial_round_opened_rows
        .iter()
        .map(|rows| {
            rows.first()
                .and_then(|q| q.first())
                .map(|r| r.len())
                .unwrap_or(0)
        })
        .collect();
    info!(
        "{label} stacked widths per commit = {widths:?}, total stacked width = {}",
        widths.iter().sum::<usize>()
    );
}

/// An embed machine at the embed preset, holding `vk_map` when there is one.
#[cfg(feature = "multi-field-transcript")]
fn embed_machine(
    trusted_vm_vk: RiscvVmVk,
    vk_verification: bool,
    vk_map: Option<std::sync::Arc<MleVkMap>>,
) -> pico_vm::mle::machine::embed::EmbedMachine {
    let mut embed = pico_vm::mle::machine::embed::EmbedMachine::new(
        pico_mle_core::config::embed_params_with_128_bits_security(),
        trusted_vm_vk,
        vk_verification,
    );
    if let Some(map) = vk_map {
        embed.set_vk_map(map);
    }
    embed
}

/// N17_EMBED_GETS_ROOT: the combine root handed to embed in place of the compress proof. Embed's
/// child guard MUST refuse it with an error before keygen; that rejection panics, as this example's
/// negative tests do. An accepted root logs FAIL-OPEN and returns, and so does an error that is not
/// the guard's (the guard did not run): both are a zero exit, the failure signal here.
#[cfg(feature = "multi-field-transcript")]
fn n17_embed_gets_root(
    root: pico_vm::mle::machine::convert::ProofWithVk,
    trusted_vm_vk: RiscvVmVk,
    vk_verification: bool,
    vk_map: Option<std::sync::Arc<MleVkMap>>,
) {
    info!(
        "N17_EMBED_GETS_ROOT: handing the combine root to embed — this run MUST FAIL (child guard)"
    );
    let mut embed = embed_machine(trusted_vm_vk, vk_verification, vk_map);
    match embed.prove(root) {
        Err(e) if format!("{e:#}").contains("embed expects a compress proof as its child") => {
            info!("N17_EMBED_GETS_ROOT: embed's child guard refused the root ✓: {e:#}");
            panic!("N17_EMBED_GETS_ROOT: rejected as required — this run MUST FAIL");
        }
        Err(e) => info!(
            "N17_EMBED_GETS_ROOT: embed refused the root, but not by its child guard — the guard \
             did not run (zero exit): {e:#}"
        ),
        Ok(_) => {
            info!("N17_EMBED_GETS_ROOT: embed accepted the combine root — FAIL-OPEN (zero exit)")
        }
    }
}

#[cfg(not(feature = "multi-field-transcript"))]
fn n17_embed_gets_root(
    _root: pico_vm::mle::machine::convert::ProofWithVk,
    _trusted_vm_vk: RiscvVmVk,
    _vk_verification: bool,
    _vk_map: Option<std::sync::Arc<MleVkMap>>,
) {
    unreachable!("main returns before proving when an embed hook is set without embed");
}

/// Re-prove the compress proof under the outer BN254-Poseidon2 config, verify it, report its size,
/// and serve the hooks of this step: `N14_TAMPER_EMBED_CHILD`, `N15_TAMPER_EMBED`,
/// `N16_FORGED_EMBED_MEMBERSHIP`, `WRAP_TAMPER`; with `wrap_committed`, also build the wrap circuit
/// for it and write the verifier's inputs. The embed key is keygen'd first, so the prove time
/// excludes keygen. Only compiled with the feature that brings the outer config into existence.
#[cfg(feature = "multi-field-transcript")]
fn run_embed_step(
    mut compress: pico_vm::mle::machine::compress::CompressProofWithVk,
    trusted_vm_vk: RiscvVmVk,
    vk_verification: bool,
    vk_map: Option<std::sync::Arc<MleVkMap>>,
    wrap_committed: Option<&[u8]>,
) {
    use pico_mle_core::codec::Encode;
    use pico_vm::mle::machine::recursion::{
        compress_proof_layout, extract_recursion_vk_layout, recursion_vk_layouts_equal,
    };

    let tamper_child = hook("N14_TAMPER_EMBED_CHILD");
    let tamper_embed = hook("N15_TAMPER_EMBED");
    let forged = hook("N16_FORGED_EMBED_MEMBERSHIP");
    // The armed hooks, named in the rejection and FAIL-OPEN lines.
    let armed = [
        ("N14_TAMPER_EMBED_CHILD", tamper_child),
        ("N15_TAMPER_EMBED", tamper_embed),
        ("N16_FORGED_EMBED_MEMBERSHIP", forged),
    ]
    .into_iter()
    .filter_map(|(name, on)| on.then_some(name))
    .collect::<Vec<_>>()
    .join(" + ");
    let negative = !armed.is_empty();
    let embed_map = if forged {
        let map = vk_map
            .as_ref()
            .expect("N16 forces whitelist mode, so there is a whitelist");
        info!(
            "N16_FORGED_EMBED_MEMBERSHIP: corrupting the whitelist paths embed witnesses — MUST \
             FAIL (embed's in-circuit membership check)"
        );
        let mut bad = (**map).clone();
        bad.corrupt_paths_for_testing();
        Some(std::sync::Arc::new(bad))
    } else {
        vk_map.clone()
    };
    let mut embed = embed_machine(trusted_vm_vk, vk_verification, embed_map);
    // The child layout embed is keyed to. In whitelist mode the compress proof is padded to the
    // compress row, so its layout must be the one the tier probe and the soundness manifest
    // synthesize; in dev mode compress runs at natural heights and only the widths are logged.
    let layout = extract_recursion_vk_layout(&compress.1, Some(&compress.0));
    info!(
        "Embed: child stacked widths per commit = {:?}, total = {}",
        layout.stacking_widths,
        layout.stacking_widths.iter().sum::<usize>()
    );
    if vk_verification {
        assert!(
            recursion_vk_layouts_equal(&layout, &compress_proof_layout(&compress.1)),
            "the compress proof's layout is not the one compress_proof_layout synthesizes from the \
             compress row"
        );
        info!("Embed: child layout = compress_proof_layout ✓");
    }
    let t_keygen = std::time::Instant::now();
    let embed_vk = embed.preregister(&layout).expect("embed keygen failed");
    let pre_hash: Vec<String> = embed_vk.pre_hash.iter().map(|x| x.to_string()).collect();
    let merged: Option<Vec<String>> = embed_vk
        .inner
        .merged_preprocessed_commit
        .map(|c| c.iter().map(|x| x.to_string()).collect());
    info!(
        "Embed: keygen_ms={} key vk_pre_hash={pre_hash:?} merged_preprocessed_commit={merged:?}",
        t_keygen.elapsed().as_millis()
    );
    if tamper_child {
        info!(
            "N14_TAMPER_EMBED_CHILD: corrupting one opened value of the compress proof — embed \
             MUST reject it"
        );
        compress.0.whir_proof.initial_round_opened_rows[0][0][0][0] += Kb::ONE;
    }
    let t_prove = std::time::Instant::now();
    // Only N14 tampers with embed's input, so only N14 may be refused at prove time. Under N15 or
    // N16 a prove error means the run never reached the check the hook tests (N15 tampers after
    // proving, N16 must be refused in-circuit): not exercised, a zero exit, as for N17's
    // unexpected refusals. A failed host-side whitelist lookup panics in witness generation.
    let mut embed_proof = match embed.prove(compress) {
        Ok(p) => p,
        Err(e) if tamper_child => {
            info!("N14_TAMPER_EMBED_CHILD: embed prove rejected the tampered child ✓: {e:#}");
            panic!("N14_TAMPER_EMBED_CHILD: rejected as required — this run MUST FAIL");
        }
        Err(e) if negative => {
            info!(
                "{armed}: embed prove failed before the check this hook tests — not exercised \
                 (zero exit): {e:#}"
            );
            return;
        }
        Err(e) => panic!("embed prove failed: {e:#}"),
    };
    let prove_ms = t_prove.elapsed().as_millis();
    if tamper_embed {
        info!(
            "N15_TAMPER_EMBED: corrupting one opened value of the embed proof — embed verify MUST \
             reject it"
        );
        embed_proof.0.whir_proof.initial_round_opened_rows[0][0][0][0] += Kb::ONE;
    }
    let t_verify = std::time::Instant::now();
    match embed.verify(&embed_proof) {
        Err(e) if negative => {
            info!("{armed}: embed verify rejected ✓: {e:#}");
            panic!("{armed}: rejected as required — this run MUST FAIL");
        }
        Err(e) => panic!("embed verify failed: {e:#}"),
        Ok(()) if negative => {
            info!("{armed}: embed ACCEPTED — FAIL-OPEN (zero exit)");
            return;
        }
        Ok(()) => {}
    }
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
    log_stacked_widths("Embed:", &embed_proof.0);
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
    _compress: pico_vm::mle::machine::compress::CompressProofWithVk,
    _trusted_vm_vk: RiscvVmVk,
    _vk_verification: bool,
    _vk_map: Option<std::sync::Arc<MleVkMap>>,
    _wrap_committed: Option<&[u8]>,
) {
    unreachable!("main stops `--step embed / wrap` before proving when embed is not built");
}
