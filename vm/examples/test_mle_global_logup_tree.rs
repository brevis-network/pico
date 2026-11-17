//! The global LogUp in the recursion tree: what a tree needs to close, case by case.
//!
//! One short fib block, cut into a few chunks, with its second phase proved in groups of two
//! tables so that the tree has more than one group node. Every case builds a tree over proofs
//! that are each valid on their own and asks whether the root proves and verifies. The host-side
//! checks of the combine machine are switched off, so what refuses a wrong tree is the circuit.
//!
//! Honest proofs, arranged:
//!
//!   * `baseline` — `[image][groups, last first][chunks]`. MUST prove, and the root's real-row
//!     count is the one the native verifier computes. Nothing else here means anything if it
//!     fails.
//!   * `no-second-phase` — the chunks alone. MUST FAIL: every other assertion of the root holds;
//!     the chain starts at its initial value, which is no image node's output.
//!   * `missing-group`, `swapped-groups`, `repeated-group` — MUST FAIL: the groups' wrapped chain
//!     values no longer meet.
//!   * `no-image`, `two-images`, `image-alone` — MUST FAIL: the image node's output is what the
//!     root's closure asks for, once, and what the first group node starts from.
//!   * `repeated-chunk` — MUST FAIL on chunk continuity.
//!   * `node-after-chunk`, `node-appended` — a group node past chunk 1. MUST FAIL: a node sits at
//!     chunk cursor 1. Appended after the last chunk it also leaves the tree ending at cursor 1,
//!     an empty execution; the host's refusal of that is switched off here, so the circuit is
//!     what refuses it.
//!   * `root-then-chunk`, `root-then-node` — the honest tree's complete root with a chunk's leaf,
//!     or a group node, appended to its right. MUST FAIL: a closed tree takes nothing more.
//!
//! The real-row limit, over the honest tree:
//!
//!   * `limit-at-count` — the root built with the block's own count as its limit. MUST prove.
//!   * `limit-below-count` — one below. MUST FAIL.
//!
//! A block whose chunks disagree (one finalize event altered; every chunk proof is still valid,
//! and the native verifier reports the global LogUp unbalanced):
//!
//!   * `unbalanced` — its honest arrangement. MUST FAIL, at the root's zero-sum assertion: the
//!     chain closes and the count is in range.
//!
//! Nodes proved from a witness of the test's choosing:
//!
//!   * `other-challenges` — the first group proved under challenges of its own and its node told
//!     so. The node proves; the tree MUST FAIL where its wrapped chain value meets its
//!     neighbour's.
//!   * `other-root` — the whole second phase under challenges derived from a chain root that is
//!     not the block's, the image node wrapping the block's chain value all the same. Every node
//!     proves and every link holds; the root MUST FAIL its chain closure, the one place the
//!     derivation's root is held to the chain.
//!   * `other-root-own-value` — the same, the image node wrapping that other root. MUST FAIL
//!     where its end meets the first group node, which folded the block's commitments.
//!   * `group-under-another-key`, `group-under-its-key` — the first group proved by the group
//!     machines of other parameters: one more bit of LogUp proof of work, which a group proof
//!     does none of, so the proof has the same shape, over the same tables, under the same
//!     challenges, and only its key's pre-hash is another. The block's group node MUST NOT
//!     prove over it: the pre-hash its transcript starts from is a constant of its program.
//!     The group node of those other parameters MUST prove, so the proof is a good one and the
//!     key is all the first case fails on.
//!   * `group-over-other-tables` — the first group's node over a proof of the second group's
//!     tables, told it covers the first group's chunks. The node proves; the tree MUST FAIL
//!     where the chain it folded those commitments into meets its neighbour's.
//!   * `published-sum-off`, `published-count-off` — a group node whose proof publishes a sum,
//!     or a real-row count, that is not the one its circuit computed. The node still verifies:
//!     its own constraints hold its public values to their digest alone. The tree MUST FAIL:
//!     the parent recomputes the digest over what the node published.
//!   * `forged-pc` — a group node publishing another entry pc. MUST FAIL on pc continuity.
//!   * `forged-pow`, `forged-identity`, `image-under-other-challenges`, `first-group-off-iv`,
//!     `forged-sum` — a node that MUST NOT prove: the image node behind another proof-of-work
//!     witness; the image node told an identity digest that is not the one over the image it
//!     opens (with the challenges derived from that digest, so nothing else is off); the image
//!     node over an image proof made under challenges that are not the ones it derives; the
//!     group node at chunk 1 entering the chain off its initial value; a group node over a group
//!     proof whose claimed sum was altered.
//!
//!   * `image-one-tier-up`, `image-one-tier-up-own-digest` — the image's commitment read as a
//!     table of the next tier, where its rows sum to nothing, by the image node of that tier.
//!     Told the program's identity digest, the node MUST NOT prove: the digest it recomputes
//!     has its own tier in it. Told the digest it computes, it proves, and so do group nodes
//!     under the challenges that go with it; the tree MUST FAIL where they meet the chunks'
//!     leaves, which carry the program's digest.
//!   * `leaf-of-another-identity` — one chunk's leaf made under another identity digest (the
//!     same program over another memory image; a leaf takes the image's commitment on trust).
//!     The leaf proves; the tree MUST FAIL where its digest meets its neighbours'. A chunk of
//!     another program stands the same way: its leaf carries another digest.
//!   * `init-cursor-off` — chunk 1 proved with its memory-initialization cursor starting off
//!     zero (the chunk initializes nothing, so the cursor it publishes is its own to choose).
//!     The chunk proof verifies and its leaf proves; the tree MUST FAIL where the leaf meets
//!     the nodes ahead of it, whose cursor is zero, and the chunk after it.
//!   * `chain-entry-off-iv`, `chain-entry-forged` — a convert leaf told another entry into the
//!     chain. Chunk 1's leaf MUST NOT prove: it enters at the initial value. A later leaf
//!     proves; the tree MUST FAIL where its entry meets the leaf before it.
//!
//! The compress layer, which runs the root's assertions again on what it is handed:
//!
//!   * `tree-to-compress` — the honest arrangement reduced to a top node that is not a root.
//!     MUST prove: every assertion of a root holds of it, and compress makes them itself.
//!   * `chunks-to-compress` — the chunks' leaves alone, reduced the same way: the second phase
//!     skipped, and the root that would refuse the tree skipped with it. MUST FAIL, on the
//!     chain's closure, the one assertion in the way.
//!   * `node-to-compress` — the image node handed over as if it were a root. MUST FAIL: a node
//!     covers no chunk, and compress makes the root's assertions on it (the host's refusal of an
//!     empty execution is switched off, as for `node-appended`).
//!
//! Which node refuses a tree: every node below the root is verified as it is proved, so a tree
//! refused at "the inner node ... of combine layer ..." broke a link between two children, and
//! one refused at "root combine proof" passed every node below and failed the root. A link that
//! happens to sit between the root's own two children fails the root too, so the cases whose
//! arrangement leaves that open only ask for a refusal; the ones that say where it must be are
//! the root's own assertions (`no-second-phase`, `no-image`, the limit, `unbalanced`,
//! `other-root`) and two links low in the tree (`image-alone`, `two-images`).
//!
//! `GLOBAL_LOGUP_TREE_CASES=a,b,c` runs those cases only (CI takes `baseline`, `no-second-phase` and
//! `chain-entry-forged`); every name has to be a case, and `root-then-*` need `baseline`.
//!
//! The process exits 0 only when every case that ran matched its expectation.
//!
//! Usage:
//!   cargo run --release -p pico-vm --example test_mle_global_logup_tree

use std::{cell::Cell, panic, sync::Arc};

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use pico_mle_core::{
    config::{
        compress_params_with_128_bits_security, koala_bear_poseidon2::EF,
        recursion_params_with_128_bits_security, riscv_params_with_128_bits_security,
    },
    global_logup::{self, GroupMachines},
    protocol::proof::Proof,
    prover::DeviceDataTransporter,
    StarkEngine,
};
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        recursion::public_values::{RecursionPublicValues, RECURSION_PUBLIC_VALUES_COL_MAP},
        riscv::record::EmulationRecord,
        stdin::EmulatorStdin,
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::logger::setup_logger,
    mle::machine::{
        combine::CombineMachine,
        compress::CompressMachine,
        convert::{ConvertMachine, ProofWithVk},
        exe::RiscvVmVk,
        global_logup::{block_count, chain_values, ChunkTable, GlobalLogUp, ImageTable},
        global_logup_nodes::GlobalLogUpNodeMachine,
        recursion::{recursion_public_values, GroupNodeWitness, ImageNodeWitness},
        riscv::{
            self, air_id, build_ctx, mle_riscv_air_refs, Engine, Kb, RiscvProof, Sc,
            VerifyRiscvError, RISCV_APP_PREP_AIR_IDS, RISCV_REQUIRED_AIR_IDS,
        },
    },
    primitives::consts::DIGEST_SIZE,
};
use tracing::info;

const ELF: &str = "./perf/bench_data/rv64/fib-elf";
const LOG_STACKED_HEIGHT: usize = 20;
const CHUNK_SIZE: u32 = 1 << 14;
/// Tables to a group: small, so that a block of a few chunks has several groups.
const GROUP_LEN: usize = 2;
/// How a tree that does not close fails: the verify of the proof whose constraints carry the
/// check.
const REJECTED: &str = "failed STARK verify";
/// How a tree fails that every node below the root accepts: at the root's own verification.
const ROOT_ALONE: &str = "root combine proof failed STARK verify";
/// How a tree fails at a link below the root.
const INNER: &str = "of combine layer";
/// How a convert leaf whose witness its own constraints refuse fails.
const LEAF_REJECTED: &str = "convert leaf verify failed";
/// How a node whose witness its own constraints refuse fails.
const NODE_REJECTED: &str = "node verify failed";

type Digest = [Kb; DIGEST_SIZE];
/// What a node's proof is made to publish in place of the values its circuit computed.
type Publish = fn(&mut RecursionPublicValues<Kb>);

/// The riscv machine of this run, at the harness level: the chunk proofs are made one by one so
/// that their Global tables stay at hand.
struct Riscv {
    program: Arc<Program>,
    engine: Engine,
    d_pk: pico_mle_core::prover::DeviceMultiStarkProvingKey<riscv::Pb>,
    vk: Arc<pico_mle_core::keygen::types::MultiStarkVerifyingKey<Sc>>,
    vm_vk: RiscvVmVk,
    logup: GlobalLogUp,
    image: ImageTable,
    params_digest: Digest,
}

/// A block's chunk proofs, the tables they committed, and the second phase over them.
struct Block {
    bundle: RiscvProof,
    tables: Vec<ChunkTable>,
}

impl Riscv {
    fn new(program: Arc<Program>) -> Self {
        let engine: Engine =
            StarkEngine::new(riscv_params_with_128_bits_security(LOG_STACKED_HEIGHT));
        let airs = mle_riscv_air_refs(Arc::clone(&program), false);
        let (pk, vk) = engine.keygen_with_app_prep_and_required(
            &airs,
            RISCV_APP_PREP_AIR_IDS,
            RISCV_REQUIRED_AIR_IDS,
        );
        let d_pk = engine.device().transport_pk_to_device(&pk);
        let vk = Arc::new(vk);
        let riscv = &vk.inner.params;
        Self {
            vm_vk: RiscvVmVk::from_program_and_vk(&program, &vk),
            logup: GlobalLogUp::new(riscv),
            image: ImageTable::new(&program, riscv).expect("the image fits"),
            params_digest: GroupMachines::new(riscv).params_digest(),
            program,
            engine,
            d_pk,
            vk,
        }
    }

    fn params(&self) -> &pico_mle_core::SystemParams {
        &self.vk.inner.params
    }

    fn prove(&self, records: &[EmulationRecord]) -> Block {
        let chips = RiscvChipType::<Kb>::all_chips();
        let mut tables = Vec::new();
        let chunk_proofs = records
            .iter()
            .map(|record| {
                let ctx = build_ctx(&chips, record, false);
                riscv::prove_host_ctx(&self.engine, &self.d_pk, ctx, &mut tables)
                    .expect("riscv prove")
            })
            .collect();
        let global = riscv::prove_global_logup_grouped(&self.program, &self.vk, &tables, GROUP_LEN)
            .expect("global LogUp");
        Block {
            bundle: RiscvProof {
                vk: Arc::clone(&self.vk),
                chunk_proofs,
                global,
            },
            tables,
        }
    }

    /// One chunk's proof on its own, verified as a proof of the riscv machine.
    fn prove_chunk(&self, record: &EmulationRecord) -> eyre::Result<Proof<Sc>> {
        let chips = RiscvChipType::<Kb>::all_chips();
        let ctx = build_ctx(&chips, record, false);
        let proof = riscv::prove_host_ctx(&self.engine, &self.d_pk, ctx, &mut Vec::new())
            .map_err(|e| eyre::eyre!("riscv chunk prove failed: {e:?}"))?;
        self.engine
            .verify(&*self.vk, &proof)
            .map_err(|e| eyre::eyre!("riscv chunk verify failed: {e:?}"))?;
        Ok(proof)
    }

    fn verify(&self, block: &Block) -> Result<(), VerifyRiscvError> {
        riscv::verify_riscv(
            &block.bundle,
            block.bundle.vk.pre_hash,
            &[(air_id::PROGRAM, riscv::riscv_program_commit(&self.vk))],
            &self.vm_vk.identity(),
        )
    }

    fn convert(&self, block: &Block) -> Vec<ProofWithVk> {
        ConvertMachine::new(
            Arc::clone(&self.vk),
            self.vm_vk.clone(),
            &block.bundle.chunk_proofs,
            recursion_params_with_128_bits_security(),
            false,
        )
        .expect("convert machine")
        .prove_with_vks(&block.bundle.chunk_proofs)
        .expect("convert prove")
    }

    /// The block's convert leaves with their entries into the chain given, each verified.
    fn convert_with_chain(
        &self,
        block: &Block,
        chain: &[Digest],
    ) -> eyre::Result<Vec<ProofWithVk>> {
        let machine = ConvertMachine::new(
            Arc::clone(&self.vk),
            self.vm_vk.clone(),
            &block.bundle.chunk_proofs,
            recursion_params_with_128_bits_security(),
            false,
        )?;
        let leaves = machine.prove_with_chain_for_testing(&block.bundle.chunk_proofs, chain)?;
        for (proof, vk) in &leaves {
            machine
                .engine
                .verify(&**vk, proof)
                .map_err(|e| eyre::eyre!("convert leaf verify failed: {e:?}"))?;
        }
        Ok(leaves)
    }

    fn nodes(&self) -> GlobalLogUpNodeMachine {
        GlobalLogUpNodeMachine::new(
            recursion_params_with_128_bits_security(),
            self.params(),
            false,
        )
    }

    /// The chain before each chunk of `block` and after the last.
    fn chain(&self, block: &Block) -> Vec<Digest> {
        chain_values(self.params(), &block.bundle.chunk_proofs).expect("chain")
    }

    /// The witness the honest prover gives the group node over the block's `group`-th group.
    fn group_witness(&self, block: &Block, group: usize, challenges: (EF, EF)) -> GroupNodeWitness {
        let first_chunk = group * GROUP_LEN + 1;
        GroupNodeWitness {
            challenges,
            first_chunk: first_chunk as u32,
            chain_before: self.chain(block)[first_chunk - 1],
            riscv_vk_digest: self.vm_vk.digest(),
            pc: self.vm_vk.pc_start,
            deferred_digest: [Kb::ZERO; DIGEST_SIZE],
            vk_root: None,
        }
    }

    /// The witness the honest prover gives the image node, under `challenges` derived from
    /// `chain_root` behind `pow_witness`.
    fn image_witness(
        &self,
        block: &Block,
        challenges: (EF, EF),
        pow_witness: Kb,
        chain_root: Digest,
    ) -> ImageNodeWitness {
        ImageNodeWitness {
            challenges,
            pow_witness,
            chain_root,
            chain_value: *self.chain(block).last().unwrap(),
            riscv_vk_digest: self.vm_vk.digest(),
            program_commit: self.vm_vk.program_commit,
            pc: self.vm_vk.pc_start,
            deferred_digest: [Kb::ZERO; DIGEST_SIZE],
            vk_root: None,
        }
    }

    /// The block's own challenges.
    fn challenges(&self, block: &Block) -> (EF, EF) {
        global_logup::check_challenges(
            &self.params_digest,
            &self.vm_vk.digest(),
            self.chain(block).last().unwrap(),
            self.params().logup.pow_bits,
            block.bundle.global.pow_witness,
        )
        .expect("the block's proof of work")
    }

    /// The tables of the block's `group`-th group.
    fn group_tables<'a>(&self, block: &'a Block, group: usize) -> Vec<&'a ChunkTable> {
        block
            .tables
            .chunks(GROUP_LEN)
            .nth(group)
            .unwrap()
            .iter()
            .collect()
    }
}

/// Prove a tree over `children` with the combine machine's host-side checks off, and verify the
/// root. `max_count` puts a real-row limit of the test's on the root.
fn tree(
    vm_vk: &RiscvVmVk,
    children: Vec<ProofWithVk>,
    max_count: Option<u64>,
) -> eyre::Result<ProofWithVk> {
    let mut combine = CombineMachine::new(
        recursion_params_with_128_bits_security(),
        vm_vk.clone(),
        false,
    );
    combine.skip_prefix_checks_for_testing();
    combine.verify_every_node_for_testing();
    if let Some(max_count) = max_count {
        combine.set_max_global_row_count_for_testing(max_count);
    }
    let root = combine.prove_tree(children)?;
    combine.verify(&root)?;
    Ok(root)
}

/// The cases `GLOBAL_LOGUP_TREE_CASES` names, or `None` for every case.
fn selected() -> Option<&'static [String]> {
    static CASES: std::sync::OnceLock<Option<Vec<String>>> = std::sync::OnceLock::new();
    CASES
        .get_or_init(|| {
            let raw = std::env::var("GLOBAL_LOGUP_TREE_CASES").ok()?;
            Some(raw.split(',').map(|name| name.trim().to_string()).collect())
        })
        .as_deref()
}

/// Whether the case `name` runs.
fn wanted(name: &str) -> bool {
    selected().is_none_or(|cases| cases.iter().any(|case| case == name))
}

/// The cases that ran.
static RAN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Run one case, report it, and count it in `failures` when it did not match its expectation;
/// the proof comes back when it proved. A must-fail case matches only when it fails with
/// `failure`: a case that died anywhere else would leave this harness green while testing
/// nothing.
fn case(
    failures: &Cell<usize>,
    name: &str,
    must_prove: bool,
    failure: &str,
    run: impl FnOnce() -> eyre::Result<ProofWithVk>,
) -> Option<ProofWithVk> {
    if !wanted(name) {
        return None;
    }
    RAN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let outcome = panic::catch_unwind(panic::AssertUnwindSafe(run));
    let (proof, reason) = match outcome {
        Ok(Ok(proof)) => (Some(proof), String::from("proved and verified")),
        Ok(Err(e)) => (None, format!("{e:#}")),
        Err(payload) => {
            let msg = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .unwrap_or_else(|| String::from("panic with no message"));
            (None, msg)
        }
    };
    let proved = proof.is_some();
    let matched = proved == must_prove && (must_prove || reason.contains(failure));
    let reason: String = reason.chars().take(200).collect();
    if matched {
        info!("case {name}: proved = {proved} (as expected) — {reason}");
    } else if proved != must_prove {
        tracing::error!("case {name}: proved = {proved} (WRONG) — {reason}");
    } else {
        tracing::error!("case {name}: failed in the WRONG PLACE — {reason}");
    }
    if !matched {
        failures.set(failures.get() + 1);
    }
    proof
}

fn main() {
    setup_logger();
    // A tree that ends at chunk cursor 1 is refused by the circuit here, not by the host.
    pico_vm::mle::machine::recursion::let_empty_executions_reach_the_circuit_for_testing();
    // The GPU riscv prover allocates from the shared pool; a CPU build has none to set up.
    #[cfg(feature = "cuda")]
    riscv::init_mle_gpu_pool(riscv::MLE_GPU_DEVICE);
    let program = Compiler::new(SourceType::RISCV, &std::fs::read(ELF).expect("elf"))
        .expect("parse elf")
        .compile();
    let riscv = Riscv::new(Arc::clone(&program));
    let mut stdin = EmulatorStdin::new_builder::<KoalaBearPoseidon2>();
    stdin.write(&6_000u32);
    let records = riscv::emulate(Arc::clone(&program), stdin.finalize(), Some(CHUNK_SIZE));

    // ── The honest block and its leaves ─────────────────────────────────────────────────────
    let block = riscv.prove(&records);
    riscv.verify(&block).expect("the honest block verifies");
    let chunks = riscv.convert(&block);
    let mut machine = riscv.nodes();
    let mut prefix = machine
        .prove(
            &riscv.vm_vk,
            &block.bundle.chunk_proofs,
            &block.bundle.global,
            [Kb::ZERO; DIGEST_SIZE],
        )
        .expect("global LogUp nodes");
    let image = prefix.remove(0);
    // Last group first, as they lead the tree.
    let groups = prefix;
    assert!(
        groups.len() >= 2 && chunks.len() >= 3,
        "{} group(s) over {} chunk(s): the cases need at least two groups",
        groups.len(),
        chunks.len()
    );
    info!(
        "block: {} chunk(s), {} group(s) of up to {GROUP_LEN}",
        chunks.len(),
        groups.len()
    );
    let honest = |image: &[ProofWithVk], groups: &[ProofWithVk], chunks: &[ProofWithVk]| {
        [image, groups, chunks].concat()
    };
    let one = std::slice::from_ref;

    let failures = Cell::new(0usize);
    let vm_vk = &riscv.vm_vk;

    // ── Honest proofs, arranged ─────────────────────────────────────────────────────────────
    let root = case(&failures, "baseline", true, REJECTED, || {
        tree(vm_vk, honest(one(&image), &groups, &chunks), None)
    });
    let count = block_count(riscv.params(), &block.bundle.chunk_proofs);
    if let Some(root) = &root {
        let pvs = recursion_public_values(&root.0.public_values).expect("root pvs");
        let in_root =
            pvs[RECURSION_PUBLIC_VALUES_COL_MAP.global_row_count].as_canonical_u32() as u64;
        if in_root != count {
            tracing::error!("baseline: the root counts {in_root} rows, the verifier {count}");
            failures.set(failures.get() + 1);
        }
    }
    let last = groups.len() - 1;
    let arrangements: Vec<(&str, Vec<ProofWithVk>)> = vec![
        ("no-second-phase", chunks.clone()),
        (
            "missing-group",
            honest(one(&image), &groups[..last], &chunks),
        ),
        ("swapped-groups", {
            let mut swapped = groups.clone();
            swapped.swap(0, last);
            honest(one(&image), &swapped, &chunks)
        }),
        ("repeated-group", {
            let mut repeated = vec![groups[0].clone()];
            repeated.extend(groups.iter().cloned());
            honest(one(&image), &repeated, &chunks)
        }),
        ("no-image", honest(&[], &groups, &chunks)),
        (
            "two-images",
            honest(&[image.clone(), image.clone()], &groups, &chunks),
        ),
        ("image-alone", honest(one(&image), &[], &chunks)),
        ("repeated-chunk", {
            let mut repeated = vec![chunks[0].clone()];
            repeated.extend(chunks.iter().cloned());
            honest(one(&image), &groups, &repeated)
        }),
        ("node-after-chunk", {
            let mut children = honest(one(&image), &groups[..last], &chunks[..1]);
            children.push(groups[last].clone());
            children.extend(chunks[1..].iter().cloned());
            children
        }),
        ("node-appended", {
            let mut children = honest(one(&image), &groups, &chunks);
            children.push(groups[last].clone());
            children
        }),
    ];
    for (name, children) in arrangements {
        let failure = match name {
            // Every link holds: the chain's closure at the root is all that is off.
            "no-second-phase" | "no-image" => ROOT_ALONE,
            // The first two children do not meet.
            "image-alone" | "two-images" => INNER,
            _ => REJECTED,
        };
        case(&failures, name, false, failure, || {
            tree(vm_vk, children, None)
        });
    }

    // A closed tree takes nothing more: the honest root with a leaf or a node to its right.
    if let Some(root) = &root {
        for (name, appended) in [
            ("root-then-chunk", &chunks[0]),
            ("root-then-node", &groups[last]),
        ] {
            case(&failures, name, false, REJECTED, || {
                tree(vm_vk, vec![root.clone(), appended.clone()], None)
            });
        }
    }

    // ── The real-row limit ──────────────────────────────────────────────────────────────────
    assert!(count > 0 && count <= global_logup::MAX_COUNT);
    for (name, limit, must_prove) in [
        ("limit-at-count", count, true),
        ("limit-below-count", count - 1, false),
    ] {
        case(&failures, name, must_prove, ROOT_ALONE, || {
            tree(vm_vk, honest(one(&image), &groups, &chunks), Some(limit))
        });
    }

    // ── A block whose chunks disagree ───────────────────────────────────────────────────────
    if wanted("unbalanced") {
        let mut records = records.clone();
        assert!(
            records.iter_mut().any(riscv::corrupt_one_record),
            "no finalize event to alter"
        );
        let unbalanced = riscv.prove(&records);
        let native = riscv.verify(&unbalanced);
        assert!(
            matches!(
                native,
                Err(VerifyRiscvError::GlobalLogUp(
                    pico_vm::mle::machine::global_logup::GlobalLogUpError::Unbalanced
                ))
            ),
            "the altered block is meant to be valid chunk by chunk and unbalanced: {native:?}"
        );
        let chunks = riscv.convert(&unbalanced);
        let prefix = riscv.nodes().prove(
            vm_vk,
            &unbalanced.bundle.chunk_proofs,
            &unbalanced.bundle.global,
            [Kb::ZERO; DIGEST_SIZE],
        );
        case(&failures, "unbalanced", false, ROOT_ALONE, || {
            let prefix = prefix.map_err(|e| eyre::eyre!("{e:#}"))?;
            tree(vm_vk, honest(&prefix, &[], &chunks), None)
        });
    }

    // ── Nodes proved from a witness of the test's choosing ──────────────────────────────────
    let honest_challenges = riscv.challenges(&block);
    let other_challenges = (honest_challenges.0 + EF::ONE, honest_challenges.1 + EF::ONE);
    // The first group is the last of `groups`.
    case(&failures, "other-challenges", false, REJECTED, || {
        let proof = riscv
            .logup
            .prove_group_under(
                &riscv.group_tables(&block, 0),
                other_challenges.0,
                other_challenges.1,
            )
            .map_err(|e| eyre::eyre!(e))?;
        let node =
            machine.prove_group_node(&proof, &riscv.group_witness(&block, 0, other_challenges))?;
        machine.verify(&node)?;
        let mut groups = groups.clone();
        groups[last] = node;
        tree(vm_vk, honest(one(&image), &groups, &chunks), None)
    });

    case(
        &failures,
        "group-over-other-tables",
        false,
        REJECTED,
        || {
            let proof = riscv
                .logup
                .prove_group_under(
                    &riscv.group_tables(&block, 1),
                    honest_challenges.0,
                    honest_challenges.1,
                )
                .map_err(|e| eyre::eyre!(e))?;
            let node = machine
                .prove_group_node(&proof, &riscv.group_witness(&block, 0, honest_challenges))?;
            machine.verify(&node)?;
            let mut groups = groups.clone();
            groups[last] = node;
            tree(vm_vk, honest(one(&image), &groups, &chunks), None)
        },
    );

    let publishes: [(&str, Publish); 2] = [
        ("published-sum-off", |pvs| pvs.global_sum[0] += Kb::ONE),
        ("published-count-off", |pvs| pvs.global_row_count += Kb::ONE),
    ];
    for (name, publish) in publishes {
        case(&failures, name, false, REJECTED, || {
            let proof = riscv
                .logup
                .prove_group_under(
                    &riscv.group_tables(&block, 0),
                    honest_challenges.0,
                    honest_challenges.1,
                )
                .map_err(|e| eyre::eyre!(e))?;
            let node = machine.prove_group_node_publishing_for_testing(
                &proof,
                &riscv.group_witness(&block, 0, honest_challenges),
                publish,
            )?;
            machine.verify(&node)?;
            let mut groups = groups.clone();
            groups[last] = node;
            tree(vm_vk, honest(one(&image), &groups, &chunks), None)
        });
    }

    for (name, own_key) in [
        ("group-under-another-key", false),
        ("group-under-its-key", true),
    ] {
        case(&failures, name, own_key, NODE_REJECTED, || {
            let mut other = riscv.params().clone();
            other.logup.pow_bits += 1;
            let proof = GlobalLogUp::new(&other)
                .prove_group_under(
                    &riscv.group_tables(&block, 0),
                    honest_challenges.0,
                    honest_challenges.1,
                )
                .map_err(|e| eyre::eyre!(e))?;
            let witness = riscv.group_witness(&block, 0, honest_challenges);
            if own_key {
                let mut its_machine = GlobalLogUpNodeMachine::new(
                    recursion_params_with_128_bits_security(),
                    &other,
                    false,
                );
                let node = its_machine.prove_group_node(&proof, &witness)?;
                its_machine.verify(&node)?;
                Ok(node)
            } else {
                let node = machine.prove_group_node(&proof, &witness)?;
                machine.verify(&node)?;
                Ok(node)
            }
        });
    }

    for (name, own_value, failure) in [
        ("other-root", false, ROOT_ALONE),
        ("other-root-own-value", true, REJECTED),
    ] {
        case(&failures, name, false, failure, || {
            let chain = riscv.chain(&block);
            // A chain root that is not the block's: the chain one chunk short.
            let other_root = chain[chain.len() - 2];
            let (pow_witness, alpha, beta) = global_logup::derive_challenges(
                &riscv.params_digest,
                &vm_vk.digest(),
                &other_root,
                riscv.params().logup.pow_bits,
            );
            let image_proof = riscv
                .logup
                .prove_image_under(&riscv.image, alpha, beta)
                .map_err(|e| eyre::eyre!(e))?;
            let mut witness = riscv.image_witness(&block, (alpha, beta), pow_witness, other_root);
            if own_value {
                witness.chain_value = other_root;
            }
            let mut children = vec![machine.prove_image_node(&image_proof, &witness)?];
            for group in (0..groups.len()).rev() {
                let proof = riscv
                    .logup
                    .prove_group_under(&riscv.group_tables(&block, group), alpha, beta)
                    .map_err(|e| eyre::eyre!(e))?;
                children.push(machine.prove_group_node(
                    &proof,
                    &riscv.group_witness(&block, group, (alpha, beta)),
                )?);
            }
            for node in &children {
                machine.verify(node)?;
            }
            children.extend(chunks.iter().cloned());
            tree(vm_vk, children, None)
        });
    }

    case(&failures, "forged-pc", false, REJECTED, || {
        let mut witness = riscv.group_witness(&block, 0, honest_challenges);
        witness.pc[0] += Kb::ONE;
        let node = machine.prove_group_node(&block.bundle.global.group_proofs[0], &witness)?;
        machine.verify(&node)?;
        let mut groups = groups.clone();
        groups[last] = node;
        tree(vm_vk, honest(one(&image), &groups, &chunks), None)
    });

    let chain_root = *riscv.chain(&block).last().unwrap();
    case(&failures, "forged-pow", false, NODE_REJECTED, || {
        let witness = riscv.image_witness(
            &block,
            honest_challenges,
            block.bundle.global.pow_witness + Kb::ONE,
            chain_root,
        );
        let node = machine.prove_image_node(&block.bundle.global.image_proof, &witness)?;
        machine.verify(&node)?;
        Ok(node)
    });

    case(&failures, "forged-identity", false, NODE_REJECTED, || {
        // An identity digest that is not the program's, and the second phase the prover would
        // make for it: the challenges derived from it, the image group under them.
        let mut digest = vm_vk.digest();
        digest[0] += Kb::ONE;
        let (pow_witness, alpha, beta) = global_logup::derive_challenges(
            &riscv.params_digest,
            &digest,
            &chain_root,
            riscv.params().logup.pow_bits,
        );
        let image_proof = riscv
            .logup
            .prove_image_under(&riscv.image, alpha, beta)
            .map_err(|e| eyre::eyre!(e))?;
        let mut witness = riscv.image_witness(&block, (alpha, beta), pow_witness, chain_root);
        witness.riscv_vk_digest = digest;
        let node = machine.prove_image_node(&image_proof, &witness)?;
        machine.verify(&node)?;
        Ok(node)
    });

    case(
        &failures,
        "image-under-other-challenges",
        false,
        NODE_REJECTED,
        || {
            let image_proof = riscv
                .logup
                .prove_image_under(&riscv.image, other_challenges.0, other_challenges.1)
                .map_err(|e| eyre::eyre!(e))?;
            let witness = riscv.image_witness(
                &block,
                honest_challenges,
                block.bundle.global.pow_witness,
                chain_root,
            );
            let node = machine.prove_image_node(&image_proof, &witness)?;
            machine.verify(&node)?;
            Ok(node)
        },
    );

    case(&failures, "forged-sum", false, NODE_REJECTED, || {
        let mut proof = block.bundle.global.group_proofs[0].clone();
        *proof
            .gkr_proof
            .p0_claim
            .as_mut()
            .expect("a group proof's sum") += EF::ONE;
        let node =
            machine.prove_group_node(&proof, &riscv.group_witness(&block, 0, honest_challenges))?;
        machine.verify(&node)?;
        Ok(node)
    });

    case(
        &failures,
        "first-group-off-iv",
        false,
        NODE_REJECTED,
        || {
            let mut witness = riscv.group_witness(&block, 0, honest_challenges);
            assert_eq!(witness.first_chunk, 1);
            witness.chain_before[0] += Kb::ONE;
            let node = machine.prove_group_node(&block.bundle.global.group_proofs[0], &witness)?;
            machine.verify(&node)?;
            Ok(node)
        },
    );

    // ── The image read one tier up ──────────────────────────────────────────────────────────
    let one_tier_up = riscv
        .image
        .read_one_tier_up(riscv.params())
        .expect("the image's commitment reads as a table of the next tier too");
    case(&failures, "image-one-tier-up", false, NODE_REJECTED, || {
        let image_proof = riscv
            .logup
            .prove_image_under(&one_tier_up, honest_challenges.0, honest_challenges.1)
            .map_err(|e| eyre::eyre!(e))?;
        let witness = riscv.image_witness(
            &block,
            honest_challenges,
            block.bundle.global.pow_witness,
            chain_root,
        );
        let node = machine.prove_image_node(&image_proof, &witness)?;
        machine.verify(&node)?;
        Ok(node)
    });
    case(
        &failures,
        "image-one-tier-up-own-digest",
        false,
        REJECTED,
        || {
            // The identity the next tier's node computes over the same commitment, and the
            // second phase a prover would make for it.
            let mut identity = vm_vk.clone();
            identity.image_log_height += Kb::ONE;
            let digest = identity.digest();
            let (pow_witness, alpha, beta) = global_logup::derive_challenges(
                &riscv.params_digest,
                &digest,
                &chain_root,
                riscv.params().logup.pow_bits,
            );
            let image_proof = riscv
                .logup
                .prove_image_under(&one_tier_up, alpha, beta)
                .map_err(|e| eyre::eyre!(e))?;
            let mut witness = riscv.image_witness(&block, (alpha, beta), pow_witness, chain_root);
            witness.riscv_vk_digest = digest;
            let mut children = vec![machine.prove_image_node(&image_proof, &witness)?];
            for group in (0..groups.len()).rev() {
                let proof = riscv
                    .logup
                    .prove_group_under(&riscv.group_tables(&block, group), alpha, beta)
                    .map_err(|e| eyre::eyre!(e))?;
                let mut witness = riscv.group_witness(&block, group, (alpha, beta));
                witness.riscv_vk_digest = digest;
                children.push(machine.prove_group_node(&proof, &witness)?);
            }
            for node in &children {
                machine.verify(node)?;
            }
            children.extend(chunks.iter().cloned());
            tree(vm_vk, children, None)
        },
    );

    // ── A convert leaf told another entry into the chain ────────────────────────────────────
    let chain = riscv.chain(&block);
    case(
        &failures,
        "chain-entry-off-iv",
        false,
        LEAF_REJECTED,
        || {
            let mut chain = chain.clone();
            chain[0][0] += Kb::ONE;
            let leaves = riscv.convert_with_chain(&block, &chain)?;
            Ok(leaves[0].clone())
        },
    );
    case(&failures, "chain-entry-forged", false, REJECTED, || {
        let mut chain = chain.clone();
        chain[1][0] += Kb::ONE;
        let leaves = riscv.convert_with_chain(&block, &chain)?;
        tree(vm_vk, honest(one(&image), &groups, &leaves), None)
    });

    // ── Leaves that do not belong ───────────────────────────────────────────────────────────
    case(
        &failures,
        "leaf-of-another-identity",
        false,
        REJECTED,
        || {
            let mut other_vm_vk = vm_vk.clone();
            other_vm_vk.image_commit[0] += Kb::ONE;
            let other = ConvertMachine::new(
                Arc::clone(&riscv.vk),
                other_vm_vk,
                &block.bundle.chunk_proofs,
                recursion_params_with_128_bits_security(),
                false,
            )?;
            let (leaf, leaf_vk) = other
                .prove_with_chain_for_testing(&block.bundle.chunk_proofs, &chain)?
                .swap_remove(1);
            other
                .engine
                .verify(&*leaf_vk, &leaf)
                .map_err(|e| eyre::eyre!("convert leaf verify failed: {e:?}"))?;
            let mut leaves = chunks.clone();
            leaves[1] = (leaf, leaf_vk);
            tree(vm_vk, honest(one(&image), &groups, &leaves), None)
        },
    );

    case(&failures, "init-cursor-off", false, REJECTED, || {
        let mut first = records[0].clone();
        eyre::ensure!(
            first.memory_initialize_events.is_empty(),
            "chunk 1 initializes memory: its cursor is not free"
        );
        first.public_values.previous_init_addr_limbs = [5, 0, 0];
        first.public_values.last_init_addr_limbs = [5, 0, 0];
        let mut chunk_proofs = block.bundle.chunk_proofs.clone();
        chunk_proofs[0] = riscv.prove_chunk(&first)?;
        // The chunk's events are the block's, so its table and the chain over it are too.
        eyre::ensure!(
            chain_values(riscv.params(), &chunk_proofs).map_err(|e| eyre::eyre!("{e:?}"))? == chain,
            "the altered chunk commits another Global table"
        );
        let leaves = riscv.convert_with_chain(
            &Block {
                bundle: RiscvProof {
                    vk: Arc::clone(&riscv.vk),
                    chunk_proofs,
                    global: block.bundle.global.clone(),
                },
                tables: Vec::new(),
            },
            &chain,
        )?;
        let mut altered = chunks.clone();
        altered[0] = leaves[0].clone();
        tree(vm_vk, honest(one(&image), &groups, &altered), None)
    });

    // ── The compress layer ──────────────────────────────────────────────────────────────────
    let to_compress = |top: ProofWithVk| -> eyre::Result<ProofWithVk> {
        let mut compress = CompressMachine::new(
            compress_params_with_128_bits_security(),
            vm_vk.clone(),
            false,
        );
        let proof = compress.prove(top.clone())?;
        compress.verify(&proof)?;
        Ok(top)
    };
    // A tree over `children` whose top node is an inner combine node, not a root.
    let top_of = |children: Vec<ProofWithVk>| -> eyre::Result<ProofWithVk> {
        let mut combine = CombineMachine::new(
            recursion_params_with_128_bits_security(),
            vm_vk.clone(),
            false,
        );
        combine.skip_prefix_checks_for_testing();
        combine.prove_partial_tree(children)
    };
    // Under `cuda` the compress machine is the GPU pipeline's, which this harness does not
    // drive: the two cases that prove a compress proof are the CPU build's.
    if cfg!(feature = "cuda") {
        info!("cases tree-to-compress, chunks-to-compress: not run under cuda");
    } else {
        case(&failures, "tree-to-compress", true, REJECTED, || {
            to_compress(top_of(honest(one(&image), &groups, &chunks))?)
        });
        case(&failures, "chunks-to-compress", false, REJECTED, || {
            to_compress(top_of(chunks.clone())?)
        });
    }
    case(&failures, "node-to-compress", false, REJECTED, || {
        to_compress(image.clone())
    });

    let ran = RAN.load(std::sync::atomic::Ordering::Relaxed);
    if let Some(cases) = selected() {
        assert_eq!(
            ran,
            cases.len(),
            "GLOBAL_LOGUP_TREE_CASES names {} case(s) and {ran} ran: a name that is no case, or one that \
             needs another (`root-then-*` need `baseline`; two are not the cuda build's)",
            cases.len()
        );
    }
    let failures = failures.get();
    assert_eq!(failures, 0, "{failures} case(s) did not match expectation");
    info!("every one of the {ran} case(s) matched its expectation ✓");
}
