//! Deferred proving under the VK whitelist: the node checks its sub-proof against the same
//! whitelist the tree is proved under, and its own VK is a whitelist member.
//!
//! Two guests, as in `test_mle_deferred_chain`: fib, whose root is the sub-proof, and the
//! aggregator guest (`perf/bench_data/rv64/aggregator-elf`), which claims fib's root twice.
//!
//!   * `sub-root` — fib's tree under the whitelist. MUST prove; its root carries the map's root.
//!   * `happy` — two deferred nodes over fib's root ahead of the aggregator's leaves. MUST prove,
//!     verify, and pass the standalone apex pinned to the map's root.
//!   * `sub-unlisted` — the sub-proof's VK is not a member: refused by the host check, and with
//!     that check skipped, by the witness lookup (fail-closed).
//!   * `sub-other-root` — the sub-proof was proved under another whitelist: refused by the host
//!     check, and with that check skipped, by the node's in-circuit `child.vk_root == vk_root`.
//!   * `forged-path` — the node's Merkle path is corrupted (entries and root intact, so the host
//!     check passes): the in-circuit membership check rejects the node.
//!   * `node-unlisted` — the deferred node's own VK is not a member: its parent's witness lookup
//!     refuses it.
//!   * `dev-node` — a node proved outside the whitelist, in a whitelist tree: refused by name.
//!   * `sub-not-complete` — a sub-proof that is a member but not a complete root: a deferred node
//!     is refused by the host check, and a convert leaf, with that check skipped, by the node's
//!     in-circuit `flag_complete == 1`.
//!   * `wrong-trusted-root` — the happy root handed to an apex pinned to another whitelist root.
//!
//! The whitelist is `MLE_VK_MAP` (with `MLE_VK_ROOT` pinning its root) when set — the shipped
//! artifact, which is what shows the deferred leaf it carries is the one this binary keygens —
//! and otherwise a self-map of this run's own keys.
//!
//! Run by hand; the process exits 0 only when every case matched its expectation.
//!
//! Usage:
//!   MLE_VK_MAP=vm/src/mle/shape_vk_bins/mle_vk_map_kb.bin \
//!   MLE_VK_ROOT="$(sed -n 's/^MLE_VK_ROOT="\(.*\)"$/\1/p' vm/src/mle/shape_vk_bins/mle_vk_root.txt)" \
//!     cargo run --release -p pico-vm --example test_mle_deferred_whitelist

use std::{panic, sync::Arc};

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use pico_mle_core::{
    config::recursion_params_with_100_bits_security, keygen::types::MultiStarkVerifyingKey,
    protocol::proof::Proof,
};
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{recursion::public_values::RECURSION_PUBLIC_VALUES_COL_MAP, stdin::EmulatorStdin},
    machine::logger::setup_logger,
    mle::machine::{
        apex::MleApexVerifier,
        combine::CombineMachine,
        convert::{ConvertMachine, ProofWithVk},
        deferred::DeferredMachine,
        exe::RiscvVmVk,
        recursion::{recursion_public_values, Kb},
        riscv::{self, Sc},
        vk_map::{pinned_root_from_env, vk_identity, MleVkMap, VkIdentity},
    },
    primitives::consts::DIGEST_SIZE,
};
use tracing::info;

#[path = "common/emulate.rs"]
mod emulate;

const ELF: &str = "./perf/bench_data/rv64/fib-elf";
const AGGREGATOR_ELF: &str = "./perf/bench_data/rv64/aggregator-elf";
const LOG_STACKED_HEIGHT: usize = 23;

/// One guest, proved at the RISC-V layer in whitelist (bucketed) mode.
struct Guest {
    riscv_vk: Arc<MultiStarkVerifyingKey<Sc>>,
    vm_vk: RiscvVmVk,
    proofs: Vec<Proof<Sc>>,
    committed_bytes: Vec<u8>,
}

fn prove_guest(elf: &str, stdin: EmulatorStdin<Program, Vec<u8>>) -> Guest {
    let program = Arc::new(
        Compiler::new(SourceType::RISCV, &std::fs::read(elf).expect("elf"))
            .expect("parse elf")
            .compile(),
    );
    let opts = emulate::opts_from_env_chunk_size(1 << 23);
    assert!(
        (opts.chunk_size as u64) <= (1u64 << LOG_STACKED_HEIGHT),
        "chunk_size {} exceeds 2^{LOG_STACKED_HEIGHT}",
        opts.chunk_size
    );
    let emulated = emulate::emulate_with_opts(Arc::clone(&program), &stdin, opts);
    let (riscv_vk, proofs) = riscv::prove_riscv(
        Arc::clone(&program),
        &emulated.records,
        LOG_STACKED_HEIGHT,
        true,
    )
    .expect("riscv prove failed")
    .into_parts();
    let vm_vk = RiscvVmVk::from_program_and_vk(&program, &riscv_vk);
    info!("{elf}: {} chunk proof(s) ✓", proofs.len());
    Guest {
        riscv_vk,
        vm_vk,
        proofs,
        committed_bytes: emulated.committed_bytes,
    }
}

fn convert_machine(guest: &Guest) -> ConvertMachine {
    ConvertMachine::new(
        guest.riscv_vk.clone(),
        guest.vm_vk.clone(),
        &guest.proofs,
        recursion_params_with_100_bits_security(),
        true,
    )
    .expect("convert machine")
}

/// A whitelist of this run's own keys: every convert key the guests use, the standard combine
/// nodes and the deferred node — the same leaf families `mle_build_vk_map` writes.
fn self_map(guests: &[&Guest]) -> MleVkMap {
    let mut ids: Vec<VkIdentity> = Vec::new();
    let mut convert_vk = None;
    for guest in guests {
        for entry in &convert_machine(guest).pks {
            let id = vk_identity(&entry.3);
            if !ids.contains(&id) {
                ids.push(id);
            }
            convert_vk.get_or_insert_with(|| entry.3.clone());
        }
    }
    let convert_vk = convert_vk.expect("a convert key");
    let mut combine = CombineMachine::new(
        recursion_params_with_100_bits_security(),
        guests[0].vm_vk.clone(),
        true,
    );
    ids.extend(
        combine
            .preregister_standard_shapes(&convert_vk)
            .unwrap_or_else(|e| panic!("{e}"))
            .iter()
            .map(|vk| vk_identity(vk)),
    );
    let mut deferred = DeferredMachine::new(
        recursion_params_with_100_bits_security(),
        guests[0].vm_vk.clone(),
        true,
    );
    let combine_tier = combine
        .combine_tier_child_layout(&convert_vk)
        .unwrap_or_else(|e| panic!("{e}"));
    let node = deferred
        .preregister(&combine_tier)
        .unwrap_or_else(|e| panic!("{e}"));
    ids.push(vk_identity(&node));
    MleVkMap::build(ids)
}

/// Convert + combine `guest` under `map`, with `prefix` (deferred nodes) at the head and the
/// leaves carrying `chain`; the root is verified by the machine before it is returned.
fn tree(
    guest: &Guest,
    map: &Arc<MleVkMap>,
    chain: [Kb; DIGEST_SIZE],
    prefix: &[ProofWithVk],
) -> eyre::Result<ProofWithVk> {
    let mut convert = convert_machine(guest);
    convert.set_vk_root(map.root())?;
    convert.set_final_deferred_digest(chain);
    let mut children = prefix.to_vec();
    children.extend(convert.prove_with_vks(&guest.proofs)?);
    let mut combine = CombineMachine::new(
        recursion_params_with_100_bits_security(),
        guest.vm_vk.clone(),
        true,
    );
    combine.set_vk_map(map.clone());
    let root = combine.prove_tree(children)?;
    combine.verify(&root)?;
    Ok(root)
}

/// Deferred nodes over `subs` for `main`, under `map`; each node is STARK-verified.
fn nodes(
    main: &Guest,
    map: &Arc<MleVkMap>,
    subs: &[ProofWithVk],
    skip_host_checks: bool,
) -> eyre::Result<(Vec<ProofWithVk>, [Kb; DIGEST_SIZE])> {
    let mut deferred = DeferredMachine::new(
        recursion_params_with_100_bits_security(),
        main.vm_vk.clone(),
        true,
    );
    deferred.set_vk_map(map.clone());
    if skip_host_checks {
        deferred.skip_host_checks_for_testing();
    }
    let (nodes, end) = deferred.prove_chain(subs)?;
    for node in &nodes {
        deferred.verify(node)?;
    }
    Ok((nodes, end))
}

/// `map` without `id`, re-rooted.
fn without(map: &MleVkMap, id: &VkIdentity) -> MleVkMap {
    let ids: Vec<VkIdentity> = map.entries.iter().filter(|e| *e != id).copied().collect();
    assert_eq!(ids.len() + 1, map.entries.len(), "the key was a member");
    MleVkMap::build(ids)
}

/// `guest`'s first convert leaf under `map`.
fn convert_leaf(guest: &Guest, map: &MleVkMap) -> ProofWithVk {
    let mut convert = convert_machine(guest);
    convert.set_vk_root(map.root()).expect("vk root");
    convert
        .prove_with_vks(&guest.proofs[..1])
        .expect("convert leaf")
        .remove(0)
}

/// Same members, another root.
fn reordered(map: &MleVkMap) -> Arc<MleVkMap> {
    let mut ids = map.entries.clone();
    ids.swap(0, 1);
    Arc::new(MleVkMap::build(ids))
}

fn vk_root_of(proof: &ProofWithVk) -> [Kb; 8] {
    let pvs = recursion_public_values(&proof.0.public_values).expect("recursion pvs");
    std::array::from_fn(|j| pvs[RECURSION_PUBLIC_VALUES_COL_MAP.vk_root[j]])
}

fn main() {
    setup_logger();
    // The GPU riscv prover allocates from the shared pool; a CPU build has none to set up.
    #[cfg(feature = "cuda")]
    riscv::init_mle_gpu_pool(riscv::MLE_GPU_DEVICE);

    let mut fib_stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    fib_stdin.write(&10u32);
    let fib = prove_guest(ELF, fib_stdin.finalize());
    // The aggregator is handed fib's exe identity and output, so its digest is a chain over
    // fib's root; the identity is fixed by the program, so it is known before fib is proved.
    let fib_identity: [u32; DIGEST_SIZE] = fib.vm_vk.digest().map(|l| l.as_canonical_u32());
    let mut agg_stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    agg_stdin.write(&vec![fib_identity; 2]);
    agg_stdin.write(&vec![fib.committed_bytes.clone(); 2]);
    let agg = prove_guest(AGGREGATOR_ELF, agg_stdin.finalize());

    let map = Arc::new(match std::env::var("MLE_VK_MAP") {
        Ok(path) => {
            let map = MleVkMap::load(&path);
            if let Some(pinned) = pinned_root_from_env() {
                assert_eq!(map.root(), pinned, "`{path}` does not carry MLE_VK_ROOT");
            }
            info!("whitelist: `{path}`, {} leaves", map.entries.len());
            map
        }
        Err(_) => {
            let map = self_map(&[&fib, &agg]);
            info!("whitelist: self-map, {} leaves", map.entries.len());
            map
        }
    });
    let root = map.root();

    let mut failures = 0;
    let mut check = |name: &str, ok: bool, detail: String| {
        if ok {
            info!("case {name}: as expected — {detail}");
        } else {
            tracing::error!("case {name}: WRONG — {detail}");
            failures += 1;
        }
    };

    // ── Must prove ──────────────────────────────────────────────────────────────────────────
    let sub_root = tree(&fib, &map, [Kb::ZERO; DIGEST_SIZE], &[]).expect("fib's tree");
    check(
        "sub-root",
        vk_root_of(&sub_root) == root,
        "proved and verified, carrying the map's root".into(),
    );
    let subs = [sub_root.clone(), sub_root.clone()];
    let (agg_nodes, chain_end) = nodes(&agg, &map, &subs, false).expect("deferred nodes");
    let happy = tree(&agg, &map, chain_end, &agg_nodes).expect("the aggregator's tree");
    let pvs = recursion_public_values(&happy.0.public_values).expect("root pvs");
    let col = RECURSION_PUBLIC_VALUES_COL_MAP;
    let closes = (0..DIGEST_SIZE).all(|j| pvs[col.deferred_proofs_digest[j]] == chain_end[j]);
    let nodes_rooted = agg_nodes.iter().all(|n| vk_root_of(n) == root);
    let apex = MleApexVerifier::new(
        recursion_params_with_100_bits_security(),
        map.clone(),
        agg.vm_vk.clone(),
        root,
    )
    .verify(&happy);
    check(
        "happy",
        closes && nodes_rooted && apex.is_ok(),
        format!("closes on the chain = {closes}, nodes carry the root = {nodes_rooted}, apex = {apex:?}"),
    );

    // ── Must fail ───────────────────────────────────────────────────────────────────────────
    let sub_vk = vk_identity(&sub_root.1);
    let unlisted = Arc::new(without(&map, &sub_vk));
    // Membership is checked before the root, so the honest sub-root is refused for its key.
    expect_err(
        &mut check,
        "sub-unlisted (host)",
        || nodes(&agg, &unlisted, &subs[..1], false),
        "not in the whitelist",
    );
    expect_err(
        &mut check,
        "sub-unlisted (witness)",
        || nodes(&agg, &unlisted, &subs[..1], true),
        "child VK not in the whitelist",
    );

    let other = reordered(&map);
    let foreign = tree(&fib, &other, [Kb::ZERO; DIGEST_SIZE], &[]).expect("fib under another root");
    expect_err(
        &mut check,
        "sub-other-root (host)",
        || nodes(&agg, &map, std::slice::from_ref(&foreign), false),
        "another whitelist root",
    );
    expect_err(
        &mut check,
        "sub-other-root (circuit)",
        || nodes(&agg, &map, std::slice::from_ref(&foreign), true),
        "deferred node failed STARK verify",
    );

    let mut forged = (*map).clone();
    forged.corrupt_paths_for_testing();
    expect_err(
        &mut check,
        "forged-path (circuit)",
        || nodes(&agg, &Arc::new(forged.clone()), &subs[..1], false),
        "deferred node failed STARK verify",
    );

    let node_vk = vk_identity(&agg_nodes[0].1);
    let no_node = Arc::new(without(&map, &node_vk));
    expect_err(
        &mut check,
        "node-unlisted (parent witness)",
        || {
            // Everything under `no_node`, which still holds every key but the node's: the
            // sub-proof, the node and the leaves all carry its root, so the node's own membership
            // is the only thing the parent can object to.
            let sub = tree(&fib, &no_node, [Kb::ZERO; DIGEST_SIZE], &[])?;
            let (nodes, end) = nodes(&agg, &no_node, std::slice::from_ref(&sub), false)?;
            tree(&agg, &no_node, end, &nodes)
        },
        "child VK not in the whitelist",
    );

    expect_err(
        &mut check,
        "dev-node (host)",
        || {
            // A node proved outside the whitelist carries no root.
            let mut dev = DeferredMachine::new(
                recursion_params_with_100_bits_security(),
                agg.vm_vk.clone(),
                false,
            );
            let (nodes, end) = dev.prove_chain(std::slice::from_ref(&sub_root))?;
            tree(&agg, &map, end, &nodes)
        },
        "does not carry this tree's whitelist root",
    );

    expect_err(
        &mut check,
        "sub-not-complete (host)",
        || nodes(&agg, &map, &agg_nodes[..1], false),
        "not a complete root",
    );
    // A convert leaf is a member, carries the root and has `next_chunk` > 1, so with the host
    // check skipped only the node's `flag_complete == 1` stands between it and the chain.
    let leaf = convert_leaf(&fib, &map);
    expect_err(
        &mut check,
        "sub-not-complete (circuit)",
        || nodes(&agg, &map, std::slice::from_ref(&leaf), true),
        "deferred node failed STARK verify",
    );

    let wrong = reordered(&map);
    let apex = MleApexVerifier::new(
        recursion_params_with_100_bits_security(),
        wrong.clone(),
        agg.vm_vk.clone(),
        wrong.root(),
    )
    .verify(&happy);
    check(
        "wrong-trusted-root (apex)",
        apex.as_ref()
            .is_err_and(|e| e.to_string().contains("vk_root")),
        format!("{apex:?}"),
    );

    assert_eq!(failures, 0, "{failures} case(s) did not match expectation");
    info!("Deferred under the whitelist: every case matched ✓");
}

/// Run a case that must fail, and require the failure to name `reason`: a case that died for
/// another reason would leave the harness green while testing nothing.
fn expect_err<T>(
    check: &mut impl FnMut(&str, bool, String),
    name: &str,
    f: impl FnOnce() -> eyre::Result<T>,
    reason: &str,
) {
    let message = match panic::catch_unwind(panic::AssertUnwindSafe(f)) {
        Ok(Ok(_)) => {
            check(name, false, "proved".into());
            return;
        }
        Ok(Err(e)) => format!("{e}"),
        Err(payload) => payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .unwrap_or_else(|| String::from("panic with no message")),
    };
    check(name, message.contains(reason), message);
}
