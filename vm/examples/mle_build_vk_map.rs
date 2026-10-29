//! Offline whitelist builder: one convert VK per RISC-V shape the whitelist admits, plus the
//! combine node VKs (every ordered child pair over the convert rows and the combine tier) and the
//! deferred node VK, into the per-config vk-map artifact (`mle_vk_map_kb.bin`, root included).
//!
//! No proving is needed for enumeration: under the shape config a proof's layout is a function
//! of its shape alone, so each shape's convert layout is synthesized from the riscv vk and the
//! convert VK is keygen'd from that. Every convert program goes through `check_recursion_tier`
//! first, so a shape the convert tier cannot hold fails the build rather than a proving run.
//!
//! The convert keygens (one per whitelist shape) are spread over `MLE_VK_MAP_THREADS` workers
//! and checkpointed by shape
//! CONTENT (the sorted `name:height` list), so a stopped build resumes and a ladder edit that
//! moves every index still reuses what was already keygen'd. Leaves are laid out in
//! `mle_riscv_shapes()` order, then the combine VKs, then the deferred one.
//!
//! Self-validation, two layers:
//!   (a) `MLE_VK_MAP_RETH_BLOCKS=<id,id,...>`: emulate those reth blocks and check that the shape
//!       the prover would select for EVERY chunk is an exact member of the enumeration --
//!       emulation only, so it covers each real chunk of the corpus in minutes;
//!   (b) `MLE_VK_MAP_PROVE_BLOCK=<id>` (or, unset, fib-10): prove the chunks and check that each
//!       real proof's layout equals the layout synthesized for its selected shape, and that the
//!       convert VKs a real `ConvertMachine` keygens are map members -- the lookup the combine
//!       witness performs.
//!
//! Exit code: 0 when the build and every validation passed; 3 when the artifact was written but
//! a validation failed (the artifact is kept; each failure is logged as VALIDATION FAILED); a
//! panic exit (101) means the build itself failed.
//!
//! Environment:
//!   MLE_VK_MAP_OUT         artifact path, default mle_vk_map_kb.bin (a .json sibling is written
//!                          too)
//!   MLE_VK_MAP_ROOT_OUT    root file path, default mle_vk_root.txt beside the artifact
//!   MLE_VK_MAP_CKPT        checkpoint path, default mle_vk_map.ckpt
//!   MLE_VK_MAP_THREADS     keygen workers, default 8
//!   MLE_VK_MAP_LIMIT       keygen only the first N shapes (timing runs; no artifact is written,
//!                          the checkpoint is still appended)
//!   MLE_VK_MAP_RETH_DIR    where fib-elf, reth-elf and reth-<id>.bin live, default
//!                          ./perf/bench_data/rv64
//!   MLE_VK_MAP_RETH_BLOCKS self-check (a): reth block ids to emulate, comma separated
//!   MLE_VK_MAP_PROVE_BLOCK self-check (b): a reth block to prove instead of fib-10
//!   MLE_LOG_STACKED_HEIGHT leave unset: the artifact is keyed to the height the prover ships
//!                          with
//!
//! Usage:
//!   cargo run --release -p pico-vm --example mle_build_vk_map
//!
//! A change to the shape tables, the riscv AIRs, the params or the recursion compiler is followed
//! by a full rebuild from no checkpoint.
//!
//! Beside the artifact the builder writes `mle_vk_root.txt` (the config digest and the pinned
//! root, `MLE_VK_MAP_ROOT_OUT`), the file that ships next to the bin. On resume the first
//! checkpointed shape is keygen'd again and the checkpoint is refused when the identity differs:
//! a probe of one shape, which catches a build of the convert programs that moved every key and
//! not one that moved only shapes the probe is not in.
//!
//! Every key the build admits scores at least 100 bits: each keygen is refused below that budget
//! (`admit_production_vk`), the probe's included. A checkpointed identity is admitted without its
//! key being scored again, because every convert key has the same recursion AIR set and preset,
//! so the same shape and score; when the probe keygens one under this build's calculator and
//! it is admitted, every checkpointed key scores the same.

use std::{
    collections::{BTreeSet, HashMap},
    fs,
    io::Write,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc,
    },
    time::Instant,
};

use p3_field::PrimeField32;
use pico_mle_core::{
    config::recursion_params_with_100_bits_security, keygen::types::MultiStarkVerifyingKey,
    StarkEngine,
};
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::kb_poseidon2::KoalaBearPoseidon2,
    emulator::{riscv::record::EmulationRecord, stdin::EmulatorStdin},
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::{chip::MetaChip, logger::setup_logger},
    mle::{
        compiler::recursion::RecursionVkLayout,
        machine::{
            combine::CombineMachine,
            convert::ConvertMachine,
            deferred::DeferredMachine,
            exe::RiscvVmVk,
            recursion::{extract_recursion_vk_layout, recursion_vk_layouts_equal, Engine},
            riscv,
            shape::{mle_natural_heights, mle_riscv_shapes, select_riscv_shape},
            vk_map::{
                checkpoint_line, parse_checkpoint_line, root_file_text, shape_content_key,
                synthesized_convert_layout, vk_identity, whitelist_convert_vk, whitelist_riscv_vk,
                MleVkMap, VkIdentity, VkMapArtifact,
            },
        },
    },
};
use tracing::info;

type Stdin = EmulatorStdin<Program, Vec<u8>>;
type Shape = Vec<(String, usize)>;
type Chips = [MetaChip<riscv::Kb, RiscvChipType<riscv::Kb>>];

fn env(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn read_file(dir: &str, name: &str) -> Vec<u8> {
    let path = format!("{dir}/{name}");
    fs::read(&path).unwrap_or_else(|e| panic!("cannot read `{path}`: {e}"))
}

fn fib_stdin(n: u32) -> Stdin {
    let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin.write(&n);
    stdin.finalize()
}

fn reth_stdin(dir: &str, block: &str) -> Stdin {
    let input = read_file(dir, &format!("reth-{block}.bin"));
    let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin.write_slice(&input);
    stdin.finalize()
}

/// `mle_vk_root.txt` in the artifact's directory: the name the tree ships it under.
fn root_file_beside(out: &str) -> String {
    match Path::new(out).parent() {
        Some(dir) if !dir.as_os_str().is_empty() => {
            dir.join("mle_vk_root.txt").to_string_lossy().into_owned()
        }
        _ => "mle_vk_root.txt".to_string(),
    }
}

/// Today's date, `YYYY-MM-DD` in UTC, off the system clock (civil-from-days).
fn today_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Write `mle_vk_root.txt` beside the artifact (see [`root_file_text`]).
fn write_root_file(
    path: &str,
    out: &str,
    artifact: &VkMapArtifact,
    n_convert: usize,
    n_combine: usize,
    n_deferred: usize,
    riscv_vk: &MultiStarkVerifyingKey<riscv::Sc>,
) {
    let bin = Path::new(out)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(out);
    let pre_hash = riscv_vk.pre_hash.map(|f| f.as_canonical_u32());
    let text = root_file_text(
        artifact,
        bin,
        n_convert,
        n_combine,
        n_deferred,
        pre_hash,
        &today_utc(),
    );
    fs::write(path, text).unwrap_or_else(|e| panic!("cannot write root file `{path}`: {e}"));
}

/// The shape the prover selects for a record: the same three steps `build_ctx` takes.
fn selected_shape(chips: &Chips, record: &EmulationRecord) -> Shape {
    let augmented = riscv::augmented_record(chips, record);
    let present: Vec<String> = riscv::bucketed_air_ids(chips, record)
        .into_iter()
        .map(|id| riscv::air_name(id).expect("named air").to_string())
        .collect();
    let natural = mle_natural_heights(&augmented);
    select_riscv_shape(&present, &natural, augmented.is_cpu_chunk)
}

fn load_checkpoint(path: &str) -> HashMap<String, VkIdentity> {
    let Ok(text) = fs::read_to_string(path) else {
        return HashMap::new();
    };
    text.lines()
        .filter(|l| !l.is_empty())
        .map(parse_checkpoint_line)
        .collect()
}

fn main() {
    setup_logger();
    let out = env("MLE_VK_MAP_OUT", "mle_vk_map_kb.bin");
    let ckpt_path = env("MLE_VK_MAP_CKPT", "mle_vk_map.ckpt");
    let threads: usize = env("MLE_VK_MAP_THREADS", "8")
        .parse()
        .expect("MLE_VK_MAP_THREADS");
    let limit: Option<usize> = std::env::var("MLE_VK_MAP_LIMIT")
        .ok()
        .map(|v| v.parse().expect("MLE_VK_MAP_LIMIT"));
    let reth_dir = env("MLE_VK_MAP_RETH_DIR", "./perf/bench_data/rv64");
    let chips = RiscvChipType::<riscv::Kb>::all_chips();

    // One riscv vk serves every shape: under the shape config its layout-relevant content (DAGs,
    // params, geometry, byte-table commit) is app-independent; the app-varying program commit is
    // witnessed, never baked, so it cannot reach a convert program. fib is just a program to
    // keygen it from.
    let fib_program = Compiler::new(SourceType::RISCV, &read_file(&reth_dir, "fib-elf"))
        .expect("parse fib")
        .compile();
    let riscv_vk =
        Arc::new(whitelist_riscv_vk(fib_program.clone()).unwrap_or_else(|e| panic!("{e}")));

    // ── Convert VKs: one per whitelist shape, checkpointed by shape content ──
    let shapes: Vec<(String, Shape)> = mle_riscv_shapes();
    let keys: Vec<String> = shapes.iter().map(|(_, s)| shape_content_key(s)).collect();
    let key_set: BTreeSet<&String> = keys.iter().collect();
    let mut done = load_checkpoint(&ckpt_path);
    // A checkpoint is keyed by shape content, not by the code that keygen'd it, so after a change
    // to the convert programs (the recursion compiler, the riscv AIRs) its entries are stale and
    // would be copied into the artifact unseen. Probe: keygen the first checkpointed shape again
    // and require its checkpointed identity. Entries for shapes this config does not enumerate
    // are left unused.
    if let Some(i) = (0..shapes.len()).find(|i| done.contains_key(&keys[*i])) {
        let engine: Engine = StarkEngine::new(recursion_params_with_100_bits_security());
        let (label, shape) = &shapes[i];
        let now = vk_identity(
            &whitelist_convert_vk(&engine, &riscv_vk, label, shape)
                .unwrap_or_else(|e| panic!("{e}")),
        );
        assert!(
            now == done[&keys[i]],
            "checkpoint `{ckpt_path}` was written by another build of the convert programs \
             (shape `{label}` keygens to a different VK): delete it and rebuild in full"
        );
        let unlisted = done.keys().filter(|k| !key_set.contains(k)).count();
        info!(
            "checkpoint `{ckpt_path}` probe: `{label}` keygens to its checkpointed identity; \
             {unlisted} entries are for shapes this config does not enumerate"
        );
    }
    let todo: Vec<usize> = (0..shapes.len())
        .filter(|i| !done.contains_key(&keys[*i]))
        .take(limit.unwrap_or(usize::MAX))
        .collect();
    info!(
        "whitelist riscv shapes: {} ({} checkpointed, {} to keygen, {threads} workers)",
        shapes.len(),
        keys.iter().filter(|k| done.contains_key(*k)).count(),
        todo.len()
    );

    let t0 = Instant::now();
    let next = AtomicUsize::new(0);
    let (tx, rx) = mpsc::channel::<(usize, VkIdentity)>();
    std::thread::scope(|scope| {
        for _ in 0..threads.max(1) {
            let tx = tx.clone();
            let (next, todo, shapes, riscv_vk) = (&next, &todo, &shapes, &riscv_vk);
            scope.spawn(move || {
                let engine: Engine = StarkEngine::new(recursion_params_with_100_bits_security());
                loop {
                    let k = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&i) = todo.get(k) else { break };
                    let (label, shape) = &shapes[i];
                    let vk = whitelist_convert_vk(&engine, riscv_vk, label, shape)
                        .unwrap_or_else(|e| panic!("{e}"));
                    tx.send((i, vk_identity(&vk))).expect("collector alive");
                }
            });
        }
        drop(tx);
        // Single writer: append every finished shape to the checkpoint as it lands.
        let mut ckpt = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&ckpt_path)
            .unwrap_or_else(|e| panic!("cannot open checkpoint `{ckpt_path}`: {e}"));
        let mut n = 0usize;
        for (i, id) in rx {
            writeln!(ckpt, "{}", checkpoint_line(&keys[i], &shapes[i].0, &id))
                .expect("checkpoint write");
            done.insert(keys[i].clone(), id);
            n += 1;
            if n.is_multiple_of(200) || n == todo.len() {
                let secs = t0.elapsed().as_secs_f64();
                info!(
                    "keygen {n}/{} ({:.2} s each wall, {:.0} s elapsed, ~{:.0} s left)",
                    todo.len(),
                    secs / n as f64,
                    secs,
                    secs / n as f64 * (todo.len() - n) as f64
                );
            }
        }
        ckpt.flush().expect("checkpoint flush");
    });
    info!(
        "convert keygens: {} in {:.0} s wall",
        todo.len(),
        t0.elapsed().as_secs_f64()
    );
    if limit.is_some() {
        info!("MLE_VK_MAP_LIMIT set: timing run, no artifact written");
        return;
    }

    let mut identities: Vec<VkIdentity> = keys
        .iter()
        .map(|k| *done.get(k).expect("every shape keygen'd"))
        .collect();

    // ── Combine VKs: the 36 node shapes, each through CombineMachine's own tier check ──
    // Any convert vk bootstraps the per-row C child layouts; the B layout comes from the
    // [C_last, C_last] node.
    let leaf_engine: Engine = StarkEngine::new(recursion_params_with_100_bits_security());
    let convert_vk0 = whitelist_convert_vk(&leaf_engine, &riscv_vk, &shapes[0].0, &shapes[0].1)
        .unwrap_or_else(|e| panic!("{e}"));
    let vm_vk = RiscvVmVk::from_program_and_vk(&fib_program, &riscv_vk);
    let mut combine = CombineMachine::new(
        recursion_params_with_100_bits_security(),
        vm_vk.clone(),
        true,
    );
    let combine_vks = combine
        .preregister_standard_shapes(&convert_vk0)
        .unwrap_or_else(|e| panic!("{e}"));
    identities.extend(combine_vks.iter().map(|v| vk_identity(v)));
    // ── The deferred node VK: one, over the combine-tier child every sub-proof root is ──
    let mut deferred = DeferredMachine::new(recursion_params_with_100_bits_security(), vm_vk, true);
    let combine_tier = combine
        .combine_tier_child_layout(&convert_vk0)
        .unwrap_or_else(|e| panic!("{e}"));
    let deferred_vk = deferred
        .preregister(&combine_tier)
        .unwrap_or_else(|e| panic!("{e}"));
    identities.push(vk_identity(&deferred_vk));
    info!(
        "leaves: {} convert + {} combine + 1 deferred = {}",
        shapes.len(),
        combine_vks.len(),
        identities.len()
    );

    let map = MleVkMap::build(identities);
    map.save_bin(&out);
    let json = match out.strip_suffix(".bin") {
        Some(stem) => format!("{stem}.json"),
        None => format!("{out}.json"),
    };
    map.save_json(&json);
    let artifact = map.to_artifact();
    info!(
        "vk map artifact written: `{out}` (+ `{json}`), {} entries",
        map.entries.len()
    );
    info!("  config digest = {:?}", artifact.config_digest);
    info!(
        "  root          = {:?}   (MLE_VK_ROOT=\"{}\")",
        artifact.root,
        artifact
            .root
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    );
    let root_out = env("MLE_VK_MAP_ROOT_OUT", &root_file_beside(&out));
    write_root_file(
        &root_out,
        &out,
        &artifact,
        shapes.len(),
        combine_vks.len(),
        1,
        &riscv_vk,
    );
    info!("root file written: `{root_out}`");

    // The artifact is on disk by now. What follows only checks it, so a failure here (an input
    // that will not run, a chunk whose shape is not a member, a real VK missing) is reported
    // and exits with code 3 rather than sharing the build's panic exit.
    let mut failed: Vec<String> = Vec::new();

    // ── (a) every corpus chunk's selected shape is an exact whitelist member ──
    let blocks: Vec<String> = env("MLE_VK_MAP_RETH_BLOCKS", "")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if !blocks.is_empty() {
        let reth_program = Compiler::new(SourceType::RISCV, &read_file(&reth_dir, "reth-elf"))
            .expect("parse reth")
            .compile();
        let mut chunks = 0usize;
        let mut passed = 0usize;
        for block in &blocks {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // One record at a time: a reth block's records do not all fit the GPU prover's
                // pinned event pools at once.
                let mut i = 0usize;
                riscv::emulate_each(
                    reth_program.clone(),
                    reth_stdin(&reth_dir, block),
                    None,
                    |record| {
                        let key = shape_content_key(&selected_shape(&chips, &record));
                        assert!(
                            key_set.contains(&key),
                            "VALIDATION FAILED: block {block} chunk {i} selects a shape the \
                             whitelist does not hold: {key}"
                        );
                        i += 1;
                    },
                );
                i
            }));
            match outcome {
                Ok(n) => {
                    chunks += n;
                    passed += 1;
                    info!(
                        "block {block}: {n} chunk(s), every selected shape is a whitelist member"
                    );
                }
                Err(_) => failed.push(format!(
                    "(a) block {block}: emulation or membership check failed (see the panic above)"
                )),
            }
        }
        if passed == blocks.len() {
            info!("(a) ✓ {chunks} chunk(s) over {} block(s)", blocks.len());
        } else {
            tracing::warn!("(a) ✗ {passed}/{} block(s) passed", blocks.len());
        }
    }

    // ── (b) real proofs: layout equals the synthesized one, real convert VKs are members ──
    let (label, program, stdin) = match std::env::var("MLE_VK_MAP_PROVE_BLOCK") {
        Ok(block) if !block.is_empty() => {
            let program = Compiler::new(SourceType::RISCV, &read_file(&reth_dir, "reth-elf"))
                .expect("parse reth")
                .compile();
            (
                format!("reth-{block}"),
                program,
                reth_stdin(&reth_dir, &block),
            )
        }
        _ => ("fib-10".to_string(), fib_program.clone(), fib_stdin(10)),
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let records = riscv::emulate(program.clone(), stdin, None);
        let expected: Vec<RecursionVkLayout> = records
            .iter()
            .map(|r| synthesized_convert_layout(&riscv_vk, &selected_shape(&chips, r)))
            .collect();
        let bundle = riscv::prove_riscv(
            program.clone(),
            &records,
            riscv::log_stacked_height_from_env(),
            true,
        )
        .expect("riscv prove");
        for (i, proof) in bundle.chunk_proofs.iter().enumerate() {
            let real = extract_recursion_vk_layout(&bundle.vk, Some(proof));
            assert!(
                recursion_vk_layouts_equal(&expected[i], &real),
                "VALIDATION FAILED: {label} chunk {i}: the real proof's layout differs from the \
                 one synthesized for its selected shape"
            );
        }
        let real_vm_vk = RiscvVmVk::from_program_and_vk(&program, &bundle.vk);
        let real_convert = ConvertMachine::new(
            bundle.vk.clone(),
            real_vm_vk,
            &bundle.chunk_proofs,
            recursion_params_with_100_bits_security(),
            true,
        )
        .expect("convert machine");
        for entry in &real_convert.pks {
            assert!(
                map.find(&vk_identity(&entry.3)).is_some(),
                "VALIDATION FAILED: {label}: a real convert VK is not a whitelist member"
            );
        }
        info!(
            "(b) ✓ {label}: {} real proof layout(s) match their synthesized layouts, {} real \
             convert VK(s) are whitelist members",
            bundle.chunk_proofs.len(),
            real_convert.pks.len()
        );
    }));
    if outcome.is_err() {
        failed.push(format!("(b) {label}: see the panic above"));
    }

    if !failed.is_empty() {
        for f in &failed {
            tracing::error!("VALIDATION FAILED: {f}");
        }
        tracing::error!(
            "artifact `{out}` is written; {} validation(s) failed",
            failed.len()
        );
        std::process::exit(3);
    }
    info!("validations passed; artifact `{out}`");
}
