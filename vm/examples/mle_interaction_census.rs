//! Interaction + top-degree census of the RISC-V MLE machine, straight from the keygen DAG.
//!
//! For each selected AIR prints
//!   * every interaction: bus kind, message length, max message-field degree, count degree, the
//!     count expression and the trace columns it references (the "gate");
//!   * the interactions grouped by (kind, message length) — the only shape under which two
//!     interactions could be multiplexed into one;
//!   * every plain constraint that sits at the AIR's own `max_constraint_degree`, with the columns
//!     it touches and the expression (this per-AIR degree is what sets `nc_zc = deg − 1`, the
//!     round-0 zerocheck coset count);
//!   * the degree histogram of the plain constraints.
//!
//! Column indices are printed as `c<i>` / `next.c<i>`; for CpuChip the names from `CPU_COL_MAP`
//! are attached so the gates can be read against the chip source without guessing.
//!
//! Keygen only: no emulation, no block input, no GPU.
//!
//! Usage:
//!   cargo run --release -p pico-vm --example mle_interaction_census \
//!     -- --elf reth --n 24006427 --field kb
//!   CENSUS_AIRS="Cpu,MemoryReadWrite" (short `riscv::air_name` prefixes; default: Cpu,
//!   MemoryReadWrite, Add, LessThan, Bitwise; "all" for every AIR, slow on the big precompile
//!   DAGs)
//!   CENSUS_MAX_EXPR=600 caps every printed expression (shared sub-DAGs would otherwise blow up)

use pico_mle_core::{
    air::symbolic::{symbolic_variable::Entry, SymbolicExpressionDag, SymbolicExpressionNode},
    config::riscv_params_with_100_bits_security,
    StarkEngine,
};
use pico_vm::{
    chips::chips::riscv_cpu::columns::CPU_COL_MAP,
    compiler::riscv::compiler::{Compiler, SourceType},
    configs::stark_config::KoalaBearPoseidon2,
    machine::logger::setup_logger,
    mle::machine::{recursion::Engine, riscv},
};
use std::collections::{BTreeMap, HashMap};
use tracing::info;

#[path = "common/parse_args.rs"]
mod parse_args;

/// `riscv::air_name` short names (not the keygen `…Chip<…>` names).
const DEFAULT_AIRS: &[&str] = &["Cpu", "MemoryReadWrite", "Add", "LessThan", "Bitwise"];

/// Degree of every DAG node (compound nodes cache it; leaves do not).
fn node_degrees<F: p3_field::Field>(dag: &SymbolicExpressionDag<F>) -> Vec<usize> {
    dag.nodes
        .iter()
        .map(|n| match n {
            SymbolicExpressionNode::Variable(v) => v.degree_multiple(),
            SymbolicExpressionNode::IsFirstRow
            | SymbolicExpressionNode::IsLastRow
            | SymbolicExpressionNode::IsTransition => 1,
            SymbolicExpressionNode::Constant(_) => 0,
            SymbolicExpressionNode::Add {
                degree_multiple, ..
            }
            | SymbolicExpressionNode::Sub {
                degree_multiple, ..
            }
            | SymbolicExpressionNode::Neg {
                degree_multiple, ..
            }
            | SymbolicExpressionNode::Mul {
                degree_multiple, ..
            } => *degree_multiple,
        })
        .collect()
}

/// Column names for CpuChip (main trace, offset 0), from `CPU_COL_MAP`.
fn cpu_col_names() -> HashMap<usize, String> {
    let m = &CPU_COL_MAP;
    let mut n: HashMap<usize, String> = HashMap::new();
    let mut put = |i: usize, s: String| {
        n.insert(i, s);
    };
    put(m.clk, "clk".into());
    put(m.num_extra_clk, "num_extra_clk".into());
    for i in 0..2 {
        put(m.pc[i], format!("pc[{i}]"));
        put(m.next_pc[i], format!("next_pc[{i}]"));
    }
    put(m.pc_carry, "pc_carry".into());
    put(m.instruction.opcode, "instr.opcode".into());
    put(m.instruction.op_a, "instr.op_a".into());
    put(m.instruction.op_a_0, "instr.op_a_0".into());
    for i in 0..2 {
        put(m.instruction.op_b.limb[i], format!("instr.op_b.limb[{i}]"));
        put(m.instruction.op_c.limb[i], format!("instr.op_c.limb[{i}]"));
    }
    put(m.instruction.op_b.sign, "instr.op_b.sign".into());
    put(m.instruction.op_c.sign, "instr.op_c.sign".into());
    let s = &m.opcode_selector;
    for (idx, name) in [
        (s.imm_b, "sel.imm_b"),
        (s.imm_c, "sel.imm_c"),
        (s.is_ecall, "sel.is_ecall"),
        (s.is_memory, "sel.is_memory"),
        (s.is_store, "sel.is_store"),
        (s.is_beq, "sel.is_beq"),
        (s.is_bne, "sel.is_bne"),
        (s.is_blt, "sel.is_blt"),
        (s.is_bge, "sel.is_bge"),
        (s.is_bltu, "sel.is_bltu"),
        (s.is_bgeu, "sel.is_bgeu"),
        (s.is_jalr, "sel.is_jalr"),
        (s.is_jal, "sel.is_jal"),
    ] {
        put(idx, name.into());
    }
    let acc =
        |n: &mut HashMap<usize, String>,
         tag: &str,
         a: &pico_vm::chips::chips::riscv_memory::read_write::columns::MemoryAccessLiteCols<
            usize,
        >| {
            for i in 0..4 {
                n.insert(a.value[i], format!("{tag}.value[{i}]"));
            }
            n.insert(a.diff_16bit_limb, format!("{tag}.diff_16bit_limb"));
            n.insert(a.diff_hi9, format!("{tag}.diff_hi9"));
        };
    for i in 0..4 {
        put(m.op_a_access.prev_value[i], format!("op_a.prev_value[{i}]"));
    }
    acc(&mut n, "op_a", &m.op_a_access.access);
    acc(&mut n, "op_b", &m.op_b_access.access);
    acc(&mut n, "op_c", &m.op_c_access.access);
    n.insert(m.a_gt_b, "a_gt_b".into());
    n.insert(m.a_lt_b, "a_lt_b".into());
    n.insert(m.is_halt, "is_halt".into());
    n.insert(m.is_real, "is_real".into());
    n.insert(m.is_last, "is_last".into());
    n.insert(m.is_alu_not_x0, "is_alu_not_x0".into());
    n.insert(m.jalr_lsb, "jalr_lsb".into());
    n
}

struct Printer<'a, F> {
    dag: &'a SymbolicExpressionDag<F>,
    names: Option<&'a HashMap<usize, String>>,
    memo: HashMap<usize, String>,
    /// Cap on any memoized rendering. A DAG with heavy sharing (Keccak, curve ops) would
    /// otherwise expand to an exponentially long string; beyond this the text is elided.
    cap: usize,
}

impl<F: p3_field::Field> Printer<'_, F> {
    fn var_name(&self, e: &Entry, index: usize) -> String {
        match e {
            Entry::Main { offset, .. } => {
                let base = self
                    .names
                    .and_then(|n| n.get(&index).cloned())
                    .unwrap_or_else(|| format!("c{index}"));
                if *offset == 0 {
                    base
                } else {
                    format!("next.{base}")
                }
            }
            Entry::Preprocessed { offset } => {
                if *offset == 0 {
                    format!("p{index}")
                } else {
                    format!("next.p{index}")
                }
            }
            Entry::Public => format!("pv{index}"),
        }
    }

    fn fmt(&mut self, idx: usize) -> String {
        if let Some(s) = self.memo.get(&idx) {
            return s.clone();
        }
        let s = match &self.dag.nodes[idx] {
            SymbolicExpressionNode::Variable(v) => self.var_name(&v.entry, v.index),
            SymbolicExpressionNode::IsFirstRow => "FIRST".into(),
            SymbolicExpressionNode::IsLastRow => "LAST".into(),
            SymbolicExpressionNode::IsTransition => "TRANS".into(),
            SymbolicExpressionNode::Constant(c) => format!("{c}"),
            SymbolicExpressionNode::Add {
                left_idx,
                right_idx,
                ..
            } => format!("({} + {})", self.fmt(*left_idx), self.fmt(*right_idx)),
            SymbolicExpressionNode::Sub {
                left_idx,
                right_idx,
                ..
            } => format!("({} - {})", self.fmt(*left_idx), self.fmt(*right_idx)),
            SymbolicExpressionNode::Neg { idx, .. } => format!("(-{})", self.fmt(*idx)),
            SymbolicExpressionNode::Mul {
                left_idx,
                right_idx,
                ..
            } => format!("{}*{}", self.fmt(*left_idx), self.fmt(*right_idx)),
        };
        let s = clip(s, self.cap);
        self.memo.insert(idx, s.clone());
        s
    }

    /// Trace columns (offset, index) reachable from `root`, sorted and deduplicated.
    fn cols(&self, root: usize) -> Vec<String> {
        let mut seen = vec![false; self.dag.nodes.len()];
        let mut stack = vec![root];
        let mut out: Vec<(usize, usize, String)> = Vec::new();
        while let Some(nid) = stack.pop() {
            if seen[nid] {
                continue;
            }
            seen[nid] = true;
            match &self.dag.nodes[nid] {
                SymbolicExpressionNode::Variable(v) => {
                    if let Some(off) = v.entry.offset() {
                        out.push((off, v.index, self.var_name(&v.entry, v.index)));
                    }
                }
                SymbolicExpressionNode::Add {
                    left_idx,
                    right_idx,
                    ..
                }
                | SymbolicExpressionNode::Sub {
                    left_idx,
                    right_idx,
                    ..
                }
                | SymbolicExpressionNode::Mul {
                    left_idx,
                    right_idx,
                    ..
                } => {
                    stack.push(*left_idx);
                    stack.push(*right_idx);
                }
                SymbolicExpressionNode::Neg { idx, .. } => stack.push(*idx),
                _ => {}
            }
        }
        out.sort_unstable();
        out.dedup();
        out.into_iter().map(|(_, _, s)| s).collect()
    }
}

fn clip(s: String, max: usize) -> String {
    if s.len() <= max {
        s
    } else {
        format!("{}…(+{} chars)", &s[..max], s.len() - max)
    }
}

fn main() {
    setup_logger();
    let (elf, _stdin, args) = parse_args::parse_args::<KoalaBearPoseidon2>();
    assert_eq!(args.field, "kb", "kb-only");
    let selection: Vec<String> = match std::env::var("CENSUS_AIRS") {
        Ok(s) if s == "all" => vec![],
        Ok(s) => s.split(',').map(|x| x.trim().to_string()).collect(),
        Err(_) => DEFAULT_AIRS.iter().map(|s| s.to_string()).collect(),
    };
    let max_expr = std::env::var("CENSUS_MAX_EXPR")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(600usize);

    let program = Compiler::new(SourceType::RISCV, elf)
        .expect("failed to parse ELF")
        .compile();
    let engine: Engine = StarkEngine::new(riscv_params_with_100_bits_security(23));
    let airs = riscv::mle_riscv_air_refs(program, true);
    let (_, vk) = engine.keygen_with_app_prep(&airs, riscv::RISCV_APP_PREP_AIR_IDS);
    info!(
        "[census] global max_constraint_degree = {}",
        vk.inner.max_constraint_degree()
    );
    let cpu_names = cpu_col_names();

    for (air_id, avk) in vk.inner.per_air.iter().enumerate() {
        let name = riscv::air_name(air_id).unwrap_or("?");
        if !selection.is_empty() && !selection.iter().any(|s| name.starts_with(s.as_str())) {
            continue;
        }
        let deg = avk.max_constraint_degree as usize;
        let dag = &avk.symbolic_constraints;
        let degs = node_degrees(&dag.constraints);
        let names = if name == "Cpu" {
            Some(&cpu_names)
        } else {
            None
        };
        let mut pr = Printer {
            dag: &dag.constraints,
            names,
            memo: HashMap::new(),
            cap: max_expr,
        };

        info!(
            "[census] air={air_id} {name} deg={deg} cols={} prep={} constraints={} interactions={} rot={}",
            avk.params.width.common_main,
            avk.params.width.preprocessed.unwrap_or(0),
            dag.constraints.constraint_idx.len(),
            dag.interactions.len(),
            u8::from(avk.params.need_rot),
        );

        // ---- interactions ----
        let mut groups: BTreeMap<(String, usize), Vec<usize>> = BTreeMap::new();
        for (k, it) in dag.interactions.iter().enumerate() {
            let fdeg = it.message.iter().map(|f| degs[*f]).max().unwrap_or(0);
            let cdeg = degs[it.count];
            let count = pr.fmt(it.count);
            let gate = pr.cols(it.count);
            let nontrivial_fields: Vec<String> = it
                .message
                .iter()
                .enumerate()
                .filter(|(_, f)| {
                    !matches!(
                        dag.constraints.nodes[**f],
                        SymbolicExpressionNode::Variable(_) | SymbolicExpressionNode::Constant(_)
                    )
                })
                .map(|(i, f)| format!("m{i}={}", clip(pr.fmt(*f), 120)))
                .collect();
            info!(
                "[census]   int#{k:<2} kind={:<11} len={:<2} fdeg={fdeg} cdeg={cdeg} count={} gate={:?}{}",
                format!("{:?}", it.kind),
                it.message.len(),
                clip(count, 200),
                gate,
                if nontrivial_fields.is_empty() { String::new() } else { format!(" fields:{}", nontrivial_fields.join(" ; ")) }
            );
            groups
                .entry((format!("{:?}", it.kind), it.message.len()))
                .or_default()
                .push(k);
        }
        for ((kind, len), idxs) in &groups {
            if idxs.len() < 2 {
                continue;
            }
            let gates: Vec<String> = idxs
                .iter()
                .map(|k| format!("#{k}:{}", clip(pr.fmt(dag.interactions[*k].count), 60)))
                .collect();
            info!(
                "[census]   group kind={kind} len={len} n={} → {}",
                idxs.len(),
                gates.join(" | ")
            );
        }

        // ---- plain constraints: histogram + top-degree list ----
        let mut hist: BTreeMap<usize, usize> = BTreeMap::new();
        for idx in &dag.constraints.constraint_idx {
            *hist.entry(degs[*idx]).or_default() += 1;
        }
        info!("[census]   constraint degree histogram {:?}", hist);
        for (i, root) in dag.constraints.constraint_idx.iter().enumerate() {
            if degs[*root] < deg {
                continue;
            }
            let cols = pr.cols(*root);
            let expr = clip(pr.fmt(*root), max_expr);
            info!(
                "[census]   top-deg constraint #{i} deg={} cols={:?} expr={expr}",
                degs[*root], cols
            );
        }
    }
}
