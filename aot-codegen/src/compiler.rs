//! Main AOT Compiler
//!
//! This module provides the main AOT compilation pipeline that coordinates
//! block analysis and code generation.
//!
//! ## Chunk Crates + Dispatch Crate
//!
//! The compiler emits one crate per chunk plus a dispatcher crate that links
//! all chunks and provides the execution entry points.

use crate::{
    block_analysis::BlockAnalyzer,
    cfg_analysis::CfgAnalysis,
    config::AotConfig,
    constants,
    elf_parser::to_vm_opcode,
    instruction_translator::InstructionTranslator,
    metrics::{AotMetrics, ChunkMetrics, LookupStrategy, ProgramMetrics},
    types::{Opcode, ProgramInfo},
};
use pico_vm::emulator::riscv::chunk_split::{add_insn_leaf_rows, LEAF_INSN_CHIPS};
use quote::{format_ident, quote};
use std::{collections::HashSet, fs};
use syn::visit_mut::VisitMut;

/// The runtime contract the generated code is written against, exported in the dispatch crate's
/// `AOT` for `pico_aot_runtime::register` to check: [`pico_vm::AOT_CODEGEN_STAMP`], which the
/// runtime accepts as `AotProgram::CODEGEN_STAMP`.
pub const CODEGEN_STAMP: u32 = pico_vm::AOT_CODEGEN_STAMP;

/// A hash of this generator's source: a host that caches pure-mode libraries keys them by it, so
/// a change to the generator rebuilds them.
pub const GENERATOR_FINGERPRINT: &str = env!("PICO_AOT_CODEGEN_FINGERPRINT");

/// The package name of the pure-mode dispatch crate generated from the ELF whose SHA-256 is
/// `elf_sha256`. Named per ELF, so the crates of several guests can link into one binary.
pub fn pure_dispatch_package(elf_sha256: &[u8; 32]) -> String {
    format!("pico-aot-pure-dispatch-{}", &hex(elf_sha256)[..16])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Information about a compiled basic block
struct BlockInfo {
    pc: u64,
    name: proc_macro2::Ident,
    insn_count: u32,
    mem_rw_events: usize,
    non_register_global_lookup_base_max: usize,
    reg_write_mask: u32,
    global_lookup_base_max: usize,
    code: proc_macro2::TokenStream,
    is_terminal: bool,
}

/// Information about a chunk of blocks
struct ChunkInfo {
    chunk_idx: usize,
    blocks: Vec<BlockInfo>,
    pc_min: u64,
    pc_max: u64,
}

#[inline(always)]
fn run_table_word_u32(word_offset: u64) -> u32 {
    u32::try_from(word_offset).expect("run-table word offset exceeds u32")
}

/// Which `pico-aot-runtime` the generated crates depend on.
///
/// It has to be the one the host's `pico-vm` resolves to: a second copy is a second `AotProgram`
/// type, and the host's use of the generated `AOT` then fails to typecheck.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum RuntimeSpec {
    /// `aot-runtime/` beside the output directory: the layout of `aot-generated/` at the root of a
    /// Pico checkout.
    #[default]
    InTree,
    /// The body of the dependency entry, written verbatim into every generated manifest, e.g.
    /// `git = "https://github.com/brevis-network/pico", tag = "v3.1.1"`. A `path` here must be
    /// absolute: the chunk crates sit two directories below the dispatch crate.
    Entry(String),
}

impl RuntimeSpec {
    /// `PICO_AOT_RUNTIME_SPEC` when it is set and non-empty, else [`RuntimeSpec::InTree`]: what
    /// [`AotCompiler::compile`] uses, so a script that exports it keeps working.
    pub fn from_env() -> Self {
        match std::env::var("PICO_AOT_RUNTIME_SPEC") {
            Ok(spec) if !spec.trim().is_empty() => Self::Entry(spec),
            _ => Self::InTree,
        }
    }
}

/// Emit the `pico-aot-runtime = { ... }` line for a generated Cargo.toml. `in_tree_path` is
/// [`RuntimeSpec::InTree`]'s path, relative to that manifest.
fn runtime_dep_line(runtime: &RuntimeSpec, in_tree_path: &str) -> String {
    match runtime {
        RuntimeSpec::InTree => format!("pico-aot-runtime = {{ path = \"{}\" }}\n", in_tree_path),
        RuntimeSpec::Entry(entry) => {
            let trimmed = entry.trim();
            // Sanity check: a valid Cargo dep fragment always contains `=`
            // (e.g. `git = "..."`, `path = "..."`). A value missing `=` will
            // produce a cryptic Cargo parse error at the consumer; warn now
            // so the cause is obvious.
            if !trimmed.contains('=') {
                eprintln!(
                    "warning: runtime spec {:?} does not look like a Cargo dep \
                     fragment (expected `key = value`); emitting anyway",
                    trimmed
                );
            }
            format!("pico-aot-runtime = {{ {} }}\n", trimmed)
        }
    }
}

struct LookupEntry {
    pc: u64,
    name: proc_macro2::Ident,
}

pub struct AotCompiler {
    program: ProgramInfo,
    config: AotConfig,
}

impl AotCompiler {
    pub fn new(program: ProgramInfo, config: AotConfig) -> Self {
        Self { program, config }
    }

    #[inline(always)]
    fn instruction_reg_write_mask(inst: &crate::types::Instruction) -> u32 {
        let reg = match inst.opcode {
            Opcode::ADD
            | Opcode::SUB
            | Opcode::XOR
            | Opcode::OR
            | Opcode::AND
            | Opcode::SLL
            | Opcode::SRL
            | Opcode::SRA
            | Opcode::SLT
            | Opcode::SLTU
            | Opcode::AUIPC
            | Opcode::LB
            | Opcode::LH
            | Opcode::LW
            | Opcode::LBU
            | Opcode::LHU
            | Opcode::LWU
            | Opcode::LD
            | Opcode::MUL
            | Opcode::MULH
            | Opcode::MULHU
            | Opcode::MULHSU
            | Opcode::DIV
            | Opcode::DIVU
            | Opcode::REM
            | Opcode::REMU
            | Opcode::ADDW
            | Opcode::SUBW
            | Opcode::SLLW
            | Opcode::SRLW
            | Opcode::SRAW
            | Opcode::MULW
            | Opcode::DIVW
            | Opcode::DIVUW
            | Opcode::REMW
            | Opcode::REMUW
            | Opcode::JAL
            | Opcode::JALR => Some(inst.op_a),
            Opcode::ECALL => Some(5),
            _ => None,
        };

        reg.map_or(0, |reg| 1u32 << reg)
    }

    #[inline(always)]
    fn instruction_non_register_global_lookup_base_max(
        opcode: Opcode,
        translated_global_lookup_base_max: usize,
    ) -> usize {
        match opcode {
            Opcode::LB
            | Opcode::LH
            | Opcode::LW
            | Opcode::LBU
            | Opcode::LHU
            | Opcode::LWU
            | Opcode::LD
            | Opcode::SB
            | Opcode::SH
            | Opcode::SW
            | Opcode::SD => 1,
            Opcode::ECALL => translated_global_lookup_base_max.saturating_sub(1),
            _ => 0,
        }
    }

    /// Main compilation entry point, against the runtime `PICO_AOT_RUNTIME_SPEC` names
    /// ([`RuntimeSpec::from_env`])
    pub fn compile(&self) -> Result<(), String> {
        self.compile_with(&RuntimeSpec::from_env())
    }

    /// Compile against the `pico-aot-runtime` that `runtime` names. Nothing here reads the
    /// environment for it, so a host may generate from any thread.
    pub fn compile_with(&self, runtime: &RuntimeSpec) -> Result<(), String> {
        self.compile_crates(runtime)
    }

    /// Compile to chunk crates + a dispatcher crate for parallel compilation
    fn compile_crates(&self, runtime: &RuntimeSpec) -> Result<(), String> {
        // Phase 1: Block Analysis
        let analyzer = BlockAnalyzer::new(&self.program);
        let leaders = analyzer.analyze();

        // Phase 2: Generate all blocks
        let blocks = if self.config.pure {
            self.generate_blocks_pure(&leaders)
        } else {
            self.generate_blocks(&leaders)?
        };

        if blocks.is_empty() {
            return Err("No blocks generated".to_string());
        }

        // Phase 3: Partition blocks into chunks
        let chunks = self.partition_into_chunks(blocks, &leaders)?;

        // Phase 4: Clean and create output directories
        let output_dir = &self.config.output_path;

        // Remove existing output directory to ensure clean generation
        if output_dir.exists() {
            fs::remove_dir_all(output_dir)
                .map_err(|e| format!("Failed to remove existing output directory: {}", e))?;
        }

        let chunks_dir = output_dir.join("chunks");
        fs::create_dir_all(&chunks_dir)
            .map_err(|e| format!("Failed to create output directory: {}", e))?;

        // Collect metrics if enabled
        let save_metrics = std::env::var("PICO_AOT_SAVE_METRICS")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        let mut chunk_metrics_vec = Vec::new();

        // Phase 5: Generate chunk crates
        for chunk in &chunks {
            let chunk_metric = if save_metrics {
                Some(self.collect_chunk_metrics(chunk)?)
            } else {
                None
            };
            self.write_chunk_crate(chunk, &chunks_dir, runtime)?;
            if let Some(metric) = chunk_metric {
                chunk_metrics_vec.push(metric);
            }
        }

        // Phase 6: Generate dispatch crate
        self.write_dispatch_crate(&chunks, output_dir, runtime)?;

        // Save metrics if enabled
        if save_metrics {
            let program_metrics = self.collect_program_metrics(&chunks)?;
            let computed_blocks_per_chunk =
                self.compute_blocks_per_chunk(program_metrics.total_blocks);
            let metrics = AotMetrics::new(
                program_metrics,
                chunks.len(),
                computed_blocks_per_chunk,
                chunk_metrics_vec,
            );
            let metrics_path = output_dir.join("metrics.json");
            metrics.save_to_file(&metrics_path)?;
            eprintln!("Metrics saved to: {}", metrics_path.display());
        }

        Ok(())
    }

    fn compute_blocks_per_chunk(&self, total_blocks: usize) -> usize {
        if total_blocks == 0 {
            return 1;
        }

        if let Some(target_chunks) = self.config.target_chunk_count {
            let target = target_chunks.max(1).min(total_blocks);
            return total_blocks.div_ceil(target);
        }

        if self.config.blocks_per_chunk > 0 {
            return self.config.blocks_per_chunk;
        }

        // Compute target chunks based on desired blocks per chunk
        let target_chunks_by_size = total_blocks.div_ceil(constants::DESIRED_BLOCKS_PER_CHUNK);

        // Use size-based target only (deterministic across machines), clamped to max_chunk_count
        let max_chunks = self.config.max_chunk_count.max(1);
        let mut target = target_chunks_by_size;
        if target > max_chunks {
            target = max_chunks;
        }
        let target = target.min(total_blocks).max(1);

        total_blocks.div_ceil(target)
    }

    /// Generate all basic blocks from the program
    fn generate_blocks(&self, leaders: &HashSet<u64>) -> Result<Vec<BlockInfo>, String> {
        let translator = InstructionTranslator::new();
        let mut blocks = Vec::new();

        let mut current_block_name = format_ident!("block_0x{:08x}", self.program.pc_start);
        let mut current_block_pc = self.program.pc_start;
        let mut current_block_tokens = proc_macro2::TokenStream::new();
        let mut active = false;
        let mut block_terminated = false;
        let mut force_new_block = false;
        let mut block_insn_count = 0u32;
        let mut block_has_terminal = false;
        let mut block_mem_rw_events: usize = 0;
        let mut block_non_register_global_lookup_base_max: usize = 0;
        let mut block_reg_write_mask: u32 = 0;
        let mut block_global_lookup_base_max: usize = 0;
        let mut block_leaf_rows = [0u32; LEAF_INSN_CHIPS];
        let max_block_instructions = self.config.max_block_instructions;

        for (idx, inst) in self.program.instructions.iter().enumerate() {
            let pc = self.program.pc_base + ((idx as u64) * 4);

            if leaders.contains(&pc) || force_new_block {
                if active {
                    // Finalize previous block
                    if !block_terminated {
                        if block_mem_rw_events > 0 {
                            current_block_tokens.extend(quote! {
                                emu.add_memory_rw_events(#block_mem_rw_events);
                            });
                        }
                        let next_block_name = format_ident!("block_0x{:08x}", pc);
                        current_block_tokens.extend(quote! {
                                emu.pc = #pc;
                                emu.check_chunk_boundary_fast();
                                if emu.should_yield() {
                                    return Ok(crate::NextStep::Dynamic(emu.pc));
                            }
                            Ok(crate::NextStep::Direct(#next_block_name))
                        });
                    }

                    blocks.push(BlockInfo {
                        pc: current_block_pc,
                        name: current_block_name.clone(),
                        insn_count: block_insn_count,
                        mem_rw_events: block_mem_rw_events,
                        non_register_global_lookup_base_max:
                            block_non_register_global_lookup_base_max,
                        reg_write_mask: block_reg_write_mask,
                        global_lookup_base_max: block_global_lookup_base_max,
                        code: Self::with_leaf_rows(&block_leaf_rows, &current_block_tokens),
                        is_terminal: block_has_terminal,
                    });
                }

                // Start new block
                current_block_name = format_ident!("block_0x{:08x}", pc);
                current_block_pc = pc;
                current_block_tokens = proc_macro2::TokenStream::new();
                active = true;
                block_terminated = false;
                block_insn_count = 0;
                force_new_block = false;
                block_has_terminal = false;
                block_mem_rw_events = 0;
                block_non_register_global_lookup_base_max = 0;
                block_reg_write_mask = 0;
                block_global_lookup_base_max = 0;
                block_leaf_rows = [0; LEAF_INSN_CHIPS];
            }

            if active {
                let (body, is_terminal, mem_rw_events, global_lookup_base_max) =
                    translator.translate(pc, inst, leaders);
                let inst_reg_write_mask = Self::instruction_reg_write_mask(inst);
                let inst_non_register_global_lookup_base_max =
                    Self::instruction_non_register_global_lookup_base_max(
                        inst.opcode,
                        global_lookup_base_max,
                    );

                if is_terminal {
                    let total_events = block_mem_rw_events + mem_rw_events;
                    let total_non_register_global_lookup_base =
                        block_non_register_global_lookup_base_max
                            + inst_non_register_global_lookup_base_max;
                    let total_reg_write_mask = block_reg_write_mask | inst_reg_write_mask;
                    let total_global_lookup_base = total_non_register_global_lookup_base
                        + (total_reg_write_mask.count_ones() as usize);
                    if total_events > 0 {
                        current_block_tokens.extend(quote! {
                            emu.add_memory_rw_events(#total_events);
                        });
                    }
                    current_block_tokens.extend(body);
                    block_mem_rw_events = total_events;
                    block_non_register_global_lookup_base_max =
                        total_non_register_global_lookup_base;
                    block_reg_write_mask = total_reg_write_mask;
                    block_global_lookup_base_max = total_global_lookup_base;
                } else {
                    current_block_tokens.extend(body);
                    block_mem_rw_events += mem_rw_events;
                    block_non_register_global_lookup_base_max +=
                        inst_non_register_global_lookup_base_max;
                    block_reg_write_mask |= inst_reg_write_mask;
                    block_global_lookup_base_max = block_non_register_global_lookup_base_max
                        + (block_reg_write_mask.count_ones() as usize);
                }
                block_terminated = is_terminal;
                block_has_terminal = is_terminal;
                block_insn_count += 1;
                add_insn_leaf_rows(&mut block_leaf_rows, to_vm_opcode(inst.opcode));

                if !is_terminal {
                    if max_block_instructions > 0
                        && block_insn_count >= max_block_instructions
                        && !force_new_block
                    {
                        force_new_block = true;
                    }
                } else {
                    // Terminate block immediately so subsequent instructions
                    // do not get appended after a return.
                    blocks.push(BlockInfo {
                        pc: current_block_pc,
                        name: current_block_name.clone(),
                        insn_count: block_insn_count,
                        mem_rw_events: block_mem_rw_events,
                        non_register_global_lookup_base_max:
                            block_non_register_global_lookup_base_max,
                        reg_write_mask: block_reg_write_mask,
                        global_lookup_base_max: block_global_lookup_base_max,
                        code: Self::with_leaf_rows(&block_leaf_rows, &current_block_tokens),
                        is_terminal: block_has_terminal,
                    });
                    active = false;
                    block_terminated = false;
                    block_insn_count = 0;
                    current_block_tokens = proc_macro2::TokenStream::new();
                    force_new_block = true;
                    block_has_terminal = false;
                    block_mem_rw_events = 0;
                    block_non_register_global_lookup_base_max = 0;
                    block_reg_write_mask = 0;
                    block_global_lookup_base_max = 0;
                    block_leaf_rows = [0; LEAF_INSN_CHIPS];
                }
            }
        }

        // Finalize last block
        if active {
            if !block_terminated {
                if block_mem_rw_events > 0 {
                    current_block_tokens.extend(quote! {
                        emu.add_memory_rw_events(#block_mem_rw_events);
                    });
                }
                current_block_tokens.extend(quote! {
                    Ok(crate::NextStep::Halt)
                });
            }

            blocks.push(BlockInfo {
                pc: current_block_pc,
                name: current_block_name,
                insn_count: block_insn_count,
                mem_rw_events: block_mem_rw_events,
                non_register_global_lookup_base_max: block_non_register_global_lookup_base_max,
                reg_write_mask: block_reg_write_mask,
                global_lookup_base_max: block_global_lookup_base_max,
                code: Self::with_leaf_rows(&block_leaf_rows, &current_block_tokens),
                is_terminal: block_has_terminal,
            });
        }

        Ok(blocks)
    }

    /// [`Self::generate_blocks`] for pure mode: the same block boundaries, with code from
    /// [`crate::pure_translator`] and no event accounting.
    fn generate_blocks_pure(&self, leaders: &HashSet<u64>) -> Vec<BlockInfo> {
        let block =
            |pc: u64, insn_count: u32, code: proc_macro2::TokenStream, terminal: bool| BlockInfo {
                pc,
                name: format_ident!("block_0x{:08x}", pc),
                insn_count,
                mem_rw_events: 0,
                non_register_global_lookup_base_max: 0,
                reg_write_mask: 0,
                global_lookup_base_max: 0,
                code,
                is_terminal: terminal,
            };
        let max_block_instructions = self.config.max_block_instructions;
        let mut blocks = Vec::new();
        // (start pc, instructions so far, code so far) of the block being built.
        let mut open: Option<(u64, u32, proc_macro2::TokenStream)> = None;
        let mut force_new_block = false;

        for (idx, inst) in self.program.instructions.iter().enumerate() {
            let pc = self.program.pc_base + ((idx as u64) * 4);
            if leaders.contains(&pc) || force_new_block {
                if let Some((start, count, mut code)) = open.take() {
                    let next = format_ident!("block_0x{:08x}", pc);
                    code.extend(quote! { Ok(crate::NextStep::Direct(#next)) });
                    blocks.push(block(start, count, code, false));
                }
                open = Some((pc, 0, proc_macro2::TokenStream::new()));
                force_new_block = false;
            }
            let Some((start, count, code)) = open.as_mut() else {
                continue;
            };
            let (body, terminal) = crate::pure_translator::translate(pc, inst, leaders);
            code.extend(body);
            *count += 1;
            if terminal {
                let (start, count, code) = (*start, *count, std::mem::take(code));
                blocks.push(block(start, count, code, true));
                open = None;
                force_new_block = true;
            } else if max_block_instructions > 0 && *count >= max_block_instructions {
                force_new_block = true;
            }
        }
        if let Some((start, count, mut code)) = open {
            code.extend(quote! { Ok(crate::NextStep::Halt) });
            blocks.push(block(start, count, code, false));
        }
        blocks
    }

    /// `code` behind the statements that add its rows on the per-instruction chips, one per
    /// chip it touches. They lead the block so that a superblock, which keeps each inner
    /// block's statements up to its pc assignment, keeps them too.
    fn with_leaf_rows(
        rows: &[u32; LEAF_INSN_CHIPS],
        code: &proc_macro2::TokenStream,
    ) -> proc_macro2::TokenStream {
        let mut tokens = proc_macro2::TokenStream::new();
        for (chip, &count) in rows.iter().enumerate() {
            if count > 0 {
                tokens.extend(quote! { emu.add_leaf_rows(#chip, #count); });
            }
        }
        tokens.extend(code.clone());
        tokens
    }

    /// Partition blocks into chunks using CFG-aware segmentation
    fn partition_into_chunks(
        &self,
        blocks: Vec<BlockInfo>,
        leaders: &HashSet<u64>,
    ) -> Result<Vec<ChunkInfo>, String> {
        if blocks.is_empty() {
            return Ok(Vec::new());
        }

        let blocks_per_chunk = self.compute_blocks_per_chunk(blocks.len());
        let max_chunks = self.config.max_chunk_count.max(1);

        // Extract block PCs for CFG analysis
        let block_pcs: Vec<u64> = blocks.iter().map(|b| b.pc).collect();

        // Perform CFG analysis
        let cfg = CfgAnalysis::analyze(&self.program, &block_pcs, leaders);

        self.greedy_segment(&blocks, &cfg, blocks_per_chunk, max_chunks)
    }

    /// Greedy segmentation: each chunk ends at the boundary in its size window with the lowest
    /// CFG cut penalty
    fn greedy_segment(
        &self,
        segment_blocks: &[BlockInfo],
        cfg: &CfgAnalysis,
        desired_blocks_per_chunk: usize,
        max_chunks_for_segment: usize,
    ) -> Result<Vec<ChunkInfo>, String> {
        if segment_blocks.is_empty() {
            return Ok(Vec::new());
        }

        let mut chunks = Vec::new();
        let mut start = 0;

        while start < segment_blocks.len() {
            let remaining_blocks = segment_blocks.len() - start;
            let remaining_chunk_slots = max_chunks_for_segment.saturating_sub(chunks.len()).max(1);

            // Enforce chunk budget: avoid choosing chunks so small that we'd exceed max chunks.
            let budget_min = remaining_blocks.div_ceil(remaining_chunk_slots);

            // Compute window: [CFG_CHUNK_MIN_SIZE_MULTIPLIER * desired, CFG_CHUNK_MAX_SIZE_MULTIPLIER * desired], but never smaller than budget_min.
            let mut min_size = ((desired_blocks_per_chunk as f64)
                * constants::CFG_CHUNK_MIN_SIZE_MULTIPLIER) as usize;
            min_size = min_size.max(1).max(budget_min).min(remaining_blocks);

            let mut max_size = ((desired_blocks_per_chunk as f64)
                * constants::CFG_CHUNK_MAX_SIZE_MULTIPLIER) as usize;
            max_size = max_size.max(min_size).min(remaining_blocks);

            // Determine search window
            let window_start = start + min_size - 1;
            let window_end = start + max_size;

            if window_start >= segment_blocks.len() {
                // Remaining blocks are fewer than min_size, put them all in one chunk
                let end = segment_blocks.len();
                let chunk_blocks: Vec<BlockInfo> = segment_blocks[start..end].to_vec();
                let pc_min = chunk_blocks.iter().map(|b| b.pc).min().unwrap();
                let pc_max = chunk_blocks.iter().map(|b| b.pc).max().unwrap();
                chunks.push(ChunkInfo {
                    chunk_idx: chunks.len(),
                    blocks: chunk_blocks,
                    pc_min,
                    pc_max,
                });
                break;
            }

            // Find boundary with minimum cut penalty in window.
            let mut best_boundary = window_start;
            let mut best_penalty = if window_start < cfg.num_boundaries() {
                cfg.cut_penalty(window_start)
            } else {
                u32::MAX
            };

            for boundary in window_start..window_end {
                if boundary < cfg.num_boundaries() {
                    let penalty = cfg.cut_penalty(boundary);
                    if penalty < best_penalty {
                        best_penalty = penalty;
                        best_boundary = boundary;
                    }
                }
            }

            // Create chunk from start to best_boundary (inclusive)
            let end = best_boundary + 1;
            let chunk_blocks: Vec<BlockInfo> = segment_blocks[start..end].to_vec();
            let pc_min = chunk_blocks.iter().map(|b| b.pc).min().unwrap();
            let pc_max = chunk_blocks.iter().map(|b| b.pc).max().unwrap();
            chunks.push(ChunkInfo {
                chunk_idx: chunks.len(),
                blocks: chunk_blocks,
                pc_min,
                pc_max,
            });
            start = end;
        }

        Ok(chunks)
    }

    /// Write a chunk crate with block functions and per-chunk lookup
    fn write_chunk_crate(
        &self,
        chunk: &ChunkInfo,
        chunks_dir: &std::path::Path,
        runtime: &RuntimeSpec,
    ) -> Result<(), String> {
        let crate_dir = chunks_dir.join(format!("chunk_{:03}", chunk.chunk_idx));
        let src_dir = crate_dir.join("src");
        fs::create_dir_all(&src_dir)
            .map_err(|e| format!("Failed to create chunk dir {}: {}", chunk.chunk_idx, e))?;

        let crate_name = format!("{}-{:03}", self.chunk_crate_prefix(), chunk.chunk_idx);
        let cargo_toml = format!(
            "[package]\nname = \"{}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{}",
            crate_name,
            self.dep_line(runtime, "../../../"),
        );
        fs::write(crate_dir.join("Cargo.toml"), cargo_toml).map_err(|e| {
            format!(
                "Failed to write Cargo.toml for chunk {}: {}",
                chunk.chunk_idx, e
            )
        })?;

        let chunk_file = src_dir.join("lib.rs");

        let pc_min = chunk.pc_min;
        let pc_max = chunk.pc_max;
        let lookup_entries: Vec<LookupEntry> = chunk
            .blocks
            .iter()
            .map(|block| LookupEntry {
                pc: block.pc,
                name: block.name.clone(),
            })
            .collect();

        let n = lookup_entries.len();

        // Analyze chunk and generate appropriate lookup strategy
        let (lookup_body, lookup_inline_attr, _strategy) =
            self.generate_chunk_lookup(&lookup_entries, pc_min, pc_max, n)?;

        if self.config.pure {
            let block_functions = chunk.blocks.iter().map(|block| {
                let name = &block.name;
                let insn_count = u64::from(block.insn_count);
                let code = &block.code;
                let inline_attr = self.get_inline_attr(block.insn_count);
                quote! {
                    #inline_attr
                    pub fn #name(emu: &mut PureState) -> Result<crate::NextStep, Fault> {
                        emu.insn_count += #insn_count;
                        #code
                    }
                }
            });
            let chunk_code = quote! {
                // AUTO-GENERATED by AOT compiler (pure mode) - Chunk
                // DO NOT EDIT MANUALLY
                #![allow(unused_braces, clippy::all)]
                pub use pico_aot_pure::{BlockFn, PureState, Step as NextStep};
                #[allow(unused_imports)]
                use pico_aot_pure::{Fault, FAULT_BREAKPOINT, FAULT_ILLEGAL};

                pub const PC_MIN: u64 = #pc_min;
                pub const PC_MAX: u64 = #pc_max;

                #lookup_inline_attr
                pub fn lookup(pc: u64) -> Option<BlockFn> {
                    #lookup_body
                }

                #(#block_functions)*
            };
            return self.write_chunk_file(chunk, chunk_code, &chunk_file);
        }

        // Generate block functions with selective inlining
        let block_functions: Vec<_> = chunk
            .blocks
            .iter()
            .map(|block| {
                let name = &block.name;
                let insn_count = block.insn_count;
                let mem_rw_events = block.mem_rw_events;
                let non_register_global_lookup_base_max = block.non_register_global_lookup_base_max;
                let reg_write_mask = block.reg_write_mask;
                let code = &block.code;
                let inline_attr = self.get_inline_attr(insn_count);

                quote! {
                    #inline_attr
                    pub fn #name(emu: &mut AotEmulatorCore) -> Result<crate::NextStep, String> {
                        const BLOCK_INSNS: u32 = #insn_count;
                        const BLOCK_MEM_RW_EVENTS: usize = #mem_rw_events;
                        const BLOCK_NON_REGISTER_GLOBAL_LOOKUP_BASE_MAX: usize =
                            #non_register_global_lookup_base_max;
                        const BLOCK_REG_WRITE_MASK: u32 = #reg_write_mask;
                        if !emu.can_fit_block(
                            BLOCK_INSNS,
                            BLOCK_MEM_RW_EVENTS,
                            BLOCK_NON_REGISTER_GLOBAL_LOOKUP_BASE_MAX,
                            BLOCK_REG_WRITE_MASK,
                        ) {
                            return emu.interpret_from_current_pc();
                        }
                        // The `_no_count` helpers assume constrained mode; unconstrained mode is
                        // rare, so it runs in the interpreter.
                        if emu.is_unconstrained_mode() {
                            return emu.interpret_from_current_pc();
                        }
                        // Read once for the block and handed to every helper: see the
                        // instruction translator's `# Events`.
                        #[allow(unused_variables)]
                        let emitting = emu.is_emitting();
                        #code
                    }
                }
            })
            .collect();

        let chunk_code = quote! {
            // AUTO-GENERATED by AOT compiler - Chunk
            // DO NOT EDIT MANUALLY
            pub use pico_aot_runtime::{AotEmulatorCore, BlockClock, BlockFn, NextStep};

            pub const PC_MIN: u64 = #pc_min;
            pub const PC_MAX: u64 = #pc_max;

            #lookup_inline_attr
            pub fn lookup(pc: u64) -> Option<BlockFn> {
                #lookup_body
            }

            #(#block_functions)*
        };

        self.write_chunk_file(chunk, chunk_code, &chunk_file)
    }

    /// Parses a chunk's code, turns a direct jump to a block of another chunk into a dynamic one,
    /// and writes it.
    fn write_chunk_file(
        &self,
        chunk: &ChunkInfo,
        chunk_code: proc_macro2::TokenStream,
        chunk_file: &std::path::Path,
    ) -> Result<(), String> {
        let mut syntax_tree = syn::parse2(chunk_code)
            .map_err(|e| format!("Parse error in chunk {}: {}", chunk.chunk_idx, e))?;

        let allowed_blocks = chunk.blocks.iter().map(|b| b.name.to_string()).collect();
        let mut rewriter = CrossChunkDirectRewriter { allowed_blocks };
        rewriter.visit_file_mut(&mut syntax_tree);

        let formatted = prettyplease::unparse(&syntax_tree);
        fs::write(chunk_file, &formatted)
            .map_err(|e| format!("Failed to write chunk {}: {}", chunk.chunk_idx, e))?;

        Ok(())
    }

    /// The runtime dependency line of a generated manifest `up` directories below the Pico root:
    /// `pico-aot-runtime`, or in pure mode `pico-aot-pure`, which a [`RuntimeSpec::Entry`] then
    /// names.
    fn dep_line(&self, runtime: &RuntimeSpec, up: &str) -> String {
        if !self.config.pure {
            return runtime_dep_line(runtime, &format!("{up}aot-runtime"));
        }
        match runtime {
            RuntimeSpec::InTree => format!("pico-aot-pure = {{ path = \"{up}aot-pure\" }}\n"),
            RuntimeSpec::Entry(entry) => format!("pico-aot-pure = {{ {} }}\n", entry.trim()),
        }
    }

    /// Chunk crates' package-name prefix; pure mode names them per ELF, apart from the default
    /// mode's.
    fn chunk_crate_prefix(&self) -> String {
        if self.config.pure {
            format!(
                "pico-aot-pure-chunk-{}",
                &hex(&self.program.elf_sha256)[..16]
            )
        } else {
            "pico-aot-chunk".to_string()
        }
    }

    /// Write a dispatch crate that links all chunk crates
    fn write_dispatch_crate(
        &self,
        chunks: &[ChunkInfo],
        output_dir: &std::path::Path,
        runtime: &RuntimeSpec,
    ) -> Result<(), String> {
        let src_dir = output_dir.join("src");
        fs::create_dir_all(&src_dir)
            .map_err(|e| format!("Failed to create dispatch src dir: {}", e))?;

        let chunk_deps: Vec<String> = chunks
            .iter()
            .map(|c| {
                format!(
                    "{}-{:03} = {{ path = \"chunks/chunk_{:03}\" }}",
                    self.chunk_crate_prefix(),
                    c.chunk_idx,
                    c.chunk_idx
                )
            })
            .collect();

        let features = if self.config.pure {
            // `entry` exports the program under `pico_aot_pure::ENTRY_SYMBOL`, for a dynamic
            // library; a static build leaves it off, so two programs can link into one binary.
            "entry = []\n"
        } else {
            "bigint-rug = [\"pico-aot-runtime/bigint-rug\"]\nmmap-memory = [\"pico-aot-runtime/mmap-memory\"]\n"
        };
        let cargo_toml = format!(
            "[package]\nname = \"{}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{}{}\n\n[features]\n{}",
            if self.config.pure {
                pure_dispatch_package(&self.program.elf_sha256)
            } else {
                "pico-aot-dispatch".to_string()
            },
            self.dep_line(runtime, "../"),
            chunk_deps.join("\n"),
            features,
        );
        fs::write(output_dir.join("Cargo.toml"), cargo_toml)
            .map_err(|e| format!("Failed to write dispatch Cargo.toml: {}", e))?;

        // Build chunk descriptor table
        let mut chunk_descs = Vec::with_capacity(chunks.len());
        let mut global_pc_min = u64::MAX;
        let mut global_pc_max = 0u64;

        for c in chunks.iter() {
            let chunk_crate = format_ident!(
                "{}_{:03}",
                self.chunk_crate_prefix().replace('-', "_"),
                c.chunk_idx
            );
            let pc_min = c.pc_min;
            let pc_max = c.pc_max;
            chunk_descs.push(quote! {
                ChunkDesc { pc_min: #pc_min, pc_max: #pc_max, lookup: #chunk_crate::lookup },
            });
            if pc_min < global_pc_min {
                global_pc_min = pc_min;
            }
            if pc_max > global_pc_max {
                global_pc_max = pc_max;
            }
        }

        // Generate page hint table
        let page_hint_code = if chunks.is_empty() {
            quote! {}
        } else {
            let span = global_pc_max
                .saturating_sub(global_pc_min)
                .saturating_add(4);
            let chunk_count = chunks.len() as f64;
            let target_chunks_per_page = constants::PAGE_HINT_TARGET_CHUNKS_PER_PAGE;

            // Calculate adaptive page size
            let page_size_f64 = (target_chunks_per_page * span as f64) / chunk_count;
            let mut page_size = page_size_f64 as u64;

            // Clamp to [PAGE_HINT_MIN_SIZE, PAGE_HINT_MAX_SIZE]
            page_size = page_size.max(u64::from(constants::PAGE_HINT_MIN_SIZE));
            page_size = page_size.min(u64::from(constants::PAGE_HINT_MAX_SIZE));

            // Round to power-of-two
            let page_shift_val = if page_size > 0 {
                let mut shift = 0u32;
                let mut size = page_size;
                while size > 1 {
                    size >>= 1;
                    shift += 1;
                }
                shift
            } else {
                constants::PAGE_HINT_DEFAULT_SHIFT
            };
            let actual_page_size = 1u64 << page_shift_val;

            // Build page hint table
            let num_pages = usize::try_from(span.div_ceil(actual_page_size)).unwrap();
            let mut page_hints = Vec::with_capacity(num_pages);

            for page_idx in 0..num_pages {
                let page_start = global_pc_min + ((page_idx as u64) * actual_page_size);
                // Find the first chunk that could contain this page
                let mut lo = 0usize;
                let mut hi = chunks.len();
                while lo < hi {
                    let mid = lo + (hi - lo) / 2;
                    if chunks[mid].pc_max < page_start {
                        lo = mid + 1;
                    } else {
                        hi = mid;
                    }
                }
                let hint_idx = if lo < chunks.len() {
                    lo as u16
                } else {
                    chunks.len().saturating_sub(1) as u16
                };
                page_hints.push(hint_idx);
            }

            let page_hint_entries: Vec<_> = page_hints
                .iter()
                .map(|&hint| {
                    quote! { #hint, }
                })
                .collect();

            let page_hint_table = quote! {
                const PAGE_HINT: [u16; #num_pages] = [
                    #(#page_hint_entries)*
                ];
            };

            quote! {
                const GLOBAL_PC_MIN: u64 = #global_pc_min;
                const PAGE_SHIFT: u32 = #page_shift_val;
                #page_hint_table
            }
        };

        let lookup_block_body = if chunks.is_empty() {
            quote! {
                let _ = pc;
                None
            }
        } else {
            quote! {
                if pc < GLOBAL_PC_MIN {
                    return None;
                }

                let off = pc - GLOBAL_PC_MIN;
                let page = (off >> PAGE_SHIFT) as usize;

                let mut idx = if page < PAGE_HINT.len() {
                    PAGE_HINT[page] as usize
                } else {
                    CHUNKS.len().saturating_sub(1)
                };

                // Forward scan from hint (usually 0-2 increments)
                while idx < CHUNKS.len() && pc > CHUNKS[idx].pc_max {
                    idx += 1;
                }

                if idx == CHUNKS.len() {
                    return None;
                }

                let c = &CHUNKS[idx];
                if pc < c.pc_min {
                    return None;
                }

                (c.lookup)(pc)
            }
        };

        if self.config.pure {
            let elf_sha256 = self.program.elf_sha256;
            let elf_sha256_hex = hex(&elf_sha256);
            let pure_doc = format!(
                " The pure-mode program generated from the ELF with SHA-256 `{elf_sha256_hex}`."
            );
            let elf_sha256 = elf_sha256.iter();
            let dispatch_code = quote! {
                // AUTO-GENERATED by AOT compiler (pure mode) - Dispatch crate
                // DO NOT EDIT MANUALLY
                pub use pico_aot_pure::{PureProgram, PureState};
                use pico_aot_pure::{BlockFn, ABI_VERSION};

                #[doc = #pure_doc]
                pub static PURE: PureProgram = PureProgram {
                    abi_version: ABI_VERSION,
                    source_fingerprint: pico_aot_pure::SOURCE_FINGERPRINT,
                    elf_sha256: [#(#elf_sha256),*],
                    run: run,
                };

                /// [`PureProgram::run`]: runs `state` from `pc` to the guest's halt.
                ///
                /// # Safety
                ///
                /// `state` is a valid, exclusive [`PureState`] whose memory and callbacks the
                /// host set up.
                unsafe extern "C" fn run(state: *mut PureState, pc: u64) -> u32 {
                    pico_aot_pure::run(unsafe { &mut *state }, pc, lookup_block)
                }

                /// The program, under `pico_aot_pure::ENTRY_SYMBOL`, for a host loading this
                /// crate as a dynamic library.
                #[cfg(feature = "entry")]
                #[no_mangle]
                pub extern "C" fn pico_pure_program() -> *const PureProgram {
                    &PURE
                }

                type ChunkLookupFn = fn(u64) -> Option<BlockFn>;

                #[repr(C)]
                struct ChunkDesc {
                    pc_min: u64,
                    pc_max: u64,
                    lookup: ChunkLookupFn,
                }

                const CHUNKS: &[ChunkDesc] = &[
                    #(#chunk_descs)*
                ];

                #page_hint_code

                pub fn lookup_block(pc: u64) -> Option<BlockFn> {
                    #lookup_block_body
                }
            };
            let syntax_tree = syn::parse2(dispatch_code)
                .map_err(|e| format!("Parse error in dispatch crate: {}", e))?;
            let formatted = prettyplease::unparse(&syntax_tree);
            return fs::write(src_dir.join("lib.rs"), formatted)
                .map_err(|e| format!("Failed to write dispatch lib.rs: {}", e));
        }

        let elf_sha256 = self.program.elf_sha256;
        let elf_sha256_hex = hex(&elf_sha256);
        let aot_doc = format!(
            " This crate's program: the code generated from the ELF with SHA-256 `{elf_sha256_hex}`."
        );
        let elf_sha256 = elf_sha256.iter();
        let codegen_stamp = CODEGEN_STAMP;

        let dispatch_code = quote! {
            // AUTO-GENERATED by AOT compiler - Dispatch crate
            // DO NOT EDIT MANUALLY

            pub use pico_aot_runtime::AotEmulatorCore;
            use pico_aot_runtime::{set_lookup_block_fn, AotProgram, BlockFn};

            #[doc = #aot_doc]
            pub static AOT: AotProgram =
                AotProgram::stamped([#(#elf_sha256),*], #codegen_stamp, run_aot);

            pub fn run_aot(emu: &mut AotEmulatorCore) -> Result<(), String> {
                set_lookup_block_fn(lookup_block);
                emu.run_blocks(lookup_block)
            }

            type ChunkLookupFn = fn(u64) -> Option<BlockFn>;

            #[repr(C)]
            struct ChunkDesc {
                pc_min: u64,
                pc_max: u64,
                lookup: ChunkLookupFn,
            }

            const CHUNKS: &[ChunkDesc] = &[
                #(#chunk_descs)*
            ];

            #page_hint_code

            fn lookup_block(pc: u64) -> Option<BlockFn> {
                #lookup_block_body
            }
        };

        let syntax_tree = syn::parse2(dispatch_code)
            .map_err(|e| format!("Parse error in dispatch crate: {}", e))?;

        let formatted = prettyplease::unparse(&syntax_tree);
        fs::write(src_dir.join("lib.rs"), formatted)
            .map_err(|e| format!("Failed to write dispatch lib.rs: {}", e))?;

        Ok(())
    }

    /// Generate chunk lookup with hybrid strategy selection
    /// Returns (lookup_body, inline_attr, strategy)
    fn generate_chunk_lookup(
        &self,
        entries: &[LookupEntry],
        pc_min: u64,
        pc_max: u64,
        n: usize,
    ) -> Result<
        (
            proc_macro2::TokenStream,
            proc_macro2::TokenStream,
            LookupStrategy,
        ),
        String,
    > {
        // Strategy 1: Small match (n <= LOOKUP_INLINE_THRESHOLD)
        if n <= constants::LOOKUP_INLINE_THRESHOLD {
            let mut match_arms = Vec::with_capacity(n);
            for entry in entries {
                let block_name = &entry.name;
                let pc = entry.pc;
                match_arms.push(quote! {
                    #pc => Some(#block_name),
                });
            }
            let lookup_body = quote! {
                match pc {
                    #(#match_arms)*
                    _ => None,
                }
            };
            let inline_attr = self.get_lookup_inline_attr(n);
            return Ok((lookup_body, inline_attr, LookupStrategy::SmallMatch));
        }

        // Analyze chunk for dense index vs run table
        let range_words = usize::try_from(((pc_max.saturating_sub(pc_min)) >> 2).saturating_add(1))
            .map_err(|_| "chunk lookup range overflow".to_string())?;
        let density = if range_words > 0 {
            n as f64 / range_words as f64
        } else {
            0.0
        };

        // Strategy 2: Dense index table
        if range_words <= constants::DENSE_INDEX_MAX_RANGE_WORDS
            && range_words <= constants::DENSE_INDEX_MAX_RATIO * n
            && density >= constants::DENSE_INDEX_MIN_DENSITY
        {
            // Build function array
            let fn_array: Vec<_> = entries.iter().map(|entry| &entry.name).collect();

            // Build index array: IDX[word_offset] = fn_index + 1 (0 = not found)
            let mut idx_array = vec![0u16; range_words];
            for (fn_idx, entry) in entries.iter().enumerate() {
                let word_offset = usize::try_from((entry.pc - pc_min) >> 2)
                    .map_err(|_| "chunk dense lookup offset overflow".to_string())?;
                if word_offset < range_words {
                    idx_array[word_offset] = (fn_idx + 1) as u16;
                }
            }

            let fn_entries: Vec<_> = fn_array.iter().map(|name| quote! { #name, }).collect();
            let idx_entries: Vec<_> = idx_array.iter().map(|&idx| quote! { #idx, }).collect();

            let lookup_body = quote! {
                const FN: [BlockFn; #n] = [
                    #(#fn_entries)*
                ];
                const IDX: [u16; #range_words] = [
                    #(#idx_entries)*
                ];

                if !(#pc_min..=#pc_max).contains(&pc) {
                    return None;
                }
                let word_offset = match usize::try_from((pc - #pc_min) >> 2) {
                    Ok(word_offset) => word_offset,
                    Err(_) => return None,
                };
                if word_offset >= IDX.len() {
                    return None;
                }
                let idx_val = IDX[word_offset];
                if idx_val == 0 {
                    None
                } else {
                    Some(FN[(idx_val - 1) as usize])
                }
            };
            let inline_attr = quote! {}; // No inline for dense index
            return Ok((lookup_body, inline_attr, LookupStrategy::DenseIndex));
        }

        // Strategy 3: Run table
        // Detect contiguous runs (PC sequences where next PC = prev PC + 4)
        let mut runs = Vec::new();
        let mut current_run_start = 0;
        let mut current_run_len = 1;

        for i in 1..entries.len() {
            let prev_pc = entries[i - 1].pc;
            let curr_pc = entries[i].pc;
            if curr_pc == prev_pc + 4 {
                current_run_len += 1;
            } else {
                // End of current run
                if current_run_len > 0 {
                    runs.push((current_run_start, current_run_len));
                }
                current_run_start = i;
                current_run_len = 1;
            }
        }
        // Add final run
        if current_run_len > 0 {
            runs.push((current_run_start, current_run_len));
        }

        // Build function array
        let fn_array: Vec<_> = entries.iter().map(|entry| &entry.name).collect();

        // Build runs array: (start_word, len, fn_offset)
        let run_entries: Vec<_> = runs
            .iter()
            .map(|&(start_idx, len)| {
                let start_pc = entries[start_idx].pc;
                let start_word = run_table_word_u32((start_pc - pc_min) >> 2);
                quote! {
                    Run { start_word: #start_word, len: #len as u16, fn_offset: #start_idx as u16 },
                }
            })
            .collect();

        let fn_entries: Vec<_> = fn_array.iter().map(|name| quote! { #name, }).collect();
        let num_runs = runs.len();

        let lookup_body = quote! {
            const FN: [BlockFn; #n] = [
                #(#fn_entries)*
            ];
            #[inline(always)]
            fn run_table_word_u32(word_offset: u64) -> u32 {
                u32::try_from(word_offset).expect("run-table word offset exceeds u32")
            }
            #[repr(C)]
            struct Run {
                start_word: u32,
                len: u16,
                fn_offset: u16,
            }
            const RUNS: [Run; #num_runs] = [
                #(#run_entries)*
            ];

            if !(#pc_min..=#pc_max).contains(&pc) {
                return None;
            }
            let word_offset = run_table_word_u32((pc - #pc_min) >> 2);

            // Binary search runs
            let mut lo = 0usize;
            let mut hi = RUNS.len();
            while lo < hi {
                let mid = (lo + hi) >> 1;
                let run = &RUNS[mid];
                if word_offset < run.start_word {
                    hi = mid;
                } else if word_offset >= run.start_word + run.len as u32 {
                    lo = mid + 1;
                } else {
                    // Found matching run
                    let fn_idx = (run.fn_offset as usize) + (word_offset - run.start_word) as usize;
                    return Some(FN[fn_idx]);
                }
            }
            None
        };
        let inline_attr = quote! {}; // No inline for run table
        Ok((lookup_body, inline_attr, LookupStrategy::RunTable))
    }

    /// Get inline attribute based on block instruction count
    fn get_inline_attr(&self, insn_count: u32) -> proc_macro2::TokenStream {
        if insn_count <= constants::DEFAULT_SMALL_BLOCK_THRESHOLD {
            quote! { #[inline(always)] }
        } else if insn_count <= constants::DEFAULT_MEDIUM_BLOCK_THRESHOLD {
            quote! { #[inline] }
        } else {
            quote! { #[inline(never)] }
        }
    }

    /// Get inline attribute for chunk lookup() function based on block count
    /// Only inline small chunks to prevent cross-crate inlining explosion in dispatch crate
    fn get_lookup_inline_attr(&self, block_count: usize) -> proc_macro2::TokenStream {
        if block_count <= constants::LOOKUP_INLINE_THRESHOLD {
            quote! { #[inline(always)] }
        } else {
            quote! {}
        }
    }

    /// Collect program-level metrics
    fn collect_program_metrics(&self, chunks: &[ChunkInfo]) -> Result<ProgramMetrics, String> {
        let total_blocks = chunks.iter().map(|c| c.blocks.len()).sum();
        let mut total_instructions = 0usize;
        let mut block_insn_counts = Vec::new();

        for chunk in chunks {
            for block in &chunk.blocks {
                total_instructions += block.insn_count as usize;
                block_insn_counts.push(block.insn_count);
            }
        }

        let pc_min = chunks.iter().map(|c| c.pc_min).min().unwrap_or(0);
        let pc_max = chunks.iter().map(|c| c.pc_max).max().unwrap_or(0);
        let pc_span = pc_max.saturating_sub(pc_min).saturating_add(4);

        let avg_instructions_per_block = if total_blocks > 0 {
            total_instructions as f64 / total_blocks as f64
        } else {
            0.0
        };

        let block_stats = compute_block_instruction_stats(&block_insn_counts);

        Ok(ProgramMetrics {
            total_instructions,
            total_blocks,
            pc_min,
            pc_max,
            pc_span,
            avg_instructions_per_block,
            min_instructions_per_block: block_stats.min,
            max_instructions_per_block: block_stats.max,
            median_instructions_per_block: block_stats.median,
            p90_instructions_per_block: block_stats.p90,
            stddev_instructions_per_block: block_stats.stddev,
        })
    }

    /// Collect metrics for a single chunk
    fn collect_chunk_metrics(&self, chunk: &ChunkInfo) -> Result<ChunkMetrics, String> {
        let pc_min = chunk.pc_min;
        let pc_max = chunk.pc_max;
        let pc_span = pc_max.saturating_sub(pc_min).saturating_add(4);
        let n = chunk.blocks.len();
        let range_words = ((pc_max.saturating_sub(pc_min)) >> 2).saturating_add(1) as usize;
        let density = if range_words > 0 {
            n as f64 / range_words as f64
        } else {
            0.0
        };

        // Determine lookup strategy (same logic as generate_chunk_lookup)
        let lookup_strategy = if n <= constants::LOOKUP_INLINE_THRESHOLD {
            LookupStrategy::SmallMatch
        } else if range_words <= constants::DENSE_INDEX_MAX_RANGE_WORDS
            && range_words <= constants::DENSE_INDEX_MAX_RATIO * n
            && density >= constants::DENSE_INDEX_MIN_DENSITY
        {
            LookupStrategy::DenseIndex
        } else {
            LookupStrategy::RunTable
        };

        let mut block_insn_counts = Vec::new();
        let mut total_instructions: u32 = 0;
        for block in &chunk.blocks {
            total_instructions = total_instructions.saturating_add(block.insn_count);
            block_insn_counts.push(block.insn_count);
        }

        let block_stats = compute_block_instruction_stats(&block_insn_counts);
        let avg_instructions_per_block = if n > 0 {
            total_instructions as f64 / n as f64
        } else {
            0.0
        };

        // Count runs for RunTable strategy
        let run_count = if matches!(lookup_strategy, LookupStrategy::RunTable) {
            let mut runs = 0;
            let mut current_run_len = 1;
            for i in 1..chunk.blocks.len() {
                let prev_pc = chunk.blocks[i - 1].pc;
                let curr_pc = chunk.blocks[i].pc;
                if curr_pc == prev_pc + 4 {
                    current_run_len += 1;
                } else {
                    if current_run_len > 0 {
                        runs += 1;
                    }
                    current_run_len = 1;
                }
            }
            if current_run_len > 0 {
                runs += 1;
            }
            Some(runs)
        } else {
            None
        };

        let dense_index_size = if matches!(lookup_strategy, LookupStrategy::DenseIndex) {
            Some(range_words)
        } else {
            None
        };

        Ok(ChunkMetrics {
            chunk_idx: chunk.chunk_idx,
            block_count: n,
            pc_min,
            pc_max,
            pc_span,
            range_words,
            density,
            lookup_strategy,
            total_instructions,
            avg_instructions_per_block,
            min_instructions_per_block: block_stats.min,
            max_instructions_per_block: block_stats.max,
            median_instructions_per_block: block_stats.median,
            p90_instructions_per_block: block_stats.p90,
            stddev_instructions_per_block: block_stats.stddev,
            run_count,
            dense_index_size,
        })
    }
}

struct BlockInstructionStats {
    min: u32,
    max: u32,
    median: f64,
    p90: f64,
    stddev: f64,
}

fn compute_block_instruction_stats(counts: &[u32]) -> BlockInstructionStats {
    if counts.is_empty() {
        return BlockInstructionStats {
            min: 0,
            max: 0,
            median: 0.0,
            p90: 0.0,
            stddev: 0.0,
        };
    }

    let mut sorted = counts.to_vec();
    sorted.sort_unstable();

    let min = sorted[0];
    let max = sorted[sorted.len() - 1];
    let median = if sorted.len() % 2 == 1 {
        sorted[sorted.len() / 2] as f64
    } else {
        let hi = sorted.len() / 2;
        let lo = hi - 1;
        (sorted[lo] as f64 + sorted[hi] as f64) / 2.0
    };
    let p90_idx = ((0.9 * sorted.len() as f64).ceil() as usize).saturating_sub(1);
    let p90 = sorted[p90_idx.min(sorted.len() - 1)] as f64;

    let mean = counts.iter().map(|&v| v as f64).sum::<f64>() / counts.len() as f64;
    let variance = counts
        .iter()
        .map(|&v| {
            let delta = v as f64 - mean;
            delta * delta
        })
        .sum::<f64>()
        / counts.len() as f64;

    BlockInstructionStats {
        min,
        max,
        median,
        p90,
        stddev: variance.sqrt(),
    }
}

// Make BlockInfo cloneable for chunking
impl Clone for BlockInfo {
    fn clone(&self) -> Self {
        Self {
            pc: self.pc,
            name: self.name.clone(),
            insn_count: self.insn_count,
            mem_rw_events: self.mem_rw_events,
            non_register_global_lookup_base_max: self.non_register_global_lookup_base_max,
            reg_write_mask: self.reg_write_mask,
            global_lookup_base_max: self.global_lookup_base_max,
            code: self.code.clone(),
            is_terminal: self.is_terminal,
        }
    }
}

struct CrossChunkDirectRewriter {
    allowed_blocks: HashSet<String>,
}

impl VisitMut for CrossChunkDirectRewriter {
    fn visit_expr_mut(&mut self, node: &mut syn::Expr) {
        if let syn::Expr::Call(call) = node {
            if is_nextstep_direct(&call.func) && call.args.len() == 1 {
                if let Some(syn::Expr::Path(arg_path)) = call.args.first() {
                    if let Some(ident) = arg_path.path.get_ident() {
                        let name = ident.to_string();
                        if !self.allowed_blocks.contains(&name) {
                            if let Some(pc) = block_name_to_pc(&name) {
                                *node = syn::parse_quote! { crate::NextStep::Dynamic(#pc) };
                                return;
                            }
                        }
                    }
                }
            }
        }
        syn::visit_mut::visit_expr_mut(self, node);
    }
}

fn is_nextstep_direct(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Path(path) => path
            .path
            .segments
            .last()
            .map(|seg| seg.ident == "Direct")
            .unwrap_or(false),
        _ => false,
    }
}

fn block_name_to_pc(name: &str) -> Option<u64> {
    let prefix = "block_0x";
    if let Some(hex) = name.strip_prefix(prefix) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        block_analysis::BlockAnalyzer,
        elf_parser::parse_elf,
        instruction_translator::InstructionTranslator,
        types::{sign_extend_imm32_to_u64, Instruction},
    };
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn load_reth_program() -> ProgramInfo {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let elf_path = manifest_dir.join("../perf/bench_data/rv64/reth-elf");
        let elf_bytes = fs::read(&elf_path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", elf_path.display()));
        parse_elf(&elf_bytes)
    }

    fn small_program() -> ProgramInfo {
        ProgramInfo::new(
            vec![
                Instruction::new(Opcode::ADD, 1, 2, 3, false, false),
                Instruction::new(Opcode::LD, 4, 5, 8, false, true),
                Instruction::new(Opcode::JAL, 0, 4, 0, false, true),
            ],
            0x1000,
            0x1000,
        )
    }

    #[test]
    fn reth_codegen_preserves_decoded_instruction_stream_around_31ce10() {
        let program = load_reth_program();
        let pc = 0x0031ce10_u64;
        let idx = ((pc - program.pc_base) / 4) as usize;
        let inst = &program.instructions[idx];

        let leaders = BlockAnalyzer::new(&program).analyze();
        let (translated, _, _, _) = InstructionTranslator::new().translate(pc, inst, &leaders);
        let translated = translated.to_string();
        assert!(
            translated.contains("emu"),
            "translator emitted unexpectedly empty code: {translated}"
        );
        match inst.opcode {
            Opcode::ADD if inst.imm_b && inst.imm_c => {
                assert!(
                    translated.contains("constant_no_count"),
                    "translator emitted unexpected ADD-immediate code: {translated}"
                );
                assert!(
                    translated.contains(&format!("{}u64", sign_extend_imm32_to_u64(inst.op_c))),
                    "translator missed decoded immediate for ADD-like instruction: {translated}"
                );
            }
            Opcode::SD => {
                assert!(
                    translated.contains("sd_no_count"),
                    "translator emitted unexpected SD code: {translated}"
                );
            }
            _ => {
                assert!(
                    translated.contains("emu ."),
                    "translator emitted unexpected opcode shape {:?}: {translated}",
                    inst.opcode
                );
            }
        }

        let compiler = AotCompiler::new(program, AotConfig::new(PathBuf::from("/tmp/aot-test")));
        let blocks = compiler
            .generate_blocks(&leaders)
            .expect("block generation should succeed");
        assert!(
            blocks.iter().all(|block| block.pc != pc),
            "default config should not force a synthetic split at {pc:#x}"
        );

        let block = blocks
            .iter()
            .find(|block| {
                let block_end = block.pc + u64::from(block.insn_count) * 4;
                block.pc <= pc && pc < block_end
            })
            .expect("a block covering the inspected PC should exist");
        let block_code = block.code.to_string();
        assert!(
            block_code.contains(&translated),
            "block code should include the translated instruction for {pc:#x}: {block_code}"
        );
    }

    #[test]
    fn block_translate_reports_global_lookup_base_by_opcode_shape() {
        let leaders = HashSet::new();

        let (_, _, mem_rw_events, global_lookup_base) = InstructionTranslator::new().translate(
            0x1000,
            &Instruction::new(Opcode::LD, 1, 2, 8, false, true),
            &leaders,
        );
        assert_eq!(mem_rw_events, 1);
        assert_eq!(global_lookup_base, 2);

        let (_, _, mem_rw_events, global_lookup_base) = InstructionTranslator::new().translate(
            0x1004,
            &Instruction::new(Opcode::SD, 1, 2, 8, false, true),
            &leaders,
        );
        assert_eq!(mem_rw_events, 1);
        assert_eq!(global_lookup_base, 1);

        let (_, _, mem_rw_events, global_lookup_base) = InstructionTranslator::new().translate(
            0x1008,
            &Instruction::new(Opcode::BEQ, 1, 2, 4, false, true),
            &leaders,
        );
        assert_eq!(mem_rw_events, 0);
        assert_eq!(global_lookup_base, 0);
    }

    #[test]
    fn write_chunk_crate_emits_block_fit_constants_and_guard() {
        let program = small_program();
        let compiler = AotCompiler::new(
            program.clone(),
            AotConfig::new(PathBuf::from("/tmp/aot-test")),
        );
        let leaders = BlockAnalyzer::new(&program).analyze();
        let blocks = compiler
            .generate_blocks(&leaders)
            .expect("block generation should succeed");
        let chunk = ChunkInfo {
            chunk_idx: 0,
            pc_min: program.pc_base,
            pc_max: program.pc_base + ((program.instructions.len() - 1) as u64) * 4,
            blocks,
        };

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch")
            .as_nanos();
        let out_dir = std::env::temp_dir().join(format!("pico-aot-guard-{unique}"));
        let chunks_dir = out_dir.join("chunks");
        fs::create_dir_all(&chunks_dir).expect("create temp chunk root");

        compiler
            .write_chunk_crate(&chunk, &chunks_dir, &RuntimeSpec::InTree)
            .expect("write_chunk_crate should succeed");

        let lib_rs = fs::read_to_string(chunks_dir.join("chunk_000/src/lib.rs"))
            .expect("read generated chunk lib");
        assert!(lib_rs.contains("const BLOCK_MEM_RW_EVENTS: usize ="));
        assert!(lib_rs.contains("const BLOCK_NON_REGISTER_GLOBAL_LOOKUP_BASE_MAX: usize ="));
        assert!(lib_rs.contains("const BLOCK_REG_WRITE_MASK: u32 ="));
        assert!(lib_rs.contains("can_fit_block"));

        let _ = fs::remove_dir_all(out_dir);
    }

    #[test]
    fn forced_splits_preserve_instructions_and_block_exits() {
        let program = ProgramInfo::new(
            vec![
                Instruction::new(Opcode::ADD, 1, 5, 7, true, true),
                Instruction::new(Opcode::ADD, 2, 1, 1, false, true),
                Instruction::new(Opcode::ADD, 3, 2, 1, false, true),
                Instruction::new(Opcode::JALR, 0, 1, 0, false, true),
            ],
            0x1000,
            0x1000,
        );
        let leaders = BlockAnalyzer::new(&program).analyze();
        for cap in [0, 2] {
            let compiler = AotCompiler::new(
                program.clone(),
                AotConfig::new(PathBuf::from("/tmp/aot-test")).with_max_block_instructions(cap),
            );
            let blocks = compiler
                .generate_blocks(&leaders)
                .expect("block generation should succeed");
            let expected = if cap == 0 {
                vec![(0x1000, 4)]
            } else {
                vec![(0x1000, 2), (0x1008, 2)]
            };
            assert_eq!(
                blocks
                    .iter()
                    .map(|b| (b.pc, b.insn_count))
                    .collect::<Vec<_>>(),
                expected,
            );
            let translator = InstructionTranslator::new();
            for block in &blocks {
                let code = block.code.to_string();
                let start = ((block.pc - program.pc_base) / 4) as usize;
                for index in start..start + block.insn_count as usize {
                    let pc = program.pc_base + 4 * index as u64;
                    let (translated, ..) =
                        translator.translate(pc, &program.instructions[index], &leaders);
                    assert!(
                        code.contains(&translated.to_string()),
                        "missing {pc:#x}: {code}"
                    );
                }
            }
            if cap > 0 {
                let exit = blocks[0].code.to_string();
                assert!(exit.contains("emu . pc = 4104u64"));
                assert!(exit.contains("check_chunk_boundary_fast"));
                assert!(exit.contains("should_yield"));
                assert!(exit.contains("NextStep :: Dynamic (emu . pc)"));
                assert!(exit.contains("NextStep :: Direct (block_0x00001008)"));
            }
        }
    }
}
