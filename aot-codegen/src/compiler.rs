//! Main AOT Compiler
//!
//! This module provides the main AOT compilation pipeline that coordinates
//! block analysis, code generation, and post-processing.
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
    instruction_translator::InstructionTranslator,
    metrics::{AotMetrics, ChunkMetrics, LookupStrategy, ProgramMetrics},
    post_processor::AotPostProcessor,
    types::{Opcode, ProgramInfo},
};
use quote::{format_ident, quote};
use std::{
    collections::{HashMap, HashSet},
    fs,
};
use syn::visit_mut::VisitMut;

/// Information about a compiled basic block
struct BlockInfo {
    pc: u32,
    name: proc_macro2::Ident,
    insn_count: u32,
    code: proc_macro2::TokenStream,
    is_terminal: bool,
}

/// Information about a chunk of blocks
struct ChunkInfo {
    chunk_idx: usize,
    blocks: Vec<BlockInfo>,
    pc_min: u32,
    pc_max: u32,
}

struct SuperblockInfo {
    entry_pc: u32,
    entry_name: proc_macro2::Ident,
    block_pcs: Vec<u32>,
    block_codes: Vec<proc_macro2::TokenStream>,
    total_insn_count: u32,
}

struct LookupEntry {
    pc: u32,
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

    /// Main compilation entry point
    pub fn compile(&self) -> Result<(), String> {
        self.compile_crates()
    }

    /// Compile to chunk crates + a dispatcher crate for parallel compilation
    fn compile_crates(&self) -> Result<(), String> {
        // Phase 1: Block Analysis
        let analyzer = BlockAnalyzer::new(&self.program);
        let leaders = analyzer.analyze();

        // Phase 2: Generate all blocks
        let blocks = self.generate_blocks(&leaders)?;

        if blocks.is_empty() {
            return Err("No blocks generated".to_string());
        }

        let (pred_counts, succ_map) = self.analyze_block_cfg(&blocks);

        // Phase 3: Partition blocks into chunks
        let chunks = if self.config.enable_cfg_aware_chunking {
            self.partition_into_chunks_cfg_aware(blocks, &leaders)?
        } else {
            self.partition_into_chunks(blocks)
        };

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
            self.write_chunk_crate(chunk, &chunks_dir, &pred_counts, &succ_map)?;
            if let Some(metric) = chunk_metric {
                chunk_metrics_vec.push(metric);
            }
        }

        // Phase 6: Generate dispatch crate
        self.write_dispatch_crate(&chunks, output_dir)?;

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
    fn generate_blocks(&self, leaders: &HashSet<u32>) -> Result<Vec<BlockInfo>, String> {
        let translator = InstructionTranslator::new(true);
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
        let max_block_instructions = self.config.max_block_instructions;

        for (idx, inst) in self.program.instructions.iter().enumerate() {
            let pc = self.program.pc_base + (idx as u32 * 4);

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
                            return Ok(crate::NextStep::Direct(#next_block_name));
                        });
                    }

                    blocks.push(BlockInfo {
                        pc: current_block_pc,
                        name: current_block_name.clone(),
                        insn_count: block_insn_count,
                        code: current_block_tokens.clone(),
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
            }

            if active {
                let (body, is_terminal, mem_rw_events) = translator.translate(pc, inst, leaders);

                if is_terminal {
                    let total_events = block_mem_rw_events + mem_rw_events;
                    if total_events > 0 {
                        current_block_tokens.extend(quote! {
                            emu.add_memory_rw_events(#total_events);
                        });
                    }
                    current_block_tokens.extend(body);
                } else {
                    current_block_tokens.extend(body);
                    block_mem_rw_events += mem_rw_events;
                }
                block_terminated = is_terminal;
                block_has_terminal = is_terminal;
                block_insn_count += 1;

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
                        code: current_block_tokens.clone(),
                        is_terminal: block_has_terminal,
                    });
                    active = false;
                    block_terminated = false;
                    block_insn_count = 0;
                    current_block_tokens = proc_macro2::TokenStream::new();
                    force_new_block = true;
                    block_has_terminal = false;
                    block_mem_rw_events = 0;
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
                    return Ok(crate::NextStep::Halt);
                });
            }

            blocks.push(BlockInfo {
                pc: current_block_pc,
                name: current_block_name,
                insn_count: block_insn_count,
                code: current_block_tokens,
                is_terminal: block_has_terminal,
            });
        }

        Ok(blocks)
    }

    /// Partition blocks into chunks for parallel compilation (simple sequential)
    fn partition_into_chunks(&self, blocks: Vec<BlockInfo>) -> Vec<ChunkInfo> {
        let blocks_per_chunk = self.compute_blocks_per_chunk(blocks.len());
        let max_gap = self.config.max_chunk_pc_gap;
        let mut chunks = Vec::new();
        let mut current_blocks: Vec<BlockInfo> = Vec::new();
        let mut prev_pc: Option<u32> = None;
        let mut chunk_idx = 0usize;

        for block in blocks.into_iter() {
            let should_split_for_gap = prev_pc
                .map(|pc| block.pc > pc && block.pc - pc > max_gap)
                .unwrap_or(false);
            let should_split_for_size = current_blocks.len() >= blocks_per_chunk;

            if should_split_for_gap || should_split_for_size {
                let pc_min = current_blocks.iter().map(|b| b.pc).min().unwrap();
                let pc_max = current_blocks.iter().map(|b| b.pc).max().unwrap();
                chunks.push(ChunkInfo {
                    chunk_idx,
                    blocks: current_blocks,
                    pc_min,
                    pc_max,
                });
                chunk_idx += 1;
                current_blocks = Vec::new();
            }

            prev_pc = Some(block.pc);
            current_blocks.push(block);
        }

        if !current_blocks.is_empty() {
            let pc_min = current_blocks.iter().map(|b| b.pc).min().unwrap();
            let pc_max = current_blocks.iter().map(|b| b.pc).max().unwrap();
            chunks.push(ChunkInfo {
                chunk_idx,
                blocks: current_blocks,
                pc_min,
                pc_max,
            });
        }

        chunks
    }

    /// Partition blocks into chunks using CFG-aware segmentation
    fn partition_into_chunks_cfg_aware(
        &self,
        blocks: Vec<BlockInfo>,
        leaders: &HashSet<u32>,
    ) -> Result<Vec<ChunkInfo>, String> {
        if blocks.is_empty() {
            return Ok(Vec::new());
        }

        let blocks_per_chunk = self.compute_blocks_per_chunk(blocks.len());
        let max_gap = self.config.max_chunk_pc_gap;
        let max_chunks = self.config.max_chunk_count.max(1);

        // Extract block PCs for CFG analysis
        let block_pcs: Vec<u32> = blocks.iter().map(|b| b.pc).collect();

        // Perform CFG analysis
        let cfg = CfgAnalysis::analyze(&self.program, &block_pcs, leaders);

        // Find forced splits from PC gaps
        let forced_splits = self.find_forced_splits(&blocks, max_gap);

        // Segment between forced splits using greedy algorithm
        let mut chunks = Vec::new();
        let mut start = 0;
        let mut chunk_idx = 0usize;

        for &split_end in &forced_splits {
            if start > split_end {
                continue;
            }

            let segment_blocks = &blocks[start..=split_end];
            let segment_chunks = self.greedy_segment(
                segment_blocks,
                &cfg,
                start,
                blocks_per_chunk,
                max_chunks.saturating_sub(chunks.len()).max(1),
                &mut chunk_idx,
            )?;
            chunks.extend(segment_chunks);
            start = split_end + 1;
        }

        // Handle remaining blocks after last forced split
        if start < blocks.len() {
            let segment_blocks = &blocks[start..];
            let segment_chunks = self.greedy_segment(
                segment_blocks,
                &cfg,
                start,
                blocks_per_chunk,
                max_chunks.saturating_sub(chunks.len()).max(1),
                &mut chunk_idx,
            )?;
            chunks.extend(segment_chunks);
        }

        Ok(chunks)
    }

    /// Find forced split points based on PC gaps
    fn find_forced_splits(&self, blocks: &[BlockInfo], max_gap: u32) -> Vec<usize> {
        let mut splits = Vec::new();
        let mut prev_pc: Option<u32> = None;

        for (idx, block) in blocks.iter().enumerate() {
            if let Some(pc) = prev_pc {
                if block.pc > pc && block.pc - pc > max_gap {
                    // Split before this block (boundary is after previous block)
                    splits.push(idx.saturating_sub(1));
                }
            }
            prev_pc = Some(block.pc);
        }

        splits
    }

    /// Greedy segmentation within a segment (between forced splits)
    fn greedy_segment(
        &self,
        segment_blocks: &[BlockInfo],
        cfg: &CfgAnalysis,
        segment_start_idx: usize,
        desired_blocks_per_chunk: usize,
        max_chunks_for_segment: usize,
        chunk_idx: &mut usize,
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
                    chunk_idx: *chunk_idx,
                    blocks: chunk_blocks,
                    pc_min,
                    pc_max,
                });
                *chunk_idx += 1;
                break;
            }

            // Find boundary with minimum cut penalty in window.
            // NOTE: `boundary` is an absolute index into `segment_blocks`, so the global boundary
            // index is `segment_start_idx + boundary`.
            let mut best_boundary = window_start;
            let mut best_penalty = if segment_start_idx + window_start < cfg.num_boundaries() {
                cfg.cut_penalty(segment_start_idx + window_start)
            } else {
                u32::MAX
            };

            for boundary in window_start..window_end {
                let boundary_idx = segment_start_idx + boundary;
                if boundary_idx < cfg.num_boundaries() {
                    let penalty = cfg.cut_penalty(boundary_idx);
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
                chunk_idx: *chunk_idx,
                blocks: chunk_blocks,
                pc_min,
                pc_max,
            });
            *chunk_idx += 1;
            start = end;
        }

        Ok(chunks)
    }

    fn analyze_block_cfg(
        &self,
        blocks: &[BlockInfo],
    ) -> (HashMap<u32, usize>, HashMap<u32, Vec<u32>>) {
        let mut pred_counts: HashMap<u32, usize> = HashMap::new();
        let mut succ_map: HashMap<u32, Vec<u32>> = HashMap::new();

        let pc_to_idx: HashMap<u32, usize> = blocks
            .iter()
            .enumerate()
            .map(|(idx, block)| (block.pc, idx))
            .collect();

        for block in blocks {
            if block.insn_count == 0 {
                succ_map.insert(block.pc, Vec::new());
                continue;
            }

            let last_pc = block
                .pc
                .wrapping_add(block.insn_count.saturating_sub(1).saturating_mul(4));
            let inst_idx = (last_pc.saturating_sub(self.program.pc_base) >> 2) as usize;
            if inst_idx >= self.program.instructions.len() {
                succ_map.insert(block.pc, Vec::new());
                continue;
            }

            let inst = &self.program.instructions[inst_idx];
            let mut succs = Vec::new();
            match inst.opcode {
                Opcode::JAL => {
                    let (_, imm) = inst.j_type();
                    let target = last_pc.wrapping_add(imm);
                    if pc_to_idx.contains_key(&target) {
                        succs.push(target);
                    }
                }
                Opcode::BEQ
                | Opcode::BNE
                | Opcode::BLT
                | Opcode::BGE
                | Opcode::BLTU
                | Opcode::BGEU => {
                    let (_, _, imm) = inst.b_type();
                    let target = last_pc.wrapping_add(imm);
                    let fallthrough = last_pc.wrapping_add(4);
                    if pc_to_idx.contains_key(&target) {
                        succs.push(target);
                    }
                    if pc_to_idx.contains_key(&fallthrough) {
                        succs.push(fallthrough);
                    }
                }
                Opcode::JALR | Opcode::ECALL | Opcode::EBREAK | Opcode::UNIMP => {}
                _ => {
                    let next_pc = last_pc.wrapping_add(4);
                    if pc_to_idx.contains_key(&next_pc) {
                        succs.push(next_pc);
                    }
                }
            }

            for succ in &succs {
                *pred_counts.entry(*succ).or_default() += 1;
            }
            succ_map.insert(block.pc, succs);
        }

        (pred_counts, succ_map)
    }

    fn build_chunk_superblocks(
        &self,
        chunk: &ChunkInfo,
        pred_counts: &HashMap<u32, usize>,
        succ_map: &HashMap<u32, Vec<u32>>,
    ) -> Vec<SuperblockInfo> {
        let mut superblocks = Vec::new();
        let mut visited = HashSet::new();
        let mut block_lookup = HashMap::new();
        let chunk_pc_set: HashSet<u32> = chunk.blocks.iter().map(|b| b.pc).collect();

        for block in &chunk.blocks {
            block_lookup.insert(block.pc, block);
        }

        for block in &chunk.blocks {
            let pc = block.pc;
            if visited.contains(&pc) {
                continue;
            }

            // Don't use is_terminal flag - it's too conservative (marks all branches as terminal)
            // Instead, check if block has exactly one successor in the CFG
            let succs = succ_map.get(&pc);
            let succ_count = succs.map(|s| s.len()).unwrap_or(0);

            if succ_count == 0 {
                continue;
            }

            if succ_count != 1 {
                continue;
            }

            let pred_count = *pred_counts.get(&pc).unwrap_or(&0);
            if pred_count > 1 {
                continue;
            }

            let next_pc = succs.and_then(|s| s.first()).copied().unwrap_or(0);
            if !chunk_pc_set.contains(&next_pc) {
                continue;
            }

            let mut pcs = vec![pc];
            let mut codes = vec![block.code.clone()];
            let mut total_insns = block.insn_count;
            visited.insert(pc);

            let mut current_pc = pc;
            let max_superblock_insns = self.config.max_superblock_instructions.max(1);
            loop {
                // Check if current block has exactly one successor
                let succs = succ_map.get(&current_pc);
                let succ_count = succs.map(|s| s.len()).unwrap_or(0);
                if succ_count != 1 {
                    break;
                }

                let next_pc = succs.and_then(|s| s.first()).copied().unwrap_or(0);
                if !chunk_pc_set.contains(&next_pc) {
                    break;
                }

                // CRITICAL: Only merge fallthrough blocks (sequential addresses)
                // Don't merge jump targets (JAL, etc.) even if they have 1 successor
                let current_block = match block_lookup.get(&current_pc) {
                    Some(b) => *b,
                    None => break,
                };
                let expected_fallthrough = current_pc.wrapping_add(current_block.insn_count * 4);
                if next_pc != expected_fallthrough {
                    // Next block is a jump target, not a fallthrough - stop merging
                    break;
                }

                let next_pred_count = *pred_counts.get(&next_pc).unwrap_or(&0);
                if next_pred_count != 1 {
                    break;
                }

                let next_block = match block_lookup.get(&next_pc) {
                    Some(b) => *b,
                    None => break,
                };

                pcs.push(next_pc);
                codes.push(next_block.code.clone());
                total_insns += next_block.insn_count;
                visited.insert(next_pc);
                current_pc = next_pc;

                // Stop if superblock gets too large (for compilation time)
                if total_insns >= max_superblock_insns {
                    break;
                }
            }

            if pcs.len() > 1 {
                let entry_name = format_ident!("superblock_0x{:08x}", pc);
                superblocks.push(SuperblockInfo {
                    entry_pc: pc,
                    entry_name,
                    block_pcs: pcs,
                    block_codes: codes,
                    total_insn_count: total_insns,
                });
            }
        }

        if !superblocks.is_empty() {
            eprintln!(
                "Chunk {}: Created {} superblocks (merged {} blocks)",
                chunk.chunk_idx,
                superblocks.len(),
                superblocks
                    .iter()
                    .map(|sb| sb.block_pcs.len())
                    .sum::<usize>()
            );
        }
        superblocks
    }

    /// Write a chunk crate with block functions and per-chunk lookup
    fn write_chunk_crate(
        &self,
        chunk: &ChunkInfo,
        chunks_dir: &std::path::Path,
        pred_counts: &HashMap<u32, usize>,
        succ_map: &HashMap<u32, Vec<u32>>,
    ) -> Result<(), String> {
        let crate_dir = chunks_dir.join(format!("chunk_{:03}", chunk.chunk_idx));
        let src_dir = crate_dir.join("src");
        fs::create_dir_all(&src_dir)
            .map_err(|e| format!("Failed to create chunk dir {}: {}", chunk.chunk_idx, e))?;

        let crate_name = format!("pico-aot-chunk-{:03}", chunk.chunk_idx);
        let cargo_toml = format!(
            "[package]\nname = \"{}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\npico-aot-runtime = {{ path = \"../../../aot-runtime\" }}\n",
            crate_name
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
        let superblocks = self.build_chunk_superblocks(chunk, pred_counts, succ_map);

        let mut pc_to_export: HashMap<u32, proc_macro2::Ident> = HashMap::new();
        for block in &chunk.blocks {
            pc_to_export.insert(block.pc, block.name.clone());
        }
        for sb in &superblocks {
            pc_to_export.insert(sb.entry_pc, sb.entry_name.clone());
        }

        let lookup_entries: Vec<LookupEntry> = chunk
            .blocks
            .iter()
            .map(|block| LookupEntry {
                pc: block.pc,
                name: pc_to_export
                    .get(&block.pc)
                    .cloned()
                    .unwrap_or_else(|| block.name.clone()),
            })
            .collect();

        let n = lookup_entries.len();

        // Analyze chunk and generate appropriate lookup strategy
        let (lookup_body, lookup_inline_attr, _strategy) =
            self.generate_chunk_lookup(&lookup_entries, pc_min, pc_max, n)?;

        // Generate block functions with selective inlining
        let block_functions: Vec<_> = chunk
            .blocks
            .iter()
            .map(|block| {
                let name = &block.name;
                let insn_count = block.insn_count;
                let code = &block.code;
                let inline_attr = self.get_inline_attr(insn_count);

                quote! {
                    #inline_attr
                    pub fn #name(emu: &mut AotEmulatorCore) -> Result<crate::NextStep, String> {
                        const BLOCK_INSNS: u32 = #insn_count;
                        if !emu.can_fit_instructions(BLOCK_INSNS) {
                            return emu.interpret_from_current_pc();
                        }
                        // Fast path: unconstrained mode is rare, fall back to interpreter
                        // This allows using _constrained variants in generated code
                        if emu.is_unconstrained_mode() {
                            return emu.interpret_from_current_pc();
                        }
                        #code
                    }
                }
            })
            .collect();

        let superblock_functions: Vec<_> = superblocks
            .iter()
            .map(|sb| self.generate_superblock(sb))
            .collect();

        let chunk_code = quote! {
            // AUTO-GENERATED by AOT compiler - Chunk
            // DO NOT EDIT MANUALLY
            pub use pico_aot_runtime::{AotEmulatorCore, BlockClock, BlockFn, NextStep};

            pub const PC_MIN: u32 = #pc_min;
            pub const PC_MAX: u32 = #pc_max;

            #lookup_inline_attr
            pub fn lookup(pc: u32) -> Option<BlockFn> {
                #lookup_body
            }

            #(#block_functions)*
            #(#superblock_functions)*
        };

        // Parse and optionally post-process
        let mut syntax_tree = syn::parse2(chunk_code)
            .map_err(|e| format!("Parse error in chunk {}: {}", chunk.chunk_idx, e))?;

        let mut allowed_blocks: HashSet<String> =
            chunk.blocks.iter().map(|b| b.name.to_string()).collect();
        for sb in &superblocks {
            allowed_blocks.insert(sb.entry_name.to_string());
        }

        let mut superblock_map = HashMap::new();
        let block_pc_to_name: HashMap<u32, String> = chunk
            .blocks
            .iter()
            .map(|b| (b.pc, b.name.to_string()))
            .collect();
        for sb in &superblocks {
            if let Some(first_pc) = sb.block_pcs.first() {
                if let Some(block_name) = block_pc_to_name.get(first_pc) {
                    superblock_map.insert(block_name.clone(), sb.entry_name.clone());
                }
            }
        }

        let mut rewriter = CrossChunkDirectRewriter {
            allowed_blocks,
            superblock_map,
        };
        rewriter.visit_file_mut(&mut syntax_tree);

        if self.config.enable_optimizations {
            let mut processor = AotPostProcessor::new();
            processor.process(&mut syntax_tree);
        }

        let formatted = prettyplease::unparse(&syntax_tree);
        fs::write(&chunk_file, &formatted)
            .map_err(|e| format!("Failed to write chunk {}: {}", chunk.chunk_idx, e))?;

        Ok(())
    }

    /// Write a dispatch crate that links all chunk crates
    fn write_dispatch_crate(
        &self,
        chunks: &[ChunkInfo],
        output_dir: &std::path::Path,
    ) -> Result<(), String> {
        let src_dir = output_dir.join("src");
        fs::create_dir_all(&src_dir)
            .map_err(|e| format!("Failed to create dispatch src dir: {}", e))?;

        let chunk_deps: Vec<String> = chunks
            .iter()
            .map(|c| {
                format!(
                    "pico-aot-chunk-{:03} = {{ path = \"chunks/chunk_{:03}\" }}",
                    c.chunk_idx, c.chunk_idx
                )
            })
            .collect();

        let cargo_toml = format!(
            "[package]\nname = \"pico-aot-dispatch\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\npico-aot-runtime = {{ path = \"../aot-runtime\" }}\n{}\n",
            chunk_deps.join("\n")
        );
        fs::write(output_dir.join("Cargo.toml"), cargo_toml)
            .map_err(|e| format!("Failed to write dispatch Cargo.toml: {}", e))?;

        // Build chunk descriptor table
        let mut chunk_descs = Vec::with_capacity(chunks.len());
        let mut global_pc_min = u32::MAX;
        let mut global_pc_max = 0u32;

        for c in chunks.iter() {
            let chunk_crate = format_ident!("pico_aot_chunk_{:03}", c.chunk_idx);
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
            let mut page_size = page_size_f64 as u32;

            // Clamp to [PAGE_HINT_MIN_SIZE, PAGE_HINT_MAX_SIZE]
            page_size = page_size.max(constants::PAGE_HINT_MIN_SIZE);
            page_size = page_size.min(constants::PAGE_HINT_MAX_SIZE);

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
            let actual_page_size = 1u32 << page_shift_val;

            // Build page hint table
            let num_pages = span.div_ceil(actual_page_size) as usize;
            let mut page_hints = Vec::with_capacity(num_pages);

            for page_idx in 0..num_pages {
                let page_start = global_pc_min + (page_idx as u32 * actual_page_size);
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
                const GLOBAL_PC_MIN: u32 = #global_pc_min;
                const PAGE_SHIFT: u32 = #page_shift_val;
                #page_hint_table
            }
        };

        let dispatch_code = quote! {
            // AUTO-GENERATED by AOT compiler - Dispatch crate
            // DO NOT EDIT MANUALLY

            pub use pico_aot_runtime::AotEmulatorCore;
            use pico_aot_runtime::{set_lookup_block_fn, BlockFn, NextStep};

            pub fn run_aot(emu: &mut AotEmulatorCore) -> Result<(), String> {
                set_lookup_block_fn(lookup_block);
                let mut next = if emu.pc == 0 {
                    NextStep::Halt
                } else if let Some(func) = lookup_block(emu.pc) {
                    NextStep::Direct(func)
                } else {
                    NextStep::Dynamic(emu.pc)
                };

                loop {
                    if emu.should_yield() {
                        break;
                    }
                    match next {
                        NextStep::Direct(func) => {
                            next = func(emu)?;
                        }
                        NextStep::Dynamic(pc) => {
                            emu.pc = pc;
                            if emu.pc == 0 {
                                next = NextStep::Halt;
                            } else if let Some(func) = lookup_block(pc) {
                                next = NextStep::Direct(func);
                            } else {
                                next = emu.interpret_from_current_pc()?;
                            }
                        }
                        NextStep::Halt => break,
                    }
                }
                Ok(())
            }

            type ChunkLookupFn = fn(u32) -> Option<BlockFn>;

            #[repr(C)]
            struct ChunkDesc {
                pc_min: u32,
                pc_max: u32,
                lookup: ChunkLookupFn,
            }

            const CHUNKS: &[ChunkDesc] = &[
                #(#chunk_descs)*
            ];

            #page_hint_code

            fn lookup_block(pc: u32) -> Option<BlockFn> {
                if CHUNKS.is_empty() {
                    return None;
                }

                // Use page hint for O(1) initial guess
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
        pc_min: u32,
        pc_max: u32,
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
        let range_words = ((pc_max.saturating_sub(pc_min)) >> 2).saturating_add(1) as usize;
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
                let word_offset = ((entry.pc - pc_min) >> 2) as usize;
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

                if pc < #pc_min || pc > #pc_max {
                    return None;
                }
                let word_offset = ((pc - #pc_min) >> 2) as usize;
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
                let start_word = (start_pc - pc_min) >> 2;
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
            #[repr(C)]
            struct Run {
                start_word: u32,
                len: u16,
                fn_offset: u16,
            }
            const RUNS: [Run; #num_runs] = [
                #(#run_entries)*
            ];

            if pc < #pc_min || pc > #pc_max {
                return None;
            }
            let word_offset = ((pc - #pc_min) >> 2) as u32;

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

    fn generate_superblock(&self, sb: &SuperblockInfo) -> proc_macro2::TokenStream {
        if sb.block_codes.len() < 2 {
            return quote! {};
        }

        let name = &sb.entry_name;
        let total_insn_count = sb.total_insn_count;
        let inline_attr = self.get_inline_attr(total_insn_count);

        // Merge block codes: strip returns from intermediate blocks, keep last block's return
        let mut merged_code = quote! {};
        for (idx, code) in sb.block_codes.iter().enumerate() {
            let is_last = idx == sb.block_codes.len() - 1;
            if is_last {
                // Last block: keep everything including return
                merged_code.extend(quote! {
                    #code
                });
            } else {
                // Intermediate blocks: strip all terminal code (pc/clock/boundary/yield/return)
                if let Ok(block_code) = syn::parse2::<syn::Block>(quote! { { #code } }) {
                    // Find where terminal code starts (first pc assignment)
                    let mut terminal_start = None;
                    for (i, stmt) in block_code.stmts.iter().enumerate() {
                        if Self::is_pc_assignment(stmt) {
                            terminal_start = Some(i);
                            break;
                        }
                    }

                    // Include only non-terminal statements
                    if let Some(terminal_idx) = terminal_start {
                        for stmt in &block_code.stmts[..terminal_idx] {
                            merged_code.extend(quote! { #stmt });
                        }
                    } else {
                        // No terminal code found, include everything (shouldn't happen)
                        for stmt in &block_code.stmts {
                            merged_code.extend(quote! { #stmt });
                        }
                    }
                } else {
                    // Fallback: just include the code (shouldn't happen)
                    merged_code.extend(quote! { #code });
                }
            }
        }

        quote! {
            #inline_attr
            pub fn #name(emu: &mut AotEmulatorCore) -> Result<crate::NextStep, String> {
                const BLOCK_INSNS: u32 = #total_insn_count;
                if !emu.can_fit_instructions(BLOCK_INSNS) {
                    return emu.interpret_from_current_pc();
                }
                // Fast path: unconstrained mode is rare, fall back to interpreter
                // This allows using _constrained variants in generated code
                if emu.is_unconstrained_mode() {
                    return emu.interpret_from_current_pc();
                }
                #merged_code
            }
        }
    }

    /// Check if a statement is a PC assignment (marks start of terminal code)
    fn is_pc_assignment(stmt: &syn::Stmt) -> bool {
        match stmt {
            syn::Stmt::Expr(syn::Expr::Assign(assign), _) => {
                // Check if left side is emu.pc
                if let syn::Expr::Field(field) = &*assign.left {
                    if let syn::Member::Named(ident) = &field.member {
                        return ident == "pc";
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Get inline attribute based on block instruction count
    fn get_inline_attr(&self, insn_count: u32) -> proc_macro2::TokenStream {
        if insn_count <= self.config.small_block_threshold {
            quote! { #[inline(always)] }
        } else if insn_count <= self.config.medium_block_threshold {
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
            code: self.code.clone(),
            is_terminal: self.is_terminal,
        }
    }
}

struct CrossChunkDirectRewriter {
    allowed_blocks: HashSet<String>,
    superblock_map: HashMap<String, proc_macro2::Ident>,
}

impl VisitMut for CrossChunkDirectRewriter {
    fn visit_expr_mut(&mut self, node: &mut syn::Expr) {
        if let syn::Expr::Call(call) = node {
            if is_nextstep_direct(&call.func) && call.args.len() == 1 {
                if let Some(first_arg) = call.args.first_mut() {
                    if let syn::Expr::Path(arg_path) = first_arg {
                        if let Some(ident) = arg_path.path.get_ident() {
                            let name = ident.to_string();
                            if let Some(replacement) = self.superblock_map.get(&name) {
                                *first_arg = syn::parse_quote! { #replacement };
                                return;
                            }
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

fn block_name_to_pc(name: &str) -> Option<u32> {
    let prefix = "block_0x";
    if let Some(hex) = name.strip_prefix(prefix) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        None
    }
}
