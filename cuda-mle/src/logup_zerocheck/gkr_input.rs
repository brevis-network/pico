use std::cmp::max;

use crate::runtime::{
    copy::{MemCopyD2H, MemCopyH2D},
    d_buffer::DeviceBuffer,
};
use itertools::Itertools;
use mle_core::{
    air::symbolic::SymbolicConstraints,
    poly::matrix::{ColMajorMatrix, MatrixDimensions},
    protocol::stacking::{StackedLayout, StackedSlice},
    prover::{
        evaluator::InteractionEvalPlan, fractional_sumcheck_gkr::Frac, ColMajorEvalHelper,
        DeviceMultiStarkProvingKey, ProvingContext,
    },
};
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};
use tracing::instrument;

use super::errors::InteractionGpuError;
use crate::{
    cuda::field_kernels::FieldKernels, data_transporter::transport_matrix_d2h_col_major,
    gpu_backend::GenericGpuBackend, hash_scheme::GpuHashScheme,
};

const GKR_TASKS: u32 = 65536;

#[derive(Clone)]
#[allow(dead_code)]
pub struct TraceInteractionMeta {
    pub trace_idx: usize,
    pub air_idx: usize,
    pub layout_slices: Vec<StackedSlice>,
}

// TODO: check whether anything still needs this helper.
pub fn collect_trace_interactions<
    FK: FieldKernels,
    HS: GpuHashScheme<BaseField = FK::Val, ExtField = FK::ValExt>,
>(
    pk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
    ctx: &ProvingContext<GenericGpuBackend<HS>>,
    layout: &StackedLayout,
) -> Vec<Option<TraceInteractionMeta>> {
    // Bucket the layout's slices per trace once, so the per-trace pass below is a direct lookup.
    let mut per_trace_slices: Vec<Vec<(usize, StackedSlice)>> =
        vec![Vec::new(); ctx.per_trace.len()];
    for stacked_col in &layout.sorted_cols {
        let (owner, col_in_trace, col_slice) = (
            stacked_col.mat_idx,
            stacked_col.src_col_idx,
            &stacked_col.slice,
        );
        if let Some(bucket) = per_trace_slices.get_mut(owner) {
            bucket.push((col_in_trace, *col_slice));
        }
    }

    ctx.per_trace
        .iter()
        .enumerate()
        .map(|(t_idx, (a_idx, _))| {
            let air_vk = &pk.per_air[*a_idx].vk;
            if !air_vk.has_interaction() {
                return None;
            }

            let mut by_interaction = vec![None; air_vk.num_interactions()];
            for (i_idx, found) in &per_trace_slices[t_idx] {
                if let Some(cell) = by_interaction.get_mut(*i_idx) {
                    *cell = Some(*found);
                }
            }

            let slices_in_order = by_interaction
                .into_iter()
                .enumerate()
                .map(|(pos, entry)| {
                    entry.unwrap_or_else(|| {
                        panic!(
                            "interaction {} of trace {} has no stacked slice",
                            pos, t_idx
                        )
                    })
                })
                .collect_vec();

            Some(TraceInteractionMeta {
                trace_idx: t_idx,
                air_idx: *a_idx,
                layout_slices: slices_in_order,
            })
        })
        .collect()
}

/// Evaluates the interactions over the trace evaluation matrices, producing the (p, q) leaves
/// that feed the fractional sumcheck. The leaves come back without alpha; alpha is returned
/// alongside so the first tree layer can add it.
#[allow(clippy::too_many_arguments)]
#[instrument(name = "prover.rap_constraints.logup_gkr.input_evals", skip_all)]
pub fn log_gkr_input_evals<
    FK: FieldKernels,
    HS: GpuHashScheme<BaseField = FK::Val, ExtField = FK::ValExt>,
>(
    trace_interactions: &[Option<TraceInteractionMeta>],
    pk: &DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>,
    ctx: &ProvingContext<GenericGpuBackend<HS>>,
    l_skip: usize,
    alpha_logup: FK::ValExt,
    d_challenges: &DeviceBuffer<FK::ValExt>,
    total_leaves: usize,
    // fill-tail: number of leaves actually written by the interaction kernels;
    // only [used_leaves, total_leaves) needs zeroing.
    used_leaves: usize,
) -> Result<(DeviceBuffer<Frac<FK::ValExt>>, FK::ValExt), InteractionGpuError> {
    if trace_interactions.iter().all(|meta| meta.is_none()) {
        return Ok((DeviceBuffer::new(), alpha_logup));
    }

    let t_fz = std::time::Instant::now();
    // reuse the multi-GiB leaves region across proves (a fresh allocation triggers
    // ~7-8 ms of allocator defragmentation stalls per prove). Checked back in by
    // fractional_sumcheck_gpu.
    let leaves = super::buf_cache_checkout::<Frac<FK::ValExt>>("gkr_leaves", total_leaves);
    // The interaction kernels fully write `[0, used_leaves)` (the stacked interaction slices are
    // contiguous from row 0; short traces are filled via vertical repeat) — only the pow2 padding
    // tail needs zeroing (8.6 GiB memset → ~1.5 GiB).
    debug_assert!(used_leaves <= total_leaves);
    leaves.fill_zero_suffix(used_leaves)?;
    if std::env::var("STEP_PROF").is_ok() {
        let _ = crate::runtime::stream::current_stream_sync();
        tracing::info!(
            target: "bench",
            "[stepprof] leaves_alloc_fill_zero={}us",
            t_fz.elapsed().as_micros()
        );
    }
    let null_preprocessed = DeviceBuffer::<FK::Val>::new();

    let mut d_partition_ptrs = DeviceBuffer::<u64>::new();
    let mut tmp = DeviceBuffer::<Frac<FK::ValExt>>::new();
    for meta in trace_interactions.iter().flatten() {
        let air_ctx = &ctx.per_trace[meta.trace_idx].1;
        let pk_air = &pk.per_air[meta.air_idx];

        let preprocessed_matrix = pk_air
            .preprocessed_data
            .as_ref()
            .map(|committed| &committed.trace);

        let mut partitioned_main = Vec::with_capacity(air_ctx.cached_mains.len() + 1);
        for committed in &air_ctx.cached_mains {
            partitioned_main.push(&committed.trace);
        }
        partitioned_main.push(&air_ctx.common_main);

        let rules = &pk_air.other_data.interaction_rules;
        let num_interactions = pk_air.vk.symbolic_constraints.interactions.len();

        let d_preprocessed = preprocessed_matrix
            .as_ref()
            .map(|m| m.buffer())
            .unwrap_or(&null_preprocessed);
        let d_public_values = if air_ctx.public_values.is_empty() {
            DeviceBuffer::<FK::Val>::new()
        } else {
            air_ctx.public_values.to_device()?
        };

        let height = air_ctx.height();
        debug_assert_eq!(height, partitioned_main[0].height());
        let partition_ptrs = partitioned_main
            .iter()
            .map(|m| m.buffer().as_ptr() as u64)
            .collect_vec();
        if partition_ptrs.len() > d_partition_ptrs.len() {
            d_partition_ptrs = DeviceBuffer::with_capacity(partition_ptrs.len());
        }
        partition_ptrs.copy_to(&mut d_partition_ptrs)?;

        let buffer_size = rules.inner.buffer_size;
        // TODO: give the spill threshold of 10 a name instead of a bare literal.
        let is_global = buffer_size > 10;
        // [g1diag] per-AIR interpreter shape: which AIRs take the GLOBAL-intermediates variant
        // (strided global-memory traffic) vs the register/local variant.
        if std::env::var("G1_DIAG").is_ok() {
            tracing::info!(
                target: "bench",
                "[g1diag] air_idx={} height={} num_interactions={} buffer_size={} used_nodes={} \
                 rules_len={} is_global={}",
                meta.air_idx, height, num_interactions, buffer_size,
                rules.inner.d_used_nodes.len(), rules.inner.d_rules.len(), is_global
            );
        }
        let intermediates = if is_global {
            crate::scratch::alloc::<FK::ValExt>((GKR_TASKS as usize) * buffer_size as usize)
        } else {
            crate::scratch::alloc::<FK::ValExt>(1)
        };

        let num_rows_per_tile = height.div_ceil(GKR_TASKS as usize).max(1);

        let slice = meta.layout_slices.first().unwrap();
        if slice.col_idx != 0 {
            return Err(InteractionGpuError::Layout);
        }
        let dst_offset = slice.row_idx;
        let lifted_height = max(height, 1 << l_skip);
        debug_assert_eq!(slice.len(l_skip), lifted_height);
        // SAFETY: by definition of interactions stacked layout, `leaves` has enough capacity
        let leaves_ptr = unsafe { leaves.as_mut_ptr().add(dst_offset) };

        let trace_output = if height != lifted_height {
            let required = height * num_interactions;
            if required > tmp.len() {
                tmp = DeviceBuffer::with_capacity(required);
            }
            tmp.as_mut_ptr()
        } else {
            leaves_ptr
        };
        // Closure that computes the interaction fracs on CPU (interaction-major layout),
        // returning the Vec. Used both for the CPU fallback path and for the optional
        // GPU-vs-CPU verification (MLE_VERIFY_INPUT_EVAL).
        let compute_cpu_fracs = || -> Result<Vec<Frac<FK::ValExt>>, InteractionGpuError> {
            // Interactions are consumed by ColMajorEvalHelper as the compact InteractionEvalPlan
            // sub-DAG (mle-core replaced the raw `Vec<Interaction>` field).
            let interaction_plan = InteractionEvalPlan::from_dag(&pk_air.vk.symbolic_constraints);
            let eval_helper = ColMajorEvalHelper {
                constraints_dag: &pk_air.vk.symbolic_constraints.constraints,
                interactions: &interaction_plan,
                public_values: air_ctx.public_values.clone(),
                preprocessed_trace: None, // preprocessed handled via row_parts ordering
                needs_next: pk_air.vk.params.need_rot,
                constraint_degree: 0,
            };

            // Download challenges: d_challenges = [alpha_logup, beta^0, beta^1, ...].
            // eval_interactions expects beta_pows = [beta^0, beta^1, ...], so skip alpha at index
            // 0.
            let challenges_host = d_challenges.to_host().map_err(InteractionGpuError::Copy)?;
            let beta_pows_host = &challenges_host[1..];

            // Download all trace matrices to CPU (in ColMajorEvalHelper.view_mats order).
            // cpu_mats: (ColMajorMatrix<FK::Val>, is_rotated) - same order as ColMajorEvalHelper.view_mats
            let mut cpu_mats: Vec<(ColMajorMatrix<FK::Val>, bool)> = Vec::new();
            if let Some(prep) = preprocessed_matrix {
                let m = transport_matrix_d2h_col_major(prep).map_err(InteractionGpuError::Copy)?;
                let needs_rot = pk_air.vk.params.need_rot;
                cpu_mats.push((m.clone(), false));
                if needs_rot {
                    cpu_mats.push((m, true));
                }
            }
            let needs_rot = pk_air.vk.params.need_rot;
            for committed in &air_ctx.cached_mains {
                let m = transport_matrix_d2h_col_major(&committed.trace)
                    .map_err(InteractionGpuError::Copy)?;
                cpu_mats.push((m.clone(), false));
                if needs_rot {
                    cpu_mats.push((m, true));
                }
            }
            {
                let m = transport_matrix_d2h_col_major(&air_ctx.common_main)
                    .map_err(InteractionGpuError::Copy)?;
                cpu_mats.push((m.clone(), false));
                if needs_rot {
                    cpu_mats.push((m, true));
                }
            }

            // Evaluate interactions for each row on CPU.
            // row_parts[0] = selectors; row_parts[1..] = matrix columns (all as FK::Val).
            // Output MUST match the GPU kernel layout (interaction-major):
            //   cpu_fracs[interaction_idx * height + row]   (see gkr_input.cu out_idx).
            let mut cpu_fracs: Vec<Frac<FK::ValExt>> = vec![
                Frac {
                    p: FK::ValExt::ZERO,
                    q: FK::ValExt::ZERO
                };
                height * num_interactions
            ];
            for row in 0..height {
                let is_first = FK::Val::from_bool(row == 0);
                let is_transition = FK::Val::from_bool(row != height - 1);
                let is_last = FK::Val::from_bool(row == height - 1);
                let mut row_parts: Vec<Vec<FK::Val>> = vec![vec![is_first, is_transition, is_last]];
                for (mat, is_rot) in &cpu_mats {
                    let offset = if *is_rot { 1 } else { 0 };
                    let row_idx = (row + offset) % mat.height();
                    row_parts.push((0..mat.width()).map(|j| mat.column(j)[row_idx]).collect());
                }
                let interaction_evals = eval_helper
                    .eval_interactions::<FK::Val, FK::ValExt>(&row_parts, beta_pows_host);
                for (interaction_idx, (numer_base, denom)) in
                    interaction_evals.into_iter().enumerate()
                {
                    cpu_fracs[interaction_idx * height + row] = Frac {
                        p: FK::ValExt::from(numer_base),
                        q: denom,
                    };
                }
            }
            Ok(cpu_fracs)
        };

        // Run the GPU input-eval kernel into `trace_output`.
        let run_gpu = |trace_output: *mut Frac<FK::ValExt>| -> Result<(), InteractionGpuError> {
            unsafe {
                FK::logup_gkr_input_eval(
                    is_global,
                    trace_output,
                    d_preprocessed,
                    &d_partition_ptrs,
                    &d_public_values,
                    d_challenges,
                    &intermediates,
                    &rules.inner.d_rules,
                    &rules.inner.d_used_nodes,
                    &rules.d_pair_idxs,
                    height as u32,
                    num_rows_per_tile as u32,
                )?;
            }
            Ok(())
        };

        use crate::runtime::d_buffer::DeviceBuffer as DevBuf;
        let verify_input_eval = crate::cuda::jit::env_flag("MLE_VERIFY_INPUT_EVAL", false);

        if FK::use_cpu_gkr_input_eval() {
            // CPU fallback path: compute on CPU and upload to trace_output.
            let cpu_fracs = compute_cpu_fracs()?;
            let mut trace_output_buf = unsafe {
                DevBuf::<Frac<FK::ValExt>>::from_raw_parts(
                    trace_output as *mut Frac<FK::ValExt>,
                    height * num_interactions,
                )
            };
            cpu_fracs
                .as_slice()
                .copy_to(&mut trace_output_buf)
                .map_err(InteractionGpuError::Copy)?;
            std::mem::forget(trace_output_buf);

            // Optional: run GPU into a scratch buffer and compare against CPU (proof unaffected).
            if verify_input_eval {
                use crate::runtime::copy::MemCopyD2H;
                let scratch = DevBuf::<Frac<FK::ValExt>>::with_capacity(height * num_interactions);
                run_gpu(scratch.as_mut_ptr())?;
                let gpu_fracs: Vec<Frac<FK::ValExt>> =
                    scratch.to_host().map_err(InteractionGpuError::Copy)?;
                let mut mism = 0usize;
                let mut first = None;
                for i in 0..(height * num_interactions) {
                    if gpu_fracs[i].p != cpu_fracs[i].p || gpu_fracs[i].q != cpu_fracs[i].q {
                        mism += 1;
                        if first.is_none() {
                            first = Some((i, i / height, i % height));
                        }
                    }
                }
                if mism > 0 {
                    let (i, int_idx, row) = first.unwrap();
                    tracing::warn!(
                        "INPUT_EVAL_VERIFY air_idx={} height={height} num_int={num_interactions}: \
                         {mism}/{} mismatch; first at idx={i} (interaction={int_idx}, row={row}) \
                         CPU=({:?},{:?}) GPU=({:?},{:?})",
                        meta.air_idx,
                        height * num_interactions,
                        cpu_fracs[i].p,
                        cpu_fracs[i].q,
                        gpu_fracs[i].p,
                        gpu_fracs[i].q
                    );
                } else {
                    tracing::warn!(
                        "INPUT_EVAL_VERIFY air_idx={} height={height} num_int={num_interactions}: OK ({} fracs match)",
                        meta.air_idx, height * num_interactions
                    );
                }
            }
        } else {
            // Generated straight-line kernel for this AIR (compiled lazily, cached).
            // Any compile/launch failure falls back to the interpreter.
            let jit = rules.jit_source.as_ref().and_then(|src| {
                rules
                    .jit_kernel
                    .get_or_init(|| {
                        match crate::cuda::jit::compile_kernel(src, "jit_interactions") {
                            Ok(k) => {
                                tracing::info!(
                                    target: "bench",
                                    "[g1jit] compiled air_idx={} ({} rules)",
                                    meta.air_idx,
                                    rules.inner.d_rules.len()
                                );
                                Some(k)
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "[g1jit] compile failed air_idx={}: {e}",
                                    meta.air_idx
                                );
                                None
                            }
                        }
                    })
                    .as_ref()
                    .copied()
            });
            let launch_jit = |out: *mut Frac<FK::ValExt>,
                              kernel: crate::cuda::jit::JitKernel|
             -> Result<(), String> {
                use std::ffi::c_void;
                let mut p_out = out as *mut c_void;
                let mut p_parts = d_partition_ptrs.as_ptr() as *mut c_void;
                let mut p_prep = d_preprocessed.as_ptr() as *mut c_void;
                let mut p_pub = d_public_values.as_ptr() as *mut c_void;
                let mut p_chal = d_challenges.as_ptr() as *mut c_void;
                let mut v_h: u32 = height as u32;
                let mut v_n: u32 = height as u32;
                let mut params = [
                    &mut p_out as *mut _ as *mut c_void,
                    &mut p_parts as *mut _ as *mut c_void,
                    &mut p_prep as *mut _ as *mut c_void,
                    &mut p_pub as *mut _ as *mut c_void,
                    &mut p_chal as *mut _ as *mut c_void,
                    &mut v_h as *mut u32 as *mut c_void,
                    &mut v_n as *mut u32 as *mut c_void,
                ];
                let grid = (height as u32).div_ceil(256);
                unsafe { kernel.launch(grid, 256, 0, &mut params) }
            };
            match jit {
                // Off unless explicitly on — it allocates a device-side reference buffer per
                // launch; see the `Z1_JIT_VERIFY` note in `round0.rs`.
                Some(kernel) if crate::cuda::jit::env_flag("G1_JIT_VERIFY", false) => {
                    // Verify: JIT into scratch, interpreter into the real output, compare.
                    use crate::runtime::copy::MemCopyD2H;
                    let scratch =
                        DevBuf::<Frac<FK::ValExt>>::with_capacity(height * num_interactions);
                    let jit_ok = launch_jit(scratch.as_mut_ptr(), kernel);
                    run_gpu(trace_output)?;
                    match jit_ok {
                        Ok(()) => {
                            let a: Vec<Frac<FK::ValExt>> =
                                scratch.to_host().map_err(InteractionGpuError::Copy)?;
                            let b_buf = unsafe {
                                DevBuf::<Frac<FK::ValExt>>::from_raw_parts(
                                    trace_output,
                                    height * num_interactions,
                                )
                            };
                            let b: Vec<Frac<FK::ValExt>> =
                                b_buf.to_host().map_err(InteractionGpuError::Copy)?;
                            std::mem::forget(b_buf);
                            let mism = a
                                .iter()
                                .zip(b.iter())
                                .filter(|(x, y)| x.p != y.p || x.q != y.q)
                                .count();
                            if mism > 0 {
                                tracing::warn!(
                                    "[g1jit] VERIFY MISMATCH air_idx={}: {mism}/{} fracs differ",
                                    meta.air_idx,
                                    a.len()
                                );
                            } else {
                                tracing::info!(
                                    target: "bench",
                                    "[g1jit] VERIFY OK air_idx={} ({} fracs)",
                                    meta.air_idx,
                                    a.len()
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!("[g1jit] launch failed air_idx={}: {e}", meta.air_idx)
                        }
                    }
                }
                Some(kernel) => {
                    if let Err(e) = launch_jit(trace_output, kernel) {
                        // The bound device is part of the diagnosis, not decoration: a handle
                        // loaded on another card fails here with `CUDA_ERROR_INVALID_HANDLE` (400),
                        // and without the device printed that is indistinguishable from an ordinary
                        // launch failure. The fallback then hides it until a later, unrelated call
                        // reports the sticky error.
                        tracing::warn!(
                            "[g1jit] launch failed air_idx={} dev={:?}: {e}; falling back",
                            meta.air_idx,
                            crate::runtime::context::get_device()
                        );
                        run_gpu(trace_output)?;
                    }
                }
                None => {
                    // GPU interpreter path.
                    run_gpu(trace_output)?;
                }
            }
        }
        if height != lifted_height {
            debug_assert_eq!(lifted_height % height, 0);
            debug_assert!(!tmp.is_empty());
            let norm_factor_denom = lifted_height / height;
            let norm_factor = FK::Val::from_usize(norm_factor_denom).inverse();
            unsafe {
                // SAFETY: scaling within buffer length. Scale tmp in-place.
                FK::frac_vector_scalar_multiply_ext_fp(&mut tmp, norm_factor)?;
                // SAFETY: stacked interaction layout is defined with respect to lifted height, and
                // the vertical-repeat kernel guards rounded-up tail threads beyond lifted_height.
                FK::frac_matrix_vertically_repeat(
                    leaves_ptr,
                    &tmp,
                    num_interactions as u32,
                    lifted_height as u32,
                    height as u32,
                )?;
            }
        }
    }

    // alpha is deliberately left out of the leaves: `fractional_sumcheck_gpu` adds it while
    // building the first tree layer, which saves a separate pass over memory.
    Ok((leaves, alpha_logup))
}
