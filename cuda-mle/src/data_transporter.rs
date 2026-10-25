//! Host↔device transport for the `mle-core` HAL (`DeviceDataTransporter`): proving keys,
//! col-major trace matrices, stacked-PCS data, and Merkle trees. Row-major H2D/D2H goes through
//! the GPU transpose kernel (`matrix_transpose_fp_any`).
//!
//! **Sync contract:** H2D work is enqueued on the per-thread stream; every **public**
//! `transport_*` entry point synchronizes before returning, so its source may be dropped on
//! return. The one exception, `transport_and_unstack_single_data_h2d`, returns with transfers
//! merely enqueued — it is `pub(crate)` so that contract can't be violated from outside, and its
//! caller `transport_pk_to_device` owns the tail sync.
//!
//! **Transpose-dims convention:** `matrix_transpose_fp*` takes the dimensions of the INPUT
//! interpreted row-major — `(width, height)` for a row-major H2D source
//! (`transport_matrix_h2d_row_major`), and `(height, width)` for a col-major device source
//! (`transport_matrix_d2h_row_major`), because a col-major H×W buffer *is* a row-major W×H buffer.
//!
//! CPU counterpart: `mle-cpu/src/device.rs` (`impl DeviceDataTransporter for CpuDevice`);
//! reference oracle: `mle-core/src/prover/reference.rs`.

use std::{cmp::max, fmt::Debug, sync::Arc};

use crate::runtime::{
    copy::{cuda_memcpy, MemCopyD2H, MemCopyH2D},
    d_buffer::DeviceBuffer,
    error::MemCopyError,
    stream::current_stream_sync,
};
use mle_core::{
    keygen::types::MultiStarkProvingKey,
    p3_matrix::{dense::RowMajorMatrix, Matrix},
    poly::matrix::{ColMajorMatrix, MatrixDimensions, MatrixView},
    prover::{
        stacked_pcs::{ColMajorMerkleTree, StackedPcsData},
        CommittedTraceData, DeviceDataTransporter, DeviceMultiStarkProvingKey,
        DeviceStarkProvingKey, ProvingContext,
    },
};
use tracing::{debug, info_span};

use crate::{
    base::DeviceMatrix,
    gpu_backend::GenericGpuBackend,
    hash_scheme::GpuHashScheme,
    merkle_tree::MerkleTreeGpu,
    poly::PleMatrix,
    stacked_pcs::{stacked_commit, StackedPcsDataGpu},
    AirDataGpu, GpuDevice, GpuProverConfig, ProverError,
};

impl<HS> DeviceDataTransporter<HS::SC, GenericGpuBackend<HS>> for GpuDevice
where
    HS: GpuHashScheme,
{
    fn transport_pk_to_device(
        &self,
        mpk: &MultiStarkProvingKey<HS::SC>,
    ) -> DeviceMultiStarkProvingKey<GenericGpuBackend<HS>> {
        let _span = info_span!("transport_pk_to_device").entered();
        // GPU transport of a merged preprocessed commitment isn't implemented yet.
        // Dropping it silently would be unsound, not benign: the prover derives `merged_prep`
        // from the device key it's handed, while the verifier derives it from the verifying key —
        // passing `None` would build a proving key that skips the commit against a vk that still
        // expects it, a transcript divergence with no error at transport time.
        //
        // Tested on the commitment, which is merged mode's single source of truth — NOT on
        // `merged_preprocessed_data`: a key whose commit was deferred to an external committer
        // (`keygen_merged_preprocessed_deferred_commit`) carries the value with no host PCS data at all,
        // so testing the data would wave exactly those keys through this guard.
        assert!(
            mpk.merged_preprocessed_commit.is_none(),
            "GPU transport of merged preprocessed traces not implemented"
        );
        let per_air = mpk
            .per_air
            .iter()
            .map(|pk| {
                let preprocessed_data = pk.preprocessed_data.as_ref().map(|d| {
                    transport_and_unstack_single_data_h2d::<HS>(d.as_ref(), &self.prover_config)
                        .unwrap()
                });
                // Uncached: this is the per-AIR (RISC-V) path, whose key is built once per process.
                let other_data = Arc::new(AirDataGpu::<HS::BaseField>::new(pk).unwrap());
                let num_monomials = other_data
                    .zerocheck_monomials
                    .as_ref()
                    .map(|m| m.num_monomials)
                    .unwrap_or(0);
                // The zerocheck kernels' cost scales with `num_monomials` or `rules_len` depending
                // on which path a trace takes, and neither is reachable from the VK — so both are
                // logged here, where they are built.
                let rules_len = other_data.zerocheck_mle.inner.d_rules.len();
                debug!(air = %pk.air_name, num_monomials, rules_len, cols = pk.vk.params.width.common_main, deg = pk.vk.max_constraint_degree, "monomial expansion");

                DeviceStarkProvingKey {
                    air_name: pk.air_name.clone(),
                    vk: pk.vk.clone(),
                    preprocessed_data,
                    other_data,
                    symbolic_constraints_cache: std::sync::OnceLock::new(),
                }
            })
            .collect();
        // Wait for the uploads to land: other threads or streams may read this proving key.
        current_stream_sync().unwrap();

        DeviceMultiStarkProvingKey::new(
            per_air,
            mpk.trace_height_constraints.clone(),
            mpk.max_constraint_degree,
            mpk.params.clone(),
            mpk.vk_pre_hash,
            // Not yet transported — see the assert above.
            None,
        )
    }

    fn transport_matrix_to_device(
        &self,
        matrix: &ColMajorMatrix<<HS::SC as mle_core::StarkProtocolConfig>::F>,
    ) -> DeviceMatrix<<HS::SC as mle_core::StarkProtocolConfig>::F> {
        transport_matrix_h2d_col_major(matrix).unwrap()
    }

    fn transport_pcs_data_to_device(
        &self,
        pcs_data: &StackedPcsData<<HS::SC as mle_core::StarkProtocolConfig>::F, HS::Digest>,
    ) -> StackedPcsDataGpu<<HS::SC as mle_core::StarkProtocolConfig>::F, HS::Digest> {
        transport_pcs_data_h2d(pcs_data, &self.prover_config).unwrap()
    }

    fn transport_matrix_from_device_to_host(
        &self,
        matrix: &DeviceMatrix<<HS::SC as mle_core::StarkProtocolConfig>::F>,
    ) -> ColMajorMatrix<<HS::SC as mle_core::StarkProtocolConfig>::F> {
        transport_matrix_d2h_col_major(matrix).unwrap()
    }
}

/// Enqueue-only variant of [`transport_matrix_h2d_col_major`]: enqueues the H2D copy on the
/// per-thread stream and returns **without synchronizing**. Private — only callers in this module
/// own the tail sync.
///
/// Col-major already matches the device layout, so this is a plain byte copy with no kernel.
/// `matrix` is borrowed from a caller that outlives the sync; safe because the H2D source is
/// pageable host memory, which `cudaMemcpyAsync` stages inside the driver before returning.
fn enqueue_matrix_h2d_col_major<T>(
    matrix: &ColMajorMatrix<T>,
) -> Result<DeviceMatrix<T>, MemCopyError> {
    let buffer = matrix.values.to_device()?;
    Ok(DeviceMatrix::new(
        Arc::new(buffer),
        matrix.height(),
        matrix.width(),
    ))
}

/// H2D-transports an already-col-major matrix — a plain byte copy, no transpose kernel —
/// synchronizing before returning.
///
/// The sync is load-bearing for the external callers: the `transport_matrix_to_device` trait
/// method has no sync of its own, and `stacked_pcs.rs`'s callers likewise rely on this one.
pub fn transport_matrix_h2d_col_major<T>(
    matrix: &ColMajorMatrix<T>,
) -> Result<DeviceMatrix<T>, MemCopyError> {
    let out = enqueue_matrix_h2d_col_major(matrix)?;
    current_stream_sync()?;
    Ok(out)
}

/// H2D-transports a row-major matrix, transposing it to col-major on the GPU via the
/// byte-level `matrix_transpose_fp_any` kernel.
///
/// Works for any 4-byte field element — field-agnostic because
/// the kernel operates on raw bytes.
///
/// Synchronizes before returning, so the result is safe to hand to any consumer (including another
/// thread) and both the staging buffer and `matrix` may be dropped immediately.
pub fn transport_matrix_h2d_row_major<T: Copy + Send + Sync + 'static>(
    matrix: &RowMajorMatrix<T>,
) -> Result<DeviceMatrix<T>, MemCopyError> {
    use crate::cuda::matrix::matrix_transpose_fp_any;
    let data = matrix.values.as_slice();
    let input_buffer = data.to_device()?;
    let output = DeviceMatrix::<T>::with_capacity(Matrix::height(matrix), Matrix::width(matrix));
    unsafe {
        matrix_transpose_fp_any(
            output.buffer(),
            &input_buffer,
            Matrix::width(matrix),
            Matrix::height(matrix),
        )?;
    }
    current_stream_sync()?;
    debug_assert_eq!(output.strong_count(), 1);
    Ok(output)
}

/// Uploads the stacked PCS data of exactly one trace matrix (`src_pcs`) and unstacks it into a
/// freshly allocated `CommittedTraceData<GenericGpuBackend<HS>>`.
///
/// **Returns with its transfers merely enqueued** — there is no tail sync. Same-thread device
/// consumers are stream-ordered and need none; what makes the resulting proving key safe to
/// *share across threads* is `transport_pk_to_device`'s own tail sync. `pub(crate)` precisely so
/// that contract cannot be violated from outside the crate.
///
/// The sync in the middle (strided traces only) is a different matter: it keeps
/// `drop(padded_trace)` from racing the collapse kernel, and has nothing to do with batching.
pub(crate) fn transport_and_unstack_single_data_h2d<HS: GpuHashScheme>(
    src_pcs: &StackedPcsData<HS::BaseField, HS::Digest>,
    prover_config: &GpuProverConfig,
) -> Result<CommittedTraceData<GenericGpuBackend<HS>>, ProverError> {
    use crate::cuda::matrix::collapse_strided_matrix_any;
    let _span = info_span!("transport_unstack_h2d").entered();
    debug_assert!(src_pcs
        .layout
        .sorted_cols
        .iter()
        .all(|col| col.mat_idx == 0));
    let l_skip = src_pcs.layout.l_skip();
    let trace_view_0 = src_pcs.mat_view(0);
    let h = trace_view_0.height();
    let w = trace_view_0.width();
    let row_stride = trace_view_0.stride();
    let lifted_h = h * row_stride;
    debug_assert_eq!(lifted_h, max(h, 1 << l_skip));
    debug_assert_eq!(lifted_h * w, trace_view_0.values().len());
    debug_assert!(src_pcs.matrix.values.len() >= lifted_h * w);
    let stk_w = src_pcs.matrix.width();
    let stk_h = src_pcs.matrix.height();
    // The trace occupies exactly the `lifted_h * w` prefix of the stacked matrix
    // (`StackedLayout::new` never lets a column straddle beyond its lifted height), so that
    // prefix is all the unstacked trace needs. Whether the full matrix is also uploaded depends
    // only on whether it's kept as `PleMatrix` below.
    let (dev_evals, padded_trace) = if prover_config.cache_stacked_matrix {
        // Cached: the full stacked matrix must live on device anyway, so upload it once and take
        // the prefix out with a D2D copy.
        let ev = src_pcs.matrix.values.to_device()?;
        let pref = DeviceBuffer::<HS::BaseField>::with_capacity(lifted_h * w);
        // SAFETY: D2D copy using raw bytes (all 4-byte field elements have same layout)
        unsafe {
            cuda_memcpy::<true, true>(
                pref.as_mut_raw_ptr(),
                ev.as_raw_ptr(),
                lifted_h * w * size_of::<HS::BaseField>(),
            )?;
        }
        (Some(ev), pref)
    } else {
        // Production default: upload only the prefix from the host directly, rather than
        // uploading the full matrix and D2D-copying the prefix out — avoids a redundant
        // device-to-device copy and a transient full-size allocation. Also safer: the
        // `debug_assert!` above compiles out in release, so slicing on the host turns a would-be
        // out-of-bounds D2D read into a panic.
        (None, src_pcs.matrix.values[..lifted_h * w].to_device()?)
    };
    let trace_dev = if row_stride == 1 {
        padded_trace
    } else {
        let dense = DeviceBuffer::<HS::BaseField>::with_capacity(h * w);
        unsafe {
            collapse_strided_matrix_any(
                dense.as_mut_ptr(),
                padded_trace.as_ptr(),
                w as u32,
                h as u32,
                row_stride as u32,
            )
            .map_err(ProverError::CollapseStrided)?;
        }
        // The collapse kernel still reads padded_trace; let it finish before freeing.
        current_stream_sync().map_err(ProverError::CurrentStreamSync)?;
        drop(padded_trace);
        dense
    };
    // `Some` exactly when `cache_stacked_matrix` — the branch above is the only producer.
    let ple = dev_evals.map(|ev| PleMatrix::from_evals(l_skip, ev, stk_h, stk_w));
    let dev_tree = enqueue_merkle_tree_h2d(&src_pcs.tree, prover_config.cache_rs_code_matrix)?;
    let dev_data = StackedPcsDataGpu {
        layout: src_pcs.layout.clone(),
        matrix: ple,
        tree: dev_tree,
    };
    // Cheap consistency check only: the tree was copied over, not rebuilt from the data.
    assert!(
        dev_data.tree.root() == src_pcs.commit().unwrap(),
        "transported tree root mismatch"
    );
    Ok(CommittedTraceData {
        commitment: src_pcs.commit().unwrap(),
        trace: DeviceMatrix::new(Arc::new(trace_dev), h, w),
        data: Arc::new(dev_data),
    })
}

/// Enqueues the backing-matrix copy (when cached) and every digest-layer copy on the per-thread
/// stream, returning **without synchronizing**. Private; callers own a tail sync.
///
/// `root` is read off the **host** tree, never from device memory, so the returned value is fully
/// initialized on return even though the layer copies are still in flight.
fn enqueue_merkle_tree_h2d<F, Digest: Clone>(
    tree: &ColMajorMerkleTree<F, Digest>,
    cache_backing_matrix: bool,
) -> Result<MerkleTreeGpu<F, Digest>, MemCopyError> {
    let backing_matrix = if cache_backing_matrix {
        Some(enqueue_matrix_h2d_col_major(tree.backing_matrix())?)
    } else {
        None
    };
    let digest_layers = tree
        .digest_layers()
        .iter()
        .map(|layer| layer.to_device())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(MerkleTreeGpu {
        backing_matrix,
        digest_layers,
        rows_per_query: tree.rows_per_query(),
        root: tree.root().unwrap(),
    })
}

pub fn transport_pcs_data_h2d<
    FieldT: crate::ntt_field::GpuNttField,
    D: Copy + Clone + PartialEq + Send + Sync + 'static,
>(
    pcs_data: &StackedPcsData<FieldT, D>,
    prover_config: &GpuProverConfig,
) -> Result<StackedPcsDataGpu<FieldT, D>, ProverError> {
    let _span = info_span!("transport_pcs_data_h2d").entered();
    let StackedPcsData {
        layout,
        matrix,
        tree,
    } = pcs_data;
    let width = matrix.width();
    let height = matrix.height();
    let d_matrix_evals = matrix.values.to_device()?;
    let d_matrix = prover_config
        .cache_stacked_matrix
        .then(|| PleMatrix::from_evals(layout.l_skip(), d_matrix_evals, height, width));
    let d_tree = enqueue_merkle_tree_h2d(tree, prover_config.cache_rs_code_matrix)?;
    // Single host-side wait for everything this entry point enqueued (backing matrix, digest
    // layers, stacked-matrix evals).
    current_stream_sync().map_err(ProverError::CurrentStreamSync)?;

    Ok(StackedPcsDataGpu {
        layout: layout.clone(),
        matrix: d_matrix,
        tree: d_tree,
    })
}

/// Whether keygen timers may insert extra stream syncs to attribute device time to the stage that
/// enqueued it. Off by default: the syncs remove real overlap, so they change what they measure.
fn keygen_timing_sync_enabled() -> bool {
    std::env::var("MLE_KEYGEN_TIMING_SYNC")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(false)
}

/// Assemble a device proving key whose merged preprocessed commitment is built ON the device from
/// device-resident preprocessed traces (one optional col-major matrix per AIR, in AIR order),
/// cross-checked against the host keygen.
///
/// The host pk is the reference for everything except the commitment: per-air vks /
/// `vk_pre_hash` / params are taken from it verbatim. The commitment itself is the device's, and
/// it is INSTALLED into `mpk` here — so the host key and the device key always agree on it, and
/// the caller's `get_vk()` is valid only after this returns.
///
/// Two host modes, both accepted:
/// - **Committing** (`merged_preprocessed_data` is `Some`): the host also ran the CPU stacked
///   commit, and the device root MUST equal it. This is the full cross-check.
/// - **Deferred** (`None`, from `keygen_merged_preprocessed_deferred_commit`): the host skipped the CPU
///   commit — an RS-encode plus a full Merkle tree that only ever produced a digest to compare
///   against this one — and carries a placeholder that this call replaces.
///
/// Either way the structural guard below is unconditional: the device traces must match the host
/// keygen's declared geometry AIR by AIR. That is what catches broken device preprocessed
/// generation, and it does not need the host to have committed anything. Panics on divergence
/// (proving under a mismatched key would surface only as a verifier rejection).
///
/// This is the merged-preprocessed device-key path that `transport_pk_to_device` rejects (its
/// assert): instead of transporting host PCS data, the caller supplies device traces and the
/// commitment is recomputed on the GPU.
///
/// Sync contract: synchronizes the per-thread stream before returning (transporter convention),
/// so the caller may release the trace sources afterwards.
pub fn assemble_pk_with_device_merged_prep<HS: GpuHashScheme>(
    device: &GpuDevice,
    mpk: &mut MultiStarkProvingKey<HS::SC>,
    mut per_air_prep: Vec<Option<DeviceMatrix<HS::BaseField>>>,
) -> Result<DeviceMultiStarkProvingKey<GenericGpuBackend<HS>>, ProverError>
where
    HS::MerkleHash: crate::merkle_tree::MerkleTreeConstructor,
{
    let _span = info_span!("assemble_pk_with_device_merged_prep").entered();
    assert!(
        mpk.merged_preprocessed_commit.is_some(),
        "assemble_pk_with_device_merged_prep requires a merged-preprocessed host pk"
    );
    let host_commit = mpk.merged_preprocessed_data.as_ref().map(|d| {
        d.commit()
            .expect("host merged preprocessed data without a commitment")
    });
    assert_eq!(
        per_air_prep.len(),
        mpk.per_air.len(),
        "one preprocessed slot per AIR"
    );

    // Presence AND geometry must match the host keygen air-by-air. Presence or dimensions that
    // differ would change the stacking layout, so the device would commit a structurally
    // different key; heights also fix the commit ordering below, so checking them here subsumes
    // an explicit ordering check. This is the always-on tripwire on device preprocessed
    // generation — the digest comparison further down only runs when the host also committed.
    let l_skip = mpk.params.l_skip as isize;
    for (pk, prep) in mpk.per_air.iter().zip(&per_air_prep) {
        assert_eq!(
            pk.vk.preprocessed_data.is_some(),
            prep.is_some(),
            "device preprocessed presence diverges from host keygen for AIR {}",
            pk.air_name
        );
        if let (Some(vdata), Some(m)) = (pk.vk.preprocessed_data.as_ref(), prep.as_ref()) {
            let host_log_height = vdata.hypercube_dim + l_skip;
            assert_eq!(
                m.height(),
                1usize << host_log_height,
                "device preprocessed height diverges from host keygen for AIR {}",
                pk.air_name
            );
            assert_eq!(
                Some(m.width()),
                pk.vk.params.width.preprocessed,
                "device preprocessed width diverges from host keygen for AIR {}",
                pk.air_name
            );
        }
    }

    // Pinned commit order: descending height, ties by ascending AIR index (must match the host
    // keygen's `commit_merged_preprocessed` sort).
    let mut ordered: Vec<(usize, &DeviceMatrix<HS::BaseField>)> = per_air_prep
        .iter()
        .enumerate()
        .filter_map(|(air_idx, m)| m.as_ref().map(|m| (air_idx, m)))
        .collect();
    ordered.sort_by_key(|(air_idx, m)| (std::cmp::Reverse(m.height()), *air_idx));
    let trace_refs: Vec<&DeviceMatrix<HS::BaseField>> = ordered.iter().map(|(_, m)| *m).collect();

    // Copied out before the `&mut mpk` below; part of the `AirDataGpu` cache key.
    let params_l_skip = mpk.params.l_skip as u32;
    let params = &mpk.params;
    let t_commit = std::time::Instant::now();
    let (root, data) = stacked_commit::<HS::BaseField, HS::MerkleHash>(
        params.l_skip,
        params.n_stack,
        params.log_blowup,
        params.k_whir(),
        &trace_refs,
        device.prover_config,
    )?;
    // `MLE_KEYGEN_TIMING_SYNC=1` charges the commit's device time to `commit_dev_ms` instead of
    // leaving it in the shared trailing sync. It costs the commit/upload overlap, so it is a
    // measurement mode, not the default — see the timing note on the info line below.
    if keygen_timing_sync_enabled() {
        current_stream_sync().map_err(ProverError::CurrentStreamSync)?;
    }
    let commit_dev_ms = t_commit.elapsed().as_millis();
    drop(trace_refs);
    drop(ordered);
    if let Some(host_commit) = host_commit {
        assert!(
            root == host_commit,
            "device merged preprocessed commitment diverges from the host keygen — device \
             preprocessed generation or the device commit is broken; refusing to build the key"
        );
    }
    // Install the device root as THE commitment, so the host vk and the device key cannot drift.
    // A no-op in committing mode (asserted equal just above).
    mpk.patch_merged_preprocessed_commit(root);
    let shared = Arc::new(data);

    let t_air_data = std::time::Instant::now();
    let per_air = mpk
        .per_air
        .iter()
        .enumerate()
        .map(|(air_idx, pk)| {
            let preprocessed_data = per_air_prep[air_idx]
                .take()
                .map(|trace| CommittedTraceData {
                    commitment: root,
                    trace,
                    data: shared.clone(),
                });
            let other_data =
                crate::pkey::air_data_gpu_cached(pk, device.id, params_l_skip).unwrap();
            DeviceStarkProvingKey {
                air_name: pk.air_name.clone(),
                vk: pk.vk.clone(),
                preprocessed_data,
                other_data,
                symbolic_constraints_cache: std::sync::OnceLock::new(),
            }
        })
        .collect();
    let air_data_ms = t_air_data.elapsed().as_millis();

    // Single host-side wait for everything enqueued above (commit kernels + AirDataGpu copies).
    let t_sync = std::time::Instant::now();
    current_stream_sync().map_err(ProverError::CurrentStreamSync)?;
    let sync_ms = t_sync.elapsed().as_millis();

    // Splits this function's cost into its one non-cacheable term (the per-layout device commit)
    // and its cacheable one (`AirDataGpu::new` per AIR: rule scheduling, monomial expansion, JIT
    // source emission, H2D). Both are enqueue-side unless `MLE_KEYGEN_TIMING_SYNC=1`; the device
    // tail they share lands in `sync_ms`. Hits/misses are cumulative over the process.
    tracing::info!(
        "mle_assemble_detail: commit_dev_ms = {commit_dev_ms}, air_data_ms = {air_data_ms}, \
         sync_ms = {sync_ms}, timing_sync = {}, air_data_hits = {}, air_data_misses = {}",
        keygen_timing_sync_enabled(),
        crate::pkey::AIR_DATA_HITS.load(std::sync::atomic::Ordering::Relaxed),
        crate::pkey::AIR_DATA_MISSES.load(std::sync::atomic::Ordering::Relaxed),
    );

    Ok(DeviceMultiStarkProvingKey::new(
        per_air,
        mpk.trace_height_constraints.clone(),
        mpk.max_constraint_degree,
        mpk.params.clone(),
        mpk.vk_pre_hash,
        Some((root, shared)),
    ))
}

/// Transport a row-major CPU proving context to GPU.
///
/// Accepts `ProvingContext<PB>` where `PB::Matrix = RowMajorMatrix<HS::BaseField>`
/// (e.g. from `pico_mle_cpu::CpuBackend`) and returns
/// `ProvingContext<GenericGpuBackend<HS>>` (col-major GPU DeviceMatrix).
/// The transpose (row→col) is performed on GPU using `matrix_transpose_fp_any`.
pub fn transport_row_major_ctx_to_device<HS, PB>(
    cpu_ctx: ProvingContext<PB>,
) -> Result<ProvingContext<GenericGpuBackend<HS>>, MemCopyError>
where
    HS: GpuHashScheme,
    PB: mle_core::prover::ProverBackend<
        Matrix = mle_core::p3_matrix::dense::RowMajorMatrix<HS::BaseField>,
        Val = HS::BaseField,
    >,
{
    use mle_core::prover::AirProvingContext as APC;
    let per_trace = cpu_ctx
        .per_trace
        .into_iter()
        .map(|(air_id, air_ctx)| {
            assert!(
                air_ctx.cached_mains.is_empty(),
                "cached_mains transport (CpuStackedPcsData -> StackedPcsDataGpu) is not \
                 implemented; the RISCV byte_prep/prog_prep path requires it"
            );
            // Transpose row-major CPU matrix to col-major GPU DeviceMatrix (generic)
            let gpu_matrix = transport_matrix_h2d_row_major(&air_ctx.common_main)?;
            // Public values stay as field elements (small, no GPU upload needed)
            Ok((
                air_id,
                APC {
                    cached_mains: vec![],
                    common_main: gpu_matrix,
                    public_values: air_ctx.public_values,
                },
            ))
        })
        .collect::<Result<Vec<_>, MemCopyError>>()?;
    current_stream_sync()?;
    Ok(ProvingContext { per_trace })
}

pub fn transport_matrix_d2h_col_major<T>(
    matrix: &DeviceMatrix<T>,
) -> Result<ColMajorMatrix<T>, MemCopyError> {
    let values_host = matrix.buffer().to_host()?;
    Ok(ColMajorMatrix::new(values_host, matrix.width()))
}

/// D2H-transports a col-major device matrix, transposing it to row-major on the GPU via the
/// byte-level `matrix_transpose_fp_any` kernel before copying it home. `to_host` already
/// synchronizes (`runtime/copy.rs`), so no extra sync is needed here.
pub fn transport_matrix_d2h_row_major<T: Copy + Send + Sync + 'static>(
    matrix: &DeviceMatrix<T>,
) -> Result<RowMajorMatrix<T>, MemCopyError> {
    use crate::cuda::matrix::matrix_transpose_fp_any;
    let matrix_buffer = DeviceBuffer::<T>::with_capacity(matrix.height() * matrix.width());
    unsafe {
        matrix_transpose_fp_any(
            &matrix_buffer,
            matrix.buffer(),
            matrix.height(),
            matrix.width(),
        )?;
    }
    Ok(RowMajorMatrix::<T>::new(
        matrix_buffer.to_host()?,
        matrix.width(),
    ))
}

#[cfg(test)]
pub fn assert_eq_host_and_device_matrix_col_maj<T: Clone + Send + Sync + PartialEq + Debug>(
    cpu: &ColMajorMatrix<T>,
    gpu: &DeviceMatrix<T>,
) {
    assert_eq!(gpu.width(), cpu.width());
    assert_eq!(gpu.height(), cpu.height());
    let gpu = gpu.to_host().unwrap();
    for r in 0..cpu.height() {
        for c in 0..cpu.width() {
            assert_eq!(
                gpu[c * cpu.height() + r],
                *cpu.get(r, c).unwrap(),
                "Mismatch at row {} column {}",
                r,
                c
            );
        }
    }
}

#[cfg(test)]
pub fn assert_eq_device_matrix<T: Clone + Send + Sync + PartialEq + Debug>(
    a: &DeviceMatrix<T>,
    b: &DeviceMatrix<T>,
) {
    assert_eq!(a.height(), b.height());
    assert_eq!(a.width(), b.width());
    assert_eq!(a.buffer().len(), b.buffer().len());
    let a_host = a.to_host().unwrap();
    let b_host = b.to_host().unwrap();
    for r in 0..a.height() {
        for c in 0..a.width() {
            assert_eq!(
                a_host[c * a.height() + r],
                b_host[c * b.height() + r],
                "Mismatch at row {} column {}",
                r,
                c
            );
        }
    }
}

#[cfg(test)]
pub fn assert_eq_host_and_device_matrix<T: Clone + Send + Sync + PartialEq + Debug>(
    cpu: Arc<RowMajorMatrix<T>>,
    gpu: &DeviceMatrix<T>,
) {
    assert_eq!(gpu.width(), Matrix::width(cpu.as_ref()));
    assert_eq!(gpu.height(), Matrix::height(cpu.as_ref()));
    let gpu = gpu.to_host().unwrap();
    for r in 0..Matrix::height(cpu.as_ref()) {
        for c in 0..Matrix::width(cpu.as_ref()) {
            assert_eq!(
                gpu[c * Matrix::height(cpu.as_ref()) + r],
                cpu.get(r, c).unwrap(),
                "Mismatch at row {} column {}",
                r,
                c
            );
        }
    }
}

/// Element-wise transport parity tests, against an independent oracle (the host original, or a
/// second host-side construction path) — never `prover == prover`. See the module doc for the
/// transpose-dims convention these tests settle empirically.
#[cfg(test)]
mod transport_tests {
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    use super::*;
    use crate::hash_scheme::KoalaBearPoseidon2HashScheme;

    type Kb = KoalaBear;

    fn kb(v: u32) -> Kb {
        Kb::from_u32(v)
    }

    #[test]
    fn col_major_h2d_d2h_round_trip_is_element_wise_identity() {
        let (height, width) = (8, 3);
        let values: Vec<Kb> = (0..height * width).map(|i| kb(i as u32 + 1)).collect();
        let host = ColMajorMatrix::new(values.clone(), width);
        let dev = transport_matrix_h2d_col_major(&host).unwrap();
        assert_eq!((dev.height(), dev.width()), (height, width));
        // H2D oracle: the device buffer matches the host original element-wise. The col-major
        // path is a plain byte copy (no transpose kernel), so this pins down copy fidelity
        // independent of the transpose kernel exercised by the row-major tests below.
        assert_eq_host_and_device_matrix_col_maj(&host, &dev);
        let back = transport_matrix_d2h_col_major(&dev).unwrap();
        assert_eq!(back.values, values); // element-wise, same layout — oracle is the host original
    }

    #[test]
    fn row_major_h2d_transposes_exactly() {
        // Non-square on purpose: a swapped (width, height) argument pair cannot pass this test.
        // This is the test that settles the matrix_transpose_fp dims question (see module doc).
        let (height, width) = (8, 3);
        let values: Vec<Kb> = (0..height * width).map(|i| kb(i as u32 + 1)).collect();
        let host = RowMajorMatrix::new(values, width);
        let dev = transport_matrix_h2d_row_major(&host).unwrap();

        // Oracle 1 (GPU-GPU, independent of the transpose kernel): transpose the same values on
        // the CPU (`ColMajorMatrix::from_row_major`, a plain-Rust transpose used all over the
        // codebase's test fixtures — no GPU involved) and H2D the result through the
        // *untransposed* col-major path (a raw byte copy, no kernel). If the GPU transpose
        // kernel is correct, the two independently-produced device buffers must agree
        // element-wise.
        let host_col = ColMajorMatrix::from_row_major(&host);
        let dev_col = transport_matrix_h2d_col_major(&host_col).unwrap();
        assert_eq_device_matrix(&dev, &dev_col);

        // Oracle 2 (host-device): the row-major host original directly, via the
        // host-row-major/device-col-major helper — exactly the index mapping the transpose
        // kernel promises.
        assert_eq_host_and_device_matrix(Arc::new(host), &dev);
    }

    #[test]
    fn row_major_d2h_inverts_row_major_h2d() {
        let (height, width) = (5, 7);
        let values: Vec<Kb> = (0..height * width).map(|i| kb(i as u32)).collect();
        let host = RowMajorMatrix::new(values.clone(), width);
        let dev = transport_matrix_h2d_row_major(&host).unwrap();
        let back = transport_matrix_d2h_row_major(&dev).unwrap();
        // NOTE: this passes even if BOTH directions swapped dims consistently —
        // `row_major_h2d_transposes_exactly` is the binding direction test.
        assert_eq!(back.values, values);
    }

    /// Small **single-trace** stacked-PCS fixture — built the way `mle-cpu/src/device.rs`'s
    /// transport round-trip tests and `cuda-mle/src/tests.rs`'s stacked-reduction test do.
    /// Single-trace matters: `transport_and_unstack_single_data_h2d` debug-asserts
    /// `sorted_cols[*].mat_idx == 0`.
    ///
    /// Returns the host trace (an oracle independent of every transport path), the commitment
    /// root, and the committed data.
    #[allow(clippy::type_complexity)]
    fn build_host_pcs_fixture() -> (
        ColMajorMatrix<Kb>,
        <KoalaBearPoseidon2HashScheme as GpuHashScheme>::Digest,
        StackedPcsData<Kb, <KoalaBearPoseidon2HashScheme as GpuHashScheme>::Digest>,
    ) {
        use mle_core::{
            prover::stacked_pcs::stacked_commit, test_utils::test_system_params_small, StarkEngine,
            StarkProtocolConfig,
        };

        use crate::KoalaBearPoseidon2GpuEngine;

        let (l_skip, n_stack, k_whir) = (0usize, 3usize, 1usize);
        let params = test_system_params_small(l_skip, n_stack, k_whir);
        let engine = KoalaBearPoseidon2GpuEngine::new(params.clone());
        let config = engine.config();
        let hasher = config.hasher();

        let height = 1usize << (l_skip + n_stack);
        let width = 3usize;
        let values: Vec<Kb> = (0..(width * height) as u32).map(|v| kb(v + 1)).collect();
        let trace = ColMajorMatrix::new(values, width);

        let (root, host_data) = stacked_commit(
            hasher,
            params.l_skip,
            params.n_stack,
            params.log_blowup,
            params.k_whir(),
            &[&trace],
        )
        .unwrap();
        (trace, root, host_data)
    }

    /// `StackedPcsData` H2D parity: commitment identity, element-wise matrix identity, and
    /// digest-layer identity, all against the host `stacked_commit` oracle.
    #[test]
    fn pcs_data_h2d_preserves_root_and_matrix_element_wise() {
        let (_trace, root, host_data) = build_host_pcs_fixture();

        let gpu_config = GpuProverConfig {
            cache_stacked_matrix: true,
            cache_rs_code_matrix: true,
            ..Default::default()
        };
        let gpu = transport_pcs_data_h2d(&host_data, &gpu_config).unwrap();

        // 1. Commitment identity: the transported tree root equals the host commit — an oracle
        // independent of the transport path (the host `stacked_commit` computed `root` and
        // `host_data`'s own tree agree by construction; the GPU side's `root` field is uploaded,
        // never recomputed, so this checks the upload didn't corrupt it).
        assert_eq!(gpu.tree.root(), root);
        assert_eq!(gpu.tree.root(), host_data.commit().unwrap());

        // 2. Element-wise matrix identity after D2H. `l_skip == 0` so `PleMatrix::from_evals`
        // skips its NTT step entirely (see `from_evals`'s `if l_skip > 0` guard) and `mixed` is
        // byte-identical to the input evals — safe to read directly via a raw D2H. (`to_evals` is
        // generic over any `GpuNttField`, including `PleMatrix<KoalaBear>`; the raw D2H here is
        // just a shortcut since `l_skip == 0` makes the NTT a no-op anyway.)
        let mixed_host = gpu.matrix.as_ref().unwrap().mixed().to_host().unwrap();
        assert_eq!(mixed_host, host_data.matrix.values);

        // 3. Digest layers element-wise, against the host tree's own layers. The length assert is
        // load-bearing: `zip` stops at the shorter side, so without it a dropped layer would pass
        // vacuously.
        assert_eq!(
            gpu.tree.digest_layers.len(),
            host_data.tree.digest_layers().len()
        );
        for (gpu_layer, host_layer) in gpu
            .tree
            .digest_layers
            .iter()
            .zip(host_data.tree.digest_layers())
        {
            assert_eq!(&gpu_layer.to_host().unwrap(), host_layer);
        }
    }

    /// The `cache_stacked_matrix == false` arm uploads only the `lifted_height * width` prefix
    /// instead of the full stacked matrix; the `== true` arm still uploads the whole thing and
    /// D2D-copies the prefix out. Both must yield the same unstacked trace.
    ///
    /// Note on oracles: `a.commitment == b.commitment` is **tautological** — both arms read
    /// `d.commit()` off the host, untouched by the branch — so it is kept only as a labelled
    /// sanity line. The GPU↔GPU trace comparison alone is also insufficient, since both arms
    /// derive the prefix bound from the same `lifted_height * width` expression: a wrong bound
    /// would move both together. The binding assertion is therefore against the **host** oracle,
    /// `mat_view(0)` — `mle-core`'s own unstacking of the stacked matrix, computed without the GPU.
    #[test]
    fn unstack_prefix_upload_matches_cached_path() {
        let (trace, _root, host_data) = build_host_pcs_fixture();

        let cached = GpuProverConfig {
            cache_stacked_matrix: true,
            cache_rs_code_matrix: true,
            ..Default::default()
        };
        let default_cfg = GpuProverConfig {
            cache_stacked_matrix: false,
            cache_rs_code_matrix: true,
            ..Default::default()
        };

        let a = transport_and_unstack_single_data_h2d::<KoalaBearPoseidon2HashScheme>(
            &host_data, &cached,
        )
        .unwrap();
        let b = transport_and_unstack_single_data_h2d::<KoalaBearPoseidon2HashScheme>(
            &host_data,
            &default_cfg,
        )
        .unwrap();

        // Sanity line only (see the doc above): not evidence.
        assert_eq!(a.commitment, b.commitment);

        // The full stacked matrix is retained on the cached arm and absent on the default arm —
        // this is what makes the two config values exercise genuinely different code paths.
        assert!(
            a.data.matrix.is_some(),
            "cached arm must keep the stacked matrix"
        );
        assert!(
            b.data.matrix.is_none(),
            "default arm must not keep the stacked matrix"
        );

        // Dimensions agree with the host view.
        let view = host_data.mat_view(0);
        assert_eq!(
            view.stride(),
            1,
            "fixture must be stride-1 so the trace is directly comparable element-wise"
        );
        assert_eq!(
            (a.trace.height(), a.trace.width()),
            (view.height(), view.width())
        );
        assert_eq!(
            (b.trace.height(), b.trace.width()),
            (view.height(), view.width())
        );

        // Binding assertion: both arms match the host oracle element-wise. `mat_view(0).values()`
        // is `mle-core`'s host-side unstack of the same stacked matrix, so a wrong prefix bound on
        // either arm shows up here even though it would move both GPU arms together.
        let a_host = a.trace.to_host().unwrap();
        let b_host = b.trace.to_host().unwrap();
        assert_eq!(a_host, view.values());
        assert_eq!(b_host, view.values());
        // ...and against the original host trace, which never went near the stacking code.
        assert_eq!(a_host, trace.values);
        assert_eq!(b_host, trace.values);
    }

    /// Tests transport of a whole `ProvingContext`, not just a single matrix: two
    /// differently-shaped traces catch a per-trace indexing mistake that a single-entry context
    /// could not (the wrong trace's bytes under the wrong `air_id`, or dims swapped for one trace
    /// but not the other). Unlike `mle-core`'s HAL default
    /// (`transport_row_major_proving_ctx_to_device`), which transposes each trace on the host,
    /// this path transposes on the GPU (`transport_matrix_h2d_row_major`), so the assertion below
    /// checks the GPU transpose element-wise against the untouched host original.
    #[test]
    fn row_major_ctx_to_device_transposes_each_trace() {
        use mle_core::prover::{AirProvingContext, ProvingContext, RowMajorHostBackend};

        type Sc = mle_core::config::koala_bear_poseidon2::KoalaBearPoseidon2Config;

        /// Per-trace check, extracted so the same element-wise assertion runs for both traces
        /// below without duplicating the loop.
        fn assert_trace_transposed(
            air_id: usize,
            dev_air: &AirProvingContext<GenericGpuBackend<KoalaBearPoseidon2HashScheme>>,
            host_trace: &RowMajorMatrix<Kb>,
            expected_pv: &[Kb],
        ) {
            assert!(
                dev_air.cached_mains.is_empty(),
                "cached_mains must stay empty through transport (air_id {air_id})"
            );
            assert_eq!(
                dev_air.public_values.as_slice(),
                expected_pv,
                "public values must survive transport unchanged (air_id {air_id})"
            );

            // Bring the device matrix back to host via the crate's own D2H entry point, and check
            // every element against the untouched row-major host original — same
            // (c * height + r) <-> (r * width + c) convention `row_major_h2d_transposes_exactly`
            // settles for the single-matrix path. This is the assertion that proves the ctx-level
            // entry point's per-trace GPU transpose is correct, not merely that it returned.
            let col = transport_matrix_d2h_col_major(&dev_air.common_main).unwrap();
            // Disambiguated: both `Matrix` and `MatrixDimensions` are in scope and both provide
            // `height`/`width` for `RowMajorMatrix` (see `transport_matrix_h2d_row_major` above,
            // which does the same for the same reason).
            let (height, width) = (Matrix::height(host_trace), Matrix::width(host_trace));
            assert_eq!(
                (col.height(), col.width()),
                (height, width),
                "dims must survive transport (air_id {air_id})"
            );
            for r in 0..height {
                for c in 0..width {
                    assert_eq!(
                        col.values[c * height + r],
                        host_trace.values[r * width + c],
                        "Mismatch at row {r} column {c} (air_id {air_id})"
                    );
                }
            }
        }

        // Two traces, non-square with distinct dimensions each — neither a swapped
        // (width, height) pair nor a trace landing under the wrong air_id can pass. Heights are
        // powers of two (widths need not be): `transport_matrix_d2h_col_major` wraps the result in
        // a `ColMajorMatrix`, whose constructor (`mle-core/src/poly/matrix.rs`) asserts
        // `height.is_power_of_two()` — a real, pre-existing precondition of the host oracle type,
        // not a transpose-correctness question, so the fixture must respect it.
        let (h0, w0) = (4usize, 7usize);
        let values0: Vec<Kb> = (0..(h0 * w0) as u32).map(|i| kb(i + 1)).collect();
        let trace0 = RowMajorMatrix::new(values0, w0);
        let pv0 = vec![kb(101), kb(202)];

        let (h1, w1) = (8usize, 3usize);
        let values1: Vec<Kb> = (0..(h1 * w1) as u32).map(|i| kb(i + 1000)).collect();
        let trace1 = RowMajorMatrix::new(values1, w1);
        let pv1 = vec![kb(303)];

        // air_ids deliberately out of ascending order, to check they survive transport as given
        // rather than being resorted or reassigned by position.
        let air0 =
            AirProvingContext::<RowMajorHostBackend<Sc>>::simple(trace0.clone(), pv0.clone());
        let air1 =
            AirProvingContext::<RowMajorHostBackend<Sc>>::simple(trace1.clone(), pv1.clone());
        let host_ctx = ProvingContext::new(vec![(5usize, air0), (2usize, air1)]);

        let dev_ctx = transport_row_major_ctx_to_device::<
            KoalaBearPoseidon2HashScheme,
            RowMajorHostBackend<Sc>,
        >(host_ctx)
        .unwrap();

        assert_eq!(
            dev_ctx.per_trace.len(),
            2,
            "per-trace count must survive transport"
        );

        let (air_id0, dev0) = &dev_ctx.per_trace[0];
        assert_eq!(*air_id0, 5, "air_id must survive transport unchanged");
        assert_trace_transposed(*air_id0, dev0, &trace0, &pv0);

        let (air_id1, dev1) = &dev_ctx.per_trace[1];
        assert_eq!(*air_id1, 2, "air_id must survive transport unchanged");
        assert_trace_transposed(*air_id1, dev1, &trace1, &pv1);
    }
}
