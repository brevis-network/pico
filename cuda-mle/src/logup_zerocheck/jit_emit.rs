//! Straight-line CUDA codegen for GKR interaction evaluation.
//!
//! Walks the same typed rule list (`SymbolicRulesGpu`) the runtime interpreter executes and emits
//! one CUDA statement per rule, with variables resolved to direct loads and constants embedded as
//! Montgomery literals. The generated source is fully self-contained (its own KoalaBear Montgomery
//! and extension arithmetic for the crate's `D_EF` — x^4 − 3 or x^5 + x^2 − 1, REDC with
//! M0 = −MOD⁻¹ mod 2³²; see [`preamble`]), so nvrtc needs no
//! host headers. Output ABI matches `evaluate_interactions_gkr_kernel` exactly (FpExt writes at
//! `(pair>>1)*H + row`, parity-selected) — bit-exact with the interpreter by construction
//! (`G1_JIT_VERIFY=1` compares).

use mle_core::air::symbolic::symbolic_variable::{Entry, SymbolicVariable};
use p3_field::PrimeField32;
use rustc_hash::FxHashMap;

use super::rules::{Rule, Source, SymbolicRulesGpu};
use crate::prelude::D_EF;

const KB_MOD: u64 = 0x7F000001;

pub(crate) fn monty(c: u32) -> u32 {
    (((c as u64) << 32) % KB_MOD) as u32
}

// The generated source carries its own extension arithmetic, so its degree has to follow the
// field the rest of the prover uses. Two are supported: the quartic binomial X^4 = 3 that
// KoalaBear ran on before the 128-bit work, and the quintic trinomial X^5 = 1 - X^2
// (Plonky3's `QuinticTrinomialExtensionField`) after it.
const _: () = assert!(
    D_EF == 4 || D_EF == 5,
    "jit_emit: only the KoalaBear quartic binomial and quintic trinomial extensions are emitted"
);

const FIELD_PREAMBLE: &str = r#"
#define MODP 0x7F000001u
#define M0P  0x7EFFFFFFu
#define ONE_M 0x01FFFFFEu
typedef unsigned u32; typedef unsigned long long u64;
__device__ __forceinline__ u32 fadd(u32 a, u32 b){ u32 r=a+b; return r>=MODP? r-MODP: r; }
__device__ __forceinline__ u32 fsub(u32 a, u32 b){ return a>=b? a-b: a+MODP-b; }
__device__ __forceinline__ u32 fneg(u32 a){ return a? MODP-a: 0u; }
__device__ __forceinline__ u32 fmul(u32 a, u32 b){
    u64 t=(u64)a*b; u32 m=(u32)t*M0P; u32 r=(u32)((t+(u64)m*MODP)>>32);
    return r>=MODP? r-MODP: r;
}
"#;

/// X^4 = 3. Unchanged from before the extension degree became a parameter.
const QUARTIC_MUL: &str = r#"
#define BETA 0x05FFFFFAu
__device__ __forceinline__ EXT emul(EXT a, EXT b){
    EXT r;
    r.u[0]=fadd(fmul(a.u[0],b.u[0]), fmul(BETA, fadd(fadd(fmul(a.u[1],b.u[3]),fmul(a.u[2],b.u[2])),fmul(a.u[3],b.u[1]))));
    r.u[1]=fadd(fadd(fmul(a.u[0],b.u[1]),fmul(a.u[1],b.u[0])), fmul(BETA, fadd(fmul(a.u[2],b.u[3]),fmul(a.u[3],b.u[2]))));
    r.u[2]=fadd(fadd(fmul(a.u[0],b.u[2]),fmul(a.u[1],b.u[1])), fadd(fmul(a.u[2],b.u[0]), fmul(BETA, fmul(a.u[3],b.u[3]))));
    r.u[3]=fadd(fadd(fmul(a.u[0],b.u[3]),fmul(a.u[1],b.u[2])), fadd(fmul(a.u[2],b.u[1]),fmul(a.u[3],b.u[0])));
    return r;
}
"#;

/// X^5 = 1 - X^2, so X^6 = X - X^3, X^7 = X^2 - X^4, X^8 = X^3 + X^2 - 1. Schoolbook into nine
/// convolution coefficients, each accumulated in 64 bits and reduced once (9 Montgomery reductions
/// rather than 25), then folded. The accumulation and reduction are `e5mul_raw` from the
/// benchmark (pico-gpu `src/field/test/ext_bench.cu`), which is checked there against
/// Plonky3 before anything is timed; `facc` keeps the accumulator below MODP * 2^32 so `fred`'s
/// sum cannot overflow 64 bits.
const QUINTIC_MUL: &str = r#"
__device__ __forceinline__ u32 fred(u64 t){
    u32 m=(u32)t*M0P; u32 r=(u32)((t+(u64)m*MODP)>>32);
    return r>=MODP? r-MODP: r;
}
__device__ __forceinline__ void facc(u64 &acc, u32 a, u32 b){
    acc += (u64)a*b;
    if ((u32)(acc>>32) >= MODP) acc -= ((u64)MODP<<32);
}
__device__ __forceinline__ EXT emul(EXT a, EXT b){
    u32 c[9];
#pragma unroll
    for (int k = 0; k < 9; k++) {
        u64 acc = 0;
#pragma unroll
        for (int i = 0; i < 5; i++) {
            int j = k - i;
            if (j >= 0 && j < 5) facc(acc, a.u[i], b.u[j]);
        }
        c[k] = fred(acc);
    }
    EXT r;
    r.u[0]=fsub(fadd(c[0],c[5]),c[8]);
    r.u[1]=fadd(c[1],c[6]);
    r.u[2]=fadd(fsub(c[2],c[5]),fadd(c[7],c[8]));
    r.u[3]=fadd(fsub(c[3],c[6]),c[8]);
    r.u[4]=fsub(c[4],c[7]);
    return r;
}
"#;

/// A whole element store. At 16 bytes every element sits at a 16-byte-aligned offset, so one uint4
/// store is legal and byte-identical. Packed 20-byte elements sit at 20-byte offsets, so
/// there the store is plain scalar stores; the extension-field benchmark measured packed 20-byte data at the
/// same bandwidth as aligned 16-byte data.
const QUARTIC_STORE: &str = r#"
__device__ __forceinline__ void estore(EXT *dst, EXT v){
    uint4 t; t.x=v.u[0]; t.y=v.u[1]; t.z=v.u[2]; t.w=v.u[3];
    *reinterpret_cast<uint4*>(dst) = t;
}
"#;
const QUINTIC_STORE: &str = r#"
__device__ __forceinline__ void estore(EXT *dst, EXT v){ *dst = v; }
"#;

/// The self-contained field and extension prelude every generated kernel starts with, for the
/// crate's extension degree `D_EF`.
pub(crate) fn preamble() -> String {
    let d = D_EF;
    let mut s = String::with_capacity(4096);
    s.push_str(FIELD_PREAMBLE);
    s.push_str(&format!(
        r#"struct EXT {{ u32 u[{d}]; }};
__device__ __forceinline__ EXT eadd(EXT a, EXT b){{ EXT r; for(int i=0;i<{d};i++) r.u[i]=fadd(a.u[i],b.u[i]); return r; }}
__device__ __forceinline__ EXT esub(EXT a, EXT b){{ EXT r; for(int i=0;i<{d};i++) r.u[i]=fsub(a.u[i],b.u[i]); return r; }}
__device__ __forceinline__ EXT eneg(EXT a){{ EXT r; for(int i=0;i<{d};i++) r.u[i]=fneg(a.u[i]); return r; }}
__device__ __forceinline__ EXT lift(u32 c){{ EXT r; r.u[0]=c; for(int i=1;i<{d};i++) r.u[i]=0u; return r; }}
__device__ __forceinline__ EXT boolext(bool b){{ return lift(b? ONE_M: 0u); }}
"#
    ));
    let (mul, store) = if d == 4 {
        (QUARTIC_MUL, QUARTIC_STORE)
    } else {
        (QUINTIC_MUL, QUINTIC_STORE)
    };
    s.push_str(mul);
    s.push_str(store);
    s
}

/// Generate the full kernel source for one AIR's interaction evaluation.
#[allow(clippy::too_many_arguments)]
pub fn emit_interaction_kernel<F: PrimeField32>(
    rules: &SymbolicRulesGpu<F>,
    used_nodes: &[usize],
    pair_idxs: &[u32],
) -> String {
    let mut s = String::with_capacity(64 * 1024);
    s.push_str(&preamble());
    s.push_str(
        r#"
extern "C" __global__ void jit_interactions(
    EXT *out,                 // FpExt array: out[(pair>>1)*H*2 ... ] interpreter layout
    const u64 *parts,        // device pointers to main partitions
    const u32 *prep,         // preprocessed matrix (col-major), may be null
    const u32 *pubv,         // public values, may be null
    const EXT *chal,          // challenges (ext field)
    u32 H,
    u32 n_rows
) {
    u32 row = blockIdx.x * blockDim.x + threadIdx.x;
    if (row >= n_rows) return;
"#,
    );

    let src_expr = |src: &Source<F>| -> String {
        match src {
            Source::Intermediate(i) => format!("b{i}"),
            Source::TerminalIntermediate => {
                unreachable!("TerminalIntermediate cannot be an operand")
            }
            Source::Constant(c) => format!("lift({}u)", monty(c.as_canonical_u32())),
            Source::IsFirst => "boolext(row == 0u)".to_string(),
            Source::IsLast => "boolext(row == H - 1u)".to_string(),
            Source::IsTransition => "boolext(row != H - 1u)".to_string(),
            // LogUp β leaf: read the (extension) challenge buffer directly. Matches the
            // interpreter's `ENTRY_CHALLENGE => d_challenges[src.index]` path.
            Source::Challenge(i) => format!("chal[{i}u]"),
            Source::Var(sv) => {
                let idx = sv.index;
                match sv.entry {
                    Entry::Preprocessed { offset } => format!(
                        "lift(prep[(u64){idx}u * H + ((row + {offset}u) % H)])"
                    ),
                    Entry::Main { part_index, offset } => format!(
                        "lift(((const u32*)parts[{part_index}u])[(u64){idx}u * H + ((row + {offset}u) % H)])"
                    ),
                    Entry::Public => format!("lift(pubv[{idx}u])"),
                }
            }
        }
    };
    let store_z = |s: &mut String, z: &Source<F>, val: &str| match z {
        Source::Intermediate(i) => s.push_str(&format!("    b{i} = {val};\n")),
        Source::TerminalIntermediate => {}
        _ => unreachable!("rule destination must be an intermediate"),
    };

    // Buffer-slot locals.
    for i in 0..rules.buffer_size {
        s.push_str(&format!("    EXT b{i} = lift(0u);\n"));
    }

    // Store each output right after the rule that produces it, so its value dies there. Batched at
    // the end of the kernel, every used node stays live to the last statement and ptxas spills the
    // lot to a per-thread stack frame the driver then backs for the whole card.
    let mut pairs_by_rule: FxHashMap<usize, Vec<u32>> = FxHashMap::default();
    for (u, &rule_idx) in used_nodes.iter().enumerate() {
        pairs_by_rule
            .entry(rule_idx)
            .or_default()
            .push(pair_idxs[u]);
    }
    // Interpreter layout: reinterpret<FpExt*>(d_fracs)[(interaction*H + row)*2 + parity].
    let store_out = |s: &mut String, val: &str, pair: u32| {
        let interaction = pair >> 1;
        let parity = pair & 1;
        s.push_str(&format!(
            "    estore(out + ((u64){interaction}u * H + row) * 2u + {parity}u, {val});\n"
        ));
    };
    let mut emitted = 0usize;

    for (k, rule) in rules.rules.iter().enumerate() {
        match &rule.inner {
            Rule::Add(x, y, z) => {
                s.push_str(&format!(
                    "    EXT r{k} = eadd({}, {});\n",
                    src_expr(x),
                    src_expr(y)
                ));
                store_z(&mut s, z, &format!("r{k}"));
            }
            Rule::Sub(x, y, z) => {
                s.push_str(&format!(
                    "    EXT r{k} = esub({}, {});\n",
                    src_expr(x),
                    src_expr(y)
                ));
                store_z(&mut s, z, &format!("r{k}"));
            }
            Rule::Mul(x, y, z) => {
                s.push_str(&format!(
                    "    EXT r{k} = emul({}, {});\n",
                    src_expr(x),
                    src_expr(y)
                ));
                store_z(&mut s, z, &format!("r{k}"));
            }
            Rule::Neg(x, z) => {
                s.push_str(&format!("    EXT r{k} = eneg({});\n", src_expr(x)));
                store_z(&mut s, z, &format!("r{k}"));
            }
            Rule::Variable(x) => {
                s.push_str(&format!("    EXT r{k} = {};\n", src_expr(x)));
            }
            Rule::BufferVar(x, z) => {
                s.push_str(&format!("    EXT r{k} = {};\n", src_expr(x)));
                store_z(&mut s, z, &format!("r{k}"));
            }
        }
        if let Some(pairs) = pairs_by_rule.get(&k) {
            for &pair in pairs {
                store_out(&mut s, &format!("r{k}"), pair);
                emitted += 1;
            }
        }
    }
    // A used node outside `rules` would otherwise vanish silently instead of failing to compile.
    debug_assert_eq!(emitted, used_nodes.len());

    s.push_str("}\n");
    s
}

/// Device-side helpers for the generated zerocheck round-0 kernel — base-field
/// Montgomery utilities plus a warp-shuffle transcription of `device_ntt.cuh`'s
/// `ntt_natural_to_bitrev<true,false>` (DIF iNTT, semi-sums) and `ntt_bitrev_to_natural<false,false>`
/// (DIT forward NTT). `NC` (num_cosets) and `LS` (l_skip) are `#define`d by the caller at compile
/// time; twiddles arrive as a kernel argument with the `DEVICE_NTT_TWIDDLES` layout (level L at
/// offset 2^L − 2) since nvrtc modules cannot see the main module's `__constant__` table.
/// Restricted to the lockstep / no-shared-memory regime: 1 <= LS <= 5, so each logical NTT fits in
/// a warp subgroup and `__shfl_xor_sync` covers every butterfly.
const Z1_PREAMBLE: &str = r#"
#define SKIP (1u << LS)
#define HALF_P1 0x3F800001u
__device__ __forceinline__ u32 fhalve(u32 a){ return (a >> 1) + (a & 1u) * HALF_P1; }
__device__ __forceinline__ u32 fexp2(u32 x, u32 k){ while (k--) x = fmul(x, x); return x; }
__device__ __forceinline__ u32 fpow(u32 x, u32 n){
    u32 r = ONE_M;
    while (n) { if (n & 1u) r = fmul(r, x); x = fmul(x, x); n >>= 1u; }
    return r;
}
__device__ __forceinline__ u32 finv(u32 x){ return fpow(x, MODP - 2u); }
__device__ __forceinline__ u32 favg_gp(u32 x, u32 n){
    u32 r = ONE_M;
    for (u32 i = 1u; i < n; i <<= 1u) { r = fhalve(fmul(r, fadd(ONE_M, x))); x = fmul(x, x); }
    return r;
}
__device__ __forceinline__ EXT emulf(EXT a, u32 b){
    EXT r; for (int i = 0; i < (int)(sizeof(EXT) / sizeof(u32)); i++) r.u[i] = fmul(a.u[i], b); return r;
}
__device__ __forceinline__ unsigned submask(u32 i){
    if (LS >= 5u) return 0xffffffffu;
    u32 lane = threadIdx.x & 31u;
    return ((1u << SKIP) - 1u) << (lane - (i & (SKIP - 1u)));
}
// DIF iNTT, natural -> bit-reversed, with the 1/2 folded into every butterfly (semi-sums).
__device__ __forceinline__ u32 intt_n2b(u32 v, u32 i, const u32 *tw){
    unsigned m = submask(i);
    u32 tj = i ? (SKIP - i) : 0u;
    u32 t = tw[SKIP - 2u + tj];
    for (u32 log_len = LS; log_len-- > 0u;) {
        u32 len = 1u << log_len;
        u32 other = __shfl_xor_sync(m, v, len);
        if (!(i & len)) v = fhalve(fadd(v, other));
        else            v = fmul(fhalve(fsub(v, other)), t);
        t = fmul(t, t);
    }
    return v;
}
// DIT forward NTT, bit-reversed -> natural.
__device__ __forceinline__ u32 ntt_b2n(u32 v, u32 i, const u32 *tw){
    unsigned m = submask(i);
    for (u32 lvl = 0u; lvl < LS; lvl++) {
        u32 len = 1u << lvl;
        u32 j = i & (len - 1u);
        u32 t = tw[(2u << lvl) - 2u + j];
        u32 other = __shfl_xor_sync(m, v, len);
        if (i & len) v = fsub(other, fmul(v, t));
        else         v = fadd(v, fmul(other, t));
    }
    return v;
}
// ntt_coset_interpolate (lockstep, FIRST_COSET_IS_IDENTITY=false): one trace load, one iNTT,
// then per-coset omega shift + forward NTT.
__device__ __forceinline__ void interp(
    u32 *res, const u32 *col, u32 row, u32 hmask, u32 i, const u32 *tw, const u32 *osh
){
    u32 coeff = intt_n2b(col[row & hmask], i, tw);
    #pragma unroll
    for (u32 c = 0u; c < NC; c++) res[c] = ntt_b2n(fmul(coeff, osh[c]), i, tw);
}
// Cross-block reduction, replacing sumcheck::final_reduce_block_sums for the JIT path.
// tmp layout: [num_blocks][NC*SKIP]; one output element per block. Field addition is exact and
// commutative, so any summation order matches the interpreter bit-for-bit.
extern "C" __global__ void z1_reduce(EXT *out, const EXT *tmp, u32 num_blocks){
    __shared__ EXT sh[256];
    u32 d = NC << LS;
    u32 i = blockIdx.x;
    EXT acc = lift(0u);
    for (u32 b = threadIdx.x; b < num_blocks; b += blockDim.x) acc = eadd(acc, tmp[b * d + i]);
    sh[threadIdx.x] = acc;
    __syncthreads();
    for (u32 s = blockDim.x >> 1; s; s >>= 1) {
        if (threadIdx.x < s) sh[threadIdx.x] = eadd(sh[threadIdx.x], sh[threadIdx.x + s]);
        __syncthreads();
    }
    if (!threadIdx.x) out[i] = sh[0];
}
"#;

/// Generate the zerocheck round-0 constraint-evaluation kernel for one AIR.
/// Transcribes the lockstep `zerocheck_ntt_evaluate_constraints_kernel` with the DAG
/// interpreter loop replaced by straight-line per-coset code: every rule becomes a named local
/// `u32 r{k}[NC]`, intermediates live in registers/local memory instead of the GLOBAL spill
/// buffer, and lambda accumulation follows the interpreter's single-pass `used_nodes` walk.
/// The caller prepends `#define NC ...` / `#define LS ...` before nvrtc compilation.
///
/// `seg_rules > 0` enables segmentation for rule lists larger than the threshold: the body is cut
/// into `__device__ __noinline__ z1_seg{j}` functions of at most `seg_rules` rules each, called in
/// order from the kernel. This is legal at ANY rule boundary because cross-rule dataflow only ever
/// flows through the `b` buffer slots (rule operands are never another rule's `r{k}`); the slots
/// become one flat local array passed by pointer. Purpose: nvrtc's frontend passes are superlinear
/// in FUNCTION size (5956 rules ≈ 21 min, 9377 > 60 min, ~72k never finishes) and the monolithic
/// body's live set pins 255 registers (16.7% occupancy) — smaller functions restore both.
/// `seg_rules == 0` (or a rule list within the threshold) emits the original monolithic body,
/// byte-identical to the pre-segmentation emitter so existing cubin cache entries stay valid.
pub fn emit_round0_zc_kernel<F: PrimeField32>(
    rules: &SymbolicRulesGpu<F>,
    used_nodes: &[usize],
    seg_rules: usize,
) -> String {
    let segmented = seg_rules > 0 && rules.rules.len() > seg_rules;
    let mut s = String::with_capacity(256 * 1024);
    s.push_str(&preamble());
    s.push_str(Z1_PREAMBLE);
    let kernel_header = r#"
extern "C" __global__ void z1_round0(
    EXT *tmp_sums,        // [gridDim.x][NC*SKIP]
    const u32 *sel,      // selectors_cube [3][num_x]
    const u32 *prep,     // preprocessed (col-major), may be null
    const u64 *parts,    // device pointers to main partitions
    const EXT *eq_cube,   // [num_x]
    const EXT *lam,       // lambda powers
    const u32 *pubv,     // public values, may be null
    const u32 *tw,       // DEVICE_NTT_TWIDDLES contents
    u32 num_x,
    u32 height,
    u32 g_shift
) {
    extern __shared__ char smem[];
    EXT *shared_sum = (EXT *)smem;
    u32 tidx = threadIdx.x + blockIdx.x * blockDim.x;
    u32 ntt_idx = tidx & (SKIP - 1u);
    u32 x_int_base = tidx >> LS;
    u32 ntt_idx_rev = __brev(ntt_idx) >> (32u - LS);
    u32 hmask = height - 1u;
    u32 log_height = (u32)__ffs(height) - 1u;
    u32 log_segment = LS < log_height ? LS : log_height;
    u32 segment_size = 1u << log_segment;
    u32 log_stride = LS - log_segment;
    u32 eta = log_segment ? tw[(1u << log_segment) - 2u + 1u] : ONE_M;
    u32 omega_skip_ntt = tw[SKIP - 2u + ntt_idx];
    u32 ifm[NC], ilm[NC], osh[NC];
    {
        u32 g = g_shift;
        #pragma unroll
        for (u32 c = 0u; c < NC; c++) {
            u32 om = fexp2(fmul(g, omega_skip_ntt), log_stride);
            ifm[c] = favg_gp(om, segment_size);
            ilm[c] = favg_gp(fmul(om, eta), segment_size);
            g = fmul(g, g_shift);
        }
        u32 ob = fpow(g_shift, ntt_idx_rev);
        u32 o = ob;
        #pragma unroll
        for (u32 c = 0u; c < NC; c++) { osh[c] = o; o = fmul(o, ob); }
    }
    EXT sums[NC];
    #pragma unroll
    for (u32 c = 0u; c < NC; c++) sums[c] = lift(0u);
    u32 x_stride = (gridDim.x * blockDim.x) >> LS;
    for (u32 x_int = x_int_base; x_int < num_x; x_int += x_stride) {
        u32 isf[NC], isl[NC];
        u32 s0 = sel[x_int], s2 = sel[2u * num_x + x_int];
        #pragma unroll
        for (u32 c = 0u; c < NC; c++) { isf[c] = fmul(ifm[c], s0); isl[c] = fmul(ilm[c], s2); }
        EXT csum[NC];
        #pragma unroll
        for (u32 c = 0u; c < NC; c++) csum[c] = lift(0u);
        u32 rb = x_int * SKIP + ntt_idx;
"#;

    // Per-rule body. Operand kinds: per-coset arrays (intermediates, selectors, interpolated
    // vars), or scalars broadcast across cosets (constants, public values).
    let col_expr = |sv: &SymbolicVariable<F>| -> Option<(String, usize)> {
        let idx = sv.index;
        match sv.entry {
            Entry::Preprocessed { offset } => {
                Some((format!("prep + (u64){idx}u * height"), offset))
            }
            Entry::Main { part_index, offset } => Some((
                format!("(const u32 *)parts[{part_index}u] + (u64){idx}u * height"),
                offset,
            )),
            _ => None,
        }
    };
    // Element expression for an operand inside the per-coset loop; trace vars are interpolated
    // into a temp array first (emitted as a prelude statement). Buffer-slot naming depends on the
    // emission mode: monolithic keeps per-slot arrays `b{i}[c]` (register-promotable, and
    // byte-identical to the pre-segmentation emitter); segmented uses one flat array `b[i*NC+c]`
    // that crosses `__noinline__` segment boundaries by pointer.
    let slot = |i: usize| -> String {
        if segmented {
            format!("b[{i}u * NC + c]")
        } else {
            format!("b{i}[c]")
        }
    };
    let src_elem = |s: &mut String, src: &Source<F>, tmp_name: &str| -> String {
        match src {
            Source::Intermediate(i) => slot(*i),
            Source::TerminalIntermediate => {
                unreachable!("TerminalIntermediate cannot be an operand")
            }
            Source::Constant(c) => format!("{}u", monty(c.as_canonical_u32())),
            Source::IsFirst => "isf[c]".to_string(),
            Source::IsLast => "isl[c]".to_string(),
            Source::IsTransition => "fsub(ONE_M, isl[c])".to_string(),
            // Zerocheck round-0 rules come from `dag.constraints` (constraints only, no
            // interactions), so a LogUp challenge leaf can never reach here.
            Source::Challenge(_) => {
                unreachable!("challenge leaf cannot appear in zerocheck constraint rules")
            }
            Source::Var(sv) => match col_expr(sv) {
                Some((col, offset)) => {
                    s.push_str(&format!(
                        "        u32 {tmp_name}[NC]; interp({tmp_name}, {col}, rb + {offset}u, hmask, ntt_idx, tw, osh);\n"
                    ));
                    format!("{tmp_name}[c]")
                }
                None => match sv.entry {
                    Entry::Public => format!("pubv[{}u]", sv.index),
                    _ => unreachable!("unsupported entry kind in zerocheck rules"),
                },
            },
        }
    };
    let store_z = |s: &mut String, z: &Source<F>, k: usize| match z {
        // Buffer slots are reused across rules (priority-queue scheduling), so they are declared
        // once below and only assigned here.
        Source::Intermediate(i) => s.push_str(&format!(
            "        #pragma unroll\n        for (u32 c = 0u; c < NC; c++) {} = r{k}[c];\n",
            slot(*i)
        )),
        Source::TerminalIntermediate => {}
        _ => unreachable!("rule destination must be an intermediate"),
    };

    // Emit every rule body into segment buffers (monolithic mode = one unbounded segment). A cut
    // is taken after a rule's store + lambda block, so `r{k}` never crosses a segment.
    let budget = if segmented { seg_rules } else { usize::MAX };
    let mut bodies: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut cnt = 0usize;
    let mut lambda_idx = 0usize;
    for (k, rule) in rules.rules.iter().enumerate() {
        match &rule.inner {
            Rule::Add(x, y, z) | Rule::Sub(x, y, z) | Rule::Mul(x, y, z) => {
                let op = match &rule.inner {
                    Rule::Add(..) => "fadd",
                    Rule::Sub(..) => "fsub",
                    _ => "fmul",
                };
                let ex = src_elem(&mut cur, x, &format!("t{k}x"));
                let ey = src_elem(&mut cur, y, &format!("t{k}y"));
                cur.push_str(&format!(
                    "        u32 r{k}[NC];\n        #pragma unroll\n        for (u32 c = 0u; c < NC; c++) r{k}[c] = {op}({ex}, {ey});\n"
                ));
                store_z(&mut cur, z, k);
            }
            Rule::Neg(x, z) => {
                let ex = src_elem(&mut cur, x, &format!("t{k}x"));
                cur.push_str(&format!(
                    "        u32 r{k}[NC];\n        #pragma unroll\n        for (u32 c = 0u; c < NC; c++) r{k}[c] = fneg({ex});\n"
                ));
                store_z(&mut cur, z, k);
            }
            Rule::Variable(x) => {
                let ex = src_elem(&mut cur, x, &format!("t{k}x"));
                cur.push_str(&format!(
                    "        u32 r{k}[NC];\n        #pragma unroll\n        for (u32 c = 0u; c < NC; c++) r{k}[c] = {ex};\n"
                ));
            }
            Rule::BufferVar(x, z) => {
                let ex = src_elem(&mut cur, x, &format!("t{k}x"));
                cur.push_str(&format!(
                    "        u32 r{k}[NC];\n        #pragma unroll\n        for (u32 c = 0u; c < NC; c++) r{k}[c] = {ex};\n"
                ));
                store_z(&mut cur, z, k);
            }
        }
        // Mirror the interpreter's single-pass lambda walk: each used_nodes entry equal to this
        // rule index consumes the next lambda power.
        if rule.need_accumulate {
            while lambda_idx < used_nodes.len() && used_nodes[lambda_idx] == k {
                cur.push_str(&format!(
                    "        {{ EXT l = lam[{lambda_idx}u];\n          #pragma unroll\n          for (u32 c = 0u; c < NC; c++) csum[c] = eadd(csum[c], emulf(l, r{k}[c])); }}\n"
                ));
                lambda_idx += 1;
            }
        }
        cnt += 1;
        if cnt >= budget {
            bodies.push(std::mem::take(&mut cur));
            cnt = 0;
        }
    }
    if !cur.is_empty() || bodies.is_empty() {
        bodies.push(cur);
    }
    debug_assert_eq!(lambda_idx, used_nodes.len());

    // Segment functions must precede the kernel that calls them.
    if segmented {
        for (j, body) in bodies.iter().enumerate() {
            s.push_str(&format!(
                "__device__ __noinline__ void z1_seg{j}(\n    u32 *b, EXT *csum, u32 rb, u32 hmask, u32 ntt_idx, u32 height,\n    const u32 *tw, const u32 *osh, const u32 *isf, const u32 *isl,\n    const u64 *parts, const u32 *prep, const u32 *pubv, const EXT *lam\n) {{\n{body}}}\n"
            ));
        }
    }

    s.push_str(kernel_header);

    if segmented {
        s.push_str(&format!("        u32 b[{}u * NC];\n", rules.buffer_size));
        for j in 0..bodies.len() {
            s.push_str(&format!(
                "        z1_seg{j}(b, csum, rb, hmask, ntt_idx, height, tw, osh, isf, isl, parts, prep, pubv, lam);\n"
            ));
        }
    } else {
        for i in 0..rules.buffer_size {
            s.push_str(&format!("        u32 b{i}[NC];\n"));
        }
        s.push_str(&bodies[0]);
    }

    s.push_str(
        r#"        EXT eq = eq_cube[x_int];
        #pragma unroll
        for (u32 c = 0u; c < NC; c++) sums[c] = eadd(sums[c], emul(csum[c], eq));
    }
    // Epilogue: divide by the coset zerofier, then per-block reduction into tmp_sums with the
    // interpreter's [block][coset][ntt_idx] layout.
    u32 g = g_shift;
    for (u32 c = 0u; c < NC; c++) {
        u32 zf = fsub(fexp2(fmul(g, omega_skip_ntt), LS), ONE_M);
        shared_sum[threadIdx.x] = emulf(sums[c], finv(zf));
        __syncthreads();
        if (threadIdx.x < SKIP) {
            EXT ts = shared_sum[threadIdx.x];
            for (u32 lane = 1u; lane < (blockDim.x >> LS); ++lane)
                ts = eadd(ts, shared_sum[(lane << LS) + threadIdx.x]);
            tmp_sums[blockIdx.x * (NC << LS) + c * SKIP + ntt_idx] = ts;
        }
        __syncthreads();
        g = fmul(g, g_shift);
    }
}
"#,
    );
    s
}

/// The emitted extension arithmetic against the CPU field.
///
/// The JIT source carries its own copy of the extension arithmetic, so nothing else in the crate
/// checks it; `G1_JIT_VERIFY` only compares JIT output with the interpreter, which is a second
/// hand-written implementation and can share a mistake. This compares with Plonky3 instead, at
/// whatever degree the crate is built for -- which is also what lets the quintic multiply be
/// checked before any kernel in pico-gpu is quintic.
///
/// Needs a GPU, so it runs on a CUDA host rather than in CI:
///   cargo test --release --package cuda-mle jit_emit -- --nocapture
#[cfg(test)]
mod tests {
    use std::ffi::c_void;

    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField32};

    use crate::{
        cuda::jit::compile_kernel,
        prelude::{D_EF, EF, F},
        runtime::{
            copy::{MemCopyD2H, MemCopyH2D},
            d_buffer::DeviceBuffer,
            stream::device_synchronize,
        },
    };

    const KERNEL: &str = r#"
extern "C" __global__ void t_ext(const EXT *a, const EXT *b, EXT *mul, EXT *add, EXT *sub,
                                 EXT *neg, EXT *lft, u32 n){
    u32 i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    estore(mul + i, emul(a[i], b[i]));
    estore(add + i, eadd(a[i], b[i]));
    estore(sub + i, esub(a[i], b[i]));
    estore(neg + i, eneg(a[i]));
    estore(lft + i, lift(a[i].u[0]));
}
"#;

    fn x_pow(k: usize) -> EF {
        let x = EF::from_basis_coefficients_fn(|i| if i == 1 { F::ONE } else { F::ZERO });
        (0..k).fold(EF::ONE, |acc, _| acc * x)
    }

    /// Inputs that cross the reduction boundary on purpose, plus enough pseudo-random full
    /// elements that every coefficient pair meets.
    fn inputs() -> (Vec<EF>, Vec<EF>) {
        let p = F::ORDER_U32;
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for i in 0..D_EF {
            for j in 0..D_EF {
                a.push(x_pow(i));
                b.push(x_pow(j));
            }
        }
        let all = |v: u32| EF::from_basis_coefficients_fn(|_| F::from_u32(v));
        a.extend([all(1), all(p - 1), EF::ZERO]);
        b.extend([all(1), all(p - 1), all(p - 1)]);
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            F::from_u32(((s >> 33) as u32) % p)
        };
        for _ in 0..4096 {
            a.push(EF::from_basis_coefficients_fn(|_| next()));
            b.push(EF::from_basis_coefficients_fn(|_| next()));
        }
        (a, b)
    }

    #[test]
    fn emitted_extension_arithmetic_matches_cpu() {
        // Device work first: `compile_kernel` loads its module through the driver API, which needs
        // the runtime's primary context to be current already (CUDA_ERROR_INVALID_CONTEXT, 201,
        // otherwise). In the prover a runtime call always precedes the first JIT compile.
        let (a, b) = inputs();
        let n = a.len();
        let d_a = a.to_device().unwrap();
        let d_b = b.to_device().unwrap();

        let src = format!("{}{}", super::preamble(), KERNEL);
        let kernel = compile_kernel(&src, "t_ext").expect("nvrtc compile of the emitted preamble");
        let outs: Vec<DeviceBuffer<EF>> = (0..5).map(|_| DeviceBuffer::with_capacity(n)).collect();

        let mut p_a = d_a.as_ptr() as *mut c_void;
        let mut p_b = d_b.as_ptr() as *mut c_void;
        let mut p_out: Vec<*mut c_void> =
            outs.iter().map(|o| o.as_mut_ptr() as *mut c_void).collect();
        let mut v_n = n as u32;
        let mut params: Vec<*mut c_void> = vec![
            &mut p_a as *mut _ as *mut c_void,
            &mut p_b as *mut _ as *mut c_void,
        ];
        for p in p_out.iter_mut() {
            params.push(p as *mut _ as *mut c_void);
        }
        params.push(&mut v_n as *mut u32 as *mut c_void);
        unsafe { kernel.launch((n as u32).div_ceil(256), 256, 0, &mut params) }.unwrap();
        device_synchronize().unwrap();

        let got: Vec<Vec<EF>> = outs.iter().map(|o| o.to_host().unwrap()).collect();
        let mut bad = 0usize;
        for i in 0..n {
            let want = [
                a[i] * b[i],
                a[i] + b[i],
                a[i] - b[i],
                -a[i],
                <EF as From<F>>::from(a[i].as_basis_coefficients_slice()[0]),
            ];
            for (k, name) in ["emul", "eadd", "esub", "eneg", "lift"].iter().enumerate() {
                if got[k][i] != want[k] {
                    if bad < 8 {
                        eprintln!(
                            "{name}[{i}]: a={:?} b={:?}\n  gpu={:?}\n  cpu={:?}",
                            a[i], b[i], got[k][i], want[k]
                        );
                    }
                    bad += 1;
                }
            }
        }
        assert_eq!(bad, 0, "{bad} mismatches over {n} inputs at D_EF = {D_EF}");
        println!("PASS: emitted extension arithmetic, {n} inputs x 5 ops, D_EF = {D_EF}");
    }
}
