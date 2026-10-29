//! Straight-line CUDA codegen for GKR interaction evaluation.
//!
//! Walks the same typed rule list (`SymbolicRulesGpu`) the runtime interpreter executes and emits
//! one CUDA statement per rule, with variables resolved to direct loads and constants embedded as
//! Montgomery literals. The generated source is fully self-contained (its own KoalaBear Montgomery
//! and quartic-extension arithmetic — x^4 − 3, REDC with M0 = −MOD⁻¹ mod 2³²), so nvrtc needs no
//! host headers. Output ABI matches `evaluate_interactions_gkr_kernel` exactly (FpExt writes at
//! `(pair>>1)*H + row`, parity-selected) — bit-exact with the interpreter by construction
//! (`G1_JIT_VERIFY=1` compares).

use mle_core::air::symbolic::symbolic_variable::{Entry, SymbolicVariable};
use p3_field::PrimeField32;
use rustc_hash::FxHashMap;

use super::rules::{Rule, Source, SymbolicRulesGpu};

const KB_MOD: u64 = 0x7F000001;

pub(crate) fn monty(c: u32) -> u32 {
    (((c as u64) << 32) % KB_MOD) as u32
}

const PREAMBLE: &str = r#"
#define MODP 0x7F000001u
#define M0P  0x7EFFFFFFu
#define BETA 0x05FFFFFAu
#define ONE_M 0x01FFFFFEu
typedef unsigned u32; typedef unsigned long long u64;
__device__ __forceinline__ u32 fadd(u32 a, u32 b){ u32 r=a+b; return r>=MODP? r-MODP: r; }
__device__ __forceinline__ u32 fsub(u32 a, u32 b){ return a>=b? a-b: a+MODP-b; }
__device__ __forceinline__ u32 fneg(u32 a){ return a? MODP-a: 0u; }
__device__ __forceinline__ u32 fmul(u32 a, u32 b){
    u64 t=(u64)a*b; u32 m=(u32)t*M0P; u32 r=(u32)((t+(u64)m*MODP)>>32);
    return r>=MODP? r-MODP: r;
}
struct E4 { u32 u[4]; };
__device__ __forceinline__ E4 eadd(E4 a, E4 b){ E4 r; for(int i=0;i<4;i++) r.u[i]=fadd(a.u[i],b.u[i]); return r; }
__device__ __forceinline__ E4 esub(E4 a, E4 b){ E4 r; for(int i=0;i<4;i++) r.u[i]=fsub(a.u[i],b.u[i]); return r; }
__device__ __forceinline__ E4 eneg(E4 a){ E4 r; for(int i=0;i<4;i++) r.u[i]=fneg(a.u[i]); return r; }
__device__ __forceinline__ E4 emul(E4 a, E4 b){
    E4 r;
    r.u[0]=fadd(fmul(a.u[0],b.u[0]), fmul(BETA, fadd(fadd(fmul(a.u[1],b.u[3]),fmul(a.u[2],b.u[2])),fmul(a.u[3],b.u[1]))));
    r.u[1]=fadd(fadd(fmul(a.u[0],b.u[1]),fmul(a.u[1],b.u[0])), fmul(BETA, fadd(fmul(a.u[2],b.u[3]),fmul(a.u[3],b.u[2]))));
    r.u[2]=fadd(fadd(fmul(a.u[0],b.u[2]),fmul(a.u[1],b.u[1])), fadd(fmul(a.u[2],b.u[0]), fmul(BETA, fmul(a.u[3],b.u[3]))));
    r.u[3]=fadd(fadd(fmul(a.u[0],b.u[3]),fmul(a.u[1],b.u[2])), fadd(fmul(a.u[2],b.u[1]),fmul(a.u[3],b.u[0])));
    return r;
}
__device__ __forceinline__ E4 lift(u32 c){ E4 r; r.u[0]=c; r.u[1]=0u; r.u[2]=0u; r.u[3]=0u; return r; }
__device__ __forceinline__ E4 boolext(bool b){ return lift(b? ONE_M: 0u); }
// E4 has 4B alignment so `out[i] = r` compiles to 4 scalar stores; every output
// element sits at a 16B-aligned offset, so a single uint4 store is legal and byte-identical.
__device__ __forceinline__ void estore16(E4 *dst, E4 v){
    uint4 t; t.x=v.u[0]; t.y=v.u[1]; t.z=v.u[2]; t.w=v.u[3];
    *reinterpret_cast<uint4*>(dst) = t;
}
"#;

/// Generate the full kernel source for one AIR's interaction evaluation.
#[allow(clippy::too_many_arguments)]
pub fn emit_interaction_kernel<F: PrimeField32>(
    rules: &SymbolicRulesGpu<F>,
    used_nodes: &[usize],
    pair_idxs: &[u32],
) -> String {
    let mut s = String::with_capacity(64 * 1024);
    s.push_str(PREAMBLE);
    s.push_str(
        r#"
extern "C" __global__ void jit_interactions(
    E4 *out,                 // FpExt array: out[(pair>>1)*H*2 ... ] interpreter layout
    const u64 *parts,        // device pointers to main partitions
    const u32 *prep,         // preprocessed matrix (col-major), may be null
    const u32 *pubv,         // public values, may be null
    const E4 *chal,          // challenges (ext field)
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
        s.push_str(&format!("    E4 b{i} = lift(0u);\n"));
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
            "    estore16(out + ((u64){interaction}u * H + row) * 2u + {parity}u, {val});\n"
        ));
    };
    let mut emitted = 0usize;

    for (k, rule) in rules.rules.iter().enumerate() {
        match &rule.inner {
            Rule::Add(x, y, z) => {
                s.push_str(&format!(
                    "    E4 r{k} = eadd({}, {});\n",
                    src_expr(x),
                    src_expr(y)
                ));
                store_z(&mut s, z, &format!("r{k}"));
            }
            Rule::Sub(x, y, z) => {
                s.push_str(&format!(
                    "    E4 r{k} = esub({}, {});\n",
                    src_expr(x),
                    src_expr(y)
                ));
                store_z(&mut s, z, &format!("r{k}"));
            }
            Rule::Mul(x, y, z) => {
                s.push_str(&format!(
                    "    E4 r{k} = emul({}, {});\n",
                    src_expr(x),
                    src_expr(y)
                ));
                store_z(&mut s, z, &format!("r{k}"));
            }
            Rule::Neg(x, z) => {
                s.push_str(&format!("    E4 r{k} = eneg({});\n", src_expr(x)));
                store_z(&mut s, z, &format!("r{k}"));
            }
            Rule::Variable(x) => {
                s.push_str(&format!("    E4 r{k} = {};\n", src_expr(x)));
            }
            Rule::BufferVar(x, z) => {
                s.push_str(&format!("    E4 r{k} = {};\n", src_expr(x)));
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
__device__ __forceinline__ E4 emulf(E4 a, u32 b){
    E4 r; for (int i = 0; i < 4; i++) r.u[i] = fmul(a.u[i], b); return r;
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
extern "C" __global__ void z1_reduce(E4 *out, const E4 *tmp, u32 num_blocks){
    __shared__ E4 sh[256];
    u32 d = NC << LS;
    u32 i = blockIdx.x;
    E4 acc = lift(0u);
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
    s.push_str(PREAMBLE);
    s.push_str(Z1_PREAMBLE);
    let kernel_header = r#"
extern "C" __global__ void z1_round0(
    E4 *tmp_sums,        // [gridDim.x][NC*SKIP]
    const u32 *sel,      // selectors_cube [3][num_x]
    const u32 *prep,     // preprocessed (col-major), may be null
    const u64 *parts,    // device pointers to main partitions
    const E4 *eq_cube,   // [num_x]
    const E4 *lam,       // lambda powers
    const u32 *pubv,     // public values, may be null
    const u32 *tw,       // DEVICE_NTT_TWIDDLES contents
    u32 num_x,
    u32 height,
    u32 g_shift
) {
    extern __shared__ char smem[];
    E4 *shared_sum = (E4 *)smem;
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
    E4 sums[NC];
    #pragma unroll
    for (u32 c = 0u; c < NC; c++) sums[c] = lift(0u);
    u32 x_stride = (gridDim.x * blockDim.x) >> LS;
    for (u32 x_int = x_int_base; x_int < num_x; x_int += x_stride) {
        u32 isf[NC], isl[NC];
        u32 s0 = sel[x_int], s2 = sel[2u * num_x + x_int];
        #pragma unroll
        for (u32 c = 0u; c < NC; c++) { isf[c] = fmul(ifm[c], s0); isl[c] = fmul(ilm[c], s2); }
        E4 csum[NC];
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
                    "        {{ E4 l = lam[{lambda_idx}u];\n          #pragma unroll\n          for (u32 c = 0u; c < NC; c++) csum[c] = eadd(csum[c], emulf(l, r{k}[c])); }}\n"
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
                "__device__ __noinline__ void z1_seg{j}(\n    u32 *b, E4 *csum, u32 rb, u32 hmask, u32 ntt_idx, u32 height,\n    const u32 *tw, const u32 *osh, const u32 *isf, const u32 *isl,\n    const u64 *parts, const u32 *prep, const u32 *pubv, const E4 *lam\n) {{\n{body}}}\n"
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
        r#"        E4 eq = eq_cube[x_int];
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
            E4 ts = shared_sum[threadIdx.x];
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
