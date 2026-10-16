use core::mem::size_of;

use p3_keccak_air::{NUM_ROUNDS, U64_LIMBS};
use pico_derive::AlignedBorrow;

/// Rotation offsets of the rho step, `R[x][y]` (`p3_keccak_air::constants::R`, which that crate
/// keeps private).
const R: [[u8; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

/// The Keccak-f permutation columns of one round row: `p3_keccak_air::KeccakCols` without its
/// `preimage` block.
///
/// Upstream carries the permutation input (`preimage`, 100 limbs) on all 24 rows of a permutation
/// so that the final step can export it. Here the input is exported from the first step instead,
/// where it is `a` itself (`constraint.rs`), so the 100 copies and the 200 constraints that pinned
/// them are gone. Everything else is the upstream layout, field for field and in the same order
/// (the `y, x, z` ordering follows the spec's `s[w(5y + x) + z] = a[x][y][z]`); the trace rows are
/// the upstream generator's rows projected onto this layout (`copy_from_upstream`).
#[derive(AlignedBorrow, Debug)]
#[repr(C)]
pub struct KeccakCols<T> {
    /// The `i`th value is set to 1 if we are in the `i`th round, otherwise 0.
    pub step_flags: [T; NUM_ROUNDS],

    /// 1 on the final step of a real permutation: the row that exports the permutation output.
    pub export: T,

    /// The round input, stored in y-major order. On the first step this is the permutation input.
    pub a: [[[T; U64_LIMBS]; 5]; 5],

    /// `C[x] = xor(A[x, 0], A[x, 1], A[x, 2], A[x, 3], A[x, 4])`, as bits.
    pub c: [[T; 64]; 5],

    /// `C'[x, z] = xor(C[x, z], C[x - 1, z], C[x + 1, z - 1])`, as bits.
    pub c_prime: [[T; 64]; 5],

    /// `A'[x, y] = xor(A[x, y], D[x])`, as bits; D is inlined, not stored.
    pub a_prime: [[[T; 64]; 5]; 5],

    /// `A''[x, y] = xor(B[x, y], andn(B[x + 1, y], B[x + 2, y]))`, as limbs.
    pub a_prime_prime: [[[T; U64_LIMBS]; 5]; 5],

    /// The bits of `A''[0, 0]`.
    pub a_prime_prime_0_0_bits: [T; 64],

    /// `A'''[0, 0, z] = A''[0, 0, z] ^ RC[k, z]`, as limbs.
    pub a_prime_prime_prime_0_0_limbs: [T; U64_LIMBS],
}

impl<T: Copy> KeccakCols<T> {
    /// `B` is a rotation of `A'`, so these are aliases of `a_prime` cells. From the spec,
    /// `B[y, (2x + 3y) % 5] = ROT(A'[x, y], r[x, y])`, so `B[x, y] = f((x + 3y) % 5, x)` with
    /// `f(a, b) = ROT(A'[a, b], r[a, b])`.
    pub fn b(&self, x: usize, y: usize, z: usize) -> T {
        debug_assert!(x < 5);
        debug_assert!(y < 5);
        debug_assert!(z < 64);
        let a = (x + 3 * y) % 5;
        let b = x;
        let rot = R[a][b] as usize;
        self.a_prime[b][a][(z + 64 - rot) % 64]
    }

    pub fn a_prime_prime_prime(&self, y: usize, x: usize, limb: usize) -> T {
        debug_assert!(y < 5);
        debug_assert!(x < 5);
        debug_assert!(limb < U64_LIMBS);
        if y == 0 && x == 0 {
            self.a_prime_prime_prime_0_0_limbs[limb]
        } else {
            self.a_prime_prime[y][x][limb]
        }
    }

    /// Copies an upstream row (`p3_keccak_air::generate_trace_rows`) into this layout: every field
    /// but `preimage`.
    pub fn copy_from_upstream(&mut self, src: &p3_keccak_air::KeccakCols<T>) {
        self.step_flags = src.step_flags;
        self.export = src.export;
        self.a = src.a;
        self.c = src.c;
        self.c_prime = src.c_prime;
        self.a_prime = src.a_prime;
        self.a_prime_prime = src.a_prime_prime;
        self.a_prime_prime_0_0_bits = src.a_prime_prime_0_0_bits;
        self.a_prime_prime_prime_0_0_limbs = src.a_prime_prime_prime_0_0_limbs;
    }
}

/// Columns of the permutation part of a row (2533 with 16-bit limbs).
pub const NUM_KECCAK_PERM_COLS: usize = size_of::<KeccakCols<u8>>();

/// KeccakMemCols is the column layout for the keccak permutation.
///
/// The permutation columns (`keccak`, the local copy of the `p3_keccak_air` layout without
/// `preimage`) come first; the other columns track the VM context. The syscall receive, the
/// address gadgets and the 25 state memory accesses live in the one-row-per-permutation
/// `KeccakControlChip` (`control.rs`); the two AIRs meet on the `LookupType::KeccakPermute` state
/// bus, which this side receives on the first step of each permutation for the input
/// (`export_in`) and on the final step for the output (`keccak.export`).
#[derive(AlignedBorrow)]
#[repr(C)]
pub struct KeccakMemCols<T> {
    /// Permutation columns. Note it is assumed in trace gen to be the first field.
    pub keccak: KeccakCols<T>,

    pub chunk: T,
    pub clk: T,
    pub is_real: T,
    /// `step_flags[0] * is_real`: 1 on the first step of a real permutation, the row that exports
    /// the permutation input (`keccak.a`) onto the state bus.
    pub export_in: T,
}

pub const NUM_KECCAK_MEM_COLS: usize = size_of::<KeccakMemCols<u8>>();
