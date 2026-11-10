// Device tracegen for the sliced Keccak AIR (`vm/src/chips/precompiles/keccak256/sliced/`)
// and the multiplicities of its two lookup tables. Mirrors the host `sliced_trace` /
// `sliced_counts` cell for cell: two permutations per 27-row slot, events paired (2j, 2j+1).

#include <cstdint>
#include "tracegen/common/prelude.cuh"
#include "common/rusterror.h"
#include "common/exception.cuh"
#include "field/ff_config.hpp"

namespace pico_gpu::keccak_sliced {

  constexpr int SLOT_ROWS = 27;
  constexpr int NUM_ROUNDS = 24;
  // Column offsets of `KeccakSlicedCols`.
  constexpr int COL_CLK = 0;
  constexpr int COL_IN_USE_A = 27;
  constexpr int COL_IN_USE_B = 28;
  constexpr int COL_CTX = 29;
  constexpr int COL_STATE = 33;
  constexpr int COL_C = 33 + 1600;
  constexpr int NUM_COLS = COL_C + 320;  // 1953
  // Both tables live in one AIR of 2^20 rows, each as two side-by-side halves: table row `idx`
  // counts into row `idx mod 2^20`, column `idx >> 20` (chi) or `2 + (idx >> 20)` (xor5).
  constexpr int HALF_ROWS = 1 << 20;
  constexpr int TABLES_COLS = 4;

  /// Matches the Rust `SlicedEventFfi` (`#[repr(C)]`).
  struct SlicedEvent {
    uint32_t chunk;
    uint32_t clk;
    uint64_t state[25];
  };

  __constant__ uint64_t RC[NUM_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
  };
  // R[x][y]
  __constant__ uint32_t RHO[5][5] = {
    {0, 36, 3, 41, 18}, {1, 44, 10, 45, 2}, {62, 6, 43, 15, 61}, {28, 55, 25, 21, 56}, {27, 20, 39, 8, 14},
  };

  __device__ __forceinline__ uint64_t rotl(uint64_t v, uint32_t n) { return n == 0 ? v : (v << n) | (v >> (64 - n)); }

  /// The (x, y) whose rotated theta output lands at B[X][Y]: pi sends (x, y) to (y, (2x + 3y) % 5).
  __device__ __forceinline__ void pi_src(int bx, int by, int& x, int& y) {
    y = bx;
    for (int c = 0; c < 5; c++)
      if ((2 * c + 3 * y) % 5 == by) x = c;
  }

  /// The slot's two instances advanced by `rounds` rounds, cooperatively: threads 0..24 run A's
  /// lanes and 32..56 B's, on `s[2][25]` in shared memory. Every thread of the block must call it.
  __device__ void advance(uint64_t (*s)[25], uint64_t (*c)[5], uint64_t (*b)[25], int rounds) {
    const int inst = threadIdx.x / 32, lane = threadIdx.x % 32;
    const bool act = inst < 2 && lane < 25;
    for (int r = 0; r < rounds; r++) {
      if (act && lane < 5)
        c[inst][lane] = s[inst][lane] ^ s[inst][lane + 5] ^ s[inst][lane + 10] ^ s[inst][lane + 15] ^ s[inst][lane + 20];
      __syncthreads();
      if (act) {
        const int x = lane % 5, y = lane / 5;
        const uint64_t d = c[inst][(x + 4) % 5] ^ rotl(c[inst][(x + 1) % 5], 1);
        b[inst][y + 5 * ((2 * x + 3 * y) % 5)] = rotl(s[inst][lane] ^ d, RHO[x][y]);
      }
      __syncthreads();
      if (act) {
        const int x = lane % 5, y = lane / 5;
        uint64_t v = b[inst][lane] ^ (~b[inst][(x + 1) % 5 + 5 * y] & b[inst][(x + 2) % 5 + 5 * y]);
        if (lane == 0) v ^= RC[r];
        s[inst][lane] = v;
      }
      __syncthreads();
    }
    // Column parities of the state reached.
    if (act && lane < 5)
      c[inst][lane] = s[inst][lane] ^ s[inst][lane + 5] ^ s[inst][lane + 10] ^ s[inst][lane + 15] ^ s[inst][lane + 20];
    __syncthreads();
  }

  /// Loads slot `j`'s inputs into `s` (thread 0 sets the flags): a real slot pairs events 2j, 2j+1
  /// (B zero when absent); a dummy slot runs A = the first input and B = zero, not in use.
  __device__ void load_slot(
    const SlicedEvent* ev, size_t n, size_t j, uint64_t (*s)[25], bool& real, bool& use_b, uint32_t* ctx)
  {
    const size_t slots = (n + 1) / 2;
    real = j < slots;
    use_b = real && (2 * j + 1 < n);
    const int inst = threadIdx.x / 32, lane = threadIdx.x % 32;
    if (inst < 2 && lane < 25) {
      uint64_t v = 0;
      if (real) {
        const size_t e = 2 * j + inst;
        v = e < n ? ev[e].state[lane] : 0;
      } else if (n > 0 && inst == 0) {
        // Dummy slot: A = the first input, B = zero (see `sliced_trace`).
        v = ev[0].state[lane];
      }
      s[inst][lane] = v;
    }
    if (real) {
      ctx[0] = ev[2 * j].chunk;
      ctx[1] = ev[2 * j].clk;
      ctx[2] = use_b ? ev[2 * j + 1].chunk : 0;
      ctx[3] = use_b ? ev[2 * j + 1].clk : 0;
    } else {
      ctx[0] = ctx[1] = ctx[2] = ctx[3] = 0;
    }
    __syncthreads();
  }

  /// One block (64 threads) per trace row.
  template <class F>
  __global__ void trace_kernel(const SlicedEvent* ev, size_t n, size_t height, F* trace) {
    const size_t row = blockIdx.x;
    if (row >= height) return;
    const size_t j = row / SLOT_ROWS;
    const int g = row % SLOT_ROWS;
    __shared__ uint64_t s[2][25], c[2][5], b[2][25];
    __shared__ uint32_t ctx[4];
    bool real, use_b;
    load_slot(ev, n, j, s, real, use_b, ctx);
    const int rounds = g == 0 ? 0 : (g == SLOT_ROWS - 1 ? NUM_ROUNDS : g - 1);
    advance(s, c, b, rounds);

    F* out = trace + row * NUM_COLS;
    const bool plain = g == 0 || g == SLOT_ROWS - 1;
    const bool round_row = g >= 1 && g <= NUM_ROUNDS;
    for (int col = threadIdx.x; col < NUM_COLS; col += blockDim.x) {
      uint32_t v = 0;
      if (col < COL_IN_USE_A) {
        v = col == g;
      } else if (col == COL_IN_USE_A) {
        v = real;
      } else if (col == COL_IN_USE_B) {
        v = real && use_b;
      } else if (col < COL_STATE) {
        v = ctx[col - COL_CTX];
      } else if (col < COL_C) {
        const int i = col - COL_STATE, lane = i / 64, z = i % 64;
        const uint32_t a = (s[0][lane] >> z) & 1;
        v = plain ? a : a + 8 * ((s[1][lane] >> z) & 1);
      } else {
        const int k = col - COL_C;
        if (round_row) {
          const int x = k / 64, z = k % 64;
          v = ((c[0][x] >> z) & 1) + 8 * ((c[1][x] >> z) & 1);
        } else {
          // Boundary rows: A's limbs at 0..100 (rows 0, 26), B's at 100..200 (rows 0, 25).
          const bool a_side = k < 100 && (g == 0 || g == SLOT_ROWS - 1);
          const bool b_side = k >= 100 && k < 200 && (g == 0 || g == SLOT_ROWS - 2);
          if (a_side || b_side) {
            const int w = a_side ? k : k - 100, inst = a_side ? 0 : 1;
            v = (uint32_t)((s[inst][w / 4] >> (16 * (w % 4))) & 0xffff);
          }
        }
      }
      out[col] = F::from_canonical_u32(v);
    }
  }

  /// One block (64 threads) per (real slot, round): the round row's 80 xor5 and 320 chi keys.
  __global__ void count_kernel(const SlicedEvent* ev, size_t n, uint32_t* tables) {
    constexpr uint32_t MASK = HALF_ROWS - 1;
    const size_t j = blockIdx.x / NUM_ROUNDS;
    const int r = blockIdx.x % NUM_ROUNDS;
    __shared__ uint64_t s[2][25], c[2][5], b[2][25];
    __shared__ uint32_t ctx[4];
    bool real, use_b;
    load_slot(ev, n, j, s, real, use_b, ctx);
    if (!real) return;  // uniform per block
    advance(s, c, b, r);
    auto bit = [&](int inst, int x, int y, int z) -> uint32_t { return (s[inst][x + 5 * y] >> z) & 1; };
    auto par = [&](int inst, int x, int z) -> uint32_t { return (c[inst][x] >> z) & 1; };
    for (int t = threadIdx.x; t < 80 + 320; t += blockDim.x) {
      if (t < 80) {
        uint32_t idx = 0, w = 1;
        for (int k = 0; k < 4; k++) {
          const int p = t * 4 + k, x = p / 64, z = p % 64;
          uint32_t sa = 0, sb = 0;
          for (int y = 0; y < 5; y++) { sa += bit(0, x, y, z); sb += bit(1, x, y, z); }
          idx += w * (sa + 6 * sb);
          w *= 36;
        }
        atomicAdd(&tables[(idx & MASK) * TABLES_COLS + 2 + (idx >> 20)], 1u);
      } else {
        const int q = t - 80, by = q / 64, z = q % 64;
        const bool rc = by == 0 && ((RC[r] >> z) & 1);
        uint32_t idx = (uint32_t)rc << 20;
        for (int bx = 0; bx < 5; bx++) {
          int x, y;
          pi_src(bx, by, x, y);
          const int zz = (z + 64 - (int)RHO[x][y]) % 64;
          const uint32_t ta = bit(0, x, y, zz) + par(0, (x + 4) % 5, zz) + par(0, (x + 1) % 5, (zz + 63) % 64);
          const uint32_t tb = bit(1, x, y, zz) + par(1, (x + 4) % 5, zz) + par(1, (x + 1) % 5, (zz + 63) % 64);
          idx |= (ta + 4 * tb) << (4 * bx);
        }
        atomicAdd(&tables[(idx & MASK) * TABLES_COLS + (idx >> 20)], 1u);
      }
    }
  }

  /// Raw counts to field elements, in place.
  template <class F>
  __global__ void finalize_kernel(uint32_t* cells, size_t n) {
    const size_t i = blockIdx.x * (size_t)blockDim.x + threadIdx.x;
    if (i < n) reinterpret_cast<F*>(cells)[i] = F::from_canonical_u32(cells[i]);
  }

  template <class F>
  RustError generate(
    const SlicedEvent* ev, size_t n, size_t height, F* trace, F* tables, cudaStream_t stream) {
    try {
      if (trace) {
        trace_kernel<F><<<(unsigned)height, 64, 0, stream>>>(ev, n, height, trace);
        CUDA_OK(cudaGetLastError());
      }
      if (tables) {
        uint32_t* t_u = reinterpret_cast<uint32_t*>(tables);
        const size_t cells = (size_t)HALF_ROWS * TABLES_COLS;
        CUDA_OK(cudaMemsetAsync(t_u, 0, cells * sizeof(uint32_t), stream));
        const size_t slots = (n + 1) / 2;
        if (slots > 0) {
          count_kernel<<<(unsigned)(slots * NUM_ROUNDS), 64, 0, stream>>>(ev, n, t_u);
          CUDA_OK(cudaGetLastError());
        }
        finalize_kernel<F><<<(unsigned)(cells / 256), 256, 0, stream>>>(t_u, cells);
        CUDA_OK(cudaGetLastError());
      }
    } catch (const cuda_error& e) {
      return RustError{e.code()};
    }
    return RustError{cudaSuccess};
  }

  PICO_FFI
  RustError::by_value cuda_keccak_sliced_generate(
    const SlicedEvent* events,
    size_t event_size,
    size_t height,
    field_t* trace,
    field_t* tables,
    cudaStream_t stream)
  {
    return generate<field_t>(events, event_size, height, trace, tables, stream);
  }

} // namespace pico_gpu::keccak_sliced
