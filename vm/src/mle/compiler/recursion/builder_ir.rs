//! `Builder` IR-construction primitives: address allocation, constant/hint reads,
//! base- and extension-field ALU ops, block pack/unpack, MLE openings, and low-level asserts.

use super::*;

impl<F: PrimeField32 + TwoAdicField + FieldSepticCurve> Builder<F> {
    pub(super) fn new() -> Self {
        Builder {
            next_addr: 0,
            instructions: Vec::new(),
            read_counts: ReadCounts::default(),
            sponge: [0u32; WIDTH],
            lane_fresh: [false; WIDTH],
            sponge_blocks: [0u32; 4],
            sponge_unpacked: [None; 4],
            absorb_idx: 0,
            sample_idx: 0,
            addr_zero: 0,
            addr_one: 0,
            addr_two: 0,
            addr_inv2: 0,
            ef_basis: [0u32; 3],
            const_f_addrs: HashMap::new(),
        }
    }

    pub(super) fn alloc(&mut self) -> u32 {
        let a = self.next_addr;
        self.next_addr += 1;
        a
    }

    pub(super) fn mark_read(&mut self, addr: u32) {
        self.read_counts.bump(addr);
    }

    /// Emit Mem(Write) with mult=0 (backfilled later). Returns the allocated address.
    pub(super) fn write_const(&mut self, val: Block<F>) -> u32 {
        let addr = self.alloc();
        self.instructions
            .push(mem_block(MemAccessKind::Write, 0, addr, val));
        addr
    }

    /// `Block([c,0,0,0])` for a canonical `c`, written on first use and read from that one address
    /// thereafter. Sharing is sound for the reason `addr_zero` is: `finish` backfills the write's
    /// mult with every read. The cache spans the whole program, so a constant first written
    /// inside one child's span can be read by the next (`Runtime::run_split` hoists such writes).
    pub(super) fn const_f(&mut self, c: u32) -> u32 {
        if let Some(&addr) = self.const_f_addrs.get(&c) {
            return addr;
        }
        let addr = self.write_const(Block([F::from_u32(c), F::ZERO, F::ZERO, F::ZERO]));
        self.const_f_addrs.insert(c, addr);
        addr
    }

    /// Allocate addr_zero, addr_one, addr_two, addr_inv2, EF basis constants, and initialize the sponge.
    pub(super) fn init_constants(&mut self) -> u32 {
        let az = self.const_f(0);
        self.addr_one = self.const_f(1);
        // 2 as EF constant.
        self.addr_two = self.const_f(2);
        // 2^{-1} = (P+1)/2 (KoalaBear → 1065353217).
        self.addr_inv2 = self.const_f(F::ORDER_U64.div_ceil(2) as u32);
        self.ef_basis = [
            self.write_const(Block([F::ZERO, F::ONE, F::ZERO, F::ZERO])),
            self.write_const(Block([F::ZERO, F::ZERO, F::ONE, F::ZERO])),
            self.write_const(Block([F::ZERO, F::ZERO, F::ZERO, F::ONE])),
        ];
        self.sponge = [az; WIDTH];
        self.lane_fresh = [false; WIDTH];
        self.sponge_blocks = [az; 4];
        self.sponge_unpacked = [None; 4];
        az
    }

    // ─── Hint helpers ─────────────────────────────────────────────────────────

    /// Hint 1 F value (Block([f,0,0,0])) from witness_stream. Returns the output address.
    pub(super) fn hint_f(&mut self) -> u32 {
        let addr = self.alloc();
        self.instructions.push(Instruction::Hint(HintInstr {
            output_addrs_mults: vec![(Address(F::from_u32(addr)), F::ZERO)],
        }));
        addr
    }

    /// Hint `n` F values from witness_stream with a SINGLE multi-output Hint
    /// instruction (1 cycle instead of n). Returns the n output addresses in
    /// stream order. Only valid where the n stream blocks are consecutive —
    /// i.e. where the values were previously read by n back-to-back `hint_f`
    /// calls with no other hint instruction in between (the drain order of the
    /// witness stream is unchanged).
    pub(super) fn hint_fs(&mut self, n: usize) -> Vec<u32> {
        let addrs: Vec<u32> = (0..n).map(|_| self.alloc()).collect();
        self.instructions.push(Instruction::Hint(HintInstr {
            output_addrs_mults: addrs
                .iter()
                .map(|&a| (Address(F::from_u32(a)), F::ZERO))
                .collect(),
        }));
        addrs
    }

    /// Hint 1 EF value (Block([c0,c1,c2,c3])) then decompose into 4 F addresses.
    /// Returns (ef_block_addr, [f0_addr, f1_addr, f2_addr, f3_addr]).
    ///
    /// The decomposition is CONSTRAINED via `UnpackBlock`, whose AIR receives the input block
    /// on the memory bus and forwards `val.0[i]` as the four outputs — forcing
    /// `f_addrs == lanes(ef_addr)`. A raw `HintExt2Felts` would NOT: that instruction is
    /// handled only by MemoryVar, which writes the outputs with no receive/interaction on the
    /// input, leaving the four felts unconstrained relative to the EF block. Since callers
    /// absorb `f_addrs` into the Fiat-Shamir sponge / hash them into WHIR Merkle leaves while
    /// feeding `ef_addr` to the field algebra, an unconstrained split would let the absorbed /
    /// Merkle-verified felts diverge from the checked EF value (a Fiat-Shamir + WHIR-opening
    /// soundness break). Keep this decomposition constrained.
    pub(super) fn hint_ef_full(&mut self) -> (u32, [u32; EXTENSION_DEGREE]) {
        let ef_addr = self.hint_f();
        let f_addrs = self.unpack_block(ef_addr);
        (ef_addr, f_addrs)
    }

    // ─── ExtAlu helpers ───────────────────────────────────────────────────────

    /// Emit an ExtAlu instruction.  Returns the output address (mult=0, backfilled later).
    pub(super) fn ext_alu_op(&mut self, opcode: ExtAluOpcode, in1: u32, in2: u32) -> u32 {
        let out = self.alloc();
        self.mark_read(in1);
        self.mark_read(in2);
        self.instructions.push(ext_alu(opcode, 0, out, in1, in2));
        out
    }

    pub(super) fn ext_add(&mut self, a: u32, b: u32) -> u32 {
        self.ext_alu_op(ExtAluOpcode::AddE, a, b)
    }

    pub(super) fn ext_sub(&mut self, a: u32, b: u32) -> u32 {
        self.ext_alu_op(ExtAluOpcode::SubE, a, b)
    }

    pub(super) fn ext_mul(&mut self, a: u32, b: u32) -> u32 {
        self.ext_alu_op(ExtAluOpcode::MulE, a, b)
    }

    /// Emit AssertZeroExt: asserts val at `addr` equals zero.
    pub(super) fn assert_ext_zero(&mut self, addr: u32) {
        self.mark_read(addr);
        self.instructions
            .push(Instruction::AssertZeroExt(AssertZeroExtInstr {
                addr: Address(F::from_u32(addr)),
            }));
    }

    /// Assert a == b: ext_sub(a, b) then assert_ext_zero.
    pub(super) fn assert_ext_eq(&mut self, a: u32, b: u32) {
        let diff = self.ext_sub(a, b);
        self.assert_ext_zero(diff);
    }

    /// Pack four F-addresses (each Block([fi,0,0,0])) into a single EF Block address.
    /// Uses 6 ExtAlu instructions: 3 MulE (basis projection) + 3 AddE (accumulate).
    pub(super) fn pack_ef(&mut self, r: [u32; 4]) -> u32 {
        let [r0, r1, r2, r3] = r;
        let [t1, t2, t3] = self.ef_basis;
        // r1·(0,1,0,0) = (0,r1,0,0)  etc.
        let r1_e = self.ext_mul(r1, t1);
        let r2_e = self.ext_mul(r2, t2);
        let r3_e = self.ext_mul(r3, t3);
        let p01 = self.ext_add(r0, r1_e);
        let p012 = self.ext_add(p01, r2_e);
        self.ext_add(p012, r3_e) // Block([r0,r1,r2,r3])
    }

    /// Emit PackBlock: pack 4 single-F addresses into one 4-lane block address.
    pub(super) fn pack_block(&mut self, lanes: [u32; 4]) -> u32 {
        let out = self.alloc();
        for a in lanes {
            self.mark_read(a);
        }
        self.instructions
            .push(Instruction::PackBlock(Box::new(PackBlockInstr {
                in_addrs: lanes.map(|a| Address(F::from_u32(a))),
                out_addr: Address(F::from_u32(out)),
                mult: F::ZERO, // backfilled
            })));
        out
    }

    /// Emit UnpackBlock: expose the 4 lanes of a block as single-F addresses.
    pub(super) fn unpack_block(&mut self, block: u32) -> [u32; 4] {
        let outs: [u32; 4] = std::array::from_fn(|_| self.alloc());
        self.mark_read(block);
        self.instructions
            .push(Instruction::UnpackBlock(Box::new(UnpackBlockInstr {
                in_addr: Address(F::from_u32(block)),
                out_addrs: outs.map(|a| Address(F::from_u32(a))),
                mults: [F::ZERO; 4], // backfilled
            })));
        outs
    }

    /// Emit MleOpen: record (air_id, col_id, opening_value) for global MLE-opening consistency.
    pub(super) fn mle_open(&mut self, air_id: usize, col_id: usize, val_addr: u32) {
        let col_ref: u32 = ((air_id as u32) << 16) | (col_id as u32);
        self.mark_read(val_addr);
        self.instructions.push(Instruction::MleOpen(MleOpenInstr {
            col_ref,
            opening_value_addr: Address(F::from_u32(val_addr)),
        }));
    }

    // ─── BaseAlu helpers ──────────────────────────────────────────────────────

    pub(super) fn base_alu_op(&mut self, opcode: BaseAluOpcode, in1: u32, in2: u32) -> u32 {
        let out = self.alloc();
        self.mark_read(in1);
        self.mark_read(in2);
        self.instructions.push(base_alu(opcode, 0, out, in1, in2));
        out
    }

    pub(super) fn base_add(&mut self, a: u32, b: u32) -> u32 {
        self.base_alu_op(BaseAluOpcode::AddF, a, b)
    }

    pub(super) fn base_sub(&mut self, a: u32, b: u32) -> u32 {
        self.base_alu_op(BaseAluOpcode::SubF, a, b)
    }

    pub(super) fn base_mul(&mut self, a: u32, b: u32) -> u32 {
        self.base_alu_op(BaseAluOpcode::MulF, a, b)
    }

    /// Assert two F-addr values are equal: base_sub then assert_ext_zero.
    pub(super) fn assert_f_eq(&mut self, a: u32, b: u32) {
        let diff = self.base_sub(a, b);
        self.assert_ext_zero(diff);
    }
}
