use crate::{
    compiler::recursion::{
        instruction::{
            FieldEltType, HintAddCurveInstr, HintBitsInstr, HintExt2FeltsInstr, HintInstr,
            Instruction, PrintInstr,
        },
        ir::Block,
        prelude::*,
        program::RecursionProgram,
        types::*,
    },
    configs::config::FieldGenericConfig,
    emulator::recursion::{emulator::*, public_values::RecursionPublicValues},
    machine::septic::SepticCurve,
    primitives::consts::{EXTENSION_DEGREE, RECURSION_NUM_PVS},
};
use core::fmt::Debug;
use itertools::Itertools;
use p3_field::{
    Field, FieldAlgebra, FieldExtensionAlgebra, PrimeField, PrimeField64, TwoAdicField,
};
use std::{borrow::Borrow, collections::HashMap, mem::transmute};
use tracing::instrument;
use vec_map::VecMap;

/// The backend for the circuit compiler.
#[derive(Debug, Clone, Default)]
#[allow(clippy::type_complexity)]
pub struct DslIrCompiler<FC: FieldGenericConfig> {
    pub next_addr: FC::F,
    /// Map the frame pointers of the variables to the "physical" addresses.
    pub virtual_to_physical: VecMap<Address<FC::F>>,
    /// Map base or extension field constants to "physical" addresses and mults.
    pub consts: HashMap<Imm<FC::F, FC::EF>, (Address<FC::F>, FC::F)>,
    /// Map each "physical" address to its read count.
    pub addr_to_mult: VecMap<FC::F>,
}

impl<FC: FieldGenericConfig> DslIrCompiler<FC>
where
    FC::F: PrimeField64,
{
    /// Emit the instructions from a list of operations in the DSL.
    #[instrument(name = "compile recursion program", level = "debug", skip_all)]
    pub fn compile<F>(&mut self, operations: TracedVec<DslIr<FC>>) -> RecursionProgram<FC::F>
    where
        F: PrimeField + TwoAdicField,
        FC: FieldGenericConfig<N = F, F = F> + Debug,
    {
        // TODO: add debug mode
        // Compile each IR instruction into a list of recursion program instructions, then combine them.
        // This step also counts the number of times each address is read from.
        let (mut instrs, traces) = tracing::debug_span!("compile_one loop").in_scope(|| {
            let mut instrs = Vec::with_capacity(operations.vec.len());
            let traces = vec![];
            for (ir_instr, trace) in operations {
                self.compile_one(ir_instr, &mut |item| match item {
                    Ok(instr) => instrs.push(instr),
                    Err(CompileOneErr::CycleTrackerEnter(_) | CompileOneErr::CycleTrackerExit) => {}
                    Err(CompileOneErr::Unsupported(instr)) => {
                        panic!("unsupported instruction: {instr:?}\nbacktrace: {:?}", trace)
                    }
                });
            }
            (instrs, traces)
        });

        // Replace the mults using the address count data gathered in this previous.
        // Exhaustive match for refactoring purposes.
        let total_memory = self.addr_to_mult.len() + self.consts.len();
        let mut backfill = |(mult, addr): (&mut F, &Address<F>)| {
            *mult = self.addr_to_mult.remove(addr.as_usize()).unwrap()
        };
        tracing::debug_span!("backfill mult").in_scope(|| {
            for recur_prog_instr in instrs.iter_mut() {
                match recur_prog_instr {
                    Instruction::BaseAlu(BaseAluInstr {
                        mult,
                        addrs: BaseAluIo { out: ref addr, .. },
                        ..
                    }) => backfill((mult, addr)),
                    Instruction::ExtAlu(ExtAluInstr {
                        mult,
                        addrs: ExtAluIo { out: ref addr, .. },
                        ..
                    }) => backfill((mult, addr)),
                    Instruction::Mem(MemInstr {
                        addrs: MemIo { inner: ref addr },
                        mult,
                        kind: MemAccessKind::Write,
                        ..
                    }) => backfill((mult, addr)),
                    Instruction::Poseidon2(instr) => {
                        let Poseidon2SkinnyInstr {
                            addrs:
                                Poseidon2Io {
                                    output: ref addrs, ..
                                },
                            mults,
                        } = instr.as_mut();
                        mults.iter_mut().zip(addrs).for_each(&mut backfill);
                    }
                    Instruction::Select(SelectInstr {
                        addrs:
                            SelectIo {
                                out1: ref addr1,
                                out2: ref addr2,
                                ..
                            },
                        mult1,
                        mult2,
                    }) => {
                        backfill((mult1, addr1));
                        backfill((mult2, addr2));
                    }
                    Instruction::ExpReverseBitsLen(ExpReverseBitsInstr {
                        addrs:
                            ExpReverseBitsIo {
                                result: ref addr, ..
                            },
                        mult,
                    }) => backfill((mult, addr)),
                    Instruction::HintBits(HintBitsInstr {
                        output_addrs_mults, ..
                    })
                    | Instruction::Hint(HintInstr {
                        output_addrs_mults, ..
                    }) => {
                        output_addrs_mults
                            .iter_mut()
                            .for_each(|(addr, mult)| backfill((mult, addr)));
                    }
                    Instruction::BatchFRI(instr) => {
                        let BatchFRIInstr {
                            ext_single_addrs: BatchFRIExtSingleIo { ref acc },
                            acc_mult,
                            ..
                        } = instr.as_mut();
                        backfill((acc_mult, acc));
                    }

                    Instruction::HintExt2Felts(HintExt2FeltsInstr {
                        output_addrs_mults, ..
                    }) => {
                        output_addrs_mults
                            .iter_mut()
                            .for_each(|(addr, mult)| backfill((mult, addr)));
                    }
                    Instruction::HintAddCurve(instr) => {
                        let HintAddCurveInstr {
                            output_x_addrs_mults,
                            output_y_addrs_mults,
                            ..
                        } = instr.as_mut();
                        output_x_addrs_mults
                            .iter_mut()
                            .for_each(|(addr, mult)| backfill((mult, addr)));
                        output_y_addrs_mults
                            .iter_mut()
                            .for_each(|(addr, mult)| backfill((mult, addr)));
                    }
                    // Instructions that do not write to memory.
                    Instruction::Mem(MemInstr {
                        kind: MemAccessKind::Read,
                        ..
                    })
                    | Instruction::CommitPublicValues(_)
                    | Instruction::Print(_) => (),
                }
            }
        });
        debug_assert!(self.addr_to_mult.is_empty());
        // Initialize constants.
        let _total_consts = self.consts.len();
        let instrs_consts =
            self.consts
                .drain()
                .sorted_by_key(|x| x.1 .0 .0)
                .map(|(imm, (addr, mult))| {
                    Instruction::Mem(MemInstr {
                        addrs: MemIo { inner: addr },
                        vals: MemIo {
                            inner: imm.as_block(),
                        },
                        mult,
                        kind: MemAccessKind::Write,
                    })
                });
        tracing::debug!("number of consts to initialize: {}", instrs_consts.len());
        // Reset the other fields.
        self.next_addr = Default::default();
        self.virtual_to_physical.clear();
        // Place constant-initializing instructions at the top.
        let (instructions, traces) = tracing::debug_span!("construct program")
            .in_scope(|| (instrs_consts.chain(instrs).collect(), traces));
        RecursionProgram {
            instructions,
            total_memory,
            traces,
            shape: None,
        }
    }

    /// Compiles one instruction, passing one or more instructions to `consumer`.
    ///
    /// We do not simply return a `Vec` for performance reasons --- results would be immediately fed
    /// to `flat_map`, so we employ fusion/deforestation to eliminate intermediate data structures.
    fn compile_one<F>(
        &mut self,
        ir_instr: DslIr<FC>,
        mut consumer: impl FnMut(Result<Instruction<FC::F>, CompileOneErr<FC>>),
    ) where
        F: PrimeField + TwoAdicField,
        FC: FieldGenericConfig<N = F, F = F> + Debug,
    {
        // For readability. Avoids polluting outer scope.
        use crate::emulator::recursion::emulator::{BaseAluOpcode::*, ExtAluOpcode::*};

        let mut f = |instr| consumer(Ok(instr));
        match ir_instr {
            DslIr::ImmV(dst, src) => f(self.mem_write_const(dst, Imm::F(src))),
            DslIr::ImmF(dst, src) => f(self.mem_write_const(dst, Imm::F(src))),
            DslIr::ImmE(dst, src) => f(self.mem_write_const(dst, Imm::EF(src))),

            DslIr::AddV(dst, lhs, rhs) => f(self.base_alu(AddF, dst, lhs, rhs)),
            DslIr::AddVI(dst, lhs, rhs) => f(self.base_alu(AddF, dst, lhs, Imm::F(rhs))),
            DslIr::AddF(dst, lhs, rhs) => f(self.base_alu(AddF, dst, lhs, rhs)),
            DslIr::AddFI(dst, lhs, rhs) => f(self.base_alu(AddF, dst, lhs, Imm::F(rhs))),
            DslIr::AddE(dst, lhs, rhs) => f(self.ext_alu(AddE, dst, lhs, rhs)),
            DslIr::AddEI(dst, lhs, rhs) => f(self.ext_alu(AddE, dst, lhs, Imm::EF(rhs))),
            DslIr::AddEF(dst, lhs, rhs) => f(self.ext_alu(AddE, dst, lhs, rhs)),
            DslIr::AddEFI(dst, lhs, rhs) => f(self.ext_alu(AddE, dst, lhs, Imm::F(rhs))),
            DslIr::AddEFFI(dst, lhs, rhs) => f(self.ext_alu(AddE, dst, lhs, Imm::EF(rhs))),

            DslIr::SubV(dst, lhs, rhs) => f(self.base_alu(SubF, dst, lhs, rhs)),
            DslIr::SubVI(dst, lhs, rhs) => f(self.base_alu(SubF, dst, lhs, Imm::F(rhs))),
            DslIr::SubVIN(dst, lhs, rhs) => f(self.base_alu(SubF, dst, Imm::F(lhs), rhs)),
            DslIr::SubF(dst, lhs, rhs) => f(self.base_alu(SubF, dst, lhs, rhs)),
            DslIr::SubFI(dst, lhs, rhs) => f(self.base_alu(SubF, dst, lhs, Imm::F(rhs))),
            DslIr::SubFIN(dst, lhs, rhs) => f(self.base_alu(SubF, dst, Imm::F(lhs), rhs)),
            DslIr::SubE(dst, lhs, rhs) => f(self.ext_alu(SubE, dst, lhs, rhs)),
            DslIr::SubEI(dst, lhs, rhs) => f(self.ext_alu(SubE, dst, lhs, Imm::EF(rhs))),
            DslIr::SubEIN(dst, lhs, rhs) => f(self.ext_alu(SubE, dst, Imm::EF(lhs), rhs)),
            DslIr::SubEFI(dst, lhs, rhs) => f(self.ext_alu(SubE, dst, lhs, Imm::F(rhs))),
            DslIr::SubEF(dst, lhs, rhs) => f(self.ext_alu(SubE, dst, lhs, rhs)),

            DslIr::MulV(dst, lhs, rhs) => f(self.base_alu(MulF, dst, lhs, rhs)),
            DslIr::MulVI(dst, lhs, rhs) => f(self.base_alu(MulF, dst, lhs, Imm::F(rhs))),
            DslIr::MulF(dst, lhs, rhs) => f(self.base_alu(MulF, dst, lhs, rhs)),
            DslIr::MulFI(dst, lhs, rhs) => f(self.base_alu(MulF, dst, lhs, Imm::F(rhs))),
            DslIr::MulE(dst, lhs, rhs) => f(self.ext_alu(MulE, dst, lhs, rhs)),
            DslIr::MulEI(dst, lhs, rhs) => f(self.ext_alu(MulE, dst, lhs, Imm::EF(rhs))),
            DslIr::MulEFI(dst, lhs, rhs) => f(self.ext_alu(MulE, dst, lhs, Imm::F(rhs))),
            DslIr::MulEF(dst, lhs, rhs) => f(self.ext_alu(MulE, dst, lhs, rhs)),

            DslIr::DivF(dst, lhs, rhs) => f(self.base_alu(DivF, dst, lhs, rhs)),
            DslIr::DivFI(dst, lhs, rhs) => f(self.base_alu(DivF, dst, lhs, Imm::F(rhs))),
            DslIr::DivFIN(dst, lhs, rhs) => f(self.base_alu(DivF, dst, Imm::F(lhs), rhs)),
            DslIr::DivE(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, lhs, rhs)),
            DslIr::DivEI(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, lhs, Imm::EF(rhs))),
            DslIr::DivEIN(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, Imm::EF(lhs), rhs)),
            DslIr::DivEFI(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, lhs, Imm::F(rhs))),
            DslIr::DivEFIN(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, Imm::F(lhs), rhs)),
            DslIr::DivEF(dst, lhs, rhs) => f(self.ext_alu(DivE, dst, lhs, rhs)),

            DslIr::NegV(dst, src) => f(self.base_alu(SubF, dst, Imm::F(FC::F::ZERO), src)),
            DslIr::NegF(dst, src) => f(self.base_alu(SubF, dst, Imm::F(FC::F::ZERO), src)),
            DslIr::NegE(dst, src) => f(self.ext_alu(SubE, dst, Imm::EF(FC::EF::ZERO), src)),
            DslIr::InvV(dst, src) => f(self.base_alu(DivF, dst, Imm::F(FC::F::ONE), src)),
            DslIr::InvF(dst, src) => f(self.base_alu(DivF, dst, Imm::F(FC::F::ONE), src)),
            DslIr::InvE(dst, src) => f(self.ext_alu(DivE, dst, Imm::F(FC::F::ONE), src)),

            DslIr::AssertEqV(lhs, rhs) => self.base_assert_eq(lhs, rhs, f),
            DslIr::AssertEqF(lhs, rhs) => self.base_assert_eq(lhs, rhs, f),
            DslIr::AssertEqE(lhs, rhs) => self.ext_assert_eq(lhs, rhs, f),
            DslIr::AssertEqVI(lhs, rhs) => self.base_assert_eq(lhs, Imm::F(rhs), f),
            DslIr::AssertEqFI(lhs, rhs) => self.base_assert_eq(lhs, Imm::F(rhs), f),
            DslIr::AssertEqEI(lhs, rhs) => self.ext_assert_eq(lhs, Imm::EF(rhs), f),

            DslIr::AssertNeV(lhs, rhs) => self.base_assert_ne(lhs, rhs, f),
            DslIr::AssertNeF(lhs, rhs) => self.base_assert_ne(lhs, rhs, f),
            DslIr::AssertNeE(lhs, rhs) => self.ext_assert_ne(lhs, rhs, f),
            DslIr::AssertNeVI(lhs, rhs) => self.base_assert_ne(lhs, Imm::F(rhs), f),
            DslIr::AssertNeFI(lhs, rhs) => self.base_assert_ne(lhs, Imm::F(rhs), f),
            DslIr::AssertNeEI(lhs, rhs) => self.ext_assert_ne(lhs, Imm::EF(rhs), f),

            DslIr::PrecompilePoseidon2BabyBear(data) => f(self.poseidon2_permute(data.0, data.1)),
            DslIr::PrecompilePoseidon2KoalaBear(data) => f(self.poseidon2_permute(data.0, data.1)),
            DslIr::CircuitExpReverseBits(dst, base, exp) => {
                f(self.exp_reverse_bits(dst, base, exp))
            }
            DslIr::CircuitHintBitsF(output, value) => f(self.hint_bit_decomposition(value, output)),
            DslIr::CircuitCommitPublicValues(public_values) => {
                f(self.commit_public_values(&public_values))
            }
            DslIr::CircuitBatchFRI(data) => f(self.batch_fri(data.0, data.1, data.2, data.3)),

            DslIr::Select(bit, dst1, dst2, lhs, rhs) => f(self.select(bit, dst1, dst2, lhs, rhs)),
            DslIr::CircuitHintAddCurve(data) => f(self.add_curve(data.0, data.1, data.2)),

            DslIr::PrintV(dst) => f(self.print_f(dst)),
            DslIr::PrintF(dst) => f(self.print_f(dst)),
            DslIr::PrintE(dst) => f(self.print_e(dst)),
            DslIr::CircuitHintFelts(output) => f(self.hint(&output)),
            DslIr::CircuitHintExts(output) => f(self.hint(&output)),
            DslIr::CircuitExt2Felt(felts, ext) => f(self.ext2felts(felts, ext)),
            DslIr::CycleTrackerEnter(name) => consumer(Err(CompileOneErr::CycleTrackerEnter(name))),
            DslIr::CycleTrackerExit => consumer(Err(CompileOneErr::CycleTrackerExit)),
            DslIr::ReduceE(_) => {}
            instr => consumer(Err(CompileOneErr::Unsupported(instr))),
        }
    }

    /// Allocate a fresh address. Checks that the address space is not full.
    pub fn alloc(next_addr: &mut FC::F) -> Address<FC::F> {
        let id = Address(*next_addr);
        *next_addr += FC::F::ONE;
        if next_addr.is_zero() {
            panic!("out of address space");
        }
        id
    }

    /// Map `fp` to its existing address without changing its mult.
    ///
    /// Ensures that `fp` has already been assigned an address.
    pub fn read_ghost_vaddr(&mut self, vaddr: usize) -> Address<FC::F> {
        self.read_vaddr_internal(vaddr, false)
    }

    /// Map `fp` to its existing address and increment its mult.
    ///
    /// Ensures that `fp` has already been assigned an address.
    pub fn read_vaddr(&mut self, vaddr: usize) -> Address<FC::F> {
        self.read_vaddr_internal(vaddr, true)
    }

    pub fn read_vaddr_internal(&mut self, vaddr: usize, increment_mult: bool) -> Address<FC::F> {
        use vec_map::Entry;
        match self.virtual_to_physical.entry(vaddr) {
            Entry::Vacant(_) => panic!("expected entry: virtual_physical[{:?}]", vaddr),
            Entry::Occupied(entry) => {
                if increment_mult {
                    // This is a read, so we increment the mult.
                    match self.addr_to_mult.get_mut(entry.get().as_usize()) {
                        Some(mult) => *mult += FC::F::ONE,
                        None => panic!("expected entry: virtual_physical[{:?}]", vaddr),
                    }
                }
                *entry.into_mut()
            }
        }
    }

    /// Map `fp` to a fresh address and initialize the mult to 0.
    ///
    /// Ensures that `fp` has not already been written to.
    pub fn write_fp(&mut self, vaddr: usize) -> Address<FC::F> {
        use vec_map::Entry;
        match self.virtual_to_physical.entry(vaddr) {
            Entry::Vacant(entry) => {
                let addr = Self::alloc(&mut self.next_addr);
                // This is a write, so we set the mult to zero.
                if let Some(x) = self.addr_to_mult.insert(addr.as_usize(), FC::F::ZERO) {
                    panic!("unexpected entry in addr_to_mult: {x:?}");
                }
                *entry.insert(addr)
            }
            Entry::Occupied(entry) => {
                panic!(
                    "unexpected entry: virtual_to_physical[{:?}] = {:?}",
                    vaddr,
                    entry.get()
                )
            }
        }
    }

    /// Increment the existing `mult` associated with `addr`.
    ///
    /// Ensures that `addr` has already been assigned a `mult`.
    pub fn read_addr(&mut self, addr: Address<FC::F>) -> &mut FC::F {
        self.read_addr_internal(addr, true)
    }

    /// Retrieves `mult` associated with `addr`.
    ///
    /// Ensures that `addr` has already been assigned a `mult`.
    pub fn read_ghost_addr(&mut self, addr: Address<FC::F>) -> &mut FC::F {
        self.read_addr_internal(addr, true)
    }

    fn read_addr_internal(&mut self, addr: Address<FC::F>, increment_mult: bool) -> &mut FC::F {
        use vec_map::Entry;
        match self.addr_to_mult.entry(addr.as_usize()) {
            Entry::Vacant(_) => panic!("expected entry: addr_to_mult[{:?}]", addr.as_usize()),
            Entry::Occupied(entry) => {
                // This is a read, so we increment the mult.
                let mult = entry.into_mut();
                if increment_mult {
                    *mult += FC::F::ONE;
                }
                mult
            }
        }
    }

    /// Associate a `mult` of zero with `addr`.
    ///
    /// Ensures that `addr` has not already been written to.
    pub fn write_addr(&mut self, addr: Address<FC::F>) -> &mut FC::F {
        use vec_map::Entry;
        match self.addr_to_mult.entry(addr.as_usize()) {
            Entry::Vacant(entry) => entry.insert(FC::F::ZERO),
            Entry::Occupied(entry) => {
                panic!(
                    "unexpected entry: addr_to_mult[{:?}] = {:?}",
                    addr.as_usize(),
                    entry.get()
                )
            }
        }
    }

    /// Read a constant (a.k.a. immediate).
    ///
    /// Increments the mult, first creating an entry if it does not yet exist.
    pub fn read_const(&mut self, imm: Imm<FC::F, FC::EF>) -> Address<FC::F> {
        self.consts
            .entry(imm)
            .and_modify(|(_, x)| *x += FC::F::ONE)
            .or_insert_with(|| (Self::alloc(&mut self.next_addr), FC::F::ONE))
            .0
    }

    /// Read a constant (a.k.a. immediate).
    ///    
    /// Does not increment the mult. Creates an entry if it does not yet exist.
    pub fn read_ghost_const(&mut self, imm: Imm<FC::F, FC::EF>) -> Address<FC::F> {
        self.consts
            .entry(imm)
            .or_insert_with(|| (Self::alloc(&mut self.next_addr), FC::F::ZERO))
            .0
    }

    fn mem_write_const(
        &mut self,
        dst: impl Reg<FC>,
        src: Imm<FC::F, FC::EF>,
    ) -> Instruction<FC::F> {
        Instruction::Mem(MemInstr {
            addrs: MemIo {
                inner: dst.write(self),
            },
            vals: MemIo {
                inner: src.as_block(),
            },
            mult: FC::F::ZERO,
            kind: MemAccessKind::Write,
        })
    }

    fn base_alu(
        &mut self,
        opcode: BaseAluOpcode,
        dst: impl Reg<FC>,
        lhs: impl Reg<FC>,
        rhs: impl Reg<FC>,
    ) -> Instruction<FC::F> {
        Instruction::BaseAlu(BaseAluInstr {
            opcode,
            mult: FC::F::ZERO,
            addrs: BaseAluIo {
                out: dst.write(self),
                in1: lhs.read(self),
                in2: rhs.read(self),
            },
        })
    }

    fn ext_alu(
        &mut self,
        opcode: ExtAluOpcode,
        dst: impl Reg<FC>,
        lhs: impl Reg<FC>,
        rhs: impl Reg<FC>,
    ) -> Instruction<FC::F> {
        Instruction::ExtAlu(ExtAluInstr {
            opcode,
            mult: FC::F::ZERO,
            addrs: ExtAluIo {
                out: dst.write(self),
                in1: lhs.read(self),
                in2: rhs.read(self),
            },
        })
    }

    fn base_assert_eq(
        &mut self,
        lhs: impl Reg<FC>,
        rhs: impl Reg<FC>,
        mut f: impl FnMut(Instruction<FC::F>),
    ) {
        use BaseAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));
        f(self.base_alu(SubF, diff, lhs, rhs));
        f(self.base_alu(DivF, out, diff, Imm::F(FC::F::ZERO)));
    }

    fn base_assert_ne(
        &mut self,
        lhs: impl Reg<FC>,
        rhs: impl Reg<FC>,
        mut f: impl FnMut(Instruction<FC::F>),
    ) {
        use BaseAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));

        f(self.base_alu(SubF, diff, lhs, rhs));
        f(self.base_alu(DivF, out, Imm::F(FC::F::ONE), diff));
    }

    fn ext_assert_eq(
        &mut self,
        lhs: impl Reg<FC>,
        rhs: impl Reg<FC>,
        mut f: impl FnMut(Instruction<FC::F>),
    ) {
        use ExtAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));

        f(self.ext_alu(SubE, diff, lhs, rhs));
        f(self.ext_alu(DivE, out, diff, Imm::EF(FC::EF::ZERO)));
    }

    fn ext_assert_ne(
        &mut self,
        lhs: impl Reg<FC>,
        rhs: impl Reg<FC>,
        mut f: impl FnMut(Instruction<FC::F>),
    ) {
        use ExtAluOpcode::*;
        let [diff, out] = core::array::from_fn(|_| Self::alloc(&mut self.next_addr));

        f(self.ext_alu(SubE, diff, lhs, rhs));
        f(self.ext_alu(DivE, out, Imm::EF(FC::EF::ONE), diff));
    }

    #[inline(always)]
    fn poseidon2_permute(
        &mut self,
        dst: [impl Reg<FC>; WIDTH],
        src: [impl Reg<FC>; WIDTH],
    ) -> Instruction<FC::F> {
        Instruction::Poseidon2(Box::new(Poseidon2Instr {
            addrs: Poseidon2Io {
                input: src.map(|r| r.read(self)),
                output: dst.map(|r| r.write(self)),
            },
            mults: [FC::F::ZERO; WIDTH],
        }))
    }

    #[inline(always)]
    fn select(
        &mut self,
        bit: impl Reg<FC>,
        dst1: impl Reg<FC>,
        dst2: impl Reg<FC>,
        lhs: impl Reg<FC>,
        rhs: impl Reg<FC>,
    ) -> Instruction<FC::F> {
        Instruction::Select(SelectInstr {
            addrs: SelectIo {
                bit: bit.read(self),
                out1: dst1.write(self),
                out2: dst2.write(self),
                in1: lhs.read(self),
                in2: rhs.read(self),
            },
            mult1: FC::F::ZERO,
            mult2: FC::F::ZERO,
        })
    }

    fn exp_reverse_bits(
        &mut self,
        dst: impl Reg<FC>,
        base: impl Reg<FC>,
        exp: impl IntoIterator<Item = impl Reg<FC>>,
    ) -> Instruction<FC::F> {
        Instruction::ExpReverseBitsLen(ExpReverseBitsInstr {
            addrs: ExpReverseBitsIo {
                result: dst.write(self),
                base: base.read(self),
                exp: exp.into_iter().map(|r| r.read(self)).collect(),
            },
            mult: FC::F::ZERO,
        })
    }

    fn hint_bit_decomposition(
        &mut self,
        value: impl Reg<FC>,
        output: impl IntoIterator<Item = impl Reg<FC>>,
    ) -> Instruction<FC::F> {
        Instruction::HintBits(HintBitsInstr {
            output_addrs_mults: output
                .into_iter()
                .map(|r| (r.write(self), FC::F::ZERO))
                .collect(),
            input_addr: value.read_ghost(self),
        })
    }

    fn batch_fri(
        &mut self,
        acc: Ext<FC::F, FC::EF>,
        alpha_pows: Vec<Ext<FC::F, FC::EF>>,
        p_at_zs: Vec<Ext<FC::F, FC::EF>>,
        p_at_xs: Vec<Felt<FC::F>>,
    ) -> Instruction<FC::F> {
        Instruction::BatchFRI(Box::new(BatchFRIInstr {
            base_vec_addrs: BatchFRIBaseVecIo {
                p_at_x: p_at_xs.into_iter().map(|e| e.read(self)).collect(),
            },
            ext_single_addrs: BatchFRIExtSingleIo {
                acc: acc.write(self),
            },
            ext_vec_addrs: BatchFRIExtVecIo {
                p_at_z: p_at_zs.into_iter().map(|e| e.read(self)).collect(),
                alpha_pow: alpha_pows.into_iter().map(|e| e.read(self)).collect(),
            },
            acc_mult: FC::F::ZERO,
        }))
    }

    fn commit_public_values(
        &mut self,
        public_values: &RecursionPublicValues<Felt<FC::F>>,
    ) -> Instruction<FC::F> {
        public_values.digest.iter().for_each(|x| {
            let _ = x.read(self);
        });
        let pv_addrs = unsafe {
            transmute::<RecursionPublicValues<Felt<FC::F>>, [Felt<FC::F>; RECURSION_NUM_PVS]>(
                *public_values,
            )
        }
        .map(|pv| pv.read_ghost(self));

        let public_values_a: &RecursionPublicValues<Address<FC::F>> = pv_addrs.as_slice().borrow();
        Instruction::CommitPublicValues(Box::new(CommitPublicValuesInstr {
            pv_addrs: *public_values_a,
        }))
    }

    fn add_curve(
        &mut self,
        output: SepticCurve<Felt<FC::F>>,
        input1: SepticCurve<Felt<FC::F>>,
        input2: SepticCurve<Felt<FC::F>>,
    ) -> Instruction<FC::F> {
        Instruction::HintAddCurve(Box::new(HintAddCurveInstr {
            output_x_addrs_mults: output
                .x
                .0
                .into_iter()
                .map(|r| (r.write(self), FC::F::ZERO))
                .collect(),
            output_y_addrs_mults: output
                .y
                .0
                .into_iter()
                .map(|r| (r.write(self), FC::F::ZERO))
                .collect(),
            input1_x_addrs: input1
                .x
                .0
                .into_iter()
                .map(|value| value.read_ghost(self))
                .collect(),
            input1_y_addrs: input1
                .y
                .0
                .into_iter()
                .map(|value| value.read_ghost(self))
                .collect(),
            input2_x_addrs: input2
                .x
                .0
                .into_iter()
                .map(|value| value.read_ghost(self))
                .collect(),
            input2_y_addrs: input2
                .y
                .0
                .into_iter()
                .map(|value| value.read_ghost(self))
                .collect(),
        }))
    }

    fn print_f(&mut self, addr: impl Reg<FC>) -> Instruction<FC::F> {
        Instruction::Print(PrintInstr {
            field_elt_type: FieldEltType::Base,
            addr: addr.read_ghost(self),
        })
    }

    fn print_e(&mut self, addr: impl Reg<FC>) -> Instruction<FC::F> {
        Instruction::Print(PrintInstr {
            field_elt_type: FieldEltType::Extension,
            addr: addr.read_ghost(self),
        })
    }

    fn ext2felts(
        &mut self,
        felts: [impl Reg<FC>; EXTENSION_DEGREE],
        ext: impl Reg<FC>,
    ) -> Instruction<FC::F> {
        Instruction::HintExt2Felts(HintExt2FeltsInstr {
            output_addrs_mults: felts.map(|r| (r.write(self), FC::F::ZERO)),
            input_addr: ext.read_ghost(self),
        })
    }

    fn hint(&mut self, output: &[impl Reg<FC>]) -> Instruction<FC::F> {
        Instruction::Hint(HintInstr {
            output_addrs_mults: output
                .iter()
                .map(|r| (r.write(self), FC::F::ZERO))
                .collect(),
        })
    }
}

/// Used for cycle tracking.
#[allow(dead_code)]
const fn instr_name<F>(instr: &Instruction<F>) -> &'static str {
    match instr {
        Instruction::BaseAlu(_) => "BaseAlu",
        Instruction::ExtAlu(_) => "ExtAlu",
        Instruction::Mem(_) => "Mem",
        Instruction::Poseidon2(_) => "Poseidon2",
        Instruction::Select(_) => "Select",
        Instruction::ExpReverseBitsLen(_) => "ExpReverseBitsLen",
        Instruction::BatchFRI(_) => "BatchFRI",
        Instruction::HintBits(_) => "HintBits",
        Instruction::Print(_) => "Print",
        Instruction::HintExt2Felts(_) => "HintExt2Felts",
        Instruction::Hint(_) => "Hint",
        Instruction::CommitPublicValues(_) => "CommitPublicValues",
        Instruction::HintAddCurve(_) => "HintAddCurve",
    }
}

#[derive(Debug, Clone)]
pub enum CompileOneErr<FC: FieldGenericConfig> {
    Unsupported(DslIr<FC>),
    CycleTrackerEnter(String),
    CycleTrackerExit,
}

/// Immediate (i.e. constant) field element.
///
/// Required to distinguish a base and extension field element at the type level,
/// since the IR's instructions do not provide this information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Imm<F, EF> {
    /// Element of the base field `F`.
    F(F),
    /// Element of the extension field `EF`.
    EF(EF),
}

impl<F, EF> Imm<F, EF>
where
    F: FieldAlgebra + Copy,
    EF: FieldExtensionAlgebra<F>,
{
    // Get a `Block` of memory representing this immediate.
    pub fn as_block(&self) -> Block<F> {
        match self {
            Imm::F(f) => Block::from(*f),
            Imm::EF(ef) => ef.as_base_slice().into(),
        }
    }
}

/// Utility functions for various register types.
trait Reg<FC: FieldGenericConfig> {
    /// Mark the register as to be read from, returning the "physical" address.
    fn read(&self, compiler: &mut DslIrCompiler<FC>) -> Address<FC::F>;

    /// Get the "physical" address of the register, assigning a new address if necessary.
    fn read_ghost(&self, compiler: &mut DslIrCompiler<FC>) -> Address<FC::F>;

    /// Mark the register as to be written to, returning the "physical" address.
    fn write(&self, compiler: &mut DslIrCompiler<FC>) -> Address<FC::F>;
}

macro_rules! impl_reg_borrowed {
    ($a:ty) => {
        impl<FC, T> Reg<FC> for $a
        where
            FC: FieldGenericConfig,
            T: Reg<FC> + ?Sized,
        {
            fn read(&self, compiler: &mut DslIrCompiler<FC>) -> Address<FC::F> {
                (**self).read(compiler)
            }

            fn read_ghost(&self, compiler: &mut DslIrCompiler<FC>) -> Address<FC::F> {
                (**self).read_ghost(compiler)
            }

            fn write(&self, compiler: &mut DslIrCompiler<FC>) -> Address<FC::F> {
                (**self).write(compiler)
            }
        }
    };
}

// Allow for more flexibility in arguments.
impl_reg_borrowed!(&T);
impl_reg_borrowed!(&mut T);
impl_reg_borrowed!(Box<T>);

macro_rules! impl_reg_vaddr {
    ($a:ty) => {
        impl<FC: FieldGenericConfig<F: PrimeField64>> Reg<FC> for $a {
            fn read(&self, compiler: &mut DslIrCompiler<FC>) -> Address<FC::F> {
                compiler.read_vaddr(self.idx as usize)
            }
            fn read_ghost(&self, compiler: &mut DslIrCompiler<FC>) -> Address<FC::F> {
                compiler.read_ghost_vaddr(self.idx as usize)
            }
            fn write(&self, compiler: &mut DslIrCompiler<FC>) -> Address<FC::F> {
                compiler.write_fp(self.idx as usize)
            }
        }
    };
}

// These three types wrap a `u32` but they don't share a trait.
impl_reg_vaddr!(Var<FC::F>);
impl_reg_vaddr!(Felt<FC::F>);
impl_reg_vaddr!(Ext<FC::F, FC::EF>);

impl<FC: FieldGenericConfig<F: PrimeField64>> Reg<FC> for Imm<FC::F, FC::EF> {
    fn read(&self, compiler: &mut DslIrCompiler<FC>) -> Address<FC::F> {
        compiler.read_const(*self)
    }

    fn read_ghost(&self, compiler: &mut DslIrCompiler<FC>) -> Address<FC::F> {
        compiler.read_ghost_const(*self)
    }

    fn write(&self, _compiler: &mut DslIrCompiler<FC>) -> Address<FC::F> {
        panic!("cannot write to immediate in register: {self:?}")
    }
}

impl<FC: FieldGenericConfig<F: PrimeField64>> Reg<FC> for Address<FC::F> {
    fn read(&self, compiler: &mut DslIrCompiler<FC>) -> Address<FC::F> {
        compiler.read_addr(*self);
        *self
    }

    fn read_ghost(&self, compiler: &mut DslIrCompiler<FC>) -> Address<FC::F> {
        compiler.read_ghost_addr(*self);
        *self
    }

    fn write(&self, compiler: &mut DslIrCompiler<FC>) -> Address<FC::F> {
        compiler.write_addr(*self);
        *self
    }
}
