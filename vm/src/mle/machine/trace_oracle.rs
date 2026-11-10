//! The fixed trace oracle: a chunk's device traces held to the host's, air by air, under one table
//! of per-air rules.
//!
//! [`check_chunk`] builds the chunk's host context the way [`build_ctx`](super::riscv::build_ctx)
//! does, from the record the caller passes, and compares every air of the device context with it
//! under [`air_policy`]: whether the air's units compare in order or as a multiset, what makes a
//! unit padding, and which columns padding must still carry. An air the table does not know fails.
//! The comparison itself is [`compare`], which builds on its own.
//!
//! Five things stand between a pass and a vacuous one:
//!
//! - **The census.** Both sides count their real units with the table's classifier, so a
//!   classifier that took every unit for padding would agree with itself. The host's count is
//!   therefore held to [`census`], taken off the augmented record's events, never off a trace.
//! - **The launches** ([`history_launch`]). Every chip of [`HISTORY_READERS`] with a real unit in
//!   a chunk that carries a history must have launched its history kernel for that chunk, so a
//!   trace that came from anywhere else fails.
//! - **The poison** ([`poison`]). Armed, the history's device region is filled with
//!   [`POISON_BYTE`] before every fill by the code that fills it, which asks
//!   [`poison::history_armed`]: that must pass, and catches a kernel reading a byte no copy wrote.
//! - **The corruption** ([`corrupt`]), the positive control. Armed, one row of one history table
//!   is changed on the card after the fill has landed and before any reader runs. The same change
//!   made to the host's history says which airs it moves ([`HostSide::differing_airs`]); the
//!   device must then fail in exactly those, and a change that moves none proves nothing. The
//!   device buffers the orchestrator uploads beside the fill take no such control: the record the
//!   device is given holds no global or Poseidon2 event, so the device writes every byte of those
//!   buffers before any chip reads them.
//! - **Alternation** ([`alternate`]). Two chunks whose host traces differ are generated in turn on
//!   one device, so a kernel that reads what the previous chunk left behind diverges.
//!
//! Both sides read the record's history: the host through its accessors, the device through the
//! fill uploaded from it. The device context is the caller's: a kernel is held to the host by
//! building the context it takes part in and passing the airs it generates as `required`, which
//! also fails a chunk that does not exercise them. [`HostSide::check_with`] hands the caller each
//! device trace as copied off the card, before any rule pairs a unit: a digest of the device's own
//! output is taken from there.

pub mod compare;

use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "cuda")]
use p3_field::PrimeField32;

pub use compare::{
    check_device_only, compare_air, AirPolicy, AirReport, ChunkFailure, ChunkVerdict, Divergence,
    Order, Padding, Trace, Unit, POISON_BYTE,
};

use super::riscv::{air_id, air_name, Kb};
use crate::{
    compiler::riscv::opcode::Opcode,
    emulator::riscv::record::{AluStream, EmulationRecord},
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::chip::MetaChip,
};

type Chips = [MetaChip<Kb, RiscvChipType<Kb>>];

/// The column a field sits at: every column struct is `repr(C)`, so at `u8` a field's byte offset
/// is its column.
macro_rules! col {
    ($cols:ty, $($field:tt)+) => {
        std::mem::offset_of!($cols, $($field)+)
    };
}

fn row(order: Order, padding: Padding) -> AirPolicy {
    AirPolicy {
        order,
        unit: Unit::Row,
        padding,
        free_on_padding: Vec::new(),
        device_only_flags: Vec::new(),
    }
}

fn slot(width: usize, flags: Vec<usize>) -> AirPolicy {
    AirPolicy {
        order: Order::Multiset,
        unit: Unit::Slot(width),
        padding: Padding::Flags(flags),
        free_on_padding: Vec::new(),
        device_only_flags: Vec::new(),
    }
}

/// The rules for one air of the RISC-V machine, by air id.
///
/// In order: the CPU chip (its row chain is constrained), memory initialize and finalize (the
/// address chain runs through every row, `used = 0` rows included, so no row of theirs is
/// padding), global (its accumulation runs down the trace and the last row's `cum` is the chunk's
/// sum), ecall (its deferred-commit tally is a running total the last row publishes), program and
/// byte (tables read at their index), and every precompile, compared cell for cell. As multisets of
/// one event's columns: the ALU chips, compare, memory read/write and the RISC-V syscall chip (one
/// event per row), memory local and Poseidon2 (four per row). An ALU event's `is_real` is the sum
/// of its opcode flags.
///
/// Padding is the host's padding in every column: no air frees one today. Of the airs compared
/// cell for cell, memory initialize and finalize and the precompile syscall chip name the `is_real`
/// that tells a device-only trace's padding; any other air the device alone generates fails.
pub fn air_policy(air: usize) -> Option<AirPolicy> {
    use crate::{
        chips::chips::{
            alu::{
                add::columns::AddValueCols, addw::columns::AddwValueCols,
                bitwise::columns::BitwiseValueCols, divrem::columns::DivRemValueCols,
                lt::LtValueCols, mul::columns::MulValueCols, sll::ShiftLeftValueCols,
                sr::columns::ShiftRightValueCols, sub::columns::SubValueCols,
                subw::columns::SubwValueCols,
            },
            riscv_cpu::columns::CpuCols,
            riscv_ecall::columns::EcallChipCols,
            riscv_global::columns::GlobalCols,
            riscv_memory::{
                initialize_finalize::columns::MemoryInitializeFinalizeCols,
                local::columns::SingleMemoryLocal, read_write::columns::MemoryChipValueCols,
            },
            riscv_poseidon2::columns::RiscvPoseidon2ValueCols,
            syscall::columns::SyscallCols,
        },
        primitives::consts::KoalaBearConfig,
    };
    use std::mem::size_of;

    type Poseidon2Slot = RiscvPoseidon2ValueCols<u8, KoalaBearConfig>;
    // The global trace's last cells are the chunk's sum, which `GcsBindAir` binds.

    Some(match air {
        air_id::ADD => slot(
            size_of::<AddValueCols<u8>>(),
            vec![col!(AddValueCols<u8>, is_add)],
        ),
        air_id::SUB => slot(
            size_of::<SubValueCols<u8>>(),
            vec![col!(SubValueCols<u8>, is_sub)],
        ),
        air_id::ADDW => slot(
            size_of::<AddwValueCols<u8>>(),
            vec![col!(AddwValueCols<u8>, is_addw)],
        ),
        air_id::SUBW => slot(
            size_of::<SubwValueCols<u8>>(),
            vec![col!(SubwValueCols<u8>, is_subw)],
        ),
        air_id::MUL => slot(
            size_of::<MulValueCols<u8>>(),
            vec![
                col!(MulValueCols<u8>, is_mul),
                col!(MulValueCols<u8>, is_mulh),
                col!(MulValueCols<u8>, is_mulhu),
                col!(MulValueCols<u8>, is_mulhsu),
                col!(MulValueCols<u8>, is_mulw),
            ],
        ),
        air_id::BITWISE => slot(
            size_of::<BitwiseValueCols<u8>>(),
            vec![
                col!(BitwiseValueCols<u8>, is_xor),
                col!(BitwiseValueCols<u8>, is_or),
                col!(BitwiseValueCols<u8>, is_and),
            ],
        ),
        air_id::LT => slot(
            size_of::<LtValueCols<u8>>(),
            vec![
                col!(LtValueCols<u8>, is_slt),
                col!(LtValueCols<u8>, is_slt_u),
            ],
        ),
        air_id::SLL => slot(
            size_of::<ShiftLeftValueCols<u8>>(),
            vec![
                col!(ShiftLeftValueCols<u8>, is_sll),
                col!(ShiftLeftValueCols<u8>, is_sllw),
            ],
        ),
        air_id::SR => slot(
            size_of::<ShiftRightValueCols<u8>>(),
            vec![
                col!(ShiftRightValueCols<u8>, is_srl),
                col!(ShiftRightValueCols<u8>, is_sra),
                col!(ShiftRightValueCols<u8>, is_srlw),
                col!(ShiftRightValueCols<u8>, is_sraw),
            ],
        ),
        air_id::DIVREM => slot(
            size_of::<DivRemValueCols<u8>>(),
            vec![col!(DivRemValueCols<u8>, is_real)],
        ),
        air_id::MEM_RW => slot(
            size_of::<MemoryChipValueCols<u8>>(),
            vec![
                col!(MemoryChipValueCols<u8>, instruction.is_lb),
                col!(MemoryChipValueCols<u8>, instruction.is_lbu),
                col!(MemoryChipValueCols<u8>, instruction.is_lh),
                col!(MemoryChipValueCols<u8>, instruction.is_lhu),
                col!(MemoryChipValueCols<u8>, instruction.is_lw),
                col!(MemoryChipValueCols<u8>, instruction.is_lwu),
                col!(MemoryChipValueCols<u8>, instruction.is_ld),
                col!(MemoryChipValueCols<u8>, instruction.is_sb),
                col!(MemoryChipValueCols<u8>, instruction.is_sh),
                col!(MemoryChipValueCols<u8>, instruction.is_sw),
                col!(MemoryChipValueCols<u8>, instruction.is_sd),
            ],
        ),
        air_id::SYSCALL_RISCV => slot(
            size_of::<SyscallCols<u8>>(),
            vec![col!(SyscallCols<u8>, is_real)],
        ),
        air_id::MEM_LOCAL => slot(
            size_of::<SingleMemoryLocal<u8>>(),
            vec![col!(SingleMemoryLocal<u8>, is_real)],
        ),
        air_id::POSEIDON2 => slot(
            size_of::<Poseidon2Slot>(),
            vec![col!(Poseidon2Slot, is_real)],
        ),
        air_id::CPU => row(
            Order::InOrder,
            Padding::Flags(vec![col!(CpuCols<u8>, is_real)]),
        ),
        air_id::ECALL => row(
            Order::InOrder,
            Padding::Flags(vec![col!(EcallChipCols<u8>, is_real)]),
        ),
        air_id::GLOBAL => row(
            Order::InOrder,
            Padding::Flags(vec![col!(GlobalCols<u8>, is_real)]),
        ),
        air_id::MEM_INIT | air_id::MEM_FINAL => AirPolicy {
            device_only_flags: vec![col!(MemoryInitializeFinalizeCols<u8>, is_real)],
            ..row(Order::InOrder, Padding::None)
        },
        air if air_name(air) == Some("SyscallPrecompile") => AirPolicy {
            device_only_flags: vec![col!(SyscallCols<u8>, is_real)],
            ..row(Order::InOrder, Padding::None)
        },
        air if air_name(air).is_some() => row(Order::InOrder, Padding::None),
        _ => return None,
    })
}

/// How many real units air `air` has in a chunk, counted off its augmented record's events:
/// for every air [`air_policy`] classifies by flags, and `None` for the rest.
pub fn census(air: usize, augmented: &EmulationRecord) -> Option<usize> {
    let alu = |stream| augmented.alu_ops(stream);
    Some(match air {
        air_id::ADD => alu(AluStream::Add).count(Opcode::ADD),
        air_id::ADDW => alu(AluStream::Add).count(Opcode::ADDW),
        air_id::SUB => alu(AluStream::Sub).count(Opcode::SUB),
        air_id::SUBW => alu(AluStream::Sub).count(Opcode::SUBW),
        air_id::MUL => alu(AluStream::Mul).len(),
        air_id::BITWISE => alu(AluStream::Bitwise).len(),
        air_id::LT => alu(AluStream::Lt).len(),
        air_id::SLL => alu(AluStream::ShiftLeft).len(),
        air_id::SR => alu(AluStream::ShiftRight).len(),
        air_id::DIVREM => alu(AluStream::DivRem).len(),
        air_id::CPU => augmented.cpu_steps().len(),
        air_id::ECALL => augmented.cpu_steps().ecalls().len(),
        air_id::MEM_RW => augmented.cpu_steps().memory().len(),
        air_id::SYSCALL_RISCV => augmented.syscalls().len(),
        air_id::MEM_LOCAL => augmented.get_local_mem_events().count(),
        air_id::GLOBAL => augmented.global_lookup_events.len(),
        air_id::POSEIDON2 => augmented.poseidon2_events.len(),
        _ => return None,
    })
}

/// One line per failure, each naming its air.
pub fn describe(failures: &[ChunkFailure]) -> String {
    failures
        .iter()
        .map(|failure| match failure.air().and_then(air_name) {
            Some(name) => format!("  [{name}] {failure}"),
            None => format!("  {failure}"),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The chunk's line, and one per air at debug level.
pub fn log_verdict(chunk: usize, verdict: &ChunkVerdict) {
    let real: usize = verdict.compared.values().map(|r| r.real).sum();
    let reordered = verdict.compared.values().filter(|r| !r.identical).count();
    for (air, report) in verdict.compared.iter().chain(&verdict.device_only) {
        tracing::debug!(
            "[trace-oracle] chunk={chunk} air={air} {}: {}x{}, {} of {} units real{}",
            air_name(*air).unwrap_or("?"),
            report.height,
            report.width,
            report.real,
            report.units,
            if report.identical {
                ""
            } else {
                ", not cell for cell"
            },
        );
    }
    tracing::info!(
        "[trace-oracle] chunk={chunk}: {} airs equal ({reordered} only under their policy), {} \
         device-only airs all padding, {real} real units",
        verdict.compared.len(),
        verdict.device_only.len(),
    );
}

/// The chips, by `name()`, whose device traces a CPU chunk's history alone feeds.
pub const HISTORY_READERS: [&str; 15] = [
    "Cpu",
    "Program",
    "MemoryReadWrite",
    "LessThan",
    "Add",
    "Sub",
    "Addw",
    "Subw",
    "DivRem",
    "Mul",
    "Bitwise",
    "ShiftLeft",
    "ShiftRight",
    "Ecall",
    "SyscallRiscv",
];

/// What [`history_launches`] found in one record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryReads {
    /// The record carries no history, a deferred one: no chip reads one.
    NoHistory,
    /// The record carries one, and this many compared airs with a real unit read it.
    Read(usize),
}

impl HistoryReads {
    pub fn count(self) -> usize {
        match self {
            Self::NoHistory => 0,
            Self::Read(readers) => readers,
        }
    }
}

/// For a record that carries a history, how many of its compared airs with a real unit a chip of
/// [`HISTORY_READERS`] built; a failure for each such air with no history launch of its chip in
/// `launched` (the chunk's [`history_launch::take`]). A record without a history asks nothing.
pub fn history_launches(
    verdict: &ChunkVerdict,
    record: &EmulationRecord,
    launched: &BTreeSet<String>,
) -> Result<HistoryReads, Vec<ChunkFailure>> {
    if record.history.is_none() {
        return Ok(HistoryReads::NoHistory);
    }
    let (mut readers, mut failures) = (0, Vec::new());
    for chip in HISTORY_READERS {
        let Some(air) = super::riscv::air_id_for(chip) else {
            continue;
        };
        match verdict.compared.get(&air) {
            Some(report) if report.real > 0 => {
                if launched.contains(chip) {
                    readers += 1;
                } else {
                    failures.push(ChunkFailure::NoHistoryLaunch { air });
                }
            }
            _ => {}
        }
    }
    if failures.is_empty() {
        Ok(HistoryReads::Read(readers))
    } else {
        Err(failures)
    }
}

/// Which chips launched a history-reading kernel for the chunk being generated. A chip's wrapper
/// calls [`note`] once, right after it launches a kernel on the history; unless the oracle is
/// recording, that is one relaxed load. The oracle generates one chunk at a time on one thread,
/// and takes the record before and after each.
pub mod history_launch {
    use std::{
        collections::BTreeSet,
        sync::{
            atomic::{AtomicBool, Ordering},
            Mutex, PoisonError,
        },
    };

    static RECORDING: AtomicBool = AtomicBool::new(false);
    static LAUNCHED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

    /// `chip`, by `name()`, launched a kernel that reads the history.
    #[inline]
    pub fn note(chip: &str) {
        if RECORDING.load(Ordering::Relaxed) {
            LAUNCHED
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(chip.to_owned());
        }
    }

    /// Start or stop recording, clearing what was recorded.
    pub fn record(on: bool) {
        RECORDING.store(on, Ordering::SeqCst);
        take();
    }

    /// The chips noted since the last take.
    pub fn take() -> BTreeSet<String> {
        std::mem::take(&mut *LAUNCHED.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// A chunk's host side, built once and held to any number of device contexts.
pub struct HostSide {
    traces: BTreeMap<usize, HostTrace>,
    census: BTreeMap<usize, usize>,
}

struct HostTrace {
    cells: Vec<u32>,
    width: usize,
    public_values: Vec<Kb>,
}

impl HostTrace {
    fn trace(&self) -> Trace<'_> {
        Trace {
            cells: &self.cells,
            width: self.width,
        }
    }
}

impl HostSide {
    /// The host traces of `record`, built as [`build_ctx`](super::riscv::build_ctx) builds them:
    /// whitelist mode iff the record carries a shape, so the host pads to the shape the device did.
    pub fn build(chips: &Chips, record: &EmulationRecord) -> Self {
        let augmented = super::riscv::augmented_record(chips, record);
        let census = (0..=air_id::MEM_UNALIGNED)
            .filter_map(|air| census(air, &augmented).map(|n| (air, n)))
            .collect();
        let ctx = super::riscv::build_ctx_augmented(chips, augmented, record.shape.is_some());
        let traces = ctx
            .per_trace
            .into_iter()
            .map(|(air, ctx)| {
                let trace = HostTrace {
                    cells: ctx
                        .common_main
                        .values
                        .iter()
                        .map(p3_field::PrimeField32::to_unique_u32)
                        .collect(),
                    width: ctx.common_main.width,
                    public_values: ctx.public_values.clone(),
                };
                (air, trace)
            })
            .collect();
        Self { traces, census }
    }

    /// Hold the host side to itself: per air, the classifier's real units against the census and
    /// the padding uniform. What a device comparison checks before it looks at a device cell, so a
    /// failure here is the table's or the census's, never a kernel's.
    pub fn check_host(&self) -> Result<ChunkVerdict, Vec<ChunkFailure>> {
        let mut verdict = ChunkVerdict::default();
        for (air, host) in &self.traces {
            let result = match air_policy(*air) {
                None => Err(Divergence::NoPolicy),
                Some(policy) => {
                    let trace = Trace {
                        cells: &host.cells,
                        width: host.width,
                    };
                    compare_air(&policy, trace, trace, self.census.get(air).copied())
                }
            };
            verdict.record(*air, result);
        }
        verdict.finish(&[])
    }

    /// The airs in which `other` differs from this side under the table's rules, held to this
    /// side's census as a device context is: the airs a device context built from `other`'s record
    /// must fail in when held to this side.
    pub fn differing_airs(&self, other: &Self) -> BTreeSet<usize> {
        let airs: BTreeSet<usize> = self
            .traces
            .keys()
            .chain(other.traces.keys())
            .copied()
            .collect();
        airs.into_iter()
            .filter(|air| {
                let (Some(mine), Some(theirs)) = (self.traces.get(air), other.traces.get(air))
                else {
                    return true;
                };
                let Some(policy) = air_policy(*air) else {
                    return true;
                };
                mine.public_values != theirs.public_values
                    || compare_air(
                        &policy,
                        theirs.trace(),
                        mine.trace(),
                        self.census.get(air).copied(),
                    )
                    .is_err()
            })
            .collect()
    }
}

impl PartialEq for HostSide {
    fn eq(&self, other: &Self) -> bool {
        self.traces.len() == other.traces.len()
            && self
                .traces
                .iter()
                .zip(&other.traces)
                .all(|((a, x), (b, y))| {
                    a == b
                        && x.width == y.width
                        && x.cells == y.cells
                        && x.public_values == y.public_values
                })
    }
}

#[cfg(feature = "cuda")]
impl HostSide {
    /// Hold a device context to this host side. `required` names airs that must be compared with
    /// at least one real unit.
    pub fn check(
        &self,
        device: &pico_mle_core::prover::ProvingContext<super::riscv::Pb>,
        required: &[usize],
    ) -> Result<ChunkVerdict, Vec<ChunkFailure>> {
        self.check_with(device, required, |_, _| {})
    }

    /// [`Self::check`], handing `on_device_trace` every air of the device context by its id, the
    /// cells the comparison then reads: the device's rows in the device's order, before the air's
    /// policy pairs any unit, and whatever the verdict.
    pub fn check_with(
        &self,
        device: &pico_mle_core::prover::ProvingContext<super::riscv::Pb>,
        required: &[usize],
        mut on_device_trace: impl FnMut(usize, Trace<'_>),
    ) -> Result<ChunkVerdict, Vec<ChunkFailure>> {
        use cuda_mle::runtime::copy::MemCopyD2H;
        use pico_mle_core::poly::matrix::MatrixDimensions;

        let mut verdict = ChunkVerdict::default();
        for air in self.traces.keys() {
            if !device.per_trace.iter().any(|(id, _)| id == air) {
                verdict.missing_on_device(*air);
            }
        }
        for (air, device_air) in &device.per_trace {
            let (h, w) = (
                device_air.common_main.height(),
                device_air.common_main.width(),
            );
            let cells = {
                let column_major = device_air
                    .common_main
                    .buffer()
                    .to_host()
                    .expect("device trace D2H for the oracle");
                let mut cells = vec![0u32; h * w];
                for c in 0..w {
                    for r in 0..h {
                        cells[r * w + c] = column_major[c * h + r].to_unique_u32();
                    }
                }
                cells
            };
            let device_trace = Trace {
                cells: &cells,
                width: w,
            };
            on_device_trace(*air, device_trace);
            let Some(policy) = air_policy(*air) else {
                verdict.record(*air, Err(Divergence::NoPolicy));
                continue;
            };
            match self.traces.get(air) {
                None => verdict.record_device_only(*air, check_device_only(&policy, device_trace)),
                Some(host) => {
                    let host_trace = Trace {
                        cells: &host.cells,
                        width: host.width,
                    };
                    let result = compare_air(
                        &policy,
                        device_trace,
                        host_trace,
                        self.census.get(air).copied(),
                    )
                    .and_then(|report| {
                        if device_air.public_values == host.public_values {
                            Ok(report)
                        } else {
                            Err(Divergence::PublicValues)
                        }
                    });
                    verdict.record(*air, result);
                }
            }
        }
        verdict.finish(required)
    }
}

/// Generate `chunk`'s device context on the calling thread's device and hold it to `host`; then
/// require each chip of [`HISTORY_READERS`] with a real unit to have launched its history kernel
/// ([`history_launches`]). Returns the verdict and what the history reads came to.
#[cfg(feature = "cuda")]
pub fn generate_and_check(
    host: &HostSide,
    orchestrator_chips: &Chips,
    chunk: &super::riscv::PreparedChunk,
    required: &[usize],
) -> Result<(ChunkVerdict, HistoryReads), Vec<ChunkFailure>> {
    generate_and_check_with(host, orchestrator_chips, chunk, required, |_, _| {})
}

/// [`generate_and_check`], handing `on_device_trace` every air of the device context as
/// [`HostSide::check_with`] does.
#[cfg(feature = "cuda")]
pub fn generate_and_check_with(
    host: &HostSide,
    orchestrator_chips: &Chips,
    chunk: &super::riscv::PreparedChunk,
    required: &[usize],
    on_device_trace: impl FnMut(usize, Trace<'_>),
) -> Result<(ChunkVerdict, HistoryReads), Vec<ChunkFailure>> {
    history_launch::record(true);
    let device = super::riscv::build_ctx_gpu(&chunk.record, &chunk.prepared, orchestrator_chips);
    let launched = history_launch::take();
    history_launch::record(false);
    let verdict = host.check_with(&device, required, on_device_trace)?;
    let readers = history_launches(&verdict, &chunk.record, &launched)?;
    Ok((verdict, readers))
}

/// Hold a chunk's device context to the host's: [`HostSide::build`] then [`HostSide::check`].
#[cfg(feature = "cuda")]
pub fn check_chunk(
    chips: &Chips,
    record: &EmulationRecord,
    device: &pico_mle_core::prover::ProvingContext<super::riscv::Pb>,
    required: &[usize],
) -> Result<ChunkVerdict, Vec<ChunkFailure>> {
    HostSide::build(chips, record).check(device, required)
}

/// Why alternating two chunks failed.
#[derive(Debug)]
pub enum AlternationFailure {
    /// Fewer than two rounds generate no chunk after the other.
    TooFewRounds { rounds: usize },
    /// The two chunks' host traces are equal, so a kernel reading the other chunk's leftovers
    /// would still match.
    SameChunks,
    /// An air the caller asked for has the same host trace in both chunks, or neither has it.
    SameAir { air: usize },
    /// Round `round`, on chunk `chunk` of the two.
    Round {
        round: usize,
        chunk: usize,
        failures: Vec<ChunkFailure>,
    },
}

impl std::fmt::Display for AlternationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooFewRounds { rounds } => {
                write!(f, "{rounds} round(s): alternation needs at least 2")
            }
            Self::SameChunks => write!(f, "the two chunks' host traces are equal"),
            Self::SameAir { air } => write!(
                f,
                "air {air} ({}): the two chunks' host traces of it are equal",
                air_name(*air).unwrap_or("?")
            ),
            Self::Round {
                round,
                chunk,
                failures,
            } => write!(
                f,
                "round {round}, chunk {chunk} of the two:\n{}",
                describe(failures)
            ),
        }
    }
}

/// What [`alternate`] held to the host.
#[derive(Debug)]
pub struct Alternated {
    pub verdicts: Vec<ChunkVerdict>,
    /// Over every round on a record carrying a history, the compared airs with a real unit that
    /// read it.
    pub history_reads: usize,
}

/// Generate the device context of `chunks[0]`, then `chunks[1]`, and so on for `rounds` contexts
/// on the calling thread's device, each held to its chunk's host side by [`generate_and_check`].
/// The two chunks must differ, in every `required` air too, so a kernel that reads the other
/// chunk's leftovers diverges where it is asked about. `orchestrator_chips` are in the device
/// orchestrator's order (`gpu_generate_extra_record_and_main_chips`), `chips` in `all_chips`
/// order.
#[cfg(feature = "cuda")]
pub fn alternate(
    chips: &Chips,
    orchestrator_chips: &Chips,
    chunks: [&super::riscv::PreparedChunk; 2],
    rounds: usize,
    required: &[usize],
) -> Result<Alternated, AlternationFailure> {
    if rounds < 2 {
        return Err(AlternationFailure::TooFewRounds { rounds });
    }
    let hosts = chunks.map(|chunk| HostSide::build(chips, &chunk.record));
    if hosts[0] == hosts[1] {
        return Err(AlternationFailure::SameChunks);
    }
    for &air in required {
        let [a, b] = [&hosts[0], &hosts[1]].map(|host| host.traces.get(&air));
        let differ = match (a, b) {
            (Some(a), Some(b)) => a.width != b.width || a.cells != b.cells,
            (None, None) => false,
            _ => true,
        };
        if !differ {
            return Err(AlternationFailure::SameAir { air });
        }
    }
    let mut alternated = Alternated {
        verdicts: Vec::with_capacity(rounds),
        history_reads: 0,
    };
    for round in 0..rounds {
        let chunk = round % 2;
        let (verdict, reads) =
            generate_and_check(&hosts[chunk], orchestrator_chips, chunks[chunk], required)
                .map_err(|failures| AlternationFailure::Round {
                    round,
                    chunk,
                    failures,
                })?;
        alternated.verdicts.push(verdict);
        alternated.history_reads += reads.count();
    }
    Ok(alternated)
}

/// The device buffers the oracle poisons. Process-wide and off until [`arm`]ed; an API, not an
/// environment variable, so no production run can turn it on.
#[cfg(feature = "cuda")]
pub mod poison {
    use std::{
        ffi::c_void,
        sync::atomic::{AtomicBool, Ordering},
    };

    use cudart::stream::CudaStream;
    use cudart_sys::{cudaMemsetAsync, CudaError};

    use super::compare::POISON_BYTE;

    static HISTORY: AtomicBool = AtomicBool::new(false);

    /// Poison the history's device region before every fill from now on.
    pub fn arm() {
        HISTORY.store(true, Ordering::SeqCst);
    }

    pub fn disarm() {
        HISTORY.store(false, Ordering::SeqCst);
    }

    /// Whether the code that fills the history's device region must [`fill`] its whole capacity
    /// first.
    pub fn history_armed() -> bool {
        HISTORY.load(Ordering::SeqCst)
    }

    /// Fill `bytes` bytes at `ptr` with [`POISON_BYTE`], ordered on `stream`.
    ///
    /// # Safety
    ///
    /// `ptr` is a device allocation of at least `bytes` bytes that stays allocated until the
    /// memset has run on `stream`.
    pub unsafe fn fill(ptr: *mut c_void, bytes: usize, stream: &CudaStream) {
        let err = unsafe { cudaMemsetAsync(ptr, i32::from(POISON_BYTE), bytes, stream.into()) };
        assert_eq!(
            err,
            CudaError::Success,
            "poisoning {bytes} device bytes failed"
        );
    }
}

/// The positive control: one row of one table of a chunk's execution history, changed on the card
/// after the fill has landed and before any reader runs, by the history's upload
/// (`EmulationRecord::gpu_upload_history`) while one is armed.
///
/// Every change keeps the chunk's counted events, and with them the fill's header and every trace
/// height, as they were: a value field flips [`FLIP`] (a step's clock, an access's value, an
/// operand exception's value, a syscall's first argument), and a chip list's entry is pointed at
/// the nearest other step of the list that runs the same opcode on other operands. A change that
/// would move a count is refused for the row ([`changed_record`]).
#[cfg(feature = "cuda")]
pub mod corrupt {
    use std::{
        fmt,
        sync::{Mutex, PoisonError},
    };

    use super::Kb;
    use crate::{
        compiler::riscv::program::Program,
        emulator::riscv::{
            history::{ChipSteps, ExecutionHistory},
            history_arena::{Rows, Table},
            record::EmulationRecord,
        },
        instances::preparer::precompute_event_size,
    };

    /// The bit a value field's change flips: no sign bit, and above the low bits a load's or a
    /// store's alignment rests on.
    pub const FLIP: u32 = 1 << 4;

    static ARMED: Mutex<Option<Corruption>> = Mutex::new(None);

    /// Change `corruption`'s row in every fill uploaded from now on.
    pub fn arm(corruption: Corruption) {
        *ARMED.lock().unwrap_or_else(PoisonError::into_inner) = Some(corruption);
    }

    pub fn disarm() {
        *ARMED.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    pub fn armed() -> Option<Corruption> {
        *ARMED.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Row `row` of `table`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Corruption {
        pub table: Table,
        pub row: usize,
    }

    impl fmt::Display for Corruption {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}:{}", self.table.name(), self.row)
        }
    }

    impl Corruption {
        /// `<table>[:row]`, the table by its capacity-table name, row 0 unless named.
        pub fn parse(spec: &str) -> Result<Self, String> {
            let (name, row) = match spec.split_once(':') {
                Some((name, row)) => (
                    name,
                    row.parse()
                        .map_err(|err| format!("{spec}: row {row:?}: {err}"))?,
                ),
                None => (spec, 0),
            };
            let table = Table::ALL
                .into_iter()
                .find(|table| table.name() == name)
                .ok_or_else(|| {
                    format!(
                        "{name} is none of the history's tables {:?}",
                        Table::ALL.map(Table::name)
                    )
                })?;
            Ok(Self { table, row })
        }

        /// `history`, run against `program`, with this row changed. `Err` when the table holds no
        /// such row, or a list no other step to point its entry at.
        pub fn applied(
            self,
            history: &ExecutionHistory,
            program: &Program,
        ) -> Result<ExecutionHistory, String> {
            let flip = u64::from(FLIP);
            let mut changed = history.clone();
            match self.table {
                Table::Steps => self.row_in(&mut changed.steps)?.clk ^= FLIP,
                Table::Reads => self.row_in(&mut changed.reads)?.value ^= flip,
                Table::Writes => self.row_in(&mut changed.writes)?.value ^= flip,
                Table::OperandExceptions => {
                    self.row_in(&mut changed.operand_exceptions)?.value ^= flip;
                }
                Table::Syscalls => self.row_in(&mut changed.syscalls)?.arg1 ^= flip,
                list => {
                    let entries = list_of(&mut changed.chip_steps, list);
                    self.row_in(entries)?;
                    entries[self.row] = alias(history, program, &entries[..], self.row)?;
                }
            }
            Ok(changed)
        }

        fn row_in<T>(self, rows: &mut [T]) -> Result<&mut T, String> {
            let count = rows.len();
            rows.get_mut(self.row).ok_or_else(|| {
                format!(
                    "the {} table holds {count} row(s), so no row {}",
                    self.table.name(),
                    self.row
                )
            })
        }
    }

    fn list_of(lists: &mut ChipSteps, table: Table) -> &mut Rows<u32> {
        match table {
            Table::Add => &mut lists.add,
            Table::Sub => &mut lists.sub,
            Table::Mul => &mut lists.mul,
            Table::Bitwise => &mut lists.bitwise,
            Table::ShiftLeft => &mut lists.shift_left,
            Table::ShiftRight => &mut lists.shift_right,
            Table::Lt => &mut lists.lt,
            Table::DivRem => &mut lists.divrem,
            Table::Memory => &mut lists.memory,
            Table::Ecall => &mut lists.ecall,
            Table::Branch => &mut lists.branch,
            table => unreachable!("{} is no chip list", table.name()),
        }
    }

    /// The step entry `row` of `entries` is pointed at: the nearest other entry, the later one
    /// first at each distance, whose step runs the same opcode on other operands. The chip then
    /// holds as many rows of each opcode as before, and one of them changes.
    fn alias(
        history: &ExecutionHistory,
        program: &Program,
        entries: &[u32],
        row: usize,
    ) -> Result<u32, String> {
        let run = |step: u32| {
            let instruction = program.fetch(u64::from(history.steps[step as usize].pc));
            (
                instruction.opcode,
                history.operands(step as usize, &instruction),
            )
        };
        let (opcode, operands) = run(entries[row]);
        (1..entries.len())
            .flat_map(|distance| [row.checked_add(distance), row.checked_sub(distance)])
            .flatten()
            .filter_map(|other| entries.get(other).copied())
            .find(|&step| {
                let (other_opcode, other_operands) = run(step);
                other_opcode == opcode && other_operands != operands
            })
            .ok_or_else(|| format!("no other {opcode:?} step of the list runs on other operands"))
    }

    /// `record` with `corruption` made to its history. `Err` when the record carries none, the
    /// change cannot be made, or it would move the chunk's counted events, which size every device
    /// trace and the fill's header.
    pub fn changed_record(
        record: &EmulationRecord,
        corruption: Corruption,
    ) -> Result<EmulationRecord, String> {
        let history = record
            .history
            .as_ref()
            .ok_or("the record carries no history")?;
        let mut changed = record.clone();
        changed.history = Some(corruption.applied(history, &record.program)?);
        if precompute_event_size::<Kb>(&changed) != precompute_event_size::<Kb>(record) {
            return Err(format!(
                "changing {corruption} would move the chunk's counted events"
            ));
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "cuda")]
    #[test]
    fn a_corruption_reads_back_from_its_spec() {
        use corrupt::Corruption;
        let parsed = Corruption::parse("writes:3").unwrap();
        assert_eq!(Corruption::parse(&parsed.to_string()), Ok(parsed));
        assert_eq!(Corruption::parse("add").map(|c| c.row), Ok(0));
        assert!(Corruption::parse("nothing").is_err());
        assert!(Corruption::parse("reads:one").is_err());
    }

    /// A value field's change flips one field of the row it names and leaves every other row; a
    /// row past the table is refused.
    #[cfg(feature = "cuda")]
    #[test]
    fn a_value_corruption_changes_one_row() {
        use crate::{
            compiler::riscv::program::Program,
            emulator::riscv::history::{Access, ExecutionHistory},
        };
        use corrupt::{Corruption, FLIP};

        let history = ExecutionHistory {
            writes: vec![Access::default(); 2].into(),
            ..Default::default()
        };
        let program = Program::default();
        let changed = Corruption::parse("writes:1")
            .unwrap()
            .applied(&history, &program)
            .unwrap();
        assert_eq!(changed.writes[0], history.writes[0]);
        assert_eq!(
            changed.writes[1],
            Access {
                value: u64::from(FLIP),
                ..Access::default()
            }
        );
        let past = Corruption::parse("writes:2").unwrap();
        assert!(past.applied(&history, &program).is_err());
    }

    /// Every air the machine has has a rule, and a flag-classified air has a census: an air the
    /// oracle cannot classify, or whose real units nothing counts, fails rather than passes.
    #[test]
    fn every_air_has_a_policy_and_every_flagged_air_a_census() {
        let record = EmulationRecord::default();
        for air in 0..=air_id::MEM_UNALIGNED {
            let name = air_name(air).unwrap_or_else(|| panic!("air {air} has no name"));
            let policy = air_policy(air).unwrap_or_else(|| panic!("{name} has no policy"));
            assert_eq!(
                matches!(policy.padding, Padding::Flags(_)),
                census(air, &record).is_some(),
                "{name}: classified by flags iff counted"
            );
        }
        assert!(air_policy(air_id::MEM_UNALIGNED + 1).is_none());
    }

    #[test]
    fn the_multiset_airs_are_the_ones_the_plan_lists() {
        let multiset: Vec<&str> = (0..=air_id::MEM_UNALIGNED)
            .filter(|&air| air_policy(air).unwrap().order == Order::Multiset)
            .map(|air| air_name(air).unwrap())
            .collect();
        assert_eq!(
            multiset,
            [
                "Add",
                "Sub",
                "Mul",
                "Bitwise",
                "LessThan",
                "ShiftLeft",
                "ShiftRight",
                "DivRem",
                "Addw",
                "Subw",
                "MemoryLocal",
                "MemoryReadWrite",
                "SyscallRiscv",
                "RiscvKoalaBearPoseidon2",
            ]
        );
    }

    /// On real records the host's real units are the census's and its padding is uniform, at the
    /// whole-guest chunk size and at one that cuts the guest into many chunks.
    #[test]
    fn the_census_holds_on_host_traces() {
        use std::sync::Arc;

        use crate::{
            compiler::riscv::compiler::{Compiler, SourceType},
            configs::stark_config::KoalaBearPoseidon2,
            emulator::{
                opts::EmulatorOpts,
                riscv::{
                    emulator::RiscvEmulator, public_values::RecordFinalPvsState,
                    record_slots::hold_records_unbounded,
                },
                stdin::EmulatorStdin,
            },
        };

        let program = |name: &str| {
            let path = format!(
                "{}/../perf/bench_data/rv64/{name}-elf",
                env!("CARGO_MANIFEST_DIR")
            );
            let elf = std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
            Compiler::new(SourceType::RISCV, &elf).unwrap().compile()
        };
        hold_records_unbounded();
        let chips = RiscvChipType::<Kb>::all_chips();
        for (name, input, chunk_size) in [
            ("fib", Some(1000u32), 1u32 << 22),
            ("fib", Some(1000), 4096),
            ("chip-coverage", None, 1 << 22),
            ("chip-coverage", None, 64),
        ] {
            let mut stdin = EmulatorStdin::new_builder::<KoalaBearPoseidon2>();
            if let Some(n) = input {
                stdin.write(&n);
            }
            let mut emulator = RiscvEmulator::new_single::<Kb>(
                program(name),
                Arc::new(RecordFinalPvsState::default()),
                EmulatorOpts {
                    chunk_size,
                    ..EmulatorOpts::default()
                },
            );
            emulator.write_stdin(&stdin.finalize());
            let mut records = 0;
            loop {
                let report = emulator
                    .emulate_batch(&mut |record| {
                        if let Err(failures) = HostSide::build(&chips, &record).check_host() {
                            panic!(
                                "{name} at chunk size {chunk_size}, record {records}:\n{}",
                                describe(&failures)
                            );
                        }
                        records += 1;
                    })
                    .expect("the guest emulates");
                if report.done {
                    break;
                }
            }
            assert!(records > 0, "{name} at chunk size {chunk_size}: no record");
        }
    }

    /// Every chip the launch check asks about is a chip of the machine: a misspelled name would
    /// leave its air unchecked.
    #[test]
    fn every_history_reader_is_an_air_of_the_machine() {
        for chip in HISTORY_READERS {
            assert!(
                super::super::riscv::air_id_for(chip).is_some(),
                "{chip} is no air of the machine"
            );
        }
    }

    /// On a record carrying a history, a reader with real units and no launch noted fails, and one
    /// without real units asks for none; on a record without one, nothing is asked.
    #[test]
    fn a_history_reader_with_real_units_must_have_launched() {
        use crate::emulator::riscv::history::ExecutionHistory;

        let mut verdict = ChunkVerdict::default();
        let report = |real| AirReport {
            height: 4,
            width: 3,
            units: 4,
            real,
            identical: true,
        };
        verdict.record(air_id::MUL, Ok(report(2)));
        verdict.record(air_id::BITWISE, Ok(report(0)));
        let launched: BTreeSet<String> = ["Mul".to_owned()].into();

        let deferred = EmulationRecord::default();
        assert_eq!(
            history_launches(&verdict, &deferred, &BTreeSet::new()),
            Ok(HistoryReads::NoHistory)
        );

        let traced = EmulationRecord {
            history: Some(ExecutionHistory::default()),
            ..Default::default()
        };
        assert_eq!(
            history_launches(&verdict, &traced, &launched),
            Ok(HistoryReads::Read(1))
        );
        assert_eq!(
            history_launches(&verdict, &traced, &BTreeSet::new()),
            Err(vec![ChunkFailure::NoHistoryLaunch { air: air_id::MUL }])
        );
    }

    /// Launches are recorded only while the oracle records, and each take clears them.
    #[test]
    fn history_launches_are_recorded_only_when_asked() {
        history_launch::record(false);
        history_launch::note("Mul");
        assert!(history_launch::take().is_empty());
        history_launch::record(true);
        history_launch::note("Mul");
        history_launch::note("Mul");
        assert_eq!(history_launch::take(), BTreeSet::from(["Mul".to_owned()]));
        assert!(history_launch::take().is_empty());
        history_launch::record(false);
    }

    /// Slots tile their row, and every flag and freed column lies inside the unit.
    #[test]
    fn the_columns_lie_inside_their_units() {
        use crate::machine::chip::ChipBehavior;
        for chip in RiscvChipType::<Kb>::all_chips() {
            let Some(air) = super::super::riscv::air_id_for(&chip.name()) else {
                continue;
            };
            let width = p3_air::BaseAir::<Kb>::width(&chip);
            let policy = air_policy(air).unwrap();
            let unit = match policy.unit {
                Unit::Row => width,
                Unit::Slot(slot) => slot,
            };
            assert!(
                width.is_multiple_of(unit),
                "{}: {width} columns, {unit}-column slots",
                chip.name()
            );
            let flags: &[usize] = match &policy.padding {
                Padding::Flags(flags) => flags,
                Padding::None => &policy.device_only_flags,
            };
            let columns = flags.iter().chain(&policy.free_on_padding);
            assert!(
                columns.clone().all(|&c| c < unit),
                "{}: flag or freed columns {:?} outside a {unit}-column unit",
                chip.name(),
                columns.collect::<Vec<_>>()
            );
        }
    }
}
