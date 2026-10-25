use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        RwLock,
    },
};

use crate::emulator::riscv::{
    emulator::MIN_MAIN_MEMORY_ADDR,
    event_types::{RvAddr, RvChunk, RvTimestamp, RvValue},
};

/// Memory Record.
///
/// This object encapsulates the information needed to prove a memory access operation. This
/// includes the chunk, timestamp, and value of the memory address.
#[derive(Debug, Copy, Clone, Default, PartialEq, Serialize, Deserialize)]
#[repr(C)]
pub struct MemoryRecord {
    /// The chunk number.
    pub chunk: RvChunk,
    /// The timestamp.
    pub timestamp: RvTimestamp,
    /// The value.
    pub value: RvValue,
}

/// Memory Access Position.
///
/// This enum represents the position of a memory access in a register. For example, if a memory
/// access is performed in the C register, it will have a position of C.
///
/// Note: The register positions require that they be read and written in the following order:
/// C, B, A.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MemoryAccessPosition {
    /// Memory access position.
    Memory = 0,
    /// C register access position.
    C = 1,
    /// B register access position.
    B = 2,
    /// A register access position.
    A = 3,
}

/// Memory Read Record.
///
/// This object encapsulates the information needed to prove a memory read operation. This
/// includes the value, chunk, timestamp, and previous chunk and timestamp.
#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize, PartialEq)]
#[repr(C)]
pub struct MemoryReadRecord {
    /// The value.
    pub value: RvValue,
    /// The chunk number.
    pub chunk: RvChunk,
    /// The timestamp.
    pub timestamp: RvTimestamp,
    /// The previous chunk number.
    pub prev_chunk: RvChunk,
    /// The previous timestamp.
    pub prev_timestamp: RvTimestamp,
}

/// Memory Write Record.
///
/// This object encapsulates the information needed to prove a memory write operation. This
/// includes the value, chunk, timestamp, previous value, previous chunk, and previous timestamp.
#[allow(clippy::manual_non_exhaustive)]
#[derive(Debug, Copy, Clone, Default, Serialize, Deserialize, PartialEq)]
#[repr(C)]
pub struct MemoryWriteRecord {
    /// The value.
    pub value: RvValue,
    /// The chunk number.
    pub chunk: RvChunk,
    /// The timestamp.
    pub timestamp: RvTimestamp,
    /// The previous value.
    pub prev_value: RvValue,
    /// The previous chunk number.
    pub prev_chunk: RvChunk,
    /// The previous timestamp.
    pub prev_timestamp: RvTimestamp,
}

/// Memory Record Enum.
///
/// This enum represents the different types of memory records that can be stored in the memory
/// event such as reads and writes.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq)]
#[repr(C)]
pub enum MemoryRecordEnum {
    /// Read.
    Read(MemoryReadRecord),
    /// Write.
    Write(MemoryWriteRecord),
}

/// Memory Initialize/Finalize Event.
///
/// This object encapsulates the information needed to prove a memory initialize or finalize
/// operation. This includes the address, value, chunk, timestamp, and whether the memory is
/// initialized or finalized.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct MemoryInitializeFinalizeEvent {
    /// The address.
    pub addr: RvAddr,
    /// The value.
    pub value: RvValue,
    /// The chunk number.
    pub chunk: RvChunk,
    /// The timestamp.
    pub timestamp: RvTimestamp,
    /// The used flag.
    pub used: u32,
}

impl MemoryReadRecord {
    /// Creates a new [``MemoryReadRecord``].
    #[must_use]
    pub const fn new(
        value: RvValue,
        chunk: RvChunk,
        timestamp: RvTimestamp,
        prev_chunk: RvChunk,
        prev_timestamp: RvTimestamp,
    ) -> Self {
        assert!(chunk > prev_chunk || ((chunk == prev_chunk) && (timestamp > prev_timestamp)));
        Self {
            value,
            chunk,
            timestamp,
            prev_chunk,
            prev_timestamp,
        }
    }
}

impl MemoryWriteRecord {
    /// Creates a new [``MemoryWriteRecord``].
    #[must_use]
    pub const fn new(
        value: RvValue,
        chunk: RvChunk,
        timestamp: RvTimestamp,
        prev_value: RvValue,
        prev_chunk: RvChunk,
        prev_timestamp: RvTimestamp,
    ) -> Self {
        assert!(chunk > prev_chunk || ((chunk == prev_chunk) && (timestamp > prev_timestamp)),);
        Self {
            value,
            chunk,
            timestamp,
            prev_value,
            prev_chunk,
            prev_timestamp,
        }
    }
}

impl MemoryRecordEnum {
    /// Returns the value of the memory record.
    #[must_use]
    pub const fn value(&self) -> RvValue {
        match self {
            MemoryRecordEnum::Read(record) => record.value,
            MemoryRecordEnum::Write(record) => record.value,
        }
    }
}

impl MemoryInitializeFinalizeEvent {
    /// Creates a new [``MemoryInitializeFinalizeEvent``] for an initialization.
    #[must_use]
    pub const fn initialize(addr: RvAddr, value: RvValue, used: bool) -> Self {
        Self {
            addr,
            value,
            chunk: 1,
            timestamp: 1,
            used: if used { 1 } else { 0 },
        }
    }

    /// Creates a new [``MemoryInitializeFinalizeEvent``] for a finalization.
    #[must_use]
    pub const fn finalize_from_record(addr: RvAddr, record: &MemoryRecord) -> Self {
        Self {
            addr,
            value: record.value,
            chunk: record.chunk,
            timestamp: record.timestamp,
            used: 1,
        }
    }
}

impl From<MemoryReadRecord> for MemoryRecordEnum {
    fn from(read_record: MemoryReadRecord) -> Self {
        MemoryRecordEnum::Read(read_record)
    }
}

impl From<MemoryWriteRecord> for MemoryRecordEnum {
    fn from(write_record: MemoryWriteRecord) -> Self {
        MemoryRecordEnum::Write(write_record)
    }
}

/// Memory Local Event
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[repr(C)]
pub struct MemoryLocalEvent {
    /// The address
    pub addr: RvAddr,
    /// The initial memory access
    pub initial_mem_access: MemoryRecord,
    /// The final memory access
    pub final_mem_access: MemoryRecord,
}

/// Whether a MemoryLocal entry is *fresh*: the first touch, in the whole execution, of a main
/// memory word that is outside the program image and starts at zero.
///
/// A fresh entry declares its own initial state on the MemoryLocal AIR (`has_initial = 0`, with
/// `initial_value` pinned to zero there) instead of receiving it from the Global bus, and the
/// emulator raises no MemoryInitialize event for its address. Every other entry -- registers,
/// image words (their initial state is sent by the vk's image digest), words whose initial value
/// a hint wrote (nonzero, so a MemoryInitialize row still carries it), and entries whose
/// interval starts in an earlier chunk -- keeps `has_initial = 1` and the Global receive.
///
/// The test is on the entry's *initial* access record: `(chunk 0, timestamp 0)` means no
/// constrained access preceded it (chunks start at 1, clks at `CHUNK_CLK_START`), and `value 0`
/// is the only initial state the AIR lets a fresh entry declare. The emulator's post-processing,
/// host trace generation, the extra-record pass, the event counters and the GPU event staging
/// all go through this one function, so they agree on which entries are fresh -- the Global
/// event layout (`FfiMemoryLocalEvent::global_slot`) depends on it.
#[inline]
pub fn is_fresh_local_mem(
    addr: RvAddr,
    initial: &MemoryRecord,
    image: &BTreeMap<u64, u64>,
) -> bool {
    // Cheap record tests first: the image lookup only runs on candidates.
    let first_touch = initial.chunk == 0 && initial.timestamp == 0;
    let in_image = first_touch && initial.value == 0 && image.contains_key(&addr);
    fresh_local_mem_verdict(addr, initial, in_image)
}

/// [`is_fresh_local_mem`] for a caller that already knows whether `addr` is an image word (the
/// emulator's post-processing walks the image with a cursor instead of a per-address lookup).
/// `in_image` is only consulted when the record tests pass.
#[inline]
pub fn fresh_local_mem_verdict(addr: RvAddr, initial: &MemoryRecord, in_image: bool) -> bool {
    let first_touch = initial.chunk == 0 && initial.timestamp == 0;
    let fresh = first_touch && initial.value == 0 && addr >= MIN_MAIN_MEMORY_ADDR && !in_image;
    // Negative-test hook: the flip applies to the first-touch entry of the address only, so the
    // later intervals of the same address (whose initial state is inherited and nonzero in
    // general) keep their verdict and their chunks stay internally consistent.
    if first_touch && FRESH_FLIPS_ACTIVE.load(Ordering::Relaxed) && fresh_flip_hits(addr) {
        return !fresh;
    }
    fresh
}

/// [`is_fresh_local_mem`] on a whole entry.
#[inline]
pub fn is_fresh_local_mem_event(event: &MemoryLocalEvent, image: &BTreeMap<u64, u64>) -> bool {
    is_fresh_local_mem(event.addr, &event.initial_mem_access, image)
}

/// Addresses whose fresh verdict the negative tests invert (empty in production).
static FRESH_FLIPS: RwLock<Vec<RvAddr>> = RwLock::new(Vec::new());
/// Fast path for the hot predicate: only when a test has installed flips is the lock taken.
static FRESH_FLIPS_ACTIVE: AtomicBool = AtomicBool::new(false);

#[inline(never)]
fn fresh_flip_hits(addr: RvAddr) -> bool {
    FRESH_FLIPS
        .read()
        .map(|flips| flips.contains(&addr))
        .unwrap_or(false)
}

/// Negative-test hook (NOT public API): invert the fresh verdict of [`is_fresh_local_mem`] for
/// the first-touch entries at `addrs`, process-wide, until the next call. Every consumer of the
/// predicate -- host trace generation, the extra-record pass, the event counters, the GPU prefix
/// sums and so the CUDA kernel -- then regenerates consistently from the flipped verdict, which
/// keeps each chunk's proof self-consistent and moves the inconsistency to the cross-chunk
/// Global sum. Install it AFTER emulation: the emulator consults the same predicate when it
/// decides which addresses get a MemoryInitialize event, and a flip seen there would be an
/// honest (balanced) execution.
///
/// `pub` only so `vm/examples/test_mle_riscv.rs` can drive the two fresh-verdict rejection arms;
/// `#[doc(hidden)]` marks it as test scaffolding, like `corrupt_one_record`.
#[doc(hidden)]
pub fn set_fresh_local_mem_flips(addrs: &[RvAddr]) {
    let mut flips = FRESH_FLIPS.write().unwrap_or_else(|e| e.into_inner());
    flips.clear();
    flips.extend_from_slice(addrs);
    FRESH_FLIPS_ACTIVE.store(!flips.is_empty(), Ordering::Release);
}

/// The MemoryLocal entry as the CUDA trace generator receives it: the emulator's event plus the
/// two values the host decides and the kernel only consumes.
///
/// `has_initial` is the entry's `has_initial` column (0 for a fresh entry, see
/// [`is_fresh_local_mem`]). `global_slot` is the number of Global events the entries before this
/// one in the same record write, i.e. `2 * i - fresh_before(i)` for the `i`-th entry: a fresh
/// entry writes only its final-state event, so a fixed `2 * i` stride would leave holes. The
/// kernel writes this entry's events at `global_events_start_index + global_slot`, initial (if
/// any) first. Mirrored by `MemoryLocalEventU64` in the pico `types.cuh`; the field order is the
/// FFI layout.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct FfiMemoryLocalEvent {
    pub event: MemoryLocalEvent,
    pub has_initial: u32,
    pub global_slot: u32,
}

impl FfiMemoryLocalEvent {
    /// Stage `events` for the GPU: `has_initial` from the shared predicate, `global_slot` as the
    /// running count of Global events written by the entries before each one. The order of
    /// `events` must be the order host trace generation enumerates them in (both come from
    /// `EmulationRecord::get_local_mem_events`).
    pub fn stage<'a>(
        events: impl IntoIterator<Item = &'a MemoryLocalEvent>,
        image: &BTreeMap<u64, u64>,
        out: &mut Vec<FfiMemoryLocalEvent>,
    ) {
        let mut global_slot: u32 = 0;
        for event in events {
            let has_initial = u32::from(!is_fresh_local_mem_event(event, image));
            out.push(FfiMemoryLocalEvent {
                event: *event,
                has_initial,
                global_slot,
            });
            global_slot += 1 + has_initial;
        }
    }
}

#[cfg(test)]
mod fresh_tests {
    use super::{
        fresh_local_mem_verdict, is_fresh_local_mem, is_fresh_local_mem_event,
        set_fresh_local_mem_flips, FfiMemoryLocalEvent, MemoryLocalEvent, MemoryRecord,
        MIN_MAIN_MEMORY_ADDR,
    };
    use std::collections::BTreeMap;

    fn rec(chunk: u32, timestamp: u32, value: u64) -> MemoryRecord {
        MemoryRecord {
            chunk,
            timestamp,
            value,
        }
    }

    fn image() -> BTreeMap<u64, u64> {
        BTreeMap::from([(0x1000u64, 0xCAFEu64), (0x1008, 0)])
    }

    /// The five kinds of entry the predicate separates, plus the floor itself.
    #[test]
    fn fresh_is_zero_initial_first_touch_outside_the_image() {
        let img = image();
        // Register: below the main-memory floor, never fresh even at (0, 0, 0).
        assert!(!is_fresh_local_mem(0, &rec(0, 0, 0), &img));
        assert!(!is_fresh_local_mem(5, &rec(0, 0, 0), &img));
        assert!(!is_fresh_local_mem(
            MIN_MAIN_MEMORY_ADDR - 8,
            &rec(0, 0, 0),
            &img
        ));
        // Image word: its initial state comes from the vk digest, whatever the value.
        assert!(!is_fresh_local_mem(0x1000, &rec(0, 0, 0xCAFE), &img));
        assert!(!is_fresh_local_mem(0x1008, &rec(0, 0, 0), &img));
        // Zero-initial first touch outside the image: fresh.
        assert!(is_fresh_local_mem(
            MIN_MAIN_MEMORY_ADDR,
            &rec(0, 0, 0),
            &img
        ));
        assert!(is_fresh_local_mem(0x2000, &rec(0, 0, 0), &img));
        // Nonzero initial value (a hint wrote it): a MemoryInitialize row carries it.
        assert!(!is_fresh_local_mem(0x2000, &rec(0, 0, 7), &img));
        // Interval that starts in an earlier chunk (or later in this one): inherited state.
        assert!(!is_fresh_local_mem(0x2000, &rec(1, 4, 0), &img));
        assert!(!is_fresh_local_mem(0x2000, &rec(0, 4, 0), &img));
        assert!(!is_fresh_local_mem(0x2000, &rec(3, 0, 0), &img));
        // The emulator-side form agrees when told the image membership.
        assert!(!fresh_local_mem_verdict(0x1008, &rec(0, 0, 0), true));
        assert!(fresh_local_mem_verdict(0x2000, &rec(0, 0, 0), false));
        assert!(!fresh_local_mem_verdict(0x2000, &rec(0, 0, 7), false));
        assert!(!fresh_local_mem_verdict(8, &rec(0, 0, 0), false));
    }

    #[test]
    fn event_wrapper_reads_the_initial_access() {
        let img = image();
        let e = MemoryLocalEvent {
            addr: 0x2000,
            initial_mem_access: rec(0, 0, 0),
            final_mem_access: rec(2, 9, 5),
        };
        assert!(is_fresh_local_mem_event(&e, &img));
        let e = MemoryLocalEvent {
            initial_mem_access: rec(0, 0, 1),
            ..e
        };
        assert!(!is_fresh_local_mem_event(&e, &img));
    }

    /// `global_slot` is the prefix sum of the Global events written before each entry:
    /// two per inherited entry, one per fresh entry.
    #[test]
    fn global_slot_is_the_prefix_sum_of_written_events() {
        let img = image();
        let e = |addr, initial| MemoryLocalEvent {
            addr,
            initial_mem_access: initial,
            final_mem_access: rec(2, 9, 5),
        };
        let events = [
            e(0x2000, rec(0, 0, 0)),      // fresh        -> slot 0, writes 1
            e(0x2008, rec(1, 4, 0)),      // inherited    -> slot 1, writes 2
            e(0x1000, rec(0, 0, 0xCAFE)), // image    -> slot 3, writes 2
            e(0x2010, rec(0, 0, 0)),      // fresh        -> slot 5, writes 1
            e(3, rec(0, 0, 0)),           // register     -> slot 6, writes 2
        ];
        let mut out = Vec::new();
        FfiMemoryLocalEvent::stage(events.iter(), &img, &mut out);
        let got: Vec<(u32, u32)> = out.iter().map(|f| (f.has_initial, f.global_slot)).collect();
        assert_eq!(got, vec![(0, 0), (1, 1), (1, 3), (0, 5), (1, 6)]);
        let total: u32 = out.iter().map(|f| 1 + f.has_initial).sum();
        assert_eq!(total, 8, "2 * 5 entries - 2 fresh");
    }

    /// The FFI layout the CUDA side mirrors: the event, then two u32s, 8-byte aligned.
    #[test]
    fn ffi_event_layout_is_the_event_plus_two_u32() {
        use std::mem::{align_of, size_of};
        assert_eq!(size_of::<MemoryLocalEvent>(), 40);
        assert_eq!(size_of::<FfiMemoryLocalEvent>(), 48);
        assert_eq!(align_of::<FfiMemoryLocalEvent>(), 8);
    }

    /// The negative-test hook inverts the verdict for the listed addresses only, and clears.
    /// The hook is process-wide and the test binary runs tests in parallel, so this one works
    /// on addresses no other test in the crate touches.
    #[test]
    fn flip_hook_inverts_listed_addresses_only() {
        let img = BTreeMap::from([(0xF0F0_0000u64, 0xCAFEu64)]);
        set_fresh_local_mem_flips(&[0xF0F0_0000, 0xF0F0_0008]);
        assert!(is_fresh_local_mem(0xF0F0_0000, &rec(0, 0, 0xCAFE), &img));
        assert!(!is_fresh_local_mem(0xF0F0_0008, &rec(0, 0, 0), &img));
        assert!(is_fresh_local_mem(0xF0F0_0010, &rec(0, 0, 0), &img));
        // Only the first-touch entry of a flipped address is affected.
        assert!(!is_fresh_local_mem(0xF0F0_0008, &rec(2, 9, 0), &img));
        set_fresh_local_mem_flips(&[]);
        assert!(!is_fresh_local_mem(0xF0F0_0000, &rec(0, 0, 0xCAFE), &img));
        assert!(is_fresh_local_mem(0xF0F0_0008, &rec(0, 0, 0), &img));
    }
}

/*
#[cfg(test)]
mod tests {
    use super::{
        MemoryInitializeFinalizeEvent, MemoryLocalEvent, MemoryReadRecord, MemoryRecord,
        MemoryRecordEnum, MemoryWriteRecord,
    };

    #[test]
    fn serde_roundtrip_preserves_memory_event_fields() {
        let read = MemoryReadRecord::new(0xABCD_EF01_2345_6789, 3, u32::MAX - 1, 2, u32::MAX - 9);
        let write = MemoryWriteRecord::new(
            0x7FFF_FFFF_0000_0001,
            4,
            u32::MAX - 3,
            0x8000_0000_0000_0002,
            3,
            u32::MAX - 4,
        );
        let init_finalize = MemoryInitializeFinalizeEvent {
            addr: 0x1_0000_0000,
            value: 0x1234_5678_9ABC_DEF0,
            chunk: 5,
            timestamp: u32::MAX - 123,
            used: 1,
        };
        let local = MemoryLocalEvent {
            addr: 0x1_0000_0000,
            initial_mem_access: MemoryRecord {
                chunk: 1,
                timestamp: u32::MAX - 17,
                value: 0x1111_2222_3333_4444,
            },
            final_mem_access: MemoryRecord {
                chunk: 2,
                timestamp: u32::MAX - 16,
                value: 0x5555_6666_7777_8888,
            },
        };
        let enum_read = MemoryRecordEnum::Read(read);
        let enum_write = MemoryRecordEnum::Write(write);

        let encoded =
            serde_json::to_string(&(enum_read, enum_write, init_finalize.clone(), local.clone()))
                .expect("serialize");
        let decoded: (
            MemoryRecordEnum,
            MemoryRecordEnum,
            MemoryInitializeFinalizeEvent,
            MemoryLocalEvent,
        ) = serde_json::from_str(&encoded).expect("deserialize");

        assert_eq!(decoded.0.value(), enum_read.value());
        assert_eq!(decoded.1.value(), enum_write.value());
        assert_eq!(decoded.2.timestamp, init_finalize.timestamp);
        assert_eq!(decoded.2.addr, init_finalize.addr);
        assert_eq!(
            decoded.3.initial_mem_access.timestamp,
            local.initial_mem_access.timestamp
        );
        assert_eq!(
            decoded.3.final_mem_access.timestamp,
            local.final_mem_access.timestamp
        );
    }
}
*/
