//! The execution history's census: per chunk, the rows each table holds and the CPU memory
//! accesses that follow a precompile's access to the same address; per run, each table's largest
//! chunk, and the capacity table a slot of history storage is sized from.
//!
//! A table is every vector the history sink writes, sixteen of them ([`TABLES`]), each sized on
//! its own: a table's capacity is its largest chunk over every block the capacity table was taken
//! from, plus [`HEADROOM_PERCENT`], rounded up.
//!
//! The history holds no precompile row, but every access row holds the chunk and timestamp of the
//! access to its address before it. A load or store is stamped at its step's clock, and a
//! precompile stamps its accesses from its ECALL's clock up, inside the extra cycles that ECALL is
//! charged, so a previous stamp of the same chunk falls in the clock range of the step that made
//! it: exactly a load's or store's clock, or inside the range of an ECALL that sent a syscall row.
//! Only precompiles make stamped memory accesses from a syscall, and every precompile sends a row.
//! A stamp that is neither is counted apart, as unattributed.
//!
//! A chunk's rows do not depend on how its replay is cut: a split chunk's segments' steps sum to
//! its unsplit history. So the blocks of a capacity table share their chunking alone, and each
//! records the replay split it was measured at. They share their tree too, the source they were
//! measured on, unless a fold was asked to cross trees; a dirty tree, whose changes are not
//! recorded, is the same tree as none, its own commit's included.
//!
//! The capacity table is one JSON object:
//! - `format`: [`FORMAT`], which a reader checks before it trusts the rest;
//! - `headroom_percent`: [`HEADROOM_PERCENT`];
//! - `chunking`: what decides where a chunk ends, which every block shares: `chunk_size` and the
//!   chunk split's `memory_rw_threshold`, `commit_tail_reserve` and `commit_tail_overrun`;
//! - `blocks`: one per block the table was taken from: `elf_sha256` and `input_sha256` (one per
//!   guest input, in the order the guest reads them), which name it, `input_labels` (those inputs
//!   as its run named them), `tree` (`{"commit", "dirty"}`), `replay_split` (`{"segments",
//!   "chunks", "from_chunk"}`, `from_chunk` `null` when unset), `chunks` (the CPU chunks it ran)
//!   and `max_rows` (each table's largest chunk, `{"table", "rows", "chunk"}` in [`TABLES`] order,
//!   `chunk` the first to hold `rows`);
//! - `tables`: per table in [`TABLES`] order, `{"table", "row_bytes", "max_rows", "capacity"}`,
//!   `max_rows` over every block;
//! - `slot_bytes`: every table's capacity times its row size, summed: one slot's storage.

use std::{cmp::Reverse, fmt, path::Path};

use pico_vm::{
    chips::chips::riscv_memory::event::MemoryAccessPosition,
    compiler::riscv::program::Program,
    emulator::riscv::{
        history::{Access, ChipSteps, ExecutionHistory, OperandException, ReadAccess, Step},
        history_arena::Rows,
        syscalls::SyscallEvent,
    },
};
use serde::{Deserialize, Serialize};

/// Every vector the history sink writes, in the order the census and `realloc=` print them.
pub const TABLES: [&str; 16] = [
    "steps",
    "reads",
    "writes",
    "operand_exceptions",
    "syscalls",
    "add",
    "sub",
    "mul",
    "bitwise",
    "shift_left",
    "shift_right",
    "lt",
    "divrem",
    "memory",
    "ecall",
    "branch",
];

/// The bytes one row of each table takes, in [`TABLES`] order; every chip list holds `u32`
/// indices.
pub const ROW_BYTES: [usize; TABLES.len()] = {
    let mut bytes = [size_of::<u32>(); TABLES.len()];
    bytes[0] = size_of::<Step>();
    bytes[1] = size_of::<ReadAccess>();
    bytes[2] = size_of::<Access>();
    bytes[3] = size_of::<OperandException>();
    bytes[4] = size_of::<SyscallEvent>();
    bytes
};

/// A table's rows, the rows it has room for, and whether that room is its arena slot's region,
/// which is fixed: a table there never moved its rows.
#[derive(Clone, Copy)]
pub struct TableSize {
    pub rows: usize,
    pub capacity: usize,
    pub in_slot: bool,
}

impl TableSize {
    fn of<T: Copy>(table: &Rows<T>) -> Self {
        Self {
            rows: table.len(),
            capacity: table.capacity(),
            in_slot: table.is_resident(),
        }
    }
}

/// Each table's size, in [`TABLES`] order. Destructured whole, so a table added to the history
/// does not go uncounted.
pub fn table_sizes(history: &ExecutionHistory) -> [TableSize; TABLES.len()] {
    let ExecutionHistory {
        chunk: _,
        steps,
        reads,
        writes,
        chip_steps,
        operand_exceptions,
        syscalls,
    } = history;
    let ChipSteps {
        add,
        sub,
        mul,
        bitwise,
        shift_left,
        shift_right,
        lt,
        divrem,
        memory,
        ecall,
        branch,
    } = chip_steps;
    [
        TableSize::of(steps),
        TableSize::of(reads),
        TableSize::of(writes),
        TableSize::of(operand_exceptions),
        TableSize::of(syscalls),
        TableSize::of(add),
        TableSize::of(sub),
        TableSize::of(mul),
        TableSize::of(bitwise),
        TableSize::of(shift_left),
        TableSize::of(shift_right),
        TableSize::of(lt),
        TableSize::of(divrem),
        TableSize::of(memory),
        TableSize::of(ecall),
        TableSize::of(branch),
    ]
}

/// A chunk's CPU memory accesses whose previous access to the address was made in the same chunk,
/// by something other than a load or store.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Windows {
    /// By a precompile.
    pub after_precompile: usize,
    /// By neither a load or store nor a precompile, which no emulator path makes.
    pub unattributed: usize,
}

/// What made an access of the chunk.
enum Toucher {
    Cpu,
    Precompile,
    Unknown,
}

impl Windows {
    /// `history`'s, `program` giving each step's instruction.
    ///
    /// # Panics
    ///
    /// If a step in the memory list holds no memory access.
    pub fn of(history: &ExecutionHistory, program: &Program) -> Self {
        let mut windows = Self::default();
        for &index in &history.chip_steps.memory {
            let index = index as usize;
            let instruction = program.fetch(u64::from(history.steps[index].pc));
            let (_, access) = history
                .accesses_of(index, &instruction)
                .find(|(position, _)| *position == MemoryAccessPosition::Memory)
                .unwrap_or_else(|| panic!("step {index} is in the memory list and accesses none"));
            if access.prev_chunk != history.chunk {
                continue;
            }
            match toucher(history, program, access.prev_timestamp) {
                Toucher::Cpu => {}
                Toucher::Precompile => windows.after_precompile += 1,
                Toucher::Unknown => windows.unattributed += 1,
            }
        }
        windows
    }
}

/// What made `history`'s access stamped `timestamp`: the step whose clock range holds it.
fn toucher(history: &ExecutionHistory, program: &Program, timestamp: u32) -> Toucher {
    let after = history.steps.partition_point(|step| step.clk <= timestamp);
    let Some(step) = after.checked_sub(1).map(|index| history.steps[index]) else {
        return Toucher::Unknown;
    };
    let instruction = program.fetch(u64::from(step.pc));
    if instruction.is_memory_instruction()
        && step.timestamp(MemoryAccessPosition::Memory) == timestamp
    {
        Toucher::Cpu
    } else if instruction.is_ecall_instruction()
        && history
            .syscalls
            .binary_search_by_key(&u64::from(step.clk), |syscall| syscall.clk)
            .is_ok()
    {
        Toucher::Precompile
    } else {
        Toucher::Unknown
    }
}

/// One chunk's census.
pub struct ChunkCensus {
    pub chunk: u32,
    /// Each table's rows, in [`TABLES`] order.
    pub rows: [usize; TABLES.len()],
    pub windows: Windows,
}

impl ChunkCensus {
    pub fn of(history: &ExecutionHistory, program: &Program) -> Self {
        Self {
            chunk: history.chunk,
            rows: table_sizes(history).map(|size| size.rows),
            windows: Windows::of(history, program),
        }
    }

    /// The chunk's `CENSUS` line.
    pub fn line(&self) -> String {
        let rows: Vec<String> = TABLES
            .iter()
            .zip(self.rows)
            .map(|(table, rows)| format!("{table}={rows}"))
            .collect();
        format!(
            "CENSUS chunk={} {} after_precompile={} unattributed={}",
            self.chunk,
            rows.join(" "),
            self.windows.after_precompile,
            self.windows.unattributed
        )
    }
}

/// One table over a run's chunks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableSummary {
    pub max_rows: usize,
    /// The first chunk to hold `max_rows`.
    pub max_chunk: u32,
    /// The lower of the two middle chunks' rows, for an even count.
    pub median_rows: usize,
}

/// Each table's summary, in [`TABLES`] order; none for a run with no chunk.
pub fn summarise(chunks: &[ChunkCensus]) -> Option<[TableSummary; TABLES.len()]> {
    let first = chunks.first()?;
    Some(std::array::from_fn(|table| {
        let (mut max_rows, mut max_chunk) = (first.rows[table], first.chunk);
        for chunk in &chunks[1..] {
            if chunk.rows[table] > max_rows {
                (max_rows, max_chunk) = (chunk.rows[table], chunk.chunk);
            }
        }
        let mut rows: Vec<usize> = chunks.iter().map(|chunk| chunk.rows[table]).collect();
        rows.sort_unstable();
        TableSummary {
            max_rows,
            max_chunk,
            median_rows: rows[(rows.len() - 1) / 2],
        }
    }))
}

/// The `CENSUS_WINDOWS` line: the chunks with CPU accesses after a precompile's, most first, each
/// as `<chunk>:<accesses>`.
pub fn windows_line(chunks: &[ChunkCensus]) -> String {
    let mut picked: Vec<&ChunkCensus> = chunks
        .iter()
        .filter(|chunk| chunk.windows.after_precompile > 0)
        .collect();
    picked.sort_by_key(|chunk| (Reverse(chunk.windows.after_precompile), chunk.chunk));
    let pick: Vec<String> = picked
        .iter()
        .map(|chunk| format!("{}:{}", chunk.chunk, chunk.windows.after_precompile))
        .collect();
    let total = |count: fn(&Windows) -> usize| -> usize {
        chunks.iter().map(|chunk| count(&chunk.windows)).sum()
    };
    format!(
        "CENSUS_WINDOWS chunks={} of={} after_precompile={} unattributed={} pick={}",
        picked.len(),
        chunks.len(),
        total(|windows| windows.after_precompile),
        total(|windows| windows.unattributed),
        if pick.is_empty() {
            "-".to_string()
        } else {
            pick.join(",")
        }
    )
}

/// The room a table is given over the most rows it was seen to hold.
pub const HEADROOM_PERCENT: usize = 10;

/// `rows` plus [`HEADROOM_PERCENT`], rounded up.
pub fn with_headroom(rows: usize) -> usize {
    (rows * (100 + HEADROOM_PERCENT)).div_ceil(100)
}

pub const FORMAT: &str = "pico-history-capacity/2";

/// What decides where a chunk ends: a capacity table holds for these alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chunking {
    pub chunk_size: u32,
    pub memory_rw_threshold: usize,
    pub commit_tail_reserve: u32,
    pub commit_tail_overrun: u32,
}

/// How a run cut its chunks' replays.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaySplit {
    pub segments: u32,
    pub chunks: u32,
    pub from_chunk: Option<u32>,
}

/// The source a block was measured on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tree {
    pub commit: String,
    pub dirty: bool,
}

impl Tree {
    /// Refuses a `commit` that is not a git commit's hex digits, full or abbreviated.
    pub fn new(commit: &str, dirty: bool) -> Result<Self, String> {
        if (7..=40).contains(&commit.len()) && commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            Ok(Self {
                commit: commit.to_ascii_lowercase(),
                dirty,
            })
        } else {
            Err(format!(
                "`{commit}` is not a git commit: expected 7 to 40 hex digits"
            ))
        }
    }

    /// The same commit, however abbreviated, and neither tree dirty.
    fn is_same_tree(&self, other: &Self) -> bool {
        !self.dirty
            && !other.dirty
            && (self.commit.starts_with(&other.commit) || other.commit.starts_with(&self.commit))
    }
}

impl fmt::Display for Tree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dirty = if self.dirty { "-dirty" } else { "" };
        write!(f, "{}{dirty}", self.commit)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableRows {
    pub table: String,
    pub rows: usize,
    pub chunk: u32,
}

impl TableRows {
    /// Each table's largest chunk in `summary`, in [`TABLES`] order.
    pub fn largest(summary: &[TableSummary; TABLES.len()]) -> Vec<Self> {
        TABLES
            .iter()
            .zip(summary)
            .map(|(table, summary)| Self {
                table: (*table).to_string(),
                rows: summary.max_rows,
                chunk: summary.max_chunk,
            })
            .collect()
    }
}

/// One block's largest chunk per table, what names the block, and where it was measured.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub elf_sha256: String,
    pub input_sha256: Vec<String>,
    pub input_labels: Vec<String>,
    pub tree: Tree,
    pub replay_split: ReplaySplit,
    pub chunks: usize,
    pub max_rows: Vec<TableRows>,
}

impl Block {
    fn is_same_block(&self, other: &Self) -> bool {
        (&self.elf_sha256, &self.input_sha256) == (&other.elf_sha256, &other.input_sha256)
    }

    /// Its inputs' labels, as a `key=value` line can hold them.
    fn label(&self) -> String {
        if self.input_labels.is_empty() {
            "-".to_string()
        } else {
            self.input_labels.join(",")
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableCapacity {
    pub table: String,
    pub row_bytes: usize,
    pub max_rows: usize,
    pub capacity: usize,
}

/// Each table's capacity over the blocks it was taken from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityTable {
    pub format: String,
    pub headroom_percent: usize,
    pub chunking: Chunking,
    pub blocks: Vec<Block>,
    pub tables: Vec<TableCapacity>,
    pub slot_bytes: usize,
}

/// Refuses a list that does not name [`TABLES`], in order.
fn check_tables<'a>(names: impl Iterator<Item = &'a str>, what: &str) -> Result<(), String> {
    if names.eq(TABLES) {
        Ok(())
    } else {
        Err(format!(
            "{what} does not list the history's tables in order: {}",
            TABLES.join(",")
        ))
    }
}

impl CapacityTable {
    /// Refuses `tree` unless every block was measured on it: a fold would otherwise put readings
    /// of other code beside this run's, or replace one with it.
    pub fn check_tree(&self, tree: &Tree) -> Result<(), String> {
        let mut others: Vec<String> = self
            .blocks
            .iter()
            .filter(|block| !block.tree.is_same_tree(tree))
            .map(|block| block.tree.to_string())
            .collect();
        if others.is_empty() {
            return Ok(());
        }
        others.sort_unstable();
        others.dedup();
        let dirty = if tree.dirty || self.blocks.iter().any(|block| block.tree.dirty) {
            " (a dirty tree is the same tree as none)"
        } else {
            ""
        };
        Err(format!(
            "the capacity table to fold in holds blocks measured on {}, and this run measures \
             {tree}{dirty}",
            others.join(", ")
        ))
    }

    /// The table over `block` and, when given, `earlier`'s blocks, which must have been taken at
    /// the same `chunking`: at another, its capacities would not hold for this run's chunks. Unless
    /// `across_trees`, they must have been measured on `block`'s tree too ([`Self::check_tree`]).
    /// A block of `earlier`'s with `block`'s ELF and inputs is an earlier run of it, and `block`
    /// replaces it. The capacities are recomputed from the blocks.
    pub fn fold(
        earlier: Option<Self>,
        chunking: Chunking,
        block: Block,
        across_trees: bool,
    ) -> Result<Self, String> {
        let mut blocks = match earlier {
            Some(earlier) if earlier.chunking != chunking => {
                return Err(format!(
                    "the capacity table to fold in was taken at {:?}, and this run chunks at \
                     {chunking:?}",
                    earlier.chunking
                ))
            }
            Some(earlier) => {
                if !across_trees {
                    earlier.check_tree(&block.tree)?;
                }
                earlier.blocks
            }
            None => Vec::new(),
        };
        blocks.retain(|earlier| !earlier.is_same_block(&block));
        blocks.push(block);
        for block in &blocks {
            check_tables(
                block.max_rows.iter().map(|rows| rows.table.as_str()),
                &format!("block {}'s max_rows", block.elf_sha256),
            )?;
        }
        let tables: Vec<TableCapacity> = TABLES
            .iter()
            .enumerate()
            .map(|(index, table)| {
                let max_rows = blocks
                    .iter()
                    .map(|block| block.max_rows[index].rows)
                    .max()
                    .unwrap_or(0);
                TableCapacity {
                    table: (*table).to_string(),
                    row_bytes: ROW_BYTES[index],
                    max_rows,
                    capacity: with_headroom(max_rows),
                }
            })
            .collect();
        let slot_bytes = tables
            .iter()
            .map(|table| table.capacity * table.row_bytes)
            .sum();
        Ok(Self {
            format: FORMAT.to_string(),
            headroom_percent: HEADROOM_PERCENT,
            chunking,
            blocks,
            tables,
            slot_bytes,
        })
    }

    /// The table at `path`, refused when of another format or headroom, or of other tables. The
    /// format is read alone first: another format's fields need not parse as this one's.
    pub fn read(path: &Path) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Format {
            format: String,
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read `{}`: {e}", path.display()))?;
        let not_a_table =
            |e: serde_json::Error| format!("`{}` is not a capacity table: {e}", path.display());
        let Format { format } = serde_json::from_str(&text).map_err(not_a_table)?;
        if format != FORMAT {
            return Err(format!(
                "`{}` is a capacity table of format {format}, and this census reads {FORMAT}: \
                 re-run the census on its blocks to write it again",
                path.display()
            ));
        }
        let table: Self = serde_json::from_str(&text).map_err(not_a_table)?;
        if table.headroom_percent != HEADROOM_PERCENT {
            return Err(format!(
                "`{}` is a capacity table with {} % headroom, and this census writes \
                 {HEADROOM_PERCENT} %",
                path.display(),
                table.headroom_percent
            ));
        }
        check_tables(
            table.tables.iter().map(|table| table.table.as_str()),
            &format!("`{}`", path.display()),
        )?;
        Ok(table)
    }

    pub fn write(&self, path: &Path) -> Result<(), String> {
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(path, text + "\n")
            .map_err(|e| format!("cannot write `{}`: {e}", path.display()))
    }

    /// The first block to hold table `index`'s `max_rows`, and its largest chunk there.
    fn largest(&self, index: usize) -> Option<(&Block, &TableRows)> {
        let max_rows = self.tables[index].max_rows;
        self.blocks.iter().find_map(|block| {
            let rows = &block.max_rows[index];
            (rows.rows == max_rows).then_some((block, rows))
        })
    }
}

/// The `CENSUS_TABLE` lines and the `CENSUS_SLOT` line: `table`'s figures, over every block it
/// holds, unprefixed, and this run's `summary` beside them as `run_`.
pub fn summary_lines(summary: &[TableSummary; TABLES.len()], table: &CapacityTable) -> Vec<String> {
    let mut lines: Vec<String> = table
        .tables
        .iter()
        .zip(summary)
        .enumerate()
        .map(|(index, (capacity, run))| {
            let (block, largest) = table
                .largest(index)
                .expect("a folded table's max_rows are some block's");
            format!(
                "CENSUS_TABLE table={} max_rows={} max_block={} max_chunk={} row_bytes={} \
                 max_bytes={} capacity={} run_max_rows={} run_max_chunk={} run_median_rows={}",
                capacity.table,
                capacity.max_rows,
                block.label(),
                largest.chunk,
                capacity.row_bytes,
                capacity.max_rows * capacity.row_bytes,
                capacity.capacity,
                run.max_rows,
                run.max_chunk,
                run.median_rows
            )
        })
        .collect();
    let run_bytes = |rows: fn(&TableSummary) -> usize| -> usize {
        summary
            .iter()
            .zip(ROW_BYTES)
            .map(|(summary, row_bytes)| rows(summary) * row_bytes)
            .sum()
    };
    let sum_max_bytes: usize = table
        .tables
        .iter()
        .map(|table| table.max_rows * table.row_bytes)
        .sum();
    lines.push(format!(
        "CENSUS_SLOT blocks={} sum_max_bytes={sum_max_bytes} slot_bytes={} run_sum_max_bytes={} \
         run_sum_median_bytes={}",
        table.blocks.len(),
        table.slot_bytes,
        run_bytes(|summary| summary.max_rows),
        run_bytes(|summary| summary.median_rows)
    ));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico_vm::{
        compiler::riscv::{instruction::Instruction, opcode::Opcode},
        emulator::riscv::history::Slots,
    };

    /// Each table a different number of rows: the table at index `i` holds `i + 1`.
    fn counted_history() -> ExecutionHistory {
        let mut history = ExecutionHistory {
            chunk: 4,
            ..ExecutionHistory::default()
        };
        history.steps = vec![Step::default(); 1].into();
        history.reads = vec![ReadAccess::default(); 2].into();
        history.writes = vec![Access::default(); 3].into();
        history.operand_exceptions = vec![OperandException::default(); 4].into();
        history.syscalls = vec![SyscallEvent::default(); 5].into();
        let lists = &mut history.chip_steps;
        for (rows, list) in (6..).zip([
            &mut lists.add,
            &mut lists.sub,
            &mut lists.mul,
            &mut lists.bitwise,
            &mut lists.shift_left,
            &mut lists.shift_right,
            &mut lists.lt,
            &mut lists.divrem,
            &mut lists.memory,
            &mut lists.ecall,
            &mut lists.branch,
        ]) {
            *list = vec![0; rows].into();
        }
        history
    }

    #[test]
    fn a_chunks_census_counts_every_table_in_order() {
        let history = counted_history();
        let rows = table_sizes(&history).map(|size| size.rows);
        assert_eq!(rows, std::array::from_fn(|index| index + 1));
        let census = ChunkCensus {
            chunk: history.chunk,
            rows,
            windows: Windows::default(),
        };
        assert_eq!(
            census.line(),
            "CENSUS chunk=4 steps=1 reads=2 writes=3 operand_exceptions=4 syscalls=5 add=6 sub=7 \
             mul=8 bitwise=9 shift_left=10 shift_right=11 lt=12 divrem=13 memory=14 ecall=15 \
             branch=16 after_precompile=0 unattributed=0"
        );
    }

    /// The row sizes the history storage is priced at: a step, a read, a write, an operand
    /// exception, a syscall row, then a list index for each chip list.
    #[test]
    fn each_table_is_priced_at_its_row_size() {
        let mut expected = [4; TABLES.len()];
        expected[..5].copy_from_slice(&[20, 16, 24, 16, 40]);
        assert_eq!(ROW_BYTES, expected);
    }

    fn chunk(chunk: u32, rows: usize, after_precompile: usize) -> ChunkCensus {
        ChunkCensus {
            chunk,
            rows: [rows; TABLES.len()],
            windows: Windows {
                after_precompile,
                unattributed: 0,
            },
        }
    }

    #[test]
    fn a_tables_summary_is_its_largest_chunk_first_reached_and_its_lower_median() {
        let mut chunks = vec![chunk(1, 30, 0), chunk(2, 70, 2), chunk(3, 10, 5)];
        chunks.push(chunk(4, 70, 2));
        let summary = summarise(&chunks).expect("four chunks");
        assert!(summary.iter().all(|table| *table
            == TableSummary {
                max_rows: 70,
                max_chunk: 2,
                median_rows: 30,
            }));
        chunks.pop();
        assert_eq!(summarise(&chunks).expect("three chunks")[0].median_rows, 30);
        assert_eq!(
            summarise(&chunks[..1]).expect("one chunk")[0].median_rows,
            30
        );
        assert!(summarise(&[]).is_none());
        assert_eq!(
            windows_line(&chunks),
            "CENSUS_WINDOWS chunks=2 of=3 after_precompile=7 unattributed=0 pick=3:5,2:2"
        );
        assert!(windows_line(&chunks[..1]).ends_with(" pick=-"));
    }

    #[test]
    fn a_capacity_is_the_most_rows_plus_a_tenth_rounded_up() {
        assert_eq!(with_headroom(0), 0);
        assert_eq!(with_headroom(1), 2);
        assert_eq!(with_headroom(100), 110);
        assert_eq!(with_headroom(101), 112);
        assert_eq!(with_headroom(8_388_608), 9_227_469);
    }

    fn chunking(chunk_size: u32) -> Chunking {
        Chunking {
            chunk_size,
            memory_rw_threshold: chunk_size as usize >> 1,
            commit_tail_reserve: 2048,
            commit_tail_overrun: 0,
        }
    }

    fn tree(commit: &str, dirty: bool) -> Tree {
        Tree::new(commit, dirty).expect("a commit")
    }

    /// A block of `tree`'s whose table at index `i` reached `rows[i]`, in chunk 0.
    fn block_on(tree: Tree, input: &str, rows: [usize; TABLES.len()]) -> Block {
        let summary = rows.map(|max_rows| TableSummary {
            max_rows,
            max_chunk: 0,
            median_rows: 0,
        });
        Block {
            elf_sha256: "elf".into(),
            input_sha256: vec![input.into()],
            input_labels: vec![format!("file:{input}.bin")],
            tree,
            replay_split: ReplaySplit {
                segments: 1,
                chunks: 1,
                from_chunk: None,
            },
            chunks: 3,
            max_rows: TableRows::largest(&summary),
        }
    }

    fn block(input: &str, rows: [usize; TABLES.len()]) -> Block {
        block_on(tree("4ae1c8002", false), input, rows)
    }

    #[test]
    fn two_blocks_size_each_table_at_the_larger_of_their_largest_chunks() {
        let mut first = [100; TABLES.len()];
        first[0] = 1000;
        let mut second = [200; TABLES.len()];
        second[0] = 10;
        let fold = |earlier: Option<&CapacityTable>, chunk_size: u32, block: Block| {
            CapacityTable::fold(earlier.cloned(), chunking(chunk_size), block, false)
        };
        let one = fold(None, 1 << 23, block("a", first)).expect("a first block");
        let both = fold(Some(&one), 1 << 23, block("b", second))
            .expect("a second block at the same chunking");
        assert_eq!(both.blocks.len(), 2);
        assert_eq!(
            (both.tables[0].max_rows, both.tables[0].capacity),
            (1000, 1100)
        );
        assert!(both.tables[1..]
            .iter()
            .all(|table| (table.max_rows, table.capacity) == (200, 220)));
        let slot: usize = both
            .tables
            .iter()
            .map(|table| table.capacity * table.row_bytes)
            .sum();
        assert_eq!(both.slot_bytes, slot);
        assert_eq!(
            both.slot_bytes,
            1100 * 20 + 220 * (16 + 24 + 16 + 40 + 11 * 4)
        );

        let again = fold(Some(&both), 1 << 23, block("a", second)).expect("a block run again");
        assert_eq!(again.blocks.len(), 2, "a block run again replaces itself");
        assert_eq!(again.tables[0].max_rows, 10);

        assert!(fold(Some(&one), 1 << 22, block("b", second)).is_err());

        let mut split = block("b", second);
        split.replay_split = ReplaySplit {
            segments: 2,
            chunks: 4,
            from_chunk: None,
        };
        let split = fold(Some(&one), 1 << 23, split).expect("a block at another replay split");
        assert_eq!(split.tables, both.tables);
    }

    #[test]
    fn a_fold_across_trees_is_made_only_when_asked() {
        let rows = [5; TABLES.len()];
        let one = CapacityTable::fold(None, chunking(1 << 23), block("a", rows), false)
            .expect("a first block");
        let fold = |tree: Tree, input: &str, across_trees: bool| {
            CapacityTable::fold(
                Some(one.clone()),
                chunking(1 << 23),
                block_on(tree, input, rows),
                across_trees,
            )
        };

        let full = "4ae1c8002ab47c0fbe8e7ee0c3c03e0bd3c4a9f1";
        assert!(
            fold(tree(full, false), "b", false).is_ok(),
            "the same commit, unabbreviated"
        );
        let other = fold(tree("5bf2d9113", false), "b", false).expect_err("another tree");
        assert!(
            other.contains("measured on 4ae1c8002, and this run measures 5bf2d9113"),
            "{other}"
        );
        assert!(
            fold(tree("5bf2d9113", false), "a", false).is_err(),
            "a block's reading replaced by another tree's"
        );
        let dirty = fold(tree("4ae1c8002", true), "b", false).expect_err("a dirty tree");
        assert!(dirty.contains("4ae1c8002-dirty"), "{dirty}");

        let mixed = fold(tree("5bf2d9113", false), "b", true).expect("asked to cross trees");
        let trees: Vec<String> = mixed.blocks.iter().map(|b| b.tree.to_string()).collect();
        assert_eq!(trees, ["4ae1c8002", "5bf2d9113"]);
        let replaced = fold(tree("5bf2d9113", true), "a", true).expect("asked to replace");
        assert_eq!(replaced.blocks.len(), 1);
        assert_eq!(replaced.blocks[0].tree.to_string(), "5bf2d9113-dirty");

        let on_dirty = CapacityTable::fold(
            None,
            chunking(1 << 23),
            block_on(tree("4ae1c8002", true), "a", rows),
            false,
        )
        .expect("a first block on a dirty tree");
        assert!(
            on_dirty.check_tree(&tree("4ae1c8002", true)).is_err(),
            "a dirty tree is not its own"
        );
    }

    #[test]
    fn a_tree_is_a_git_commit() {
        assert_eq!(tree("4AE1C8002", false).commit, "4ae1c8002");
        for commit in ["", "4ae1c8", "__SHA__", &"a".repeat(41)] {
            assert!(Tree::new(commit, false).is_err(), "{commit:?}");
        }
    }

    #[test]
    fn the_summary_lines_give_the_folds_figures_and_this_runs_apart() {
        let mut earlier = block("a", [100; TABLES.len()]);
        earlier.max_rows[1].chunk = 7;
        let one = CapacityTable::fold(None, chunking(1 << 23), earlier, false).expect("a block");
        let mut rows = [50; TABLES.len()];
        rows[0] = 300;
        let summary = rows.map(|max_rows| TableSummary {
            max_rows,
            max_chunk: 2,
            median_rows: max_rows / 2,
        });
        let mut run = block("b", rows);
        run.max_rows = TableRows::largest(&summary);
        let both =
            CapacityTable::fold(Some(one), chunking(1 << 23), run, false).expect("two blocks");
        let lines = summary_lines(&summary, &both);
        assert_eq!(lines.len(), TABLES.len() + 1);
        assert_eq!(
            lines[0],
            "CENSUS_TABLE table=steps max_rows=300 max_block=file:b.bin max_chunk=2 row_bytes=20 \
             max_bytes=6000 capacity=330 run_max_rows=300 run_max_chunk=2 run_median_rows=150"
        );
        assert_eq!(
            lines[1],
            "CENSUS_TABLE table=reads max_rows=100 max_block=file:a.bin max_chunk=7 row_bytes=16 \
             max_bytes=1600 capacity=110 run_max_rows=50 run_max_chunk=2 run_median_rows=25"
        );
        let row_bytes: usize = ROW_BYTES[1..].iter().sum();
        assert_eq!(
            lines[TABLES.len()],
            format!(
                "CENSUS_SLOT blocks=2 sum_max_bytes={} slot_bytes={} run_sum_max_bytes={} \
                 run_sum_median_bytes={}",
                300 * 20 + 100 * row_bytes,
                both.slot_bytes,
                300 * 20 + 50 * row_bytes,
                150 * 20 + 25 * row_bytes
            )
        );
    }

    #[test]
    fn a_capacity_table_reads_back_as_written_and_a_foreign_one_is_refused() {
        let table = CapacityTable::fold(
            None,
            chunking(1 << 23),
            block("a", [7; TABLES.len()]),
            false,
        )
        .expect("a block");
        let dir = std::env::temp_dir().join(format!("history-census-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temporary directory");
        let path = dir.join("capacity.json");
        let read_back = |table: &CapacityTable| {
            table.write(&path).expect("written");
            CapacityTable::read(&path)
        };
        assert_eq!(read_back(&table), Ok(table.clone()));
        let mut reordered = table.clone();
        reordered.tables.swap(1, 2);
        let mut reformatted = table;
        reformatted.format = "pico-history-capacity/0".into();
        let refused = [read_back(&reordered), read_back(&reformatted)];
        // A first-format block: no tree, no replay split, no chunk per table.
        let first_format = r#"{"format": "pico-history-capacity/1", "headroom_percent": 10,
            "blocks": [{"elf_sha256": "elf", "max_rows": [{"table": "steps", "rows": 1}]}]}"#;
        std::fs::write(&path, first_format).expect("written");
        let first = CapacityTable::read(&path);
        std::fs::remove_dir_all(&dir).expect("removed");
        assert!(refused.iter().all(Result::is_err), "{refused:?}");
        assert!(
            first
                .as_ref()
                .is_err_and(|e| e.contains("format pico-history-capacity/1")
                    && e.contains("re-run the census")),
            "{first:?}"
        );
    }

    const CHUNK: u32 = 3;
    const PC_BASE: u32 = 0x1000;

    /// A step's instruction, its clock, and the previous chunk and timestamp its memory access
    /// found, if it makes one.
    type Ran = (Instruction, u32, Option<(u32, u32)>);

    /// Nine steps of chunk 3. Two loads follow a stamp of this chunk that no load, store or
    /// precompile made, and one follows the precompile's.
    fn window_steps() -> [Ran; 9] {
        let store = Instruction::new(Opcode::SD, 5, 6, 0, false, true);
        let load = Instruction::new(Opcode::LD, 7, 6, 0, false, true);
        let ecall = Instruction::new(Opcode::ECALL, 5, 10, 11, false, false);
        [
            (store, 8, Some((0, 0))),
            // A precompile, with its syscall row, charged four extra cycles.
            (ecall, 12, None),
            (load, 20, Some((CHUNK, 13))),
            (load, 24, Some((CHUNK, 20))),
            (load, 28, Some((CHUNK - 1, 13))),
            // Inside the store's range, and not its access.
            (load, 32, Some((CHUNK, 9))),
            // A syscall that sends no row.
            (ecall, 36, None),
            (load, 40, Some((CHUNK, 37))),
            (load, 44, Some((CHUNK, 8))),
        ]
    }

    /// The history the sink writes for `steps`, row by row as [`Slots`] orders them.
    fn window_history(steps: &[Ran]) -> ExecutionHistory {
        let mut history = ExecutionHistory {
            chunk: CHUNK,
            ..ExecutionHistory::default()
        };
        for (index, &(instruction, clk, previous)) in steps.iter().enumerate() {
            let pc = PC_BASE + 4 * index as u32;
            history.steps.push(Step {
                clk,
                pc,
                next_pc: pc + 4,
                first_read: history.reads.len() as u32,
                first_write: history.writes.len() as u32,
            });
            let slots = Slots::of(&instruction);
            for position in slots.iter() {
                let (prev_chunk, prev_timestamp) = match position {
                    MemoryAccessPosition::Memory => previous.expect("a memory step's stamp"),
                    _ => (0, 0),
                };
                let access = Access {
                    prev_chunk,
                    prev_timestamp,
                    ..Access::default()
                };
                if slots.writes(position) {
                    history.writes.push(access);
                } else {
                    history.reads.push(access.into());
                }
            }
            if instruction.is_memory_instruction() {
                history.chip_steps.memory.push(index as u32);
            }
            if instruction.is_ecall_instruction() {
                history.chip_steps.ecall.push(index as u32);
            }
        }
        history.syscalls.push(SyscallEvent {
            chunk: CHUNK,
            clk: 12,
            syscall_id: 0x09,
            ..SyscallEvent::default()
        });
        history
    }

    fn program(steps: &[Ran]) -> Program {
        let instructions = steps.iter().map(|&(instruction, ..)| instruction).collect();
        Program::new(instructions, PC_BASE.into(), PC_BASE.into())
    }

    #[test]
    fn a_cpu_access_after_a_precompiles_in_the_same_chunk_is_counted_and_no_other() {
        let steps = window_steps();
        let windows = Windows::of(&window_history(&steps), &program(&steps));
        assert_eq!(
            windows,
            Windows {
                after_precompile: 1,
                unattributed: 2,
            }
        );
    }

    #[test]
    fn a_stamp_before_the_chunks_first_step_is_unattributed() {
        let mut steps = window_steps();
        steps[2].2 = Some((CHUNK, 7));
        let windows = Windows::of(&window_history(&steps), &program(&steps));
        assert_eq!(windows.after_precompile, 0);
        assert_eq!(windows.unattributed, 3);
    }
}
