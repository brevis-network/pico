//! What one slot of the arena holds: the rows each table has room for, and where in the slot each
//! table starts.
//!
//! A table is every vector the history sink writes, sixteen of them, named and ordered as the
//! history census names them in its capacity table (`perf/aot/bench/history_capacity.json`, format
//! [`CAPACITY_FORMAT`]). Each is sized on its own: a chunk that outgrows one table spills that
//! table alone.

use serde_json::Value;

/// The history's tables, in the capacity table's order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Table {
    Steps,
    Reads,
    Writes,
    OperandExceptions,
    Syscalls,
    Add,
    Sub,
    Mul,
    Bitwise,
    ShiftLeft,
    ShiftRight,
    Lt,
    DivRem,
    Memory,
    Ecall,
    Branch,
}

pub const TABLE_COUNT: usize = 16;

impl Table {
    pub const ALL: [Self; TABLE_COUNT] = [
        Self::Steps,
        Self::Reads,
        Self::Writes,
        Self::OperandExceptions,
        Self::Syscalls,
        Self::Add,
        Self::Sub,
        Self::Mul,
        Self::Bitwise,
        Self::ShiftLeft,
        Self::ShiftRight,
        Self::Lt,
        Self::DivRem,
        Self::Memory,
        Self::Ecall,
        Self::Branch,
    ];

    /// The chip lists, in the order of the history's `ChipSteps` fields.
    pub const LISTS: [Self; 11] = [
        Self::Add,
        Self::Sub,
        Self::Mul,
        Self::Bitwise,
        Self::ShiftLeft,
        Self::ShiftRight,
        Self::Lt,
        Self::DivRem,
        Self::Memory,
        Self::Ecall,
        Self::Branch,
    ];

    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// The capacity table's name for it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Steps => "steps",
            Self::Reads => "reads",
            Self::Writes => "writes",
            Self::OperandExceptions => "operand_exceptions",
            Self::Syscalls => "syscalls",
            Self::Add => "add",
            Self::Sub => "sub",
            Self::Mul => "mul",
            Self::Bitwise => "bitwise",
            Self::ShiftLeft => "shift_left",
            Self::ShiftRight => "shift_right",
            Self::Lt => "lt",
            Self::DivRem => "divrem",
            Self::Memory => "memory",
            Self::Ecall => "ecall",
            Self::Branch => "branch",
        }
    }
}

/// The size and alignment of one table's row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowShape {
    pub bytes: usize,
    pub align: usize,
}

impl RowShape {
    #[must_use]
    pub const fn of<T>() -> Self {
        Self {
            bytes: size_of::<T>(),
            align: align_of::<T>(),
        }
    }
}

/// The capacity table format this reader takes.
pub const CAPACITY_FORMAT: &str = "pico-history-capacity/2";

/// The rows each table of a slot has room for, and the chunk size they were measured at: at a
/// larger chunk a slot would spill by design.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryCapacity {
    chunk_size: u32,
    rows: [usize; TABLE_COUNT],
}

impl HistoryCapacity {
    /// The committed capacity table's: reth-23993050 and reth-17106222 at a chunk size of 2^23,
    /// each table at its largest chunk plus 10 %. A test holds it to the file.
    pub const CENSUS: Self = Self {
        chunk_size: 1 << 23,
        rows: [
            9_226_708, 15_837_194, 8_298_215, 559, 113_728, 2_947_898, 306_327, 105_543, 1_086_019,
            1_122_989, 1_100_365, 197_916, 905, 4_176_629, 114_848, 2_694_800,
        ],
    };

    /// The capacities of a capacity table, `shapes` being each table's row as this build lays it
    /// out. Refused when of another format, when its tables are not [`Table::ALL`] in order, when a
    /// table's row size is not this build's (its bytes would not be what a slot holds), when a
    /// capacity is under the rows it was measured to need, or when its slot size is not its own
    /// tables' sum.
    pub fn from_capacity_table(
        text: &str,
        shapes: &[RowShape; TABLE_COUNT],
    ) -> Result<Self, String> {
        let table: Value =
            serde_json::from_str(text).map_err(|e| format!("not a capacity table: {e}"))?;
        let field = |value: &Value, key: &str| -> Result<Value, String> {
            value
                .get(key)
                .cloned()
                .ok_or_else(|| format!("a capacity table without `{key}`"))
        };
        let number = |value: &Value, key: &str| -> Result<usize, String> {
            field(value, key)?
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .ok_or_else(|| format!("`{key}` is not a count"))
        };
        let format = field(&table, "format")?;
        if format.as_str() != Some(CAPACITY_FORMAT) {
            return Err(format!(
                "a capacity table of format {format}, and this reader takes {CAPACITY_FORMAT}"
            ));
        }
        let chunk_size = u32::try_from(number(&field(&table, "chunking")?, "chunk_size")?)
            .map_err(|_| "`chunk_size` does not fit a u32".to_string())?;
        let tables = field(&table, "tables")?;
        let tables = tables
            .as_array()
            .filter(|tables| tables.len() == TABLE_COUNT)
            .ok_or_else(|| format!("`tables` does not hold {TABLE_COUNT} tables"))?;
        let mut rows = [0; TABLE_COUNT];
        let mut slot_bytes = 0usize;
        for ((entry, table), shape) in tables.iter().zip(Table::ALL).zip(shapes) {
            let name = field(entry, "table")?;
            if name.as_str() != Some(table.name()) {
                return Err(format!(
                    "`tables` names {name} where the history's table {} stands",
                    table.name()
                ));
            }
            let row_bytes = number(entry, "row_bytes")?;
            if row_bytes != shape.bytes {
                return Err(format!(
                    "table {} was measured at {row_bytes}-byte rows, and this build's are {}",
                    table.name(),
                    shape.bytes
                ));
            }
            let (max_rows, capacity) = (number(entry, "max_rows")?, number(entry, "capacity")?);
            if capacity < max_rows {
                return Err(format!(
                    "table {} has room for {capacity} rows and was measured at {max_rows}",
                    table.name()
                ));
            }
            rows[table.index()] = capacity;
            slot_bytes = capacity
                .checked_mul(row_bytes)
                .and_then(|bytes| slot_bytes.checked_add(bytes))
                .ok_or("the slot's size overflows")?;
        }
        let stated = number(&table, "slot_bytes")?;
        if stated != slot_bytes {
            return Err(format!(
                "`slot_bytes` is {stated}, and the tables' capacities sum to {slot_bytes}"
            ));
        }
        Ok(Self { chunk_size, rows })
    }

    /// The same capacities with `table` given room for `rows`: the seam that makes a chunk outgrow
    /// one table on purpose, so the spill path of each table can be driven alone.
    #[must_use]
    pub const fn with_rows(mut self, table: Table, rows: usize) -> Self {
        self.rows[table.index()] = rows;
        self
    }

    #[must_use]
    pub const fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    #[must_use]
    pub const fn rows(&self, table: Table) -> usize {
        self.rows[table.index()]
    }
}

/// Where each table of a slot starts, in bytes from the slot's base, and the slot's length.
///
/// Tables are placed by falling alignment, the capacity table's order among equals: a row's size
/// is a multiple of its alignment, so no table is padded and a slot is exactly its tables' sum,
/// the capacity table's `slot_bytes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotLayout {
    offsets: [usize; TABLE_COUNT],
    bytes: usize,
    align: usize,
}

impl SlotLayout {
    /// `None` when the slot would not fit the address space.
    #[must_use]
    pub fn new(capacity: &HistoryCapacity, shapes: &[RowShape; TABLE_COUNT]) -> Option<Self> {
        let mut order = Table::ALL;
        order.sort_by_key(|table| std::cmp::Reverse(shapes[table.index()].align));
        let mut offsets = [0; TABLE_COUNT];
        let mut end = 0usize;
        for table in order {
            let shape = shapes[table.index()];
            let start = end.checked_next_multiple_of(shape.align)?;
            offsets[table.index()] = start;
            end = capacity
                .rows(table)
                .checked_mul(shape.bytes)
                .and_then(|bytes| start.checked_add(bytes))?;
        }
        let align = shapes.iter().map(|shape| shape.align).max().unwrap_or(1);
        Some(Self {
            offsets,
            bytes: end,
            align,
        })
    }

    /// Where `table` starts.
    #[must_use]
    pub const fn offset(&self, table: Table) -> usize {
        self.offsets[table.index()]
    }

    /// The slot's length: every table's capacity times its row size, summed.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// The alignment the slot's base needs.
    #[must_use]
    pub const fn align(&self) -> usize {
        self.align
    }
}
