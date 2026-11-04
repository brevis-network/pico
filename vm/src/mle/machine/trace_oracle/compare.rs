//! One air's device trace against the host's, and the verdict over a chunk's airs.
//!
//! Cells are raw words (`PrimeField32::to_unique_u32`), so a poisoned or uninitialised device cell
//! never reads as a field element some host cell happens to hold. A trace is cut into units: a
//! row, or one slot of an air that packs several events per row. An air's [`AirPolicy`] says how
//! its units may be arranged and which of them are padding:
//!
//! - [`Order::InOrder`]: unit `i` of the device is unit `i` of the host, real or padding alike.
//! - [`Order::Multiset`]: the real units are equal as a multiset; positions are free.
//! - A unit is real iff one of the policy's flag columns is nonzero ([`Padding::Flags`]), or every
//!   unit is real ([`Padding::None`]): the air's rows are compared cell for cell.
//! - Padding units are padding on both sides, all one unit on each side, and that unit is the
//!   host's but for the policy's `free_on_padding` columns, none by default: padding rows still
//!   satisfy the constraints (a dummy curve point, a zero-state permutation, an operation's template
//!   row) and carry running totals a later row or a public value reads.
//!
//! Each side counts its real units with the same classifier, so a classifier that took every unit
//! for padding would agree with itself and compare nothing. The count is therefore also held to a
//! census taken off the record, not the traces ([`compare_air`]'s `census`), and an air classified
//! by flags without one fails. [`ChunkVerdict`] refuses a chunk where no air was compared, and one
//! where an air the caller asked for has no real unit.
//!
//! No crate types: the parent module holds the per-air table and the device glue, so this file
//! builds and tests on its own.

use std::{collections::BTreeMap, fmt};

/// How an air's units may be arranged on the device relative to the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Order {
    /// Unit `i` is unit `i` on both sides: the air constrains its row chain, stores prefixes a
    /// later row reads, or is a table read at its index.
    InOrder,
    /// The real units are equal as a multiset: every constraint is local to a unit and every
    /// interaction is a multiset argument, so a kernel may emit them in any order.
    Multiset,
}

/// What a unit is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    Row,
    /// One of the `width / slot` slots of a row, each holding one event.
    Slot(usize),
}

/// What makes a unit padding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Padding {
    /// No unit is padding: every cell is compared at its position.
    None,
    /// A unit is real iff one of these unit-relative columns is nonzero: the air's `is_real`, or
    /// the opcode flags whose sum is its `is_real`.
    Flags(Vec<usize>),
}

/// One air's comparison rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AirPolicy {
    pub order: Order,
    pub unit: Unit,
    pub padding: Padding,
    /// Unit-relative columns a device padding unit may hold other values in than the host's.
    pub free_on_padding: Vec<usize>,
    /// For an air without padding flags: the columns that tell a real unit when the device
    /// generates the air and the host does not. Empty means the oracle cannot tell, and such an
    /// air fails.
    pub device_only_flags: Vec<usize>,
}

/// One trace as raw words, row-major.
#[derive(Clone, Copy, Debug)]
pub struct Trace<'a> {
    pub cells: &'a [u32],
    pub width: usize,
}

impl Trace<'_> {
    pub fn height(&self) -> usize {
        self.cells.len().checked_div(self.width).unwrap_or(0)
    }
}

/// What one air's comparison found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AirReport {
    pub height: usize,
    pub width: usize,
    pub units: usize,
    pub real: usize,
    /// Cell for cell equal, padding included. A multiset air can pass without it.
    pub identical: bool,
}

/// Why one air's device trace is not the host's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Divergence {
    Dimensions {
        device: (usize, usize),
        host: (usize, usize),
    },
    /// The width is not a whole number of units.
    Unit {
        width: usize,
        unit: usize,
    },
    /// The air is classified by flags and nothing said how many real units it has.
    NoCensus,
    Census {
        expected: usize,
        host: usize,
    },
    RealCount {
        device: usize,
        host: usize,
    },
    /// In order, unit `unit` is real on one side and padding on the other.
    Misplaced {
        unit: usize,
        device_real: bool,
    },
    Cell {
        unit: usize,
        column: usize,
        device: u32,
        host: u32,
    },
    /// A padding unit's column the policy does not free.
    PaddingCell {
        unit: usize,
        column: usize,
        device: u32,
        host: u32,
    },
    /// A padding unit unlike the side's first padding unit.
    PaddingNotUniform {
        device: bool,
        unit: usize,
    },
    /// The real units differ as multisets: the first unit, by sort order, that only one side has.
    Multiset {
        device_only: Option<(usize, Vec<u32>)>,
        host_only: Option<(usize, Vec<u32>)>,
    },
    /// An air only the device generated holds a real unit.
    DeviceOnlyReal {
        unit: usize,
    },
    /// An air only the device generated, with nothing that tells its real units from padding.
    DeviceOnlyUnclassified,
    PublicValues,
    /// The oracle has no rule for the air.
    NoPolicy,
}

impl fmt::Display for Divergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dimensions { device, host } => write!(
                f,
                "device trace is {}x{}, host trace {}x{}",
                device.0, device.1, host.0, host.1
            ),
            Self::Unit { width, unit } => {
                write!(
                    f,
                    "width {width} is not a whole number of {unit}-cell units"
                )
            }
            Self::NoCensus => write!(
                f,
                "classified by flags with no census of its real units: the comparison could be \
                 vacuous"
            ),
            Self::Census { expected, host } => write!(
                f,
                "the host trace holds {host} real units, the record's census {expected}: the \
                 padding classifier is wrong"
            ),
            Self::RealCount { device, host } => {
                write!(f, "{device} real units on the device, {host} on the host")
            }
            Self::Misplaced { unit, device_real } => write!(
                f,
                "unit {unit} is {} on the device and {} on the host",
                if *device_real { "real" } else { "padding" },
                if *device_real { "padding" } else { "real" },
            ),
            Self::Cell {
                unit,
                column,
                device,
                host,
            } => write!(
                f,
                "real unit {unit}, column {column}: device {device:#010x}, host {host:#010x}"
            ),
            Self::PaddingCell {
                unit,
                column,
                device,
                host,
            } => write!(
                f,
                "padding unit {unit}, column {column}: device {device:#010x}, host {host:#010x}"
            ),
            Self::PaddingNotUniform { device, unit } => write!(
                f,
                "{} padding unit {unit} differs from that side's first padding unit",
                if *device { "device" } else { "host" }
            ),
            Self::Multiset {
                device_only,
                host_only,
            } => {
                write!(f, "real units differ as multisets")?;
                if let Some((unit, cells)) = device_only {
                    write!(f, "; device-only unit {unit}: {cells:x?}")?;
                }
                if let Some((unit, cells)) = host_only {
                    write!(f, "; host-only unit {unit}: {cells:x?}")?;
                }
                Ok(())
            }
            Self::DeviceOnlyReal { unit } => write!(
                f,
                "the host generates no trace for this air, and device unit {unit} is real"
            ),
            Self::DeviceOnlyUnclassified => write!(
                f,
                "the host generates no trace for this air, and nothing tells its real units"
            ),
            Self::PublicValues => write!(f, "public values differ"),
            Self::NoPolicy => write!(f, "no rule for this air"),
        }
    }
}

fn unit_width(policy: &AirPolicy, width: usize) -> Result<usize, Divergence> {
    let unit = match policy.unit {
        Unit::Row => width,
        Unit::Slot(slot) => slot,
    };
    if unit == 0 || !width.is_multiple_of(unit) {
        return Err(Divergence::Unit { width, unit });
    }
    Ok(unit)
}

fn is_real(padding: &Padding, unit: &[u32]) -> bool {
    match padding {
        Padding::None => true,
        Padding::Flags(columns) => columns.iter().any(|&c| unit[c] != 0),
    }
}

fn first_padding_mismatch<'a>(
    units: impl Iterator<Item = (usize, &'a [u32])>,
    real: &[bool],
) -> Option<usize> {
    let mut first: Option<&[u32]> = None;
    for (i, unit) in units {
        if real[i] {
            continue;
        }
        match first {
            None => first = Some(unit),
            Some(f) if f != unit => return Some(i),
            Some(_) => {}
        }
    }
    None
}

fn first_padding_cell_mismatch(free: &[usize], device: &[u32], host: &[u32]) -> Option<usize> {
    (0..device.len()).find(|&c| device[c] != host[c] && !free.contains(&c))
}

/// Compare one air's device trace with the host's under `policy`.
///
/// `census` is how many real units the record says the air has, counted without either trace:
/// required when the policy classifies by flags, ignored otherwise.
pub fn compare_air(
    policy: &AirPolicy,
    device: Trace<'_>,
    host: Trace<'_>,
    census: Option<usize>,
) -> Result<AirReport, Divergence> {
    let (h, w) = (host.height(), host.width);
    if (device.height(), device.width) != (h, w) || device.cells.len() != host.cells.len() {
        return Err(Divergence::Dimensions {
            device: (device.height(), device.width),
            host: (h, w),
        });
    }
    let uw = unit_width(policy, w)?;
    let units = host.cells.len() / uw;
    let device_units = || device.cells.chunks_exact(uw).enumerate();
    let host_units = || host.cells.chunks_exact(uw).enumerate();
    let device_real: Vec<bool> = device_units()
        .map(|(_, u)| is_real(&policy.padding, u))
        .collect();
    let host_real: Vec<bool> = host_units()
        .map(|(_, u)| is_real(&policy.padding, u))
        .collect();
    let real = host_real.iter().filter(|&&r| r).count();
    let device_count = device_real.iter().filter(|&&r| r).count();

    if let Padding::Flags(_) = policy.padding {
        let expected = census.ok_or(Divergence::NoCensus)?;
        if expected != real {
            return Err(Divergence::Census {
                expected,
                host: real,
            });
        }
    }
    if device_count != real {
        return Err(Divergence::RealCount {
            device: device_count,
            host: real,
        });
    }
    if let Some(unit) = first_padding_mismatch(device_units(), &device_real) {
        return Err(Divergence::PaddingNotUniform { device: true, unit });
    }
    if let Some(unit) = first_padding_mismatch(host_units(), &host_real) {
        return Err(Divergence::PaddingNotUniform {
            device: false,
            unit,
        });
    }

    let identical = device.cells == host.cells;
    if !identical {
        match policy.order {
            Order::InOrder => compare_in_order(policy, uw, device, host, &device_real, &host_real)?,
            Order::Multiset => {
                compare_multiset(policy, uw, device, host, &device_real, &host_real)?
            }
        }
    }
    Ok(AirReport {
        height: h,
        width: w,
        units,
        real,
        identical,
    })
}

fn compare_in_order(
    policy: &AirPolicy,
    uw: usize,
    device: Trace<'_>,
    host: Trace<'_>,
    device_real: &[bool],
    host_real: &[bool],
) -> Result<(), Divergence> {
    let pairs = device
        .cells
        .chunks_exact(uw)
        .zip(host.cells.chunks_exact(uw))
        .enumerate();
    for (unit, (d, h)) in pairs {
        if device_real[unit] != host_real[unit] {
            return Err(Divergence::Misplaced {
                unit,
                device_real: device_real[unit],
            });
        }
        if host_real[unit] {
            if let Some(column) = (0..uw).find(|&c| d[c] != h[c]) {
                return Err(Divergence::Cell {
                    unit,
                    column,
                    device: d[column],
                    host: h[column],
                });
            }
        } else if let Some(column) = first_padding_cell_mismatch(&policy.free_on_padding, d, h) {
            return Err(Divergence::PaddingCell {
                unit,
                column,
                device: d[column],
                host: h[column],
            });
        }
    }
    Ok(())
}

fn compare_multiset(
    policy: &AirPolicy,
    uw: usize,
    device: Trace<'_>,
    host: Trace<'_>,
    device_real: &[bool],
    host_real: &[bool],
) -> Result<(), Divergence> {
    let unit = |cells: &[u32], i: usize| -> Vec<u32> { cells[i * uw..(i + 1) * uw].to_vec() };
    let sorted = |cells: &'_ [u32], real: &[bool]| {
        let mut indices: Vec<usize> = (0..real.len()).filter(|&i| real[i]).collect();
        indices.sort_by(|&a, &b| cells[a * uw..(a + 1) * uw].cmp(&cells[b * uw..(b + 1) * uw]));
        indices
    };
    let (d, h) = (
        sorted(device.cells, device_real),
        sorted(host.cells, host_real),
    );
    let (mut i, mut j) = (0, 0);
    let (mut device_only, mut host_only) = (None, None);
    while (i < d.len() || j < h.len()) && (device_only.is_none() || host_only.is_none()) {
        let order = match (d.get(i), h.get(j)) {
            (Some(&a), Some(&b)) => unit(device.cells, a).cmp(&unit(host.cells, b)),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => break,
        };
        match order {
            std::cmp::Ordering::Equal => {
                i += 1;
                j += 1;
            }
            std::cmp::Ordering::Less => {
                device_only.get_or_insert((d[i], unit(device.cells, d[i])));
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                host_only.get_or_insert((h[j], unit(host.cells, h[j])));
                j += 1;
            }
        }
    }
    if device_only.is_some() || host_only.is_some() {
        return Err(Divergence::Multiset {
            device_only,
            host_only,
        });
    }
    // Padding is uniform on each side, so one pair of padding units stands for all of them.
    let first_padding = |cells: &'_ [u32], real: &[bool]| {
        (0..real.len())
            .find(|&i| !real[i])
            .map(|i| (i, unit(cells, i)))
    };
    if let (Some((at, device_padding)), Some((_, host_padding))) = (
        first_padding(device.cells, device_real),
        first_padding(host.cells, host_real),
    ) {
        if let Some(column) =
            first_padding_cell_mismatch(&policy.free_on_padding, &device_padding, &host_padding)
        {
            return Err(Divergence::PaddingCell {
                unit: at,
                column,
                device: device_padding[column],
                host: host_padding[column],
            });
        }
    }
    Ok(())
}

/// Check an air the device generated and the host did not: every unit must be padding by the air's
/// flags, or by its `device_only_flags` when it has none, and the padding uniform.
pub fn check_device_only(policy: &AirPolicy, device: Trace<'_>) -> Result<AirReport, Divergence> {
    let uw = unit_width(policy, device.width)?;
    let units = device.cells.len() / uw;
    let flags = match &policy.padding {
        Padding::Flags(flags) => Padding::Flags(flags.clone()),
        Padding::None if !policy.device_only_flags.is_empty() => {
            Padding::Flags(policy.device_only_flags.clone())
        }
        Padding::None => return Err(Divergence::DeviceOnlyUnclassified),
    };
    let real: Vec<bool> = device
        .cells
        .chunks_exact(uw)
        .map(|u| is_real(&flags, u))
        .collect();
    if let Some(unit) = real.iter().position(|&r| r) {
        return Err(Divergence::DeviceOnlyReal { unit });
    }
    if let Some(unit) = first_padding_mismatch(device.cells.chunks_exact(uw).enumerate(), &real) {
        return Err(Divergence::PaddingNotUniform { device: true, unit });
    }
    Ok(AirReport {
        height: device.height(),
        width: device.width,
        units,
        real: 0,
        identical: false,
    })
}

/// Why a chunk fails the oracle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChunkFailure {
    /// An air's comparison failed.
    Air { air: usize, divergence: Divergence },
    /// The host generated a trace for an air the device did not.
    MissingOnDevice { air: usize },
    /// The caller asked for an air neither side generated.
    NotGenerated { air: usize },
    /// The caller asked for an air this chunk holds no real unit of: the chunk does not exercise
    /// it, so a pass would say nothing about it.
    NotExercised { air: usize },
    /// The air's chip reads the history and has real units, and no history kernel of it was
    /// launched for the chunk: its trace came from somewhere else.
    NoHistoryLaunch { air: usize },
    /// No air was compared at all.
    Empty,
}

impl ChunkFailure {
    pub fn air(&self) -> Option<usize> {
        match self {
            Self::Air { air, .. }
            | Self::MissingOnDevice { air }
            | Self::NotGenerated { air }
            | Self::NotExercised { air }
            | Self::NoHistoryLaunch { air } => Some(*air),
            Self::Empty => None,
        }
    }
}

impl fmt::Display for ChunkFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Air { air, divergence } => write!(f, "air {air}: {divergence}"),
            Self::MissingOnDevice { air } => {
                write!(f, "air {air}: the host generated it and the device did not")
            }
            Self::NotGenerated { air } => write!(f, "air {air}: asked for, generated by neither"),
            Self::NotExercised { air } => write!(
                f,
                "air {air}: asked for, and the chunk holds no real unit of it"
            ),
            Self::NoHistoryLaunch { air } => write!(
                f,
                "air {air}: reads the history, and no history kernel of it was launched"
            ),
            Self::Empty => write!(f, "no air compared"),
        }
    }
}

/// One chunk's per-air reports, keyed by air id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChunkVerdict {
    pub compared: BTreeMap<usize, AirReport>,
    pub device_only: BTreeMap<usize, AirReport>,
    pub failures: Vec<ChunkFailure>,
}

impl ChunkVerdict {
    pub fn record(&mut self, air: usize, result: Result<AirReport, Divergence>) {
        match result {
            Ok(report) => {
                self.compared.insert(air, report);
            }
            Err(divergence) => self.failures.push(ChunkFailure::Air { air, divergence }),
        }
    }

    pub fn record_device_only(&mut self, air: usize, result: Result<AirReport, Divergence>) {
        match result {
            Ok(report) => {
                self.device_only.insert(air, report);
            }
            Err(divergence) => self.failures.push(ChunkFailure::Air { air, divergence }),
        }
    }

    pub fn missing_on_device(&mut self, air: usize) {
        self.failures.push(ChunkFailure::MissingOnDevice { air });
    }

    /// The verdict: every failure recorded, plus a vacuous chunk and every air in `required` that
    /// was not compared with a real unit.
    pub fn finish(mut self, required: &[usize]) -> Result<Self, Vec<ChunkFailure>> {
        if self.compared.is_empty() && self.failures.is_empty() {
            self.failures.push(ChunkFailure::Empty);
        }
        for &air in required {
            let failed = self.failures.iter().any(|f| match f {
                ChunkFailure::Air { air: a, .. } | ChunkFailure::MissingOnDevice { air: a } => {
                    *a == air
                }
                _ => false,
            });
            if failed {
                continue;
            }
            match self.compared.get(&air) {
                Some(report) if report.real > 0 => {}
                Some(_) => self.failures.push(ChunkFailure::NotExercised { air }),
                None if self.device_only.contains_key(&air) => {
                    self.failures.push(ChunkFailure::NotExercised { air })
                }
                None => self.failures.push(ChunkFailure::NotGenerated { air }),
            }
        }
        if self.failures.is_empty() {
            Ok(self)
        } else {
            Err(self.failures)
        }
    }
}

/// The byte a poisoned history region is filled with. `0xffffffff` is no canonical KoalaBear word
/// and no plausible history field, so a reader of poison cannot reproduce the host's trace.
pub const POISON_BYTE: u8 = 0xff;

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(columns: &[usize], order: Order, unit: Unit) -> AirPolicy {
        AirPolicy {
            order,
            unit,
            padding: Padding::Flags(columns.to_vec()),
            free_on_padding: Vec::new(),
            device_only_flags: Vec::new(),
        }
    }

    fn exact() -> AirPolicy {
        AirPolicy {
            order: Order::InOrder,
            unit: Unit::Row,
            padding: Padding::None,
            free_on_padding: Vec::new(),
            device_only_flags: Vec::new(),
        }
    }

    fn trace(cells: &[u32], width: usize) -> Trace<'_> {
        Trace { cells, width }
    }

    // Rows of width 3, the flag in column 2.
    const HOST: [u32; 12] = [1, 2, 1, 3, 4, 1, 0, 0, 0, 0, 0, 0];

    #[test]
    fn an_identical_trace_passes_and_counts_its_real_units() {
        let policy = flags(&[2], Order::InOrder, Unit::Row);
        let report = compare_air(&policy, trace(&HOST, 3), trace(&HOST, 3), Some(2)).unwrap();
        assert_eq!(
            report,
            AirReport {
                height: 4,
                width: 3,
                units: 4,
                real: 2,
                identical: true
            }
        );
    }

    #[test]
    fn flags_without_a_census_fail() {
        let policy = flags(&[2], Order::InOrder, Unit::Row);
        assert_eq!(
            compare_air(&policy, trace(&HOST, 3), trace(&HOST, 3), None),
            Err(Divergence::NoCensus)
        );
    }

    #[test]
    fn a_classifier_that_sees_only_padding_fails_its_census() {
        // Column 0 is zero on every row, so this classifier finds no real unit on either side.
        let host = [0, 2, 1, 0, 4, 1, 0, 0, 0, 0, 0, 0];
        let policy = flags(&[0], Order::Multiset, Unit::Row);
        assert_eq!(
            compare_air(&policy, trace(&host, 3), trace(&host, 3), Some(2)),
            Err(Divergence::Census {
                expected: 2,
                host: 0
            })
        );
    }

    #[test]
    fn in_order_refuses_a_permutation_and_multiset_accepts_it() {
        let host = [1, 2, 1, 1, 3, 4, 0, 0, 0, 0, 0, 0];
        let device = [1, 3, 4, 1, 2, 1, 0, 0, 0, 0, 0, 0];
        let in_order = flags(&[0], Order::InOrder, Unit::Row);
        assert_eq!(
            compare_air(&in_order, trace(&device, 3), trace(&host, 3), Some(2)),
            Err(Divergence::Cell {
                unit: 0,
                column: 1,
                device: 3,
                host: 2
            })
        );
        let multiset = flags(&[0], Order::Multiset, Unit::Row);
        let report = compare_air(&multiset, trace(&device, 3), trace(&host, 3), Some(2)).unwrap();
        assert!(!report.identical);
        assert_eq!(report.real, 2);
    }

    #[test]
    fn a_changed_real_unit_fails_a_multiset_air() {
        let mut device = HOST;
        device[4] = 5;
        let policy = flags(&[2], Order::Multiset, Unit::Row);
        let err = compare_air(&policy, trace(&device, 3), trace(&HOST, 3), Some(2)).unwrap_err();
        assert_eq!(
            err,
            Divergence::Multiset {
                device_only: Some((1, vec![3, 5, 1])),
                host_only: Some((1, vec![3, 4, 1])),
            }
        );
    }

    #[test]
    fn padding_must_be_padding_uniform_and_the_hosts() {
        let mut device = HOST;
        device[6] = 9;
        device[9] = 9;
        let mut policy = flags(&[2], Order::InOrder, Unit::Row);
        assert_eq!(
            compare_air(&policy, trace(&device, 3), trace(&HOST, 3), Some(2)),
            Err(Divergence::PaddingCell {
                unit: 2,
                column: 0,
                device: 9,
                host: 0
            })
        );
        policy.free_on_padding = vec![0];
        compare_air(&policy, trace(&device, 3), trace(&HOST, 3), Some(2)).unwrap();

        // Only one padding row changed: the device's padding is no longer one row.
        let mut ragged = HOST;
        ragged[9] = 9;
        assert_eq!(
            compare_air(&policy, trace(&ragged, 3), trace(&HOST, 3), Some(2)),
            Err(Divergence::PaddingNotUniform {
                device: true,
                unit: 3
            })
        );

        // A flag raised on a host padding row makes it a real unit the device lacks.
        let mut extra = HOST;
        extra[8] = 1;
        assert_eq!(
            compare_air(&policy, trace(&extra, 3), trace(&HOST, 3), Some(2)),
            Err(Divergence::RealCount { device: 3, host: 2 })
        );
    }

    #[test]
    fn a_free_column_is_the_only_one_padding_may_differ_in() {
        // Column 1 is a running total the last row carries.
        let host = [1, 5, 1, 1, 7, 1, 0, 7, 0, 0, 7, 0];
        let mut device = host;
        device[7] = 8;
        device[10] = 8;
        let mut policy = flags(&[2], Order::Multiset, Unit::Row);
        assert_eq!(
            compare_air(&policy, trace(&device, 3), trace(&host, 3), Some(2)),
            Err(Divergence::PaddingCell {
                unit: 2,
                column: 1,
                device: 8,
                host: 7
            })
        );
        policy.free_on_padding = vec![0];
        assert!(compare_air(&policy, trace(&device, 3), trace(&host, 3), Some(2)).is_err());
        policy.free_on_padding = vec![1];
        compare_air(&policy, trace(&device, 3), trace(&host, 3), Some(2)).unwrap();
    }

    #[test]
    fn in_order_padding_cannot_move() {
        let host = [1, 2, 1, 0, 0, 0, 1, 3, 1, 0, 0, 0];
        let device = [1, 2, 1, 1, 3, 1, 0, 0, 0, 0, 0, 0];
        let policy = flags(&[2], Order::InOrder, Unit::Row);
        assert_eq!(
            compare_air(&policy, trace(&device, 3), trace(&host, 3), Some(2)),
            Err(Divergence::Misplaced {
                unit: 1,
                device_real: true
            })
        );
    }

    #[test]
    fn slots_are_compared_as_units() {
        // Two slots of width 2 per row, the flag in slot column 0.
        let host = [1, 10, 1, 11, 1, 12, 0, 0];
        let device = [1, 12, 1, 10, 1, 11, 0, 0];
        let policy = flags(&[0], Order::Multiset, Unit::Slot(2));
        let report = compare_air(&policy, trace(&device, 4), trace(&host, 4), Some(3)).unwrap();
        assert_eq!((report.units, report.real), (4, 3));

        // As whole rows the two traces are not a permutation of each other.
        let rows = flags(&[0], Order::Multiset, Unit::Row);
        assert!(compare_air(&rows, trace(&device, 4), trace(&host, 4), Some(2)).is_err());

        assert_eq!(
            compare_air(
                &flags(&[0], Order::Multiset, Unit::Slot(3)),
                trace(&device, 4),
                trace(&host, 4),
                Some(3)
            ),
            Err(Divergence::Unit { width: 4, unit: 3 })
        );
    }

    #[test]
    fn without_flags_every_cell_counts() {
        let policy = exact();
        let mut device = HOST;
        device[11] = 1;
        assert_eq!(
            compare_air(&policy, trace(&device, 3), trace(&HOST, 3), None),
            Err(Divergence::Cell {
                unit: 3,
                column: 2,
                device: 1,
                host: 0
            })
        );
        let report = compare_air(&policy, trace(&HOST, 3), trace(&HOST, 3), None).unwrap();
        assert_eq!(report.real, 4);
    }

    #[test]
    fn dimensions_must_agree() {
        let policy = flags(&[2], Order::InOrder, Unit::Row);
        assert_eq!(
            compare_air(&policy, trace(&HOST[..9], 3), trace(&HOST, 3), Some(2)),
            Err(Divergence::Dimensions {
                device: (3, 3),
                host: (4, 3)
            })
        );
    }

    #[test]
    fn a_poisoned_device_trace_fails_every_policy() {
        let poison = [u32::from_ne_bytes([POISON_BYTE; 4]); 12];
        for order in [Order::InOrder, Order::Multiset] {
            let policy = flags(&[2], order, Unit::Row);
            assert!(compare_air(&policy, trace(&poison, 3), trace(&HOST, 3), Some(2)).is_err());
        }
        assert!(compare_air(&exact(), trace(&poison, 3), trace(&HOST, 3), None).is_err());
    }

    #[test]
    fn a_device_only_air_must_be_uniform_padding() {
        let policy = flags(&[2], Order::Multiset, Unit::Row);
        let padding = [0, 7, 0, 0, 7, 0];
        assert_eq!(
            check_device_only(&policy, trace(&padding, 3)).unwrap().real,
            0
        );
        assert_eq!(
            check_device_only(&policy, trace(&HOST, 3)),
            Err(Divergence::DeviceOnlyReal { unit: 0 })
        );
        // Without flags, nothing tells a real row from padding unless the policy names one.
        assert_eq!(
            check_device_only(&exact(), trace(&padding, 3)),
            Err(Divergence::DeviceOnlyUnclassified)
        );
        let named = AirPolicy {
            device_only_flags: vec![2],
            ..exact()
        };
        assert_eq!(
            check_device_only(&named, trace(&padding, 3)).unwrap().real,
            0
        );
        assert_eq!(
            check_device_only(&named, trace(&HOST, 3)),
            Err(Divergence::DeviceOnlyReal { unit: 0 })
        );
        assert_eq!(
            check_device_only(&named, trace(&[0, 7, 0, 0, 8, 0], 3)),
            Err(Divergence::PaddingNotUniform {
                device: true,
                unit: 1
            })
        );
    }

    fn report(real: usize) -> AirReport {
        AirReport {
            height: 4,
            width: 3,
            units: 4,
            real,
            identical: true,
        }
    }

    #[test]
    fn a_chunk_with_nothing_compared_fails() {
        assert_eq!(
            ChunkVerdict::default().finish(&[]),
            Err(vec![ChunkFailure::Empty])
        );
    }

    #[test]
    fn a_required_air_must_be_compared_with_a_real_unit() {
        let mut verdict = ChunkVerdict::default();
        verdict.record(0, Ok(report(2)));
        verdict.record(1, Ok(report(0)));
        verdict.record_device_only(2, Ok(report(0)));
        assert!(verdict.clone().finish(&[0]).is_ok());
        assert_eq!(
            verdict.finish(&[0, 1, 2, 3]),
            Err(vec![
                ChunkFailure::NotExercised { air: 1 },
                ChunkFailure::NotExercised { air: 2 },
                ChunkFailure::NotGenerated { air: 3 },
            ])
        );
    }

    #[test]
    fn a_divergence_is_reported_once_and_not_as_unexercised() {
        let mut verdict = ChunkVerdict::default();
        verdict.record(0, Err(Divergence::PublicValues));
        verdict.missing_on_device(1);
        assert_eq!(
            verdict.finish(&[0, 1]),
            Err(vec![
                ChunkFailure::Air {
                    air: 0,
                    divergence: Divergence::PublicValues
                },
                ChunkFailure::MissingOnDevice { air: 1 },
            ])
        );
    }
}
