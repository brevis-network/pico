# New Range Check Chip 

The main idea is separating the big table to small tables if could reduce the computation for the lookups.
We could check if could work with this refactor.

The main changes are:
- Move the `U8Range` and `U16Range` from core `ByteChip`
- Move the `U12Range` and `U16Range` from Recursion `RangeCheckChip`
- Combine to one Chip including `U8Range`, `U12Range` and `U16Range`
- This Chip could support the all range lookups for both RiscV and Recursion.

## Implement `RangeCheckChip`

### Add a trait function to `RecordBehavior`

- Add a new function to return the all range check events for record.

```
pub trait RecordBehavior {
...
// Get the events from byte_lookups from EmulationRecord,
// and recursion record already has the events.
fn range_check_events() -> Vec<RangeCheckEvent>;
...
}
```

### Range check opcode definition

- We could support U8, U12 and U16 lookups.
- U8 and U16 are used for RiscV.
- U12 and U16 are used for Recursion.
- We could use the same chip for the above both cases, since both need the maximum U16 lookups.

```
/// The number of range check opcodes.
pub const NUM_RANGE_CHECK_OPCODES: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RangeCheckOpcode {
    /// U8 range check
    /// The value could be looked up by U8, U12 or U16 (all).
    U8 = 0,

    /// U12 range check
    /// The value could be looked up by U12 or U16.
    U12 = 1,

    /// U16 range check
    /// The value could only be looked up by U16.
    U16 = 2,
}

impl RangeCheckOpcode {
    pub fn all() -> Vec<Self> {
        let opcodes = vec![
            RangeCheckOpcode::U8,
            RangeCheckOpcode::U12,
            RangeCheckOpcode::U16,
        ];
        assert_eq!(opcodes.len(), NUM_RANGE_CHECK_OPCODES);

        opcodes
    }

    pub fn as_field<F: Field>(self) -> F {
        F::from_canonical_u8(self as u8)
    }
}
```

### Range check event definition

- Range check events are used to collect the range check operations.

```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RangeCheckEvent {
    pub opcode: RangeCheckOpcode,
    pub value: u16,
}

impl RangeCheckEvent {
    pub const fn new(opcode: RangeCheckOpcode, value: u16) -> Self {
        Self { opcode, value }
    }
}
```

### Chip Definition

- We need to make Record and Program as generic parameters.

```
/// The chip handling the all range check operations.
///
/// The chip includes a preprocessed table of all possible range check operations.
/// Other chips can do lookups of this table to range check the values.
#[derive(Clone, Copy, Debug, Default)]
pub struct RangeCheckChip<F, R, P>(PhantomData<(F, R, P)>);
```

### Column Definition

- The preprocessed columns are used for listing the all possible lookup values in preprocessing.
- The Multi columns are used for the main trace lookups.

```
pub const NUM_ROWS: usize = 1 << 16;
pub const NUM_RANGE_CHECK_PREPROCESSED_COLS: usize = size_of::<RangeCheckPreprocessedCols<u8>>();
pub const NUM_RANGE_CHECK_MULT_COLS: usize = size_of::<RangeCheckMultCols<u8>>();

#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct RangeCheckPreprocessedCols<T> {
    /// Range check opcode
    pub opcode: T,

    /// The lookup value
    pub value: T,
}

#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct RangeCheckMultCols<T> {
    /// The multiplicites of each range check opcode.
    pub multiplicities: [T; NUM_RANGE_CHECK_OPCODES],
}
```

### Implement `ChipBehavor`

- Implement `ChipBehavor` for preprocessed and main traces generation.

```
impl<F: Field, R: RecordBehavior, P: ProgramBehavior<F>> ChipBehavior<F>
    for RangeCheckChip<F, R, P>
{
    type Record = R;
    type Program = P;

    fn name(&self) -> String {
        "RangeCheck".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_RANGE_CHECK_PREPROCESSED_COLS
    }

    fn generate_preprocessed(&self, _: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let (trace, _) = Self::trace_and_map();

        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let (_, event_map) = Self::trace_and_map();

        let mut trace = RowMajorMatrix::new(
            vec![F::ZERO; NUM_RANGE_CHECK_MULT_COLS * NUM_ROWS],
            NUM_RANGE_CHECK_MULT_COLS,
        );

        for (lookup, mult) in input.range_check_events.iter() {
            let (row, index) = event_map[lookup];
            let cols: &mut RangeCheckMultCols<F> = trace.row_mut(row).borrow_mut();

            // Update the multiplicity.
            cols.multiplicities[index] += F::from_canonical_usize(*mult);
        }

        trace
    }

    fn is_active(&self, _: &Self::Record) -> bool {
        true
    }
}

impl<F: Field, R, P> RangeCheckChip<F, R, P> {
    pub fn trace_and_map() -> (RowMajorMatrix<F>, HashMap<RangeCheckEvent, (usize, usize)>) {
        let mut events = HashMap::new();

        // The trace is initialized with the all zeros.
        let mut trace = RowMajorMatrix::new(
            vec![F::ZERO; NUM_ROWS * NUM_RANGE_CHECK_PREPROCESSED_COLS],
            NUM_RANGE_CHECK_PREPROCESSED_COLS,
        );

        // Iterate over U8 values.
        (0..=u8::MAX).for_each(|i| {
            let col: &mut RangeCheckPreprocessedCols<F> = trace.row_mut(i as usize).borrow_mut();

            col.opcode = F::from_canonical_u8(RangeCheckOpcode::U8 as u8);
            col.value = F::from_canonical_u8(i);

            let event = RangeCheckEvent::new(RangeCheckOpcode::U8, i as u16);

            // i is the row index, and U8 is the column index.
            events.insert(event, (i as usize, RangeCheckOpcode::U8 as usize));
        });

        // Iterate over U12 values.
        let u12_start = u8::MAX as u16 + 1;
        let u16_start = 1 << 12;
        (0..=u12_start).for_each(|i| {
            let col: &mut RangeCheckPreprocessedCols<F> = trace.row_mut(i as usize).borrow_mut();

            col.opcode = F::from_canonical_u8(RangeCheckOpcode::U12 as u8);
            col.value = F::from_canonical_u16(i);

            let event = RangeCheckEvent::new(RangeCheckOpcode::U12, i);

            // i is the row index, and U12 is the column index.
            events.insert(event, (i as usize, RangeCheckOpcode::U12 as usize));
        });

        // Iterate over U16 values.
        (u16_start..=u16::MAX).for_each(|i| {
            let col: &mut RangeCheckPreprocessedCols<F> = trace.row_mut(i as usize).borrow_mut();

            col.opcode = F::from_canonical_u8(RangeCheckOpcode::U16 as u8);
            col.value = F::from_canonical_u16(i);

            let event = RangeCheckEvent::new(RangeCheckOpcode::U16, i);

            // i is the row index, and U12 is the column index.
            events.insert(event, (i as usize, RangeCheckOpcode::U12 as usize));
        });

        (trace, events)
    }
}
```

### Implement constraints

- Implement the constraints for this chip.
- TODO: We need to check the degree, otherwise this chip could be separated to two chips (one is similar as the current range check chip in Recursion).

```
impl<F: Field, R: RecordBehavior, P: ProgramBehavior<F>> BaseAir<F> for RangeCheckChip<F, R, P> {
    fn width(&self) -> usize {
        NUM_RANGE_CHECK_MULT_COLS
    }
}

impl<F: Field, R: RecordBehavior, P: ProgramBehavior<F>, AB: ChipBuilder<F>> Air<AB>
    for RangeCheckChip<F, R, P>
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local_mult = main.row_slice(0);
        let local_mult: &RangeCheckMultCols<AB::Var> = (*local_mult).borrow();

        let prep = builder.preprocessed();
        let prep = prep.row_slice(0);
        let local: &RangeCheckPreprocessedCols<AB::Var> = (*prep).borrow();

        let [op_u12, op_u16] =
            [RangeCheckOpcode::U12, RangeCheckOpcode::U16].map(|op| op.as_field::<AB::F>());

        // Send all the lookups.
        for (i, opcode) in RangeCheckOpcode::all().iter().enumerate() {
            let field_op = opcode.as_field::<AB::F>();
            let mult = local_mult.multiplicities[i];

            match opcode {
                RangeCheckOpcode::U12 => {
                    // TODO: Test to check if has degree error, otherwise add a new column.
                    let condition = (local.opcode - op_u12) * (local.opcode - op_u16);
                    // Multi must be zero if opcode is U8.
                    builder.when(condition).assert_zero(mult);
                }
                RangeCheckOpcode::U16 => {
                    let condition = local.opcode - op_u16;
                    // Multi must be zero if opcode is U8 or U12.
                    builder.when(condition).assert_zero(mult);
                }
                // No check for U8.
                _ => (),
            }
            // Ensure that all U12 range check lookups are not outside the U12 range.
            if *opcode == RangeCheckOpcode::U12 {}

            builder.looked_range_check(field_op, local.value, mult);
        }
    }
}
```

## Use new range check chip

TODO: Check if need more details.

- Delete `U8Range` and `U16Range` from the RiscV byte lookup chip.
- Delete the Recursion range check chip.
- Replace the `looking_byte` and `looked_byte` (with `U8Range` and `U16Range`).
- Replace the `recursion_looking_range_check` and `recursion_looked_range_check`.

## Test with machines

TODO: Check if need more details.

- Add this `RangeCheckChip` to machines and run the tests to check the performance.
