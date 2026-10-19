use core::borrow::Borrow;

pub const NUM_FIBONACCI_COLS: usize = 2;

#[repr(C)]
pub struct FibonacciCols<F> {
    pub left: F,
    pub right: F,
}

impl<F> FibonacciCols<F> {
    pub const fn new(left: F, right: F) -> FibonacciCols<F> {
        FibonacciCols { left, right }
    }
}

// Manual implementation of AlignedBorrow to avoid circular git import
impl<F> Borrow<FibonacciCols<F>> for [F] {
    fn borrow(&self) -> &FibonacciCols<F> {
        debug_assert_eq!(self.len(), NUM_FIBONACCI_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<FibonacciCols<F>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}
