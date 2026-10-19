use core::borrow::Borrow;

#[repr(C)]
pub struct FibonacciSelectorCols<F> {
    pub sel: F,
}

// Manual implementation of AlignedBorrow to avoid circular git import
impl<F> Borrow<FibonacciSelectorCols<F>> for [F] {
    fn borrow(&self) -> &FibonacciSelectorCols<F> {
        debug_assert_eq!(self.len(), 1);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<FibonacciSelectorCols<F>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}
