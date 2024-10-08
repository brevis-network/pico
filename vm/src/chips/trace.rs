use p3_field::Field;
use p3_matrix::{dense::RowMajorMatrix, Matrix};

pub trait TraceBorrow<F>
where
    F: Field,
{
    fn borrow_rows<R>(&self) -> &[R];
}

pub trait TraceBorrowMut<F>
where
    F: Field,
{
    fn borrow_rows_mut<R>(&mut self) -> &mut [R];
}

impl<F> TraceBorrow<F> for RowMajorMatrix<F>
where
    F: Field,
{
    fn borrow_rows<R>(&self) -> &[R] {
        let (prefix, rows, suffix) = unsafe { self.values.align_to::<R>() };
        assert!(prefix.is_empty(), "Alignment should match");
        assert!(suffix.is_empty(), "Alignment should match");
        assert_eq!(rows.len(), self.height());
        rows
    }
}

impl<F> TraceBorrowMut<F> for RowMajorMatrix<F>
where
    F: Field,
{
    fn borrow_rows_mut<R: Sized>(&mut self) -> &mut [R] {
        let height = self.height();
        let (prefix, rows, suffix) = unsafe { self.values.align_to_mut::<R>() };
        assert!(prefix.is_empty(), "Alignment should match");
        assert!(suffix.is_empty(), "Alignment should match");
        assert_eq!(rows.len(), height);
        rows
    }
}
