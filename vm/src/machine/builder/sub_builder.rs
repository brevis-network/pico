//! A builder that presents a column range of the parent's main window as the whole main window,
//! so a sub-AIR (gadget) can be evaluated in place inside a bigger chip.

use std::ops::Range;

use p3_air::{AirBuilder, BaseAir, WindowAccess};

/// A column window of a parent window.
pub struct SubWindow<W, T> {
    inner: W,
    column_range: Range<usize>,
    _phantom: std::marker::PhantomData<T>,
}

impl<W: Clone, T> Clone for SubWindow<W, T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            column_range: self.column_range.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<W, T> SubWindow<W, T> {
    #[must_use]
    pub const fn new(inner: W, column_range: Range<usize>) -> Self {
        Self {
            inner,
            column_range,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<W: WindowAccess<T>, T> WindowAccess<T> for SubWindow<W, T> {
    #[inline]
    fn current_slice(&self) -> &[T] {
        &self.inner.current_slice()[self.column_range.clone()]
    }

    #[inline]
    fn next_slice(&self) -> &[T] {
        &self.inner.next_slice()[self.column_range.clone()]
    }
}

pub struct SubAirBuilder<'a, AB: AirBuilder, SubAir: BaseAir<T>, T> {
    inner: &'a mut AB,
    column_range: Range<usize>,
    _phantom: std::marker::PhantomData<(SubAir, T)>,
}

impl<'a, AB: AirBuilder, SubAir: BaseAir<T>, T> SubAirBuilder<'a, AB, SubAir, T> {
    #[must_use]
    pub fn new(inner: &'a mut AB, column_range: Range<usize>) -> Self {
        Self {
            inner,
            column_range,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<AB: AirBuilder, SubAir: BaseAir<F>, F> AirBuilder for SubAirBuilder<'_, AB, SubAir, F> {
    type F = AB::F;
    type Expr = AB::Expr;
    type Var = AB::Var;
    type PreprocessedWindow = AB::PreprocessedWindow;
    type MainWindow = SubWindow<AB::MainWindow, Self::Var>;
    type PublicVar = AB::PublicVar;

    fn main(&self) -> Self::MainWindow {
        SubWindow::new(self.inner.main(), self.column_range.clone())
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        self.inner.preprocessed()
    }

    fn is_first_row(&self) -> Self::Expr {
        self.inner.is_first_row()
    }

    fn is_last_row(&self) -> Self::Expr {
        self.inner.is_last_row()
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        self.inner.is_transition_window(size)
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.inner.assert_zero(x.into());
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        self.inner.public_values()
    }
}
