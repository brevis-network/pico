use super::{
    IndexedPicoIterator, IntoPicoIterator, IntoPicoRefIterator, IntoPicoRefMutIterator, PicoBridge,
    PicoExtend, PicoIterator, PicoScanIterator, PicoSlice, PicoSliceMut,
};
//use alloc::sync::Arc;
use rayon::prelude::*;

impl<I: ParallelIterator> PicoIterator for I {}
impl<I: ParallelIterator> PicoScanIterator for I {}
impl<I: IndexedParallelIterator> IndexedPicoIterator for I {}
impl<I: ParallelBridge> PicoBridge for I {}
impl<I: ?Sized + ParallelSlice<T>, T: Sync> PicoSlice<T> for I {}
impl<I: ?Sized + ParallelSliceMut<T>, T: Send> PicoSliceMut<T> for I {}
impl<T: Send, V: ParallelExtend<T>> PicoExtend<T> for V {}

impl<I: IntoParallelIterator> IntoPicoIterator for I {
    type Iterator = I::Iter;
    type Item = I::Item;

    fn into_pico_iter(self) -> Self::Iterator {
        self.into_par_iter()
    }
}

impl<'a, I: ?Sized + IntoParallelRefIterator<'a>> IntoPicoRefIterator<'a> for I {
    type Iterator = I::Iter;
    type Item = I::Item;

    fn pico_iter(&'a self) -> Self::Iterator {
        self.par_iter()
    }
}

impl<'a, I: ?Sized + IntoParallelRefMutIterator<'a>> IntoPicoRefMutIterator<'a> for I {
    type Iterator = I::Iter;
    type Item = I::Item;

    fn pico_iter_mut(&'a mut self) -> Self::Iterator {
        self.par_iter_mut()
    }
}
