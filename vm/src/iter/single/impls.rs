use super::{
    IndexedPicoIterator, IntoPicoIterator, IntoPicoRefIterator, IntoPicoRefMutIterator, PicoBridge,
    PicoExtend, PicoIterator, PicoScanIterator, PicoSlice, PicoSliceMut,
};
use core::slice::{Chunks, ChunksExact, ChunksExactMut, ChunksMut};

impl<I: Iterator> PicoIterator for I {}
impl<I: Iterator> PicoScanIterator for I {}
impl<I: Iterator> IndexedPicoIterator for I {}
impl<T> PicoBridge for T {}

impl<T, V: ?Sized + AsRef<[T]>> PicoSlice<T> for V {
    fn pico_chunks(&self, chunk_size: usize) -> Chunks<'_, T> {
        self.as_ref().chunks(chunk_size)
    }

    fn pico_chunks_exact(&self, chunk_size: usize) -> ChunksExact<'_, T> {
        self.as_ref().chunks_exact(chunk_size)
    }
}

impl<T, V: ?Sized + AsMut<[T]>> PicoSliceMut<T> for V {
    fn pico_chunks_mut(&mut self, chunk_size: usize) -> ChunksMut<'_, T> {
        self.as_mut().chunks_mut(chunk_size)
    }

    fn pico_chunks_exact_mut(&mut self, chunk_size: usize) -> ChunksExactMut<'_, T> {
        self.as_mut().chunks_exact_mut(chunk_size)
    }
}

impl<V: Extend<T>, T> PicoExtend<T> for V {}

impl<I: IntoIterator> IntoPicoIterator for I {
    type Iterator = I::IntoIter;
    type Item = I::Item;

    fn into_pico_iter(self) -> Self::Iterator {
        self.into_iter()
    }
}

impl<'a, T: 'a> IntoPicoRefIterator<'a> for Option<T> {
    type Iterator = core::option::Iter<'a, T>;
    type Item = &'a T;

    fn pico_iter(&'a self) -> Self::Iterator {
        self.iter()
    }
}

impl<'a, T: 'a, E> IntoPicoRefIterator<'a> for Result<T, E> {
    type Iterator = core::result::Iter<'a, T>;
    type Item = &'a T;

    fn pico_iter(&'a self) -> Self::Iterator {
        self.iter()
    }
}

impl<'a, T: 'a> IntoPicoRefIterator<'a> for [T] {
    type Iterator = core::slice::Iter<'a, T>;
    type Item = &'a T;

    fn pico_iter(&'a self) -> Self::Iterator {
        self.iter()
    }
}

impl<'a, T: 'a> IntoPicoRefMutIterator<'a> for Option<T> {
    type Iterator = core::option::IterMut<'a, T>;
    type Item = &'a mut T;

    fn pico_iter_mut(&'a mut self) -> Self::Iterator {
        self.iter_mut()
    }
}

impl<'a, T: 'a, E> IntoPicoRefMutIterator<'a> for Result<T, E> {
    type Iterator = core::result::IterMut<'a, T>;
    type Item = &'a mut T;

    fn pico_iter_mut(&'a mut self) -> Self::Iterator {
        self.iter_mut()
    }
}

impl<'a, T: 'a> IntoPicoRefMutIterator<'a> for [T] {
    type Iterator = core::slice::IterMut<'a, T>;
    type Item = &'a mut T;

    fn pico_iter_mut(&'a mut self) -> Self::Iterator {
        self.iter_mut()
    }
}
