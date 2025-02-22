mod impls;

use rayon::{
    iter::{
        Enumerate, Filter, FilterMap, FlatMap, FlatMapIter, Flatten, Fold, IterBridge, Map, MaxLen,
        MinLen, Zip, ZipEq,
    },
    prelude::{
        FromParallelIterator, IndexedParallelIterator, IntoParallelIterator, ParallelBridge,
        ParallelExtend, ParallelIterator, ParallelSlice, ParallelSliceMut,
    },
    slice::{Chunks, ChunksExact, ChunksExactMut, ChunksMut},
};
use rayon_scan::ScanParallelIterator;

pub trait PicoIterator: ParallelIterator {
    // rename to pico_fold to deconflict with core::iter::Iterator::fold API
    fn pico_fold<T, ID, F>(self, identity: ID, fold_op: F) -> Fold<Self, ID, F>
    where
        F: Fn(T, Self::Item) -> T + Sync + Send,
        ID: Fn() -> T + Sync + Send,
        T: Send,
    {
        ParallelIterator::fold(self, identity, fold_op)
    }

    // rename to pico_reduce to deconflict with core::iter::Iterator::reduce API
    fn pico_reduce<OP, ID>(self, identity: ID, op: OP) -> Self::Item
    where
        OP: Fn(Self::Item, Self::Item) -> Self::Item + Sync + Send,
        ID: Fn() -> Self::Item + Sync + Send,
    {
        ParallelIterator::reduce(self, identity, op)
    }

    fn map<F, R>(self, map_op: F) -> Map<Self, F>
    where
        F: Fn(Self::Item) -> R + Sync + Send,
        R: Send,
    {
        ParallelIterator::map(self, map_op)
    }

    fn collect<C>(self) -> C
    where
        C: FromParallelIterator<Self::Item>,
    {
        ParallelIterator::collect(self)
    }

    fn for_each<OP>(self, op: OP)
    where
        OP: Fn(Self::Item) + Sync + Send,
    {
        ParallelIterator::for_each(self, op)
    }

    fn filter<P>(self, filter_op: P) -> Filter<Self, P>
    where
        P: Fn(&Self::Item) -> bool + Sync + Send,
    {
        ParallelIterator::filter(self, filter_op)
    }

    fn filter_map<P, R>(self, filter_op: P) -> FilterMap<Self, P>
    where
        P: Fn(Self::Item) -> Option<R> + Sync + Send,
        R: Send,
    {
        ParallelIterator::filter_map(self, filter_op)
    }

    fn flat_map<F, PI>(self, map_op: F) -> FlatMap<Self, F>
    where
        F: Fn(Self::Item) -> PI + Sync + Send,
        PI: IntoParallelIterator,
    {
        ParallelIterator::flat_map(self, map_op)
    }

    fn flat_map_iter<F, SI>(self, map_op: F) -> FlatMapIter<Self, F>
    where
        F: Fn(Self::Item) -> SI + Sync + Send,
        SI: IntoIterator,
        SI::Item: Send,
    {
        ParallelIterator::flat_map_iter(self, map_op)
    }

    fn flatten(self) -> Flatten<Self>
    where
        Self::Item: IntoParallelIterator,
    {
        ParallelIterator::flatten(self)
    }

    fn unzip<A, B, FromA, FromB>(self) -> (FromA, FromB)
    where
        Self: ParallelIterator<Item = (A, B)>,
        FromA: Default + Send + ParallelExtend<A>,
        FromB: Default + Send + ParallelExtend<B>,
        A: Send,
        B: Send,
    {
        ParallelIterator::unzip(self)
    }
}

pub trait PicoScanIterator: ParallelIterator {
    // rename to pico_scan to deconflict with core::iter::Iterator::scan
    fn pico_scan<F>(
        self,
        scan_op: F,
        identity: Self::Item,
    ) -> impl ParallelIterator<Item = Self::Item>
    where
        F: Fn(&Self::Item, &Self::Item) -> Self::Item + Sync + Send,
        Self::Item: Send + Sync,
    {
        ScanParallelIterator::scan(self, scan_op, identity)
    }
}

pub trait IndexedPicoIterator: IndexedParallelIterator {
    fn enumerate(self) -> Enumerate<Self> {
        IndexedParallelIterator::enumerate(self)
    }

    fn with_min_len(self, min: usize) -> MinLen<Self> {
        IndexedParallelIterator::with_min_len(self, min)
    }

    fn with_max_len(self, max: usize) -> MaxLen<Self> {
        IndexedParallelIterator::with_max_len(self, max)
    }

    fn zip<Z>(self, zip_op: Z) -> Zip<Self, Z::Iter>
    where
        Z: IntoParallelIterator,
        Z::Iter: IndexedParallelIterator,
    {
        IndexedParallelIterator::zip(self, zip_op)
    }

    fn zip_eq<Z>(self, zip_op: Z) -> ZipEq<Self, Z::Iter>
    where
        Z: IntoParallelIterator,
        Z::Iter: IndexedParallelIterator,
    {
        IndexedParallelIterator::zip_eq(self, zip_op)
    }

    fn collect_into_vec(self, target: &mut Vec<Self::Item>) {
        IndexedParallelIterator::collect_into_vec(self, target)
    }

    fn unzip_into_vecs<A, B>(self, left: &mut Vec<A>, right: &mut Vec<B>)
    where
        Self: IndexedParallelIterator<Item = (A, B)>,
        A: Send,
        B: Send,
    {
        IndexedParallelIterator::unzip_into_vecs(self, left, right)
    }
}

pub trait PicoBridge: ParallelBridge {
    fn pico_bridge(self) -> IterBridge<Self> {
        self.par_bridge()
    }
}

pub trait PicoSlice<T: Sync>: ParallelSlice<T> {
    fn pico_chunks(&self, chunk_size: usize) -> Chunks<'_, T> {
        self.par_chunks(chunk_size)
    }

    fn pico_chunks_exact(&self, chunk_size: usize) -> ChunksExact<'_, T> {
        self.par_chunks_exact(chunk_size)
    }
}

pub trait PicoSliceMut<T: Send>: ParallelSliceMut<T> {
    fn pico_chunks_mut(&mut self, chunk_size: usize) -> ChunksMut<'_, T> {
        self.par_chunks_mut(chunk_size)
    }

    fn pico_chunks_exact_mut(&mut self, chunk_size: usize) -> ChunksExactMut<'_, T> {
        self.par_chunks_exact_mut(chunk_size)
    }
}

pub trait PicoExtend<T: Send>: ParallelExtend<T> {
    fn pico_extend<I>(&mut self, par_iter: I)
    where
        I: IntoParallelIterator<Item = T>,
    {
        self.par_extend(par_iter)
    }
}

pub trait IntoPicoIterator {
    type Iterator: ParallelIterator<Item = Self::Item>;
    type Item;

    fn into_pico_iter(self) -> Self::Iterator;
}

pub trait IntoPicoRefIterator<'a> {
    type Iterator: ParallelIterator<Item = Self::Item>;
    type Item: 'a;

    fn pico_iter(&'a self) -> Self::Iterator;
}

pub trait IntoPicoRefMutIterator<'a> {
    type Iterator: ParallelIterator<Item = Self::Item>;
    type Item: 'a;

    fn pico_iter_mut(&'a mut self) -> Self::Iterator;
}

pub use rayon::{current_num_threads, join, ThreadPoolBuilder};
