mod impls;

use core::{
    iter::{once, FlatMap, Once},
    slice::{Chunks, ChunksExact, ChunksExactMut, ChunksMut},
};
use itertools::{Itertools, ZipEq};

pub trait PicoIterator: Iterator {
    // rename to pico_fold to deconflict with core::iter::Iterator::fold API
    fn pico_fold<T, ID, F>(self, identity: ID, fold_op: F) -> Once<T>
    where
        F: Fn(T, Self::Item) -> T,
        ID: Fn() -> T,
        Self: Sized,
    {
        once(Iterator::fold(self, identity(), fold_op))
    }

    // rename to pico_reduce to deconflict with core::iter::Iterator::reduce API
    fn pico_reduce<OP, ID>(self, identity: ID, op: OP) -> Self::Item
    where
        OP: Fn(Self::Item, Self::Item) -> Self::Item,
        ID: Fn() -> Self::Item,
        Self: Sized,
    {
        Iterator::reduce(self, op).unwrap_or_else(identity)
    }

    // reduce this to flat_map
    fn flat_map_iter<F, SI>(self, map_op: F) -> FlatMap<Self, SI, F>
    where
        F: Fn(Self::Item) -> SI,
        SI: IntoIterator,
        Self: Sized,
    {
        Iterator::flat_map(self, map_op)
    }
}

//struct Scan<T> {
//    data: Vec<T>,
//    offset: usize,
//}
//
//impl<T> Iterator for Scan<T> {
//    type Item = T;
//
//    fn next(&mut self) -> Option<T> {
//        let result = self.data.get(self.offset);
//        self.offset += 1;
//        result
//    }
//}

pub trait PicoScanIterator: Iterator {
    // rename to pico_scan to deconflict with core::iter::Iterator::scan
    fn pico_scan<F>(self, scan_op: F, identity: Self::Item) -> impl Iterator<Item = Self::Item>
    where
        F: Fn(&Self::Item, &Self::Item) -> Self::Item,
        // TODO: write an impl that doesn't rely on Copy or Clone like rayon_scan, but I think this
        // requires allocating a backing buffer and then yielding elements out of that buffer, or
        // calling scan_op twice, which may be prohibitively expensive
        Self::Item: Copy,
        Self: Sized,
    {
        //let mut lhs = &identity;
        //let mut data = Vec::new();
        //for (i, rhs) in self.enumerate() {
        //    data.push(scan_op(lhs, &rhs));
        //    lhs = &data[i];
        //}
        Iterator::scan(self, identity, move |st, item| {
            let result = scan_op(st, &item);
            *st = result;
            Some(result)
        })
        //Scan {
        //    data,
        //    offset: 0,
        //}
    }
}

pub trait IndexedPicoIterator: Iterator {
    fn with_min_len(self, _min: usize) -> Self
    where
        Self: Sized,
    {
        self
    }

    fn with_max_len(self, _max: usize) -> Self
    where
        Self: Sized,
    {
        self
    }

    fn zip_eq<J>(self, other: J) -> ZipEq<Self, J::IntoIter>
    where
        J: IntoIterator,
        Self: Sized,
    {
        Itertools::zip_eq(self, other)
    }

    fn collect_into_vec(self, target: &mut Vec<Self::Item>)
    where
        Self: Sized,
    {
        target.clear();
        target.extend(self)
    }

    fn unzip_into_vecs<A, B>(self, left: &mut Vec<A>, right: &mut Vec<B>)
    where
        Self: Sized + Iterator<Item = (A, B)>,
    {
        left.clear();
        right.clear();
        for (a, b) in self {
            left.push(a);
            right.push(b);
        }
    }
}

// bridges Iterator into ParallelIterator, which is a no-op
pub trait PicoBridge {
    fn pico_bridge(self) -> Self
    where
        Self: Sized,
    {
        self
    }
}

pub trait PicoSlice<T> {
    fn pico_chunks(&self, chunk_size: usize) -> Chunks<'_, T>;
    fn pico_chunks_exact(&self, chunk_size: usize) -> ChunksExact<'_, T>;
}

pub trait PicoSliceMut<T> {
    fn pico_chunks_mut(&mut self, chunk_size: usize) -> ChunksMut<'_, T>;
    fn pico_chunks_exact_mut(&mut self, chunk_size: usize) -> ChunksExactMut<'_, T>;
}

pub trait PicoExtend<T>: Extend<T> {
    fn pico_extend<I>(&mut self, par_iter: I)
    where
        I: IntoIterator<Item = T>,
    {
        self.extend(par_iter)
    }
}

pub trait IntoPicoIterator {
    type Iterator: Iterator<Item = Self::Item>;
    type Item;

    fn into_pico_iter(self) -> Self::Iterator;
}

pub trait IntoPicoRefIterator<'a> {
    type Iterator: Iterator<Item = Self::Item>;
    type Item: 'a;

    fn pico_iter(&'a self) -> Self::Iterator;
}

pub trait IntoPicoRefMutIterator<'a> {
    type Iterator: Iterator<Item = Self::Item>;
    type Item: 'a;

    fn pico_iter_mut(&'a mut self) -> Self::Iterator;
}

// execute in serial
pub fn join<A, B, RA, RB>(oper_a: A, oper_b: B) -> (RA, RB)
where
    A: FnOnce() -> RA,
    B: FnOnce() -> RB,
{
    (oper_a(), oper_b())
}

pub struct ThreadPoolBuilder;

impl ThreadPoolBuilder {
    pub const fn new() -> Self {
        Self
    }

    pub const fn num_threads(self, _threads: usize) -> Self {
        Self
    }

    pub const fn build(self) -> Self {
        Self
    }

    pub const fn unwrap(self) -> Self {
        Self
    }

    pub fn install<T, F: FnOnce() -> T>(&self, f: F) -> T {
        f()
    }
}

pub const fn current_num_threads() -> usize {
    1
}
