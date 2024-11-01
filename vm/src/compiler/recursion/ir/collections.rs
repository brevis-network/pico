use super::{Builder, FromConstant, MemIndex, MemVariable, Ptr, Usize, Var, Variable};
use crate::configs::config::FieldGenericConfig;
use itertools::Itertools;
use p3_field::AbstractField;

/// An array that is either of static or dynamic size.
#[derive(Debug, Clone)]
pub enum Array<FC: FieldGenericConfig, T> {
    Fixed(Vec<T>),
    Dyn(Ptr<FC::N>, Usize<FC::N>),
}

impl<FC: FieldGenericConfig, V: MemVariable<FC>> Array<FC, V> {
    /// Gets a fixed version of the array.
    pub fn vec(&self) -> Vec<V> {
        match self {
            Self::Fixed(vec) => vec.clone(),
            _ => panic!("array is dynamic, not fixed"),
        }
    }

    /// Gets the length of the array as a variable inside the DSL.
    pub fn len(&self) -> Usize<FC::N> {
        match self {
            Self::Fixed(vec) => Usize::from(vec.len()),
            Self::Dyn(_, len) => *len,
        }
    }

    /// Shifts the array by `shift` elements.
    pub fn shift(&self, builder: &mut Builder<FC>, shift: Var<FC::N>) -> Array<FC, V> {
        match self {
            Self::Fixed(_) => {
                todo!()
            }
            Self::Dyn(ptr, len) => {
                assert!(V::size_of() == 1, "only support variables of size 1");
                let new_address = builder.eval(ptr.address + shift);
                let new_ptr = Ptr::<FC::N> {
                    address: new_address,
                };
                let len_var = len.materialize(builder);
                let new_length = builder.eval(len_var - shift);
                Array::Dyn(new_ptr, Usize::Var(new_length))
            }
        }
    }

    /// Truncates the array to `len` elements.
    pub fn truncate(&self, builder: &mut Builder<FC>, len: Usize<FC::N>) {
        match self {
            Self::Fixed(_) => {
                todo!()
            }
            Self::Dyn(_, old_len) => {
                builder.assign(*old_len, len);
            }
        };
    }

    pub fn slice(
        &self,
        builder: &mut Builder<FC>,
        start: Usize<FC::N>,
        end: Usize<FC::N>,
    ) -> Array<FC, V> {
        match self {
            Self::Fixed(vec) => {
                if let (Usize::Const(start), Usize::Const(end)) = (start, end) {
                    builder.vec(vec[start..end].to_vec())
                } else {
                    panic!("Cannot slice a fixed array with a variable start or end");
                }
            }
            Self::Dyn(_, len) => {
                if builder.debug {
                    let start_v = start.materialize(builder);
                    let end_v = end.materialize(builder);
                    let valid = builder.lt(start_v, end_v);
                    builder.assert_var_eq(valid, FC::N::one());

                    let len_v = len.materialize(builder);
                    let len_plus_1_v = builder.eval(len_v + FC::N::one());
                    let valid = builder.lt(end_v, len_plus_1_v);
                    builder.assert_var_eq(valid, FC::N::one());
                }

                let slice_len: Usize<_> = builder.eval(end - start);
                let mut slice = builder.dyn_array(slice_len);
                builder.range(0, slice_len).for_each(|i, builder| {
                    let idx: Usize<_> = builder.eval(start + i);
                    let value = builder.get(self, idx);
                    builder.set(&mut slice, i, value);
                });

                slice
            }
        }
    }
}

impl<FC: FieldGenericConfig> Builder<FC> {
    /// Initialize an array of fixed length `len`. The entries will be uninitialized.
    pub fn array<V: MemVariable<FC>>(&mut self, len: impl Into<Usize<FC::N>>) -> Array<FC, V> {
        self.dyn_array(len)
    }

    /// Creates an array from a vector.
    pub fn vec<V: MemVariable<FC>>(&mut self, v: Vec<V>) -> Array<FC, V> {
        Array::Fixed(v)
    }

    /// Creates a dynamic array for a length.
    pub fn dyn_array<V: MemVariable<FC>>(&mut self, len: impl Into<Usize<FC::N>>) -> Array<FC, V> {
        let len = match len.into() {
            Usize::Const(len) => self.eval(FC::N::from_canonical_usize(len)),
            Usize::Var(len) => len,
        };
        let len = Usize::Var(len);
        let ptr = self.alloc(len, V::size_of());
        Array::Dyn(ptr, len)
    }

    pub fn get<V: MemVariable<FC>, I: Into<Usize<FC::N>>>(
        &mut self,
        slice: &Array<FC, V>,
        index: I,
    ) -> V {
        let index = index.into();

        match slice {
            Array::Fixed(slice) => {
                if let Usize::Const(idx) = index {
                    slice[idx].clone()
                } else {
                    panic!("Cannot index into a fixed slice with a variable size")
                }
            }
            Array::Dyn(ptr, len) => {
                if self.debug {
                    let index_v = index.materialize(self);
                    let len_v = len.materialize(self);
                    let valid = self.lt(index_v, len_v);
                    self.assert_var_eq(valid, FC::N::one());
                }
                let index = MemIndex {
                    index,
                    offset: 0,
                    size: V::size_of(),
                };
                let var: V = self.uninit();
                self.load(var.clone(), *ptr, index);
                var
            }
        }
    }

    pub fn get_ptr<V: MemVariable<FC>, I: Into<Usize<FC::N>>>(
        &mut self,
        slice: &Array<FC, V>,
        index: I,
    ) -> Ptr<FC::N> {
        let index = index.into();

        match slice {
            Array::Fixed(_) => {
                todo!()
            }
            Array::Dyn(ptr, len) => {
                if self.debug {
                    let index_v = index.materialize(self);
                    let len_v = len.materialize(self);
                    let valid = self.lt(index_v, len_v);
                    self.assert_var_eq(valid, FC::N::one());
                }
                let index = MemIndex {
                    index,
                    offset: 0,
                    size: V::size_of(),
                };
                let var: Ptr<FC::N> = self.uninit();
                self.load(var, *ptr, index);
                var
            }
        }
    }

    pub fn set<V: MemVariable<FC>, I: Into<Usize<FC::N>>, Expr: Into<V::Expression>>(
        &mut self,
        slice: &mut Array<FC, V>,
        index: I,
        value: Expr,
    ) {
        let index = index.into();

        match slice {
            Array::Fixed(_) => {
                todo!()
            }
            Array::Dyn(ptr, len) => {
                if self.debug {
                    let index_v = index.materialize(self);
                    let len_v = len.materialize(self);
                    let valid = self.lt(index_v, len_v);
                    self.assert_var_eq(valid, FC::N::one());
                }
                let index = MemIndex {
                    index,
                    offset: 0,
                    size: V::size_of(),
                };
                let value: V = self.eval(value);
                self.store(*ptr, index, value);
            }
        }
    }

    pub fn set_value<V: MemVariable<FC>, I: Into<Usize<FC::N>>>(
        &mut self,
        slice: &mut Array<FC, V>,
        index: I,
        value: V,
    ) {
        let index = index.into();

        match slice {
            Array::Fixed(_) => {
                todo!()
            }
            Array::Dyn(ptr, _) => {
                let index = MemIndex {
                    index,
                    offset: 0,
                    size: V::size_of(),
                };
                self.store(*ptr, index, value);
            }
        }
    }
}

impl<FC: FieldGenericConfig, T: MemVariable<FC>> Variable<FC> for Array<FC, T> {
    type Expression = Self;

    fn uninit(builder: &mut Builder<FC>) -> Self {
        Array::Dyn(builder.uninit(), builder.uninit())
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<FC>) {
        match (self, src.clone()) {
            (Array::Dyn(lhs_ptr, lhs_len), Array::Dyn(rhs_ptr, rhs_len)) => {
                builder.assign(*lhs_ptr, rhs_ptr);
                builder.assign(*lhs_len, rhs_len);
            }
            _ => unreachable!(),
        }
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<FC>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs.clone(), rhs.clone()) {
            (Array::Fixed(lhs), Array::Fixed(rhs)) => {
                for (l, r) in lhs.iter().zip_eq(rhs.iter()) {
                    T::assert_eq(
                        T::Expression::from(l.clone()),
                        T::Expression::from(r.clone()),
                        builder,
                    );
                }
            }
            (Array::Dyn(_, lhs_len), Array::Dyn(_, rhs_len)) => {
                let lhs_len_var = builder.materialize(lhs_len);
                let rhs_len_var = builder.materialize(rhs_len);
                builder.assert_eq::<Var<_>>(lhs_len_var, rhs_len_var);

                let start = Usize::Const(0);
                let end = lhs_len;
                builder.range(start, end).for_each(|i, builder| {
                    let a = builder.get(&lhs, i);
                    let b = builder.get(&rhs, i);
                    builder.assert_eq::<T>(a, b);
                });
            }
            _ => panic!("cannot compare arrays of different types"),
        }
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<FC>,
    ) {
        let lhs = lhs.into();
        let rhs = rhs.into();

        match (lhs.clone(), rhs.clone()) {
            (Array::Fixed(lhs), Array::Fixed(rhs)) => {
                for (l, r) in lhs.iter().zip_eq(rhs.iter()) {
                    T::assert_ne(
                        T::Expression::from(l.clone()),
                        T::Expression::from(r.clone()),
                        builder,
                    );
                }
            }
            (Array::Dyn(_, lhs_len), Array::Dyn(_, rhs_len)) => {
                builder.assert_usize_eq(lhs_len, rhs_len);

                let end = lhs_len;
                builder.range(0, end).for_each(|i, builder| {
                    let a = builder.get(&lhs, i);
                    let b = builder.get(&rhs, i);
                    builder.assert_ne::<T>(a, b);
                });
            }
            _ => panic!("cannot compare arrays of different types"),
        }
    }
}

impl<FC: FieldGenericConfig, T: MemVariable<FC>> MemVariable<FC> for Array<FC, T> {
    fn size_of() -> usize {
        2
    }

    fn load(&self, src: Ptr<FC::N>, index: MemIndex<FC::N>, builder: &mut Builder<FC>) {
        match self {
            Array::Dyn(dst, Usize::Var(len)) => {
                let mut index = index;
                dst.load(src, index, builder);
                index.offset += <Ptr<FC::N> as MemVariable<FC>>::size_of();
                len.load(src, index, builder);
            }
            _ => unreachable!(),
        }
    }

    fn store(
        &self,
        dst: Ptr<<FC as FieldGenericConfig>::N>,
        index: MemIndex<FC::N>,
        builder: &mut Builder<FC>,
    ) {
        match self {
            Array::Dyn(src, Usize::Var(len)) => {
                let mut index = index;
                src.store(dst, index, builder);
                index.offset += <Ptr<FC::N> as MemVariable<FC>>::size_of();
                len.store(dst, index, builder);
            }
            _ => unreachable!(),
        }
    }
}

impl<FC: FieldGenericConfig, V: FromConstant<FC> + MemVariable<FC>> FromConstant<FC>
    for Array<FC, V>
{
    type Constant = Vec<V::Constant>;

    fn constant(value: Self::Constant, builder: &mut Builder<FC>) -> Self {
        let mut array = builder.dyn_array(value.len());
        for (i, val) in value.into_iter().enumerate() {
            let val = V::constant(val, builder);
            builder.set(&mut array, i, val);
        }
        array
    }
}

impl<FC: FieldGenericConfig, V: FromConstant<FC> + MemVariable<FC>> FromConstant<FC> for Vec<V> {
    type Constant = Vec<V::Constant>;

    fn constant(value: Self::Constant, builder: &mut Builder<FC>) -> Self {
        value.into_iter().map(|x| V::constant(x, builder)).collect()
    }
}

impl<FC: FieldGenericConfig, V: FromConstant<FC> + MemVariable<FC>, const N: usize> FromConstant<FC>
    for [V; N]
{
    type Constant = [V::Constant; N];

    fn constant(value: Self::Constant, builder: &mut Builder<FC>) -> Self {
        value.map(|x| V::constant(x, builder))
    }
}
