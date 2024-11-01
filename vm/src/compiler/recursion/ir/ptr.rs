use super::{Builder, DslIr, MemIndex, MemVariable, SymbolicVar, Usize, Var, Variable};
use crate::configs::config::FieldGenericConfig;
use core::ops::{Add, Sub};
use p3_field::Field;

/// A point to a location in memory.
#[derive(Debug, Clone, Copy)]
pub struct Ptr<N> {
    pub address: Var<N>,
}

pub struct SymbolicPtr<N: Field> {
    pub address: SymbolicVar<N>,
}

impl<FC: FieldGenericConfig> Builder<FC> {
    /// Allocates an array on the heap.
    pub(crate) fn alloc(&mut self, len: Usize<FC::N>, size: usize) -> Ptr<FC::N> {
        let ptr = Ptr::uninit(self);
        self.push(DslIr::Alloc(ptr, len, size));
        ptr
    }

    /// Loads a value from memory.
    pub fn load<V: MemVariable<FC>>(&mut self, var: V, ptr: Ptr<FC::N>, index: MemIndex<FC::N>) {
        var.load(ptr, index, self);
    }

    /// Stores a value to memory.
    pub fn store<V: MemVariable<FC>>(&mut self, ptr: Ptr<FC::N>, index: MemIndex<FC::N>, value: V) {
        value.store(ptr, index, self);
    }
}

impl<FC: FieldGenericConfig> Variable<FC> for Ptr<FC::N> {
    type Expression = SymbolicPtr<FC::N>;

    fn uninit(builder: &mut Builder<FC>) -> Self {
        Ptr {
            address: Var::uninit(builder),
        }
    }

    fn assign(&self, src: Self::Expression, builder: &mut Builder<FC>) {
        self.address.assign(src.address, builder);
    }

    fn assert_eq(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<FC>,
    ) {
        Var::assert_eq(lhs.into().address, rhs.into().address, builder);
    }

    fn assert_ne(
        lhs: impl Into<Self::Expression>,
        rhs: impl Into<Self::Expression>,
        builder: &mut Builder<FC>,
    ) {
        Var::assert_ne(lhs.into().address, rhs.into().address, builder);
    }
}

impl<FC: FieldGenericConfig> MemVariable<FC> for Ptr<FC::N> {
    fn size_of() -> usize {
        1
    }

    fn load(&self, ptr: Ptr<FC::N>, index: MemIndex<FC::N>, builder: &mut Builder<FC>) {
        self.address.load(ptr, index, builder);
    }

    fn store(
        &self,
        ptr: Ptr<<FC as FieldGenericConfig>::N>,
        index: MemIndex<FC::N>,
        builder: &mut Builder<FC>,
    ) {
        self.address.store(ptr, index, builder);
    }
}

impl<N: Field> From<Ptr<N>> for SymbolicPtr<N> {
    fn from(ptr: Ptr<N>) -> Self {
        SymbolicPtr {
            address: SymbolicVar::from(ptr.address),
        }
    }
}

impl<N: Field> Add for Ptr<N> {
    type Output = SymbolicPtr<N>;

    fn add(self, rhs: Self) -> Self::Output {
        SymbolicPtr {
            address: self.address + rhs.address,
        }
    }
}

impl<N: Field> Sub for Ptr<N> {
    type Output = SymbolicPtr<N>;

    fn sub(self, rhs: Self) -> Self::Output {
        SymbolicPtr {
            address: self.address - rhs.address,
        }
    }
}

impl<N: Field> Add for SymbolicPtr<N> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            address: self.address + rhs.address,
        }
    }
}

impl<N: Field> Sub for SymbolicPtr<N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self {
            address: self.address - rhs.address,
        }
    }
}

impl<N: Field> Add<Ptr<N>> for SymbolicPtr<N> {
    type Output = Self;

    fn add(self, rhs: Ptr<N>) -> Self {
        Self {
            address: self.address + rhs.address,
        }
    }
}

impl<N: Field> Sub<Ptr<N>> for SymbolicPtr<N> {
    type Output = Self;

    fn sub(self, rhs: Ptr<N>) -> Self {
        Self {
            address: self.address - rhs.address,
        }
    }
}

impl<N: Field> Add<SymbolicPtr<N>> for Ptr<N> {
    type Output = SymbolicPtr<N>;

    fn add(self, rhs: SymbolicPtr<N>) -> SymbolicPtr<N> {
        SymbolicPtr {
            address: self.address + rhs.address,
        }
    }
}

impl<N: Field> Add<SymbolicVar<N>> for Ptr<N> {
    type Output = SymbolicPtr<N>;

    fn add(self, rhs: SymbolicVar<N>) -> SymbolicPtr<N> {
        SymbolicPtr {
            address: self.address + rhs,
        }
    }
}

impl<N: Field> Sub<SymbolicVar<N>> for Ptr<N> {
    type Output = SymbolicPtr<N>;

    fn sub(self, rhs: SymbolicVar<N>) -> SymbolicPtr<N> {
        SymbolicPtr {
            address: self.address - rhs,
        }
    }
}

impl<N: Field> Sub<SymbolicPtr<N>> for Ptr<N> {
    type Output = SymbolicPtr<N>;

    fn sub(self, rhs: SymbolicPtr<N>) -> SymbolicPtr<N> {
        SymbolicPtr {
            address: self.address - rhs.address,
        }
    }
}

impl<N: Field> Add<Usize<N>> for Ptr<N> {
    type Output = SymbolicPtr<N>;

    fn add(self, rhs: Usize<N>) -> SymbolicPtr<N> {
        match rhs {
            Usize::Const(rhs) => SymbolicPtr {
                address: self.address + N::from_canonical_usize(rhs),
            },
            Usize::Var(rhs) => SymbolicPtr {
                address: self.address + rhs,
            },
        }
    }
}

impl<N: Field> Add<Usize<N>> for SymbolicPtr<N> {
    type Output = SymbolicPtr<N>;

    fn add(self, rhs: Usize<N>) -> SymbolicPtr<N> {
        match rhs {
            Usize::Const(rhs) => SymbolicPtr {
                address: self.address + N::from_canonical_usize(rhs),
            },
            Usize::Var(rhs) => SymbolicPtr {
                address: self.address + rhs,
            },
        }
    }
}

impl<N: Field> Sub<Usize<N>> for Ptr<N> {
    type Output = SymbolicPtr<N>;

    fn sub(self, rhs: Usize<N>) -> SymbolicPtr<N> {
        match rhs {
            Usize::Const(rhs) => SymbolicPtr {
                address: self.address - N::from_canonical_usize(rhs),
            },
            Usize::Var(rhs) => SymbolicPtr {
                address: self.address - rhs,
            },
        }
    }
}

impl<N: Field> Sub<Usize<N>> for SymbolicPtr<N> {
    type Output = SymbolicPtr<N>;

    fn sub(self, rhs: Usize<N>) -> SymbolicPtr<N> {
        match rhs {
            Usize::Const(rhs) => SymbolicPtr {
                address: self.address - N::from_canonical_usize(rhs),
            },
            Usize::Var(rhs) => SymbolicPtr {
                address: self.address - rhs,
            },
        }
    }
}
