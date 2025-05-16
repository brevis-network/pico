use std::ffi::c_void;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ValueSourceCrepr {
    pub val_type: u32,
    pub generic: u32,
    pub poly_index: u32,
    pub offset: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ValueSourceExtCrepr {
    pub bases: [ValueSourceCrepr; 4],
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CalculationCrepr {
    pub op: u32,
    pub v0: ValueSourceCrepr,
    pub v1: ValueSourceCrepr,
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MatrixVarCrepr {
    pub ptr: *const c_void,
    pub num_poly: u64,
}
