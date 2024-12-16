use crate::recursion_v2::air::RecursionPublicValues;
use std::mem::size_of;

pub const RECURSION_NUM_PVS_V2: usize = size_of::<RecursionPublicValues<u8>>();

pub const MAX_NUM_PVS_V2: usize = RECURSION_NUM_PVS_V2;

/*
For Extensions
 */

pub const EXTENSION_DEGREE: usize = 4;
