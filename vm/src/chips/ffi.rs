use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[repr(C)]
pub enum FfiOption<T> {
    #[default]
    None,
    Some(T),
}

impl<T> From<Option<T>> for FfiOption<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            None => Self::None,
            Some(x) => Self::Some(x),
        }
    }
}
