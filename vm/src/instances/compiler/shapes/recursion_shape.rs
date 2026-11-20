use hashbrown::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecursionPadShape {
    pub(crate) inner: HashMap<String, usize>,
}
