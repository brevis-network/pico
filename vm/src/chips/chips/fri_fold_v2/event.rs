use crate::recursion_v2::{
    air::Block,
    types::{FriFoldBaseIo, FriFoldExtSingleIo, FriFoldExtVecIo},
};
use serde::{Deserialize, Serialize};

/// The event encoding the data of a single iteration within the FRI fold operation.
/// For any given event, we are accessing a single element of the `Vec` inputs, so that the event
/// is not a type alias for `FriFoldIo` like many of the other events.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriFoldEvent<F> {
    pub base_single: FriFoldBaseIo<F>,
    pub ext_single: FriFoldExtSingleIo<Block<F>>,
    pub ext_vec: FriFoldExtVecIo<Block<F>>,
}
