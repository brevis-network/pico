use hashbrown::HashMap;
use p3_field::{AbstractField, Field};

// set it temporarily for now
pub const MAX_NUM_PVS: usize = 370;

pub trait RecordBehavior: Default {
    fn name(&self) -> String;

    fn stats(&self) -> HashMap<String, usize>;

    fn append(&mut self, extra: &mut Self);

    fn public_values<F: AbstractField>(&self) -> Vec<F>;
}
