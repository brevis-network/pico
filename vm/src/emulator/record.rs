use hashbrown::HashMap;
use p3_field::{AbstractField, Field};

// set it temporarily for now

pub trait RecordBehavior: Default + Sync {
    fn name(&self) -> String;

    fn stats(&self) -> HashMap<String, usize>;

    fn append(&mut self, extra: &mut Self);

    fn public_values<F: AbstractField>(&self) -> Vec<F>;

    /// Registers the nonces of the record.
    fn register_nonces(&mut self) {}
}
