use hashbrown::HashMap;
use p3_field::FieldAlgebra;

// set it temporarily for now

pub trait RecordBehavior: Default + Send + Sync {
    fn name(&self) -> String;

    fn stats(&self) -> HashMap<String, usize>;

    fn append(&mut self, extra: &mut Self);

    fn public_values<F: FieldAlgebra>(&self) -> Vec<F>;

    fn chunk_index(&self) -> usize;

    fn unconstrained(&self) -> bool {
        false
    }
}
