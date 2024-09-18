use hashbrown::HashMap;
use p3_field::Field;

pub trait RecordBehavior: Default {
    fn name(&self) -> String;

    fn stats(&self) -> HashMap<String, usize>;

    fn append(&mut self, extra: &mut Self);
}
