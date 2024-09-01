use pico_configs::config::{StarkGenericConfig, Val};
use std::marker::PhantomData;

pub struct BaseVerifier<SC: StarkGenericConfig, C>(PhantomData<SC>, PhantomData<C>);