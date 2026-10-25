use cudart::{memory_pools::DevicePoolAllocation, stream::CudaStream};
use hashbrown::HashMap;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;

use crate::{
    chips::chips::{
        events::{AluEvent, CpuEvent},
        riscv_global::event::GlobalInteractionEvent,
        riscv_poseidon2::Poseidon2Event,
    },
    instances::preparer::{GpuMemoryError, PreparedGpuEvents},
};

// set it temporarily for now

pub trait RecordBehavior: Default + Send + Sync {
    fn name(&self) -> String;

    fn stats(&self) -> HashMap<String, usize>;

    fn append(&mut self, extra: &mut Self);

    fn public_values<F: PrimeCharacteristicRing>(&self) -> Vec<F>;

    fn chunk_index(&self) -> usize;

    fn unconstrained(&self) -> bool {
        false
    }

    fn gpu_allocate_and_copy_cpu_events<'a>(
        &'a self,
        _stream: &'a CudaStream,
        _device_id: usize,
        _prepared_gpu_events: &'a PreparedGpuEvents,
    ) -> Result<Option<DevicePoolAllocation<'a, CpuEvent>>, GpuMemoryError> {
        panic!("unsupported");
    }

    fn gpu_allocate_cpu_events<'a>(
        &'a self,
        _stream: &'a CudaStream,
        _device_id: usize,
        _prepared_gpu_events: &'a PreparedGpuEvents,
    ) -> Result<Option<DevicePoolAllocation<'a, CpuEvent>>, GpuMemoryError> {
        panic!("unsupported");
    }

    fn gpu_allocate_and_copy_add_sub_events<'a>(
        &'a self,
        _stream: &'a CudaStream,
        _device_id: usize,
        _prepared_gpu_events: &'a PreparedGpuEvents,
    ) -> Result<Option<DevicePoolAllocation<'a, AluEvent>>, GpuMemoryError> {
        panic!("unsupported");
    }

    fn gpu_allocate_and_copy_lt_events<'a>(
        &'a self,
        _stream: &'a CudaStream,
        _device_id: usize,
        _prepared_gpu_events: &'a PreparedGpuEvents,
    ) -> Result<Option<DevicePoolAllocation<'a, AluEvent>>, GpuMemoryError> {
        panic!("unsupported");
    }

    fn gpu_allocate_and_copy_mul_events<'a>(
        &'a self,
        _stream: &'a CudaStream,
        _device_id: usize,
        _prepared_gpu_events: &'a PreparedGpuEvents,
    ) -> Result<Option<DevicePoolAllocation<'a, AluEvent>>, GpuMemoryError> {
        panic!("unsupported");
    }

    fn gpu_allocate_and_copy_global_events<'a>(
        &'a self,
        _stream: &'a CudaStream,
        _device_id: usize,
        _prepared_gpu_events: &'a PreparedGpuEvents,
    ) -> Result<Option<DevicePoolAllocation<'a, GlobalInteractionEvent>>, GpuMemoryError> {
        panic!("unsupported");
    }

    fn gpu_allocate_and_copy_poseidon2_events<'a>(
        &'a self,
        _stream: &'a CudaStream,
        _device_id: usize,
        _prepared_gpu_events: &'a PreparedGpuEvents,
    ) -> Result<Option<DevicePoolAllocation<'a, Poseidon2Event>>, GpuMemoryError> {
        panic!("unsupported");
    }

    fn gpu_allocate_byte_trace<'a>(
        &'a self,
        _stream: &'a CudaStream,
        _device_id: usize,
    ) -> Result<Option<DevicePoolAllocation<'a, KoalaBear>>, GpuMemoryError> {
        panic!("unsupported");
    }
}
