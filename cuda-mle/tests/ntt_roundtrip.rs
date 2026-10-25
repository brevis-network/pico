use cuda_mle::{
    ntt_field::GpuNttField,
    runtime::{
        copy::{MemCopyD2H, MemCopyH2D},
        d_buffer::DeviceBuffer,
    },
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear as F;

#[test]
#[ignore] // Run explicitly: requires large GPU memory and significant runtime.
fn ntt_roundtrip_max_log_domain_size() {
    // KoalaBear's two-adicity (P - 1 = 2^24 * 127) caps the NTT domain.
    const LOG_N: u32 = 24;
    let n = 1usize << LOG_N;
    let mut host = Vec::<F>::with_capacity(n);

    for i in 0..n {
        host.push(F::from_usize(i));
    }

    let mut device = DeviceBuffer::<F>::with_capacity(n);
    host.copy_to(&mut device).expect("host->device copy failed");

    F::batch_ntt(&device, LOG_N, 0, 1, true, false);
    F::batch_ntt(&device, LOG_N, 0, 1, true, true);

    let output = device.to_host().expect("device->host copy failed");
    for (i, got) in output.iter().enumerate() {
        assert_eq!(*got, host[i], "mismatch at index {}", i);
    }
}
