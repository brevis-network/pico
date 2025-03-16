use p3_field::PrimeField32;
use pico_patch_libs::syscall_poseidon2_permute;
/// A stateful hasher for Poseidon2.
pub struct Poseidon2<F: PrimeField32> {
    state: [F; 16],      // Poseidon2 works with a 16-element state.
    buffer_count: usize, // Number of elements currently buffered.
}

impl<F: PrimeField32> Poseidon2<F> {
    /// Creates a new Poseidon2 hasher with an empty state.
    pub fn new() -> Self {
        Self {
            state: [F::ZERO; 16],
            buffer_count: 0,
        }
    }

    /// Updates the hasher state with a new input element.
    pub fn update(&mut self, input: F) {
        // Buffer the input directly into the state.
        self.state[self.buffer_count] += input;
        self.buffer_count += 1;

        // If the buffer is full (15 elements), absorb and reset the buffer count.
        if self.buffer_count == 15 {
            self.permute();
            self.buffer_count = 0;
        }
    }

    /// Finalizes the hashing process and returns the resulting hash.
    pub fn finalize(mut self) -> F {
        // Pad remaining elements.
        if self.buffer_count > 0 {
            self.state[self.buffer_count] += F::ONE; // Padding with `1`.
        } else {
            self.state[0] += F::ONE; // If empty, pad the first element.
        }
        self.permute(); // Apply the final permutation.

        self.state[0] // Return the first element as the hash result.
    }

    /// Computes the Poseidon2 permutation on the state.
    fn permute(&mut self) {
        let mut ret = [0_u32; 16];

        unsafe {
            syscall_poseidon2_permute(
                &self.state.map(|f| f.as_canonical_u32()) as *const _,
                &mut ret as *mut _,
            );
        }
        self.state = ret.map(F::from_wrapped_u32);
    }

    /// A convenience function to hash two elements.
    pub fn hash_two(x: F, y: F) -> F {
        let mut state = [F::ZERO; 16];
        state[0] += x;
        state[1] += y;

        let mut ret = [0_u32; 16];

        unsafe {
            syscall_poseidon2_permute(
                &state.map(|f| f.as_canonical_u32()) as *const _,
                &mut ret as *mut _,
            );
        }
        F::from_wrapped_u32(ret[0])
    }

    /// A convenience function to hash a single element.
    pub fn hash_single(x: F) -> F {
        let mut state = [F::ZERO; 16];
        state[0] += x;

        let mut ret = [0_u32; 16];
        unsafe {
            syscall_poseidon2_permute(
                &state.map(|f| f.as_canonical_u32()) as *const _,
                &mut ret as *mut _,
            );
        }
        F::from_wrapped_u32(ret[0])
    }

    /// A convenience function to hash multiple elements.
    pub fn hash_many(inputs: &[F]) -> F {
        let mut hasher = Poseidon2::new();
        for &input in inputs {
            hasher.update(input);
        }
        hasher.finalize()
    }
}

impl<F: PrimeField32> Default for Poseidon2<F> {
    fn default() -> Self {
        Self::new()
    }
}
