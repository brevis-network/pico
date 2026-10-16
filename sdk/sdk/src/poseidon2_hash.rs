use p3_field::PrimeField32;
use pico_patch_libs::POSEIDON2_WIDTH;

use crate::poseidon2::permuted;

/// A stateful hasher for Poseidon2.
pub struct Poseidon2<F: PrimeField32> {
    state: [F; POSEIDON2_WIDTH], // Poseidon2 works with a 16-element state.
    buffer_count: usize,         // Number of elements currently buffered.
}

impl<F: PrimeField32> Poseidon2<F> {
    /// Creates a new Poseidon2 hasher with an empty state.
    pub fn new() -> Self {
        Self {
            state: [F::ZERO; POSEIDON2_WIDTH],
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
        self.state = permuted(&self.state);
    }

    /// A convenience function to hash two elements.
    pub fn hash_two(x: F, y: F) -> F {
        let mut state = [F::ZERO; POSEIDON2_WIDTH];
        state[0] += x;
        state[1] += y;

        permuted(&state)[0]
    }

    /// A convenience function to hash a single element.
    pub fn hash_single(x: F) -> F {
        let mut state = [F::ZERO; POSEIDON2_WIDTH];
        state[0] += x;

        permuted(&state)[0]
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
