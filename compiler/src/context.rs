use core::mem::take;
use std::marker::PhantomData;

/// Context to run a program inside Pico.
#[derive(Clone, Default)]
pub struct PicoContext {
    /// The maximum number of cpu cycles to use for execution.
    pub max_cycles: Option<u64>,
}

/// A builder for [`PicoContext`].
#[derive(Clone, Default)]
pub struct PicoContextBuilder {
    no_default_hooks: bool,
    max_cycles: Option<u64>,
}

impl PicoContext {
    /// Create a new context builder. See [`PicoContextBuilder`] for more details.
    #[must_use]
    pub fn builder() -> PicoContextBuilder {
        PicoContextBuilder::new()
    }
}

impl<'a> PicoContextBuilder {
    /// Create a new [`PicoContextBuilder`].
    ///
    /// Prefer using [`PicoContext::builder`].
    #[must_use]
    pub fn new() -> Self {
        PicoContextBuilder::default()
    }

    /// Build and return the [`PicoContext`].
    ///
    /// Clears and resets the builder, allowing it to be reused.
    pub fn build(&mut self) -> PicoContext {
        // If hook_registry_entries is nonempty or no_default_hooks true,
        // indicating a non-default value of hook_registry.

        let cycle_limit = take(&mut self.max_cycles);
        PicoContext {
            max_cycles: cycle_limit,
        }
    }

    /// Set the maximum number of cpu cycles to use for execution.
    pub fn max_cycles(&mut self, max_cycles: u64) -> &mut Self {
        self.max_cycles = Some(max_cycles);
        self
    }
}
