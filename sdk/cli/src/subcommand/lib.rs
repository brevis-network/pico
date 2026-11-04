use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

use crate::build::lib::build_library;

#[derive(Parser)]
#[command(
    name = "lib",
    about = "Build libpico_zkvm.a and pico.ld, to link a guest built without `cargo pico build`"
)]
pub struct LibCmd {
    /// The directory to write `libpico_zkvm.a` and `pico.ld` to.
    #[clap(long, default_value = "pico-zkvm")]
    pub output: PathBuf,
}

impl LibCmd {
    pub fn run(&self) -> Result<()> {
        let library = build_library(&self.output)?;
        println!(
            "wrote {} and {}",
            library.display(),
            self.output.join("pico.ld").display()
        );
        Ok(())
    }
}
