use anyhow::{Error, Result};
use clap::{Parser, Subcommand};
use pico_perf::common::{
    bench_field::BenchField,
    gnark_utils::{
        create_gnark_prover, delete_files, delete_files_all, download_files, download_files_all,
        get_download_path, gnark_prover_exists, recreate_gnark_prover, remove_gnark_prover,
        stop_gnark_prover,
    },
};
use std::{thread::sleep, time::Duration};

#[derive(Parser)]
#[command(name = "gnarkctl")]
#[command(about = "CLI tool for managing the gnark environment and resources", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start (or restart) the gnark prover container for a specified field.
    StartProver {
        /// The field type to use (e.g., "bb" or "kb").
        #[arg(long, default_value = "bb")]
        field: BenchField,
    },
    /// Stop the running prover container.
    StopProver,
    /// Remove the prover container.
    RemoveProver,
    /// Download resource files for all supported fields or a specific field.
    DownloadFiles {
        /// Download files for all supported fields.
        #[arg(long, conflicts_with = "field")]
        all: bool,
        /// The field type to use (e.g., "bb" or "kb"). If omitted, downloads for all.
        #[arg(long)]
        field: Option<BenchField>,
    },
    /// Delete resource files for the specified programs.
    DeleteFiles {
        /// Delete files for all supported fields or a specific field.
        #[arg(long, conflicts_with = "field")]
        all: bool,
        /// The field type to use (e.g., "bb" or "kb"). If omitted, downloads for all.
        #[arg(long)]
        field: Option<BenchField>,
    },
    /// Convenience command: start the prover for a specific field and download its resource files.
    Setup {
        /// The field type to use.
        #[arg(long, default_value = "bb")]
        field: BenchField,
    },
    /// Convenience command: stop the prover and delete resource files for all supported fields or a specific field.
    Teardown {
        /// The field type to use (e.g., "bb" or "kb"). If omitted, downloads for all.
        #[arg(long)]
        field: Option<BenchField>,
    },
}

fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::StartProver { field } => {
            let download_path = get_download_path(*field);

            handle_prover_creation(*field, &download_path)?;
        }
        Commands::StopProver => {
            println!("Stopping and removing prover container.");
            stop_gnark_prover()?;
        }
        Commands::RemoveProver => {
            println!("Removing prover container.");
            remove_gnark_prover()?;
        }
        Commands::DownloadFiles { all, field } => {
            if *all {
                println!("Downloading files for all supported programs with all supported fields.");
                download_files_all()?;
            } else if let Some(specified_field) = field {
                println!("Downloading files for field: {}", specified_field.to_str());
                download_files(*specified_field)?;
            } else {
                println!("Downloading files for all supported fields.");
                download_files_all()?;
            }
        }
        Commands::DeleteFiles { all, field } => {
            if *all {
                println!("Deleting files for all supported programs with all supported fields.");
                delete_files_all()?;
            } else if let Some(specified_field) = field {
                println!("Deleting files for field: {}", specified_field.to_str());
                delete_files(*specified_field)?;
            } else {
                println!("Deleting files for all supported programs.");
                delete_files_all()?;
            }
        }
        Commands::Setup { field } => {
            let field_str = field.to_str();
            let download_path = get_download_path(*field);
            println!("Setting up environment for field: {}", field_str);

            println!("Downloading resource files for field: {}", field_str);
            download_files(*field)?;

            handle_prover_creation(*field, &download_path)?;
        }
        Commands::Teardown { field } => {
            println!("Stop and remove docker container.");
            stop_gnark_prover()?;
            sleep(Duration::from_secs(1));
            remove_gnark_prover()?;
            if let Some(specified_field) = field {
                println!(
                    "Deleting resource files for field: {}",
                    specified_field.to_str()
                );
                delete_files(*specified_field)?;
            } else {
                println!("Deleting resource files for all supported fields.");
                delete_files_all()?;
            }
        }
    }

    Ok(())
}

// Note: To update the download path, we must remove the existing container
// and create a new one with the desired volume configuration.
fn handle_prover_creation(field: BenchField, download_path: &str) -> Result<(), Error> {
    if gnark_prover_exists() {
        println!("Prover container exists. Recreating with new download path.");
        recreate_gnark_prover(field, download_path)?;
    } else {
        println!("No existing container found. Creating new prover container.");
        create_gnark_prover(field, download_path)?;
    }
    Ok(())
}
