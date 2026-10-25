use anyhow::Result;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::{create_dir_all, File},
    io::{BufReader, BufWriter},
    path::Path,
};

// load and deserialize data from a file
pub fn load_serde_data<T: DeserializeOwned>(file_path: &Path) -> Option<T> {
    if !file_path.exists() {
        return None;
    }

    let file = File::open(file_path).ok()?;
    let reader = BufReader::new(file);

    bincode::deserialize_from(reader).ok()
}

// serialize and store data to a file
pub fn store_serde_data<T: Serialize>(file_path: &Path, data: &T) -> Result<()> {
    if let Some(parent_dir) = file_path.parent() {
        create_dir_all(parent_dir)?;
    }

    let file = File::create(file_path)?;
    let writer = BufWriter::new(file);
    bincode::serialize_into(writer, data)?;

    Ok(())
}
