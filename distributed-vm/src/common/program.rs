use super::BlockNum;
use crate::{ProveTaskRequest, ProvingRequest};
use std::{
    error::Error,
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

/// Where the aggregator flows expect the RISC-V vk digest on disk (was
/// `coordinator::emulator::VK_DIGEST_PATH` before the FRI coordinator was removed).
pub const VK_DIGEST_PATH: &str = "./perf/bench_data/vk_digest.bin";

#[derive(Debug, Clone)]
pub enum ProgramInput {
    Simple {
        /// block number
        block: BlockNum,
        /// input data
        input: Option<Vec<u8>>,
    },
    Common {
        /// proving task ID
        task_id: u64,
        /// inputs
        inputs: Vec<String>,
    },
    Aggregator {
        block: BlockNum,
    },
    Subblock {
        block: BlockNum,
        // Note: currently, deferred_index is handled by env
        // deferred_index: usize,
    },
    AggregatorRaw {
        block: u64,
        num_subblocks: u32,
        builder_bytes: Vec<u8>, // bincode of the stdin builder
    },
    SubblockRaw {
        block: u64,
        num_subblocks: u32,
        subblock_index: u32,
        builder_bytes: Vec<u8>, // bincode of the stdin builder
    },
}
// AggregationInput is the same struct in rsp-subblock
// Note: same version of reth_primitives & revm_primitives
use crate::{common::parse::env_usize, io::stdins::agg_file_path};
use serde::de::DeserializeOwned;

#[inline]
pub fn load_bin<T: DeserializeOwned>(path: &str) -> Result<T, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    Ok(bincode::deserialize::<T>(&bytes)?)
}

// allow: domain-complex signature — tuple reflects prover data-flow structure
#[allow(clippy::type_complexity)]
pub fn load_agg_tuple_with_suffix(
    block_num: BlockNum,
) -> Result<(Vec<Vec<u8>>, [u32; 8]), Box<dyn Error>> {
    let gas_threshold = env_usize("GAS_THRESHOLD").unwrap();
    let pvs_path = agg_file_path(block_num, gas_threshold as u64, "public_values");

    let pvs: Vec<Vec<u8>> = load_bin(&pvs_path)?;
    let vk_digest: [u32; 8] = load_bin(VK_DIGEST_PATH)?;

    Ok((pvs, vk_digest))
}

fn aggregator_data_dir(block: &str) -> String {
    let root =
        std::env::var("AGGREGATOR_DATA_ROOT").unwrap_or_else(|_| "./perf/bench_data".to_string());
    format!("{}/{}", root, block)
}

pub fn agg_file(base: &str, block: &str) -> String {
    format!("{}/{}.bin", aggregator_data_dir(block), base)
}

// convert from ethproofs request
impl From<ProvingRequest> for ProgramInput {
    fn from(req: ProvingRequest) -> Self {
        let block = req.block_number;
        let input = req.input_buffer;
        Self::Simple { block, input }
    }
}

// covnert from proving network request
impl From<ProveTaskRequest> for ProgramInput {
    fn from(req: ProveTaskRequest) -> Self {
        // generate a proving network task ID
        let task_id = task_id();

        let inputs = req.inputs;
        Self::Common { task_id, inputs }
    }
}

// generate a proving network task ID
fn task_id() -> u64 {
    let now = SystemTime::now();
    let duration = now.duration_since(UNIX_EPOCH).unwrap();
    duration.as_secs()
}
