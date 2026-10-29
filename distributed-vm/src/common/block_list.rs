use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct BlockList {
    pub blocks: Vec<u64>,
    index_by_block: HashMap<u64, usize>,
}

impl BlockList {
    pub fn new(blocks: Vec<u64>) -> Result<Self> {
        if blocks.is_empty() {
            anyhow::bail!("block list is empty");
        }

        let mut index_by_block = HashMap::with_capacity(blocks.len());
        for (idx, block) in blocks.iter().copied().enumerate() {
            if index_by_block.insert(block, idx).is_some() {
                anyhow::bail!("duplicate block in list: {}", block);
            }
        }

        Ok(Self {
            blocks,
            index_by_block,
        })
    }

    pub fn index_of(&self, block: u64) -> Option<usize> {
        self.index_by_block.get(&block).copied()
    }

    pub fn next_after_index(&self, index: usize) -> Option<u64> {
        self.blocks.get(index + 1).copied()
    }
}

fn parse_block_list_from_file(path: &Path) -> Result<BlockList> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read block list file: {}", path.display()))?;

    let mut blocks = Vec::new();
    for (line_no, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let token = line.split_whitespace().next().unwrap_or("");
        let block: u64 = token.parse().with_context(|| {
            format!(
                "invalid block number at {}:{}: '{}'",
                path.display(),
                line_no + 1,
                token
            )
        })?;
        blocks.push(block);
    }

    BlockList::new(blocks)
}

pub fn read_block_list_from_env() -> Result<Option<(BlockList, PathBuf)>> {
    let path = match std::env::var("BLOCK_LIST_FILE") {
        Ok(p) => PathBuf::from(p),
        Err(_) => return Ok(None),
    };

    let list = parse_block_list_from_file(&path)?;
    Ok(Some((list, path)))
}
