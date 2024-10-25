use anyhow::{anyhow, Result};
use crossbeam::queue::SegQueue;
use csv::Writer;
use itertools::Itertools;
use lazy_static::lazy_static;
use std::time::Duration;

type PerfTagKey = String;
type PerfTagValue = String;

lazy_static! {
    static ref PERF_ENTRIES: SegQueue<PerfEntry> = SegQueue::new();
}

#[derive(Clone, Debug, Default)]
pub struct PerfContext {
    chunk: Option<u32>,
}

impl PerfContext {
    pub fn chunk(&self) -> Option<u32> {
        self.chunk
    }

    pub fn set_chunk(&mut self, chunk: Option<u32>) {
        self.chunk = chunk;
    }
}

#[derive(Clone, Debug)]
pub enum PerfTag {
    Chunk(u32),
    Step(String),
    Chip(String),
    TimeType(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PerfTagPair {
    key: PerfTagKey,
    value: PerfTagValue,
}

impl From<PerfTag> for PerfTagPair {
    fn from(tag: PerfTag) -> Self {
        match tag {
            PerfTag::Chunk(u) => Self::new(
                "chunk".to_string(),
                if u > 0 {
                    format!("chunk_{u}")
                } else {
                    "".to_string()
                },
            ),
            PerfTag::Step(s) => Self::new("step".to_string(), s),
            PerfTag::Chip(s) => Self::new("chip".to_string(), s),
            PerfTag::TimeType(s) => Self::new("time_type".to_string(), s),
        }
    }
}

impl PerfTagPair {
    pub fn new(key: PerfTagKey, value: PerfTagValue) -> Self {
        Self { key, value }
    }
}

#[derive(Clone, Debug)]
pub struct PerfEntry {
    tags: Vec<PerfTagPair>,
    time: Duration,
}

impl PerfEntry {
    pub fn new(tags: Vec<PerfTagPair>, time: Duration) -> Self {
        Self { tags, time }
    }
}

pub struct Perf;

impl Perf {
    pub fn add(
        time: Duration,
        chunk: Option<u32>,
        step: Option<&str>,
        chip: Option<&str>,
        time_type: Option<&str>,
    ) {
        let tags = [
            PerfTag::Chunk(chunk.unwrap_or_default()),
            PerfTag::Step(step.unwrap_or_default().to_string()),
            PerfTag::Chip(chip.unwrap_or_default().to_string()),
            PerfTag::TimeType(time_type.unwrap_or_default().to_string()),
        ]
        .into_iter()
        .map(Into::into)
        .collect_vec();

        let entry = PerfEntry::new(tags, time);

        PERF_ENTRIES.push(entry);
    }

    pub fn add_custom(time: Duration, tags: Vec<PerfTagPair>) {
        let entry = PerfEntry::new(tags, time);

        PERF_ENTRIES.push(entry);
    }

    pub fn save_to_csv(file_path: &str) -> Result<()> {
        let output = PerfOutput::load();
        let rows = output.format();

        let mut writer = Writer::from_path(file_path).map_err(|err| anyhow!(err.to_string()))?;
        writer
            .write_record(["Chunk", "Step", "Chip", "Time Type", "Time (ms)"])
            .map_err(|err| anyhow!(err.to_string()))?;
        rows.iter()
            .try_for_each(|row| writer.write_record(row.as_slice()))
            .map_err(|err| anyhow!(err.to_string()))?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
struct PerfOutput {
    entries: Vec<PerfEntry>,
}

impl PerfOutput {
    fn load() -> Self {
        let mut entries = Vec::with_capacity(PERF_ENTRIES.len());
        while let Some(entry) = PERF_ENTRIES.pop() {
            entries.push(entry);
        }

        Self { entries }
    }

    fn format(&self) -> Vec<Vec<String>> {
        self.entries
            .iter()
            .map(|entry| {
                let mut row = entry
                    .tags
                    .iter()
                    .map(|tag| tag.value.to_string())
                    .collect_vec();
                row.push(entry.time.as_millis().to_string());

                row
            })
            .collect()
    }
}
