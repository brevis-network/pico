use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use strum::{EnumCount, IntoEnumIterator};
use strum_macros::EnumIter;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, EnumIter, EnumCount)]
pub enum Stage {
    CoordinatorStarted,
    CoordinatorSetupDone,
    RecordCreated,
    RecordSending,
    WorkerRecv,
    RiscvConvertDone,
    CoordinatorRecv,
    CombineStart,
    CombineSending,
    CombineDone,
    CoordinatorFinished,
}

use std::convert::TryFrom;

// TODO: use macro (keep i32 for grpc)
impl TryFrom<i32> for Stage {
    type Error = ();

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Stage::CoordinatorStarted),
            1 => Ok(Stage::CoordinatorSetupDone),
            2 => Ok(Stage::RecordCreated),
            3 => Ok(Stage::RecordSending),
            4 => Ok(Stage::WorkerRecv),
            5 => Ok(Stage::RiscvConvertDone),
            6 => Ok(Stage::CoordinatorRecv),
            7 => Ok(Stage::CombineStart),
            8 => Ok(Stage::CombineSending),
            9 => Ok(Stage::CombineDone),
            10 => Ok(Stage::CoordinatorFinished),
            _ => Err(()),
        }
    }
}

const STAGE_CNT: usize = Stage::COUNT;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timeline {
    pub start_index: usize,
    pub end_index: usize,
    events: [Option<SystemTime>; STAGE_CNT], // align with stages
}

impl Timeline {
    pub fn new(start: usize, end: usize) -> Self {
        Self {
            start_index: start,
            end_index: end,
            events: Default::default(),
        }
    }
    #[inline]
    pub fn mark(&mut self, s: Stage) {
        self.events[s as usize] = Some(SystemTime::now());
    }
    pub fn get(&self, s: Stage) -> Option<SystemTime> {
        self.events[s as usize]
    }

    #[inline]
    pub fn set(&mut self, s: Stage, t: SystemTime) {
        self.events[s as usize] = Some(t);
    }

    pub fn merge_from(&mut self, other: &Self) {
        for (dst, src) in self.events.iter_mut().zip(other.events) {
            if dst.is_none() {
                *dst = src;
            }
        }
    }
}

use prost_types::Timestamp;
use std::time::{Duration, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TlError {
    #[error("stage missing timestamp")]
    MissingTime,
}

impl From<Timeline> for crate::Timeline {
    fn from(tl: Timeline) -> Self {
        let events = Stage::iter()
            .enumerate()
            .filter_map(|(idx, stg)| {
                tl.events[idx].map(|st| {
                    let dur = st.duration_since(UNIX_EPOCH).unwrap();
                    crate::StageTime {
                        stage: stg as i32,
                        timestamp: Some(Timestamp {
                            seconds: dur.as_secs() as i64,
                            nanos: dur.subsec_nanos() as i32,
                        }),
                    }
                })
            })
            .collect();
        crate::Timeline {
            start_index: tl.start_index as u64,
            end_index: tl.end_index as u64,
            events,
        }
    }
}

impl TryFrom<crate::Timeline> for Timeline {
    type Error = TlError;
    fn try_from(pb: crate::Timeline) -> Result<Self, Self::Error> {
        let mut tl = Timeline::new(pb.start_index as usize, pb.end_index as usize);
        for ev in pb.events {
            let stg = Stage::try_from(ev.stage).unwrap();
            let ts = ev.timestamp.ok_or(TlError::MissingTime)?;
            let sys = UNIX_EPOCH + Duration::new(ts.seconds as u64, ts.nanos as u32);
            tl.set(stg, sys);
        }
        Ok(tl)
    }
}
