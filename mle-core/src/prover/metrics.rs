use std::fmt::Display;

use itertools::zip_eq;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::{
    keygen::types::TraceWidth,
    proof::TraceVData,
    prover::{DeviceMultiStarkProvingKey, ProverBackend},
    StarkProtocolConfig,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceMetrics {
    pub per_air: Vec<SingleTraceMetrics>,
    /// Total base field cells from all traces, excludes preprocessed.
    pub total_cells: usize,
    /// For each trace height constraint, the (weighted sum, threshold)
    pub trace_height_inequalities: Vec<(usize, usize)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SingleTraceMetrics {
    pub air_name: String,
    pub air_id: usize,
    pub height: usize,
    /// The after challenge width is adjusted to be in terms of **base field** elements.
    pub width: TraceWidth,
    pub cells: TraceCells,
    // TODO: update this calculation after the trace-width accounting settles.
    /// Omitting preprocessed trace, the total base field cells from main and interaction
    /// traces.
    pub total_cells: usize,
}

/// Trace cells, counted in terms of number of **base field** elements.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceCells {
    pub preprocessed: Option<usize>,
    pub cached_mains: Vec<usize>,
    pub common_main: usize,
    pub interactions: Vec<usize>,
}

impl Display for TraceMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, (weighted_sum, threshold)) in self.trace_height_inequalities.iter().enumerate() {
            writeln!(
                f,
                "trace_height_constraint_{i} | weighted_sum = {:<10} | threshold = {:<10}",
                format_number_with_underscores(*weighted_sum),
                format_number_with_underscores(*threshold)
            )?;
        }
        for trace_metrics in &self.per_air {
            writeln!(f, "{}", trace_metrics)?;
        }
        Ok(())
    }
}

impl Display for SingleTraceMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:<20} | Rows = {:<10} | Cells = {:<11} | Prep Cols = {:<5} | Main Cols = {:<5} | Intx Cells = {:<5}",
            self.air_name, format_number_with_underscores(self.height), format_number_with_underscores(self.total_cells), self.width.preprocessed.unwrap_or(0),
            format!("{:?}", self.width.main_widths()),
            format!("{:?}", self.cells.interactions),
        )?;
        Ok(())
    }
}

/// heights are the trace heights for each air
pub fn trace_metrics<SC: StarkProtocolConfig, PB: ProverBackend>(
    mpk: &DeviceMultiStarkProvingKey<PB>,
    trace_vdata: &[Option<TraceVData<SC>>],
) -> TraceMetrics {
    let heights = trace_vdata
        .iter()
        .map(|vdata| vdata.as_ref().map(|v| 1 << v.log_height).unwrap_or(0))
        .collect::<Vec<_>>();
    let trace_height_inequalities = mpk
        .trace_height_constraints
        .iter()
        .map(|trace_height_constraint| {
            let weighted_sum = heights
                .iter()
                .enumerate()
                .map(|(air_idx, h)| (trace_height_constraint.coefficients[air_idx] as usize) * h)
                .sum::<usize>();
            (weighted_sum, trace_height_constraint.threshold as usize)
        })
        .collect::<Vec<_>>();
    let per_air: Vec<_> = zip_eq(&mpk.per_air, heights)
        .enumerate()
        .filter(|(_, (_, height))| *height > 0)
        .map(|(air_idx, (pk, height))| {
            let air_name = &pk.air_name;
            let width = pk.vk.params.width.clone();
            let mut interaction_width = pk.vk.num_interactions();
            let ext_degree = PB::CHALLENGE_EXT_DEGREE as usize;
            interaction_width *= ext_degree;
            let cells = TraceCells {
                preprocessed: width.preprocessed.map(|w| w * height),
                cached_mains: width.cached_mains.iter().map(|w| w * height).collect(),
                common_main: width.common_main * height,
                interactions: vec![interaction_width * height],
            };
            let total_cells = cells
                .cached_mains
                .iter()
                .chain([&cells.common_main])
                .chain(cells.interactions.iter())
                .sum::<usize>();
            SingleTraceMetrics {
                air_name: air_name.to_string(),
                air_id: air_idx,
                height,
                width,
                cells,
                total_cells,
            }
        })
        .collect();
    let total_cells = per_air.iter().map(|m| m.total_cells).sum();
    let metrics = TraceMetrics {
        per_air,
        total_cells,
        trace_height_inequalities,
    };
    info!(
        "total_trace_cells = {} (excluding preprocessed)",
        format_number_with_underscores(metrics.total_cells)
    );
    info!(
        "preprocessed_trace_cells = {}",
        format_number_with_underscores(
            metrics
                .per_air
                .iter()
                .map(|m| m.cells.preprocessed.unwrap_or(0))
                .sum::<usize>()
        )
    );
    info!(
        "main_trace_cells = {}",
        format_number_with_underscores(
            metrics
                .per_air
                .iter()
                .map(|m| m.cells.cached_mains.iter().sum::<usize>() + m.cells.common_main)
                .sum::<usize>()
        )
    );
    info!(
        "interaction_trace_cells = {}",
        format_number_with_underscores(
            metrics
                .per_air
                .iter()
                .map(|m| m.cells.interactions.iter().sum::<usize>())
                .sum::<usize>()
        )
    );
    debug!("{}", metrics);
    metrics
}

pub fn format_number_with_underscores(n: usize) -> String {
    let num_str = n.to_string();
    let mut result = String::new();

    // Start adding characters from the end of num_str
    for (i, c) in num_str.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push('_');
        }
        result.push(c);
    }

    // Reverse the result to get the correct order
    result.chars().rev().collect()
}

#[cfg(feature = "metrics")]
mod emit {
    use metrics::counter;

    use super::{SingleTraceMetrics, TraceMetrics};

    impl TraceMetrics {
        pub fn emit(&self) {
            for (i, (weighted_sum, threshold)) in self.trace_height_inequalities.iter().enumerate()
            {
                let labels = [("trace_height_constraint", i.to_string())];
                counter!("weighted_sum", &labels).absolute(*weighted_sum as u64);
                counter!("threshold", &labels).absolute(*threshold as u64);
            }
            for trace_metrics in &self.per_air {
                trace_metrics.emit();
            }
            counter!("total_cells").absolute(self.total_cells as u64);
        }
    }

    impl SingleTraceMetrics {
        pub fn emit(&self) {
            let labels = [
                ("air_name", self.air_name.clone()),
                ("air_id", self.air_id.to_string()),
            ];
            counter!("rows", &labels).absolute(self.height as u64);
            counter!("cells", &labels).absolute(self.total_cells as u64);
            counter!("prep_cols", &labels).absolute(self.width.preprocessed.unwrap_or(0) as u64);
            counter!("main_cols", &labels).absolute(
                (self.width.cached_mains.iter().sum::<usize>() + self.width.common_main) as u64,
            );
            counter!("interaction_cells", &labels)
                .absolute(self.cells.interactions.iter().sum::<usize>() as u64);
        }
    }
}
