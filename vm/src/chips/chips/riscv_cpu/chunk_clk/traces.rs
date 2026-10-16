use super::super::{columns::CpuCols, CpuChip};
use crate::chips::chips::riscv_cpu::event::CpuEvent;
use p3_field::Field;

impl<F: Field> CpuChip<F> {
    /// Populates `clk`. There is no chunk column to fill: the AIR's messages carry the
    /// `execution_chunk` public value.
    pub(crate) fn populate_chunk_clk(&self, cols: &mut CpuCols<F>, event: &CpuEvent) {
        let clk = u32::try_from(event.clk).unwrap();

        // 25-bit budget: any clk >= 2^25 must have been rejected upstream
        // (ChunkSplitConfig::MAX_CHUNK_CLK_BITS guard) -- assert instead of silently going on.
        // The budget is a completeness bound (the syscall Global message leads with clk and the
        // Global chip range-checks that slot to 25 bits); the AIR does not range-check this
        // column (`eval_chunk_clk` explains why the row chain makes that unnecessary), so no
        // byte events are emitted here.
        assert!(
            clk < (1 << 25),
            "chunk clk {clk} exceeds the 25-bit budget; CHUNK_SIZE guard should have caught this"
        );
        cols.clk = F::from_u32(clk);
    }
}
