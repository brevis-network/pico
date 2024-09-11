use crate::chips::cpu::columns::{ChannelSelectorCols, NUM_BYTE_LOOKUP_CHANNELS};
use p3_field::Field;

impl<F: Field> ChannelSelectorCols<F> {
    #[inline(always)]
    pub fn populate(&mut self, channel: u8) {
        self.channel_selector = [F::zero(); NUM_BYTE_LOOKUP_CHANNELS as usize];
        self.channel_selector[channel as usize] = F::one();
    }
}
