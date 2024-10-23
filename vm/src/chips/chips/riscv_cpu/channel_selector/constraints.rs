use super::super::channel_selector::columns::ChannelSelectorCols;
use crate::chips::chips::byte::NUM_BYTE_LOOKUP_CHANNELS;
use p3_air::AirBuilder;
use p3_field::AbstractField;

pub fn eval_channel_selector<AB: AirBuilder>(
    builder: &mut AB,
    local: &ChannelSelectorCols<AB::Var>,
    next: &ChannelSelectorCols<AB::Var>,
    channel: impl Into<AB::Expr> + Clone,
    local_is_real: impl Into<AB::Expr> + Clone,
    next_is_real: impl Into<AB::Expr> + Clone,
) {
    // Constrain:
    // - the value of the channel is given by the channel selectors.
    // - all selectors are boolean and disjoint.
    let mut sum = AB::Expr::zero();
    let mut reconstruct_channel = AB::Expr::zero();
    for (i, selector) in local.channel_selector.into_iter().enumerate() {
        // Constrain that the selector is boolean.
        builder.assert_bool(selector);
        // Accumulate the sum of the selectors.
        sum += selector.into();
        // Accumulate the reconstructed channel.
        reconstruct_channel += selector.into() * AB::Expr::from_canonical_u32(i as u32);
    }
    // Assert that the reconstructed channel is the same as the channel.
    builder.assert_eq(reconstruct_channel, channel.clone());
    // For disjointness, assert the sum of the selectors is 1.
    builder
        .when(local_is_real.clone())
        .assert_eq(sum, AB::Expr::one());

    // Constrain the first row by asserting that the first selector on the first line is true.
    builder
        .when_first_row()
        .assert_one(local.channel_selector[0]);

    // Constrain the transition by asserting that the selectors satisfy the field_config relation:
    // selectors_next[(i + 1) % NUM_BYTE_LOOKUP_CHANNELS] = selectors[i]
    for i in 0..NUM_BYTE_LOOKUP_CHANNELS as usize {
        builder
            .when_transition()
            .when(next_is_real.clone())
            .assert_eq(
                local.channel_selector[i],
                next.channel_selector[(i + 1) % NUM_BYTE_LOOKUP_CHANNELS as usize],
            );
    }
}
