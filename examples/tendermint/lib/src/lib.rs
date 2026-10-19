use std::time::Duration;

use tendermint_light_client_verifier::{
    options::Options, types::LightBlock, ProdVerifier, Verdict, Verifier,
};

/// Verify the update from `trusted` to `untrusted`. The guest commits this verdict and the host
/// recomputes it, so both call this one function and cannot disagree on the options or the clock.
///
/// The clock is the untrusted block's own time plus 20 s, so the verdict depends on the two blocks
/// alone; the 500 s trusting period covers the gap between them.
pub fn verify_update(trusted: &LightBlock, untrusted: &LightBlock) -> Result<Verdict, String> {
    let options = Options {
        trust_threshold: Default::default(),
        trusting_period: Duration::from_secs(500),
        clock_drift: Default::default(),
    };
    let now = (untrusted.time() + Duration::from_secs(20)).map_err(|e| e.to_string())?;
    Ok(ProdVerifier::default().verify_update_header(
        untrusted.as_untrusted_state(),
        trusted.as_trusted_state(),
        &options,
        now,
    ))
}
