use itertools::Itertools;
use mle_core::utils::batch_multiplicative_inverse_serial;
use p3_field::{ExtensionField, Field};

/// Barycentric weights for evaluating at `z` a polynomial given on the 2^`l_skip`-th roots of
/// unity `omega_skip_pows`: returns `(z^n - 1) / n * 1 / (z - w_i)` for every root `w_i`, with
/// `n = 2^l_skip`. A root equal to `z` gets the factor `1` in place of `1 / 0`.
/// Reference: <https://hackmd.io/@vbuterin/barycentric_evaluation#Special-case-roots-of-unity>.
pub fn compute_barycentric_inv_lagrange_denoms<F: Field, EF: ExtensionField<F>>(
    l_skip: usize,
    omega_skip_pows: &[F],
    z: EF,
) -> Vec<EF> {
    let domain_size = 1usize << l_skip;
    debug_assert_eq!(domain_size, omega_skip_pows.len());
    let diffs = omega_skip_pows
        .iter()
        .map(|&root| match z - root {
            d if d.is_zero() => EF::ONE,
            d => d,
        })
        .collect_vec();
    let vanishing_at_z = z.exp_power_of_2(l_skip) - F::ONE;
    let n_inv = F::from_usize(domain_size).inverse();
    let scale = vanishing_at_z * n_inv;
    let mut weights = batch_multiplicative_inverse_serial(&diffs);
    weights.iter_mut().for_each(|w| *w *= scale);
    weights
}
