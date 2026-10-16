//! `Builder` septic-extension (F7) field arithmetic and the elliptic-curve point addition
//! used by the global-interaction (septic LogUp) accumulator checks.

use super::*;

impl<F: PrimeField32 + TwoAdicField + FieldSepticCurve> Builder<F> {
    // ─── F7 arithmetic (degree-7 extension field KoalaBear[z]/(z^7 + 2z^6 - 2)) ────

    pub(super) fn f7_add(&mut self, a: [u32; 7], b: [u32; 7]) -> [u32; 7] {
        std::array::from_fn(|i| self.base_add(a[i], b[i]))
    }

    pub(super) fn f7_sub(&mut self, a: [u32; 7], b: [u32; 7]) -> [u32; 7] {
        std::array::from_fn(|i| self.base_sub(a[i], b[i]))
    }

    pub(super) fn f7_neg(&mut self, a: [u32; 7]) -> [u32; 7] {
        let az = self.addr_zero;
        std::array::from_fn(|i| self.base_sub(az, a[i]))
    }

    /// Build the reduction table mapping `z^m` (m = 0..13) to a degree-<7 polynomial,
    /// derived from the field's septic extension relation `z^7 = Σ EXT_COEFFS[i]·z^i`.
    /// KoalaBear: `z^7 = 2 − 2z^6`, which needs the iterative reduction this table performs.
    /// `red[m][i]` is the canonical-u32 coeff of `z^i`.
    pub(super) fn f7_reduction_table() -> [[u32; 7]; 13] {
        let p: u64 = F::ORDER_U64;
        let ext: [u32; 7] = F::EXT_COEFFS;
        let mut red = [[0u64; 7]; 13];
        for (m, row) in red.iter_mut().enumerate().take(7) {
            row[m] = 1;
        }
        for m in 7..13 {
            let prev = red[m - 1];
            let top = prev[6]; // becomes the z^7 coefficient after the shift
            let mut cur = [0u64; 7];
            cur[1..7].copy_from_slice(&prev[..6]); // multiply by z (shift up)
            for i in 0..7 {
                cur[i] = (cur[i] + top * (ext[i] as u64)) % p; // reduce the z^7 term
            }
            red[m] = cur;
        }
        red.map(|row| row.map(|c| c as u32))
    }

    /// Multiply two F7 elements via convolution + reduction by the field's septic relation.
    pub(super) fn f7_mul(&mut self, a: [u32; 7], b: [u32; 7]) -> [u32; 7] {
        // Step 1: raw convolution c_raw[k] = sum_{i+j=k, 0<=i,j<=6} a[i]*b[j]
        let mut raw = [0u32; 13];
        for k in 0..13usize {
            let start_i = k.saturating_sub(6);
            let end_i = k.min(6);
            raw[k] = self.base_mul(a[start_i], b[k - start_i]);
            for i in (start_i + 1)..=end_i {
                let prod = self.base_mul(a[i], b[k - i]);
                raw[k] = self.base_add(raw[k], prod);
            }
        }

        // Step 2: reduce modulo the septic minimal polynomial. result[i] = Σ_m red[m][i]·raw[m].
        let red = Self::f7_reduction_table();
        let mut result = [self.addr_zero; 7];
        for i in 0..7 {
            let mut acc: Option<u32> = None;
            for m in 0..13 {
                let c = red[m][i];
                if c == 0 {
                    continue;
                }
                let term = if c == 1 {
                    raw[m]
                } else {
                    let ca = self.const_f(c);
                    self.base_mul(raw[m], ca)
                };
                acc = Some(match acc {
                    None => term,
                    Some(a) => self.base_add(a, term),
                });
            }
            result[i] = acc.unwrap_or(self.addr_zero);
        }
        result
    }

    /// Add two Septic elliptic curve points P1 + P2 using hint + sum_checker verification.
    /// Hints 21 F values from the witness stream, in this order: p3.x[0..7], p3.y[0..7],
    /// inv(dx)[0..7] — the host replay must push them in exactly this layout per add.
    ///
    /// The sum-checker constraints pin the hinted P3 uniquely only when dx = p2x - p1x != 0
    /// (at dx = 0 the x-checker collapses to -dy^2 == 0 and leaves P3 free), so the hinted
    /// F7 inverse of dx is asserted (`dx * inv_dx == 1`), making the degenerate case
    /// unsatisfiable. Honest inputs are hash-derived curve points, so an x-coordinate
    /// collision (the only way honest proving could fail this) is negligible.
    pub(super) fn curve_add_septic(
        &mut self,
        p1x: [u32; 7],
        p1y: [u32; 7],
        p2x: [u32; 7],
        p2y: [u32; 7],
    ) -> ([u32; 7], [u32; 7]) {
        // Hint: read P3 = P1 + P2 from witness stream (14 F values: x then y), then inv(dx).
        let p3x: [u32; 7] = std::array::from_fn(|_| self.hint_f());
        let p3y: [u32; 7] = std::array::from_fn(|_| self.hint_f());
        let inv_dx: [u32; 7] = std::array::from_fn(|_| self.hint_f());

        // dx = p2x - p1x,  dy = p2y - p1y
        let dx = self.f7_sub(p2x, p1x);
        let dy = self.f7_sub(p2y, p1y);

        // dx != 0: dx * inv_dx == 1 in F7 (limb 0 == 1, limbs 1..7 == 0).
        let dx_inv_check = self.f7_mul(dx, inv_dx);
        self.assert_f_eq(dx_inv_check[0], self.addr_one);
        for &limb in dx_inv_check.iter().skip(1) {
            self.assert_f_eq(limb, self.addr_zero);
        }

        // Verify sum_checker_x = (p1x + p2x + p3x) * dx^2 - dy^2 = 0
        let dx_sq = self.f7_mul(dx, dx);
        let dy_sq = self.f7_mul(dy, dy);
        let p1x_p2x = self.f7_add(p1x, p2x);
        let sx = self.f7_add(p1x_p2x, p3x);
        let sx_dx_sq = self.f7_mul(sx, dx_sq);
        let check_x = self.f7_sub(sx_dx_sq, dy_sq);
        let az = self.addr_zero;
        for i in 0..7 {
            self.assert_f_eq(check_x[i], az);
        }

        // Verify sum_checker_y = (p1y + p3y) * dx - dy * (p1x - p3x) = 0
        let sy = self.f7_add(p1y, p3y);
        let sy_dx = self.f7_mul(sy, dx);
        let x1_minus_x3 = self.f7_sub(p1x, p3x);
        let dy_x1x3 = self.f7_mul(dy, x1_minus_x3);
        let check_y = self.f7_sub(sy_dx, dy_x1x3);
        for i in 0..7 {
            self.assert_f_eq(check_y[i], az);
        }

        (p3x, p3y)
    }
}
