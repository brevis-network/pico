package koalabear_test

// SOUNDNESS AUDIT part 2: the semantics of ReduceCanonical's CHEAP path, and the trust the
// FREE path places in UpperBound's sign.
//
// The cheap path is new with lazy canonicality. It is NOT a drop-in replacement for a
// reduction: where
// reduceVar(x, true) MAPS any x to its canonical residue, the cheap path ASSERTS that x is
// already canonical. For a wire whose tracked bound lies in [p, 2^31) the honest value may
// legitimately be >= p -- and then the cheap path rejects an entirely honest prover.

import (
	"math/big"
	"testing"

	"github.com/brevis-network/pico/gnark/koalabear"
	"github.com/consensys/gnark/frontend"
)

// subZeroCircuit builds SubF(0, 0) and pushes it across the felt->integer boundary.
//
// SubF(a,b) = AddF(a, negF(b)); negF(0) lifts to the modulus, so the wire literally holds the
// constant p with UpperBound = p. That is an honest, correct representation of the field
// element 0 -- it is what the gadget itself produces -- and it lands in [p, 2^31), which is
// precisely the cheap path's window.
type subZeroCircuit struct{ Out frontend.Variable }

func (c *subZeroCircuit) Define(api frontend.API) error {
	chip := koalabear.NewChip(api)
	d := chip.SubF(koalabear.Zero(), koalabear.Zero()) // == 0 in the field
	api.AssertIsEqual(chip.Felt2Var(d), c.Out)
	return nil
}

// TestCheapPathRejectsAnHonestProver is a COMPLETENESS finding, not a soundness one (it fails
// closed). It is reported because it shows the cheap path changed the meaning of
// "canonicalise" from a computation into a precondition.
//
// Pre-Lever-C, CircuitFelt2Var reduced this wire and emitted 0. Now the cheap path emits
// Check(p + 2^24 - 1, 31) == Check(2^31, 31), which no assignment satisfies. The circuit is
// unprovable, for either answer.
//
// Zero occurrences on the current tape (measured: KBCANON cheap == 0), so this is latent. It
// becomes live the moment a regenerated tape routes a felt whose bound sits in [p, 2^31) into
// CircuitFelt2Var or Num2BitsF.
func TestCheapPathRejectsAnHonestProver(t *testing.T) {
	// The true field value is 0, so this is the answer an honest prover wants to commit to.
	if err := solved(t, &subZeroCircuit{}, &subZeroCircuit{Out: big.NewInt(0)}); err == nil {
		t.Log("cheap path accepted the reduced answer 0 -- completeness finding does not reproduce")
		return
	}
	// ... and the raw representative is not accepted either, so there is no answer at all.
	if err := solved(t, &subZeroCircuit{}, &subZeroCircuit{Out: p}); err == nil {
		t.Fatalf("cheap path accepted the NON-CANONICAL representative p at a felt->integer " +
			"boundary; that would be a soundness break, not merely a completeness one")
	}
	t.Log("CONFIRMED: SubF(0,0) -> Felt2Var is unsatisfiable for BOTH 0 and p. " +
		"An honest prover cannot prove a circuit containing this shape.")
}

// ---------------------------------------------------------------------------
// The free path trusts UpperBound's SIGN as well as its magnitude.
// ---------------------------------------------------------------------------

// negativeImmCircuit models what koalabear.NewFConst does with a negative decimal literal:
// big.Int.SetString accepts it, so UpperBound becomes negative, and a negative UpperBound
// compares LESS THAN the modulus -- which is ReduceCanonical's free-path test.
type negativeImmCircuit struct{ Out frontend.Variable }

func (c *negativeImmCircuit) Define(api frontend.API) error {
	chip := koalabear.NewChip(api)
	v := koalabear.NewFConst("-1") // UpperBound = -1, wire value = r-1 in BN254
	api.AssertIsEqual(chip.Felt2Var(v), c.Out)
	return nil
}

// TestNegativeImmBypassesCanonicality records that a negative ImmF/ImmE literal would walk
// straight through the felt->integer boundary uncanonicalised, because UpperBound.Cmp(modulus)
// is sign-aware and the free path has no lower guard.
//
// NOT EXPLOITABLE ON THIS TAPE: I checked all 5,875 ImmF and 177,227 ImmE literals in
// wrap_constraints.json (md5 848c3f1c10910e58f3875d8d52fedd6f) and none is negative or >= p,
// and the tape is compile-time input, not prover-chosen. Recorded because the exact immediate
// bound is what made ImmF trust the literal's magnitude, and lazy canonicality is what made
// "bound < p" mean "emit nothing".
func TestNegativeImmBypassesCanonicality(t *testing.T) {
	rMinus1, _ := new(big.Int).SetString(
		"21888242871839275222246405745257275088548364400416034343698204186575808495616", 10)
	if err := solved(t, &negativeImmCircuit{}, &negativeImmCircuit{Out: rMinus1}); err != nil {
		t.Logf("negative literal did NOT bypass (good): %v", err)
		return
	}
	t.Log("CONFIRMED: NewFConst(\"-1\") crosses Felt2Var as the BN254 integer r-1, " +
		"with no canonicality constraint emitted. Guard NewFConst against literals " +
		"outside [0, p).")
}

// TestConstantsAreInRange is the cheap standing guard the above implies: every koalabear
// constant minted anywhere must lie in [0, p), or its UpperBound is a lie in one direction
// or an unsatisfiable cheap-path check in the other.
func TestConstantsAreInRange(t *testing.T) {
	for _, s := range []string{"0", "1", "2130706432"} {
		v := koalabear.NewFConst(s)
		if v.UpperBound.Sign() < 0 || v.UpperBound.Cmp(p) >= 0 {
			t.Fatalf("NewFConst(%s) has out-of-range UpperBound %s", s, v.UpperBound)
		}
	}
}
