package koalabear_test

// SOUNDNESS AUDIT (external reviewer). These tests cover the ONE path that
// canonicality_test.go does not touch and that 100% of this tape's canonicalisation
// obligations actually take: ReduceCanonical's FREE branch (UpperBound < p -> return the
// wire with zero constraints emitted).
//
// The free branch emits nothing, so debugNonCanonicalRemainder -- which lives inside
// ReduceHint -- can never reach it: reduceVar is not even called. The existing harness is
// therefore structurally blind here, in exactly the way it was built to avoid being blind
// elsewhere.
//
// The free branch's soundness is carried entirely by Chip.RangeCheckWitness having emitted
// BOTH entry checks. These tests attack that directly, through the exported API, using the
// same shape the tape uses: WitnessF -> RangeCheckWitness -> Felt2Var -> BN254 wire.

import (
	"math/big"
	"testing"

	"github.com/brevis-network/pico/gnark/koalabear"
	"github.com/brevis-network/pico/gnark/poseidon2"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

var (
	p         = big.NewInt(2130706433)
	smallR    = big.NewInt(12345)
	pPlusR    = new(big.Int).Add(big.NewInt(2130706433), big.NewInt(12345))
	twoPow32  = new(big.Int).Lsh(big.NewInt(1), 32)
	twoPow31m = big.NewInt(2147483647)
)

// newWitnessFelt reproduces exactly what koalabear.NewF hands the verifier for a raw witness
// felt: the prover's wire, carrying the untrusted 2^32 bound.
func newWitnessFelt(v frontend.Variable) koalabear.Variable {
	return koalabear.Variable{Value: v, UpperBound: new(big.Int).Set(twoPow32)}
}

func solved(t *testing.T, c, a frontend.Circuit) error {
	t.Helper()
	return test.IsSolved(c, a, ecc.BN254.ScalarField())
}

func mustSolve(t *testing.T, what string, c, a frontend.Circuit) {
	t.Helper()
	if err := solved(t, c, a); err != nil {
		t.Fatalf("%s: expected SOLVED, got: %v", what, err)
	}
}

func mustReject(t *testing.T, what string, c, a frontend.Circuit) {
	t.Helper()
	if err := solved(t, c, a); err == nil {
		t.Fatalf("%s: expected REJECT, but the circuit was SATISFIED "+
			"(a non-canonical representative reached the felt->integer boundary)", what)
	}
}

// ---------------------------------------------------------------------------
// 1. The tape's actual shape: WitnessF -> RangeCheckWitness -> Felt2Var.
//    Out is the raw BN254 wire that goes on to be absorbed by the Poseidon2-BN254
//    sponge and compared against CommittedValuesDigest.
// ---------------------------------------------------------------------------

type entryToVarCircuit struct {
	Felt frontend.Variable
	Out  frontend.Variable
}

func (c *entryToVarCircuit) Define(api frontend.API) error {
	chip := koalabear.NewChip(api)
	f := chip.RangeCheckWitness(newWitnessFelt(c.Felt))
	api.AssertIsEqual(chip.Felt2Var(f), c.Out)
	return nil
}

// TestFreePathRejectsNonCanonicalWitnessFelt is the mutation-kill test.
//
// On this tape every CircuitFelt2Var takes ReduceCanonical's free branch, which emits NO
// constraint. So the only thing standing between the prover and a chosen integer
// representative at the hash boundary is RangeCheckWitness's SECOND entry check. Delete that
// one line -- keeping the tightened bound, which the code permits -- and the whole
// canonicality_test.go suite still passes. This test does not.
func TestFreePathRejectsNonCanonicalWitnessFelt(t *testing.T) {
	shape := &entryToVarCircuit{}

	// Honest: the canonical representative goes through.
	mustSolve(t, "canonical felt r", shape, &entryToVarCircuit{Felt: smallR, Out: smallR})
	mustSolve(t, "canonical felt p-1", shape,
		&entryToVarCircuit{Felt: big.NewInt(2130706432), Out: big.NewInt(2130706432)})

	// THE ATTACK. p+r is the same field element as r and still fits in 31 bits, so the first
	// entry check passes. If the circuit accepts it, the prover has just chosen which integer
	// gets hashed into CommittedValuesDigest for a field element they do not control.
	mustReject(t, "non-canonical witness felt p+r reaches Felt2Var", shape,
		&entryToVarCircuit{Felt: pPlusR, Out: pPlusR})

	// Exactly at the modulus: p is non-canonical (it is 0), must not pass.
	mustReject(t, "witness felt = p reaches Felt2Var", shape,
		&entryToVarCircuit{Felt: p, Out: p})

	// And the boundary is tight rather than merely conservative: p-1 above is accepted.

	// Control: the assert is live, so the REJECTs above are not "everything fails".
	mustReject(t, "wrong Out is rejected", shape,
		&entryToVarCircuit{Felt: smallR, Out: big.NewInt(999)})
}

// TestFreePathIsTheOnlyPathTaken documents WHY the above matters more than the hint-based
// tests: a witness felt that has been through RangeCheckWitness carries UpperBound = p-1, so
// ReduceCanonical returns it untouched. Felt2Var on such a wire emits nothing at all, and the
// misbehaving-hint switch cannot reach it because no hint is involved.
//
// Demonstrated by showing Felt2Var is a pure no-op here: asserting the output equals the
// input wire is satisfiable for every in-range value, with no reduction in between.
func TestFreePathIsTheOnlyPathTaken(t *testing.T) {
	for _, v := range []*big.Int{big.NewInt(0), big.NewInt(1), smallR, big.NewInt(2130706432)} {
		mustSolve(t, "Felt2Var is identity on a post-entry felt "+v.String(),
			&entryToVarCircuit{}, &entryToVarCircuit{Felt: v, Out: v})
	}
}

// ---------------------------------------------------------------------------
// 2. The consequence is a chosen digest, not an abstract one.
// ---------------------------------------------------------------------------

// digestDivergesCircuit hashes the two 31-bit representatives of the SAME KoalaBear field
// element through the same Poseidon2-BN254 sponge the tape uses for CommittedValuesDigest,
// and asserts the two digests differ.
type digestDivergesCircuit struct{}

func (c *digestDivergesCircuit) Define(api frontend.API) error {
	h := poseidon2.NewChip(api)
	s1 := [3]frontend.Variable{smallR, 0, 0}
	s2 := [3]frontend.Variable{pPlusR, 0, 0}
	h.PermuteMut(&s1)
	h.PermuteMut(&s2)
	api.AssertIsDifferent(s1[0], s2[0])
	return nil
}

// TestNonCanonicalRepresentativeChangesTheDigest closes the argument: r and p+r are the same
// felt but hash to different BN254 digests. So "the prover picks the representative" is
// literally "the prover picks the CommittedValuesDigest".
func TestNonCanonicalRepresentativeChangesTheDigest(t *testing.T) {
	mustSolve(t, "hash(r) != hash(p+r)", &digestDivergesCircuit{}, &digestDivergesCircuit{})
}

// ---------------------------------------------------------------------------
// 3. The bound invariant that the free branch trusts is not enforced by the type system.
// ---------------------------------------------------------------------------

// forgedBoundCircuit constructs a koalabear.Variable with a canonical-looking UpperBound and
// no constraint behind it. Both struct fields are exported, so any package that imports
// koalabear can do this; ReduceCanonical then believes the bound and emits nothing.
type forgedBoundCircuit struct {
	Felt frontend.Variable
	Out  frontend.Variable
}

func (c *forgedBoundCircuit) Define(api frontend.API) error {
	chip := koalabear.NewChip(api)
	forged := koalabear.Variable{Value: c.Felt, UpperBound: big.NewInt(2130706432)} // "< p", unbacked
	api.AssertIsEqual(chip.Felt2Var(forged), c.Out)
	return nil
}

// TestForgedUpperBoundIsBelieved is not a bug report against lazy canonicality -- no in-tree
// caller does this -- but it pins the residual risk: ReduceCanonical's free branch is a
// STATEMENT OF TRUST in UpperBound, and UpperBound is a public field on a public struct. Any
// future code path that sets a sub-p bound without emitting the two checks silently unsounds
// every felt->integer boundary in the circuit. This test records that the trust is real by
// showing an arbitrary huge value sails through Felt2Var unchallenged.
func TestForgedUpperBoundIsBelieved(t *testing.T) {
	huge := new(big.Int).Lsh(big.NewInt(1), 200)
	if err := solved(t, &forgedBoundCircuit{}, &forgedBoundCircuit{Felt: huge, Out: huge}); err != nil {
		t.Fatalf("expected the forged bound to be believed (documenting the trust), got: %v", err)
	}
}
