package koalabear

// Negative tests for lazy canonicality.
//
// WHY THIS FILE EXISTS. reduceVar with canonical=false drops the proof that the reduction's
// remainder is < p, keeping only "< 31 bits". ReduceHint nevertheless always returns the
// canonical remainder, so an honest witness satisfies the dropped check whether or not it is
// constrained. Every ordinary satisfiability check therefore passes identically on the
// constrained and the unconstrained circuit and is worthless as evidence about this lever.
//
// The tests below instead flip debugNonCanonicalRemainder, which makes the hint return
// r + p (the other 31-bit representative of the same field element), and then assert BOTH
// directions:
//
//	ACCEPT  -- at a site where canonicality was deliberately dropped the circuit must accept
//	           r + p. If it rejected, the check would still be there and laziness would be
//	           silently inert.
//	REJECT  -- at every site that reads a felt as an integer the circuit must reject r + p.
//	           This is the property the lever is trading against.
//
// TestHazardIsReal_AssertNotEqual and TestHazardIsReal_ToBinary additionally build the
// pre-fix shape by hand and show it accepting a FALSE statement, so the reader can see that
// the forced-canonical sites are load-bearing and not defensive decoration.

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// smallR is a remainder small enough that r + p still fits in 31 bits (needs r < 2^24 - 1),
// which is exactly the window in which the dropped check would have mattered. It is odd, so
// its low bit differs from that of r + p (p is odd, so r + p is even) -- see the ToBinary test.
const smallR = 12345

var (
	// pPlusSmallR = p + smallR. Reduced honestly this is smallR with quotient 1; the
	// misbehaving hint returns it unchanged with quotient 0.
	pPlusSmallR = new(big.Int).Add(modulus, big.NewInt(smallR))
	wideBound   = new(big.Int).SetUint64(1 << 32)
)

func solve(t *testing.T, circuit, assignment frontend.Circuit) error {
	t.Helper()
	return test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
}

func mustSolve(t *testing.T, what string, circuit, assignment frontend.Circuit) {
	t.Helper()
	if err := solve(t, circuit, assignment); err != nil {
		t.Fatalf("%s: expected SOLVED, got error: %v", what, err)
	}
}

func mustReject(t *testing.T, what string, circuit, assignment frontend.Circuit) {
	t.Helper()
	if err := solve(t, circuit, assignment); err == nil {
		t.Fatalf("%s: expected REJECT, but the circuit was satisfied", what)
	}
}

func withEvilHint(t *testing.T, f func()) {
	t.Helper()
	debugNonCanonicalRemainder = true
	defer func() { debugNonCanonicalRemainder = false }()
	f()
}

// ---------------------------------------------------------------------------
// 0. Harness sanity. If the test engine does not actually enforce the lookup range
//    checks, every "REJECT" below would be vacuous. Establish that it does before
//    believing anything else in this file.
// ---------------------------------------------------------------------------

type rangeProbe struct{ V frontend.Variable }

func (c *rangeProbe) Define(api frontend.API) error {
	chip := NewChip(api)
	chip.RangeChecker.Check(c.V, 8)
	return nil
}

func TestHarnessEnforcesRangeChecks(t *testing.T) {
	mustSolve(t, "in-range probe", &rangeProbe{}, &rangeProbe{V: 200})
	mustReject(t, "out-of-range probe", &rangeProbe{}, &rangeProbe{V: 1000})
}

// TestMisbehavingHintIsWiredUp checks the other half of the harness: that flipping
// debugNonCanonicalRemainder really changes what the hint returns. Otherwise the ACCEPT
// tests below would pass for the boring reason.
func TestMisbehavingHintIsWiredUp(t *testing.T) {
	in := []*big.Int{new(big.Int).Set(pPlusSmallR)}
	out := []*big.Int{new(big.Int), new(big.Int)}
	if err := ReduceHint(nil, in, out); err != nil {
		t.Fatal(err)
	}
	if out[0].Cmp(big.NewInt(1)) != 0 || out[1].Cmp(big.NewInt(smallR)) != 0 {
		t.Fatalf("honest hint should give (1, %d), got (%v, %v)", smallR, out[0], out[1])
	}
	withEvilHint(t, func() {
		out := []*big.Int{new(big.Int), new(big.Int)}
		if err := ReduceHint(nil, in, out); err != nil {
			t.Fatal(err)
		}
		if out[0].Sign() != 0 || out[1].Cmp(pPlusSmallR) != 0 {
			t.Fatalf("misbehaving hint should give (0, p+%d), got (%v, %v)", smallR, out[0], out[1])
		}
	})
}

// ---------------------------------------------------------------------------
// 1. ACCEPT direction: the lazy reduce really did drop the check.
// ---------------------------------------------------------------------------

// reduceCircuit reduces a wide input and compares the reduced wire against Out.
// Canonical selects ReduceSlow (lazy) or ReduceCanonical.
type reduceCircuit struct {
	In        frontend.Variable
	Out       frontend.Variable
	Canonical bool
}

func (c *reduceCircuit) Define(api frontend.API) error {
	chip := NewChip(api)
	v := Variable{Value: c.In, UpperBound: new(big.Int).Set(wideBound)}
	var r Variable
	if c.Canonical {
		r = chip.ReduceCanonical(v)
	} else {
		r = chip.ReduceSlow(v)
	}
	api.AssertIsEqual(r.Value, c.Out)
	return nil
}

func TestLazyReduceAcceptsNonCanonicalRemainder(t *testing.T) {
	shape := func(canon bool) *reduceCircuit { return &reduceCircuit{Canonical: canon} }

	// Control: honest hint, lazy reduce, canonical answer.
	mustSolve(t, "honest/lazy", shape(false),
		&reduceCircuit{In: pPlusSmallR, Out: big.NewInt(smallR), Canonical: false})

	withEvilHint(t, func() {
		// THE POINT. Lazy canonicality means the circuit no longer knows the difference: it
		// accepts the non-canonical representative p + smallR as the output of ReduceSlow. If this
		// were to start failing, the second lookup would be back and the lever inert.
		mustSolve(t, "evil/lazy accepts p+r", shape(false),
			&reduceCircuit{In: pPlusSmallR, Out: pPlusSmallR, Canonical: false})

		// ... and the assert is genuinely live, so the ACCEPT above is not "everything passes".
		mustReject(t, "evil/lazy still rejects the wrong answer", shape(false),
			&reduceCircuit{In: pPlusSmallR, Out: big.NewInt(smallR), Canonical: false})
	})
}

// ---------------------------------------------------------------------------
// 2. REJECT direction: ReduceCanonical still nails it down.
// ---------------------------------------------------------------------------

func TestReduceCanonicalRejectsNonCanonicalRemainder(t *testing.T) {
	shape := &reduceCircuit{Canonical: true}

	mustSolve(t, "honest/canonical", shape,
		&reduceCircuit{In: pPlusSmallR, Out: big.NewInt(smallR), Canonical: true})

	withEvilHint(t, func() {
		mustReject(t, "evil/canonical rejects p+r", shape,
			&reduceCircuit{In: pPlusSmallR, Out: pPlusSmallR, Canonical: true})
		// Not satisfiable with the canonical answer either: the hint's quotient/remainder
		// pair is what it is, and the shifted lookup fails on it.
		mustReject(t, "evil/canonical rejects r too", shape,
			&reduceCircuit{In: pPlusSmallR, Out: big.NewInt(smallR), Canonical: true})
	})
}

// cheapPathCircuit exercises ReduceCanonical's middle branch: a wire whose tracked bound is
// already 2^31-1 (what a lazy reduce hands out) gets upgraded with one shifted lookup and no
// new hint. That branch is where almost all of the lazy canonicalisation happens, so it
// needs its own negative test -- no hint is involved, so the misbehaving-hint switch would
// not reach it.
// cheapPathCircuit drives ReduceCanonical over the bound window (p, 2^31) -- the window the
// deleted shortcut used to claim. Want is the canonical representative the reduction must
// produce, so the circuit pins the VALUE, not merely satisfiability: a reduction that returned
// the input unchanged would satisfy a bare call and is caught here.
type cheapPathCircuit struct {
	In   frontend.Variable
	Want frontend.Variable
}

func (c *cheapPathCircuit) Define(api frontend.API) error {
	chip := NewChip(api)
	v := Variable{Value: c.In, UpperBound: new(big.Int).Set(twoPow31_sub_1)}
	got := chip.ReduceCanonical(v)
	api.AssertIsEqual(got.Value, c.Want)
	return nil
}

// The shortcut this used to test is gone. It fired when the BOUND was under 2^31 and emitted a
// single shifted lookup, which is unsatisfiable for a value honestly in [p, 2^31) -- the
// circuit became unprovable rather than the proof invalid, and no honest prover could recover.
// The previous version of this test asserted that rejection as if it were the specification,
// which meant it would have gone green on the bug forever.
//
// What must hold now: every value in the window is PROVABLE, and reduction yields the canonical
// representative. p reduces to 0 and p+r to r; those two cases are exactly the ones the old
// shortcut could not prove.
func TestReduceCanonicalOverBoundWindowIsCompleteAndCanonical(t *testing.T) {
	cases := []struct {
		name     string
		in, want *big.Int
	}{
		{"r stays r", big.NewInt(smallR), big.NewInt(smallR)},
		{"p-1 stays p-1", modulus_sub_1, modulus_sub_1},
		{"p reduces to 0", modulus, big.NewInt(0)},
		{"p+r reduces to r", pPlusSmallR, big.NewInt(smallR)},
	}
	for _, c := range cases {
		mustSolve(t, c.name, &cheapPathCircuit{}, &cheapPathCircuit{In: c.in, Want: c.want})
	}
	// And the reduction is not vacuous: claiming p reduces to anything but 0 must fail.
	mustReject(t, "p does not reduce to r", &cheapPathCircuit{},
		&cheapPathCircuit{In: modulus, Want: big.NewInt(smallR)})
}

// ---------------------------------------------------------------------------
// 3. The hazard is real: the pre-fix shapes certify false statements.
// ---------------------------------------------------------------------------

// assertNeCircuit asserts In != smallR as felts. In is assigned p + smallR, which IS smallR
// mod p, so the honest answer is always REJECT. Unsafe==true reproduces what AssertNotEqualF
// looked like before lazy canonicality forced the canonical form on it.
type assertNeCircuit struct {
	In     frontend.Variable
	Unsafe bool
}

func (c *assertNeCircuit) Define(api frontend.API) error {
	chip := NewChip(api)
	a := Variable{Value: c.In, UpperBound: new(big.Int).Set(wideBound)}
	b := NewFConst("12345")
	if c.Unsafe {
		api.AssertIsDifferent(chip.ReduceSlow(a).Value, chip.ReduceSlow(b).Value)
		return nil
	}
	chip.AssertNotEqualF(a, b)
	return nil
}

func TestHazardIsReal_AssertNotEqual(t *testing.T) {
	// Honest hint: both shapes correctly refuse to certify p+r != r.
	mustReject(t, "honest/safe", &assertNeCircuit{}, &assertNeCircuit{In: pPlusSmallR})
	mustReject(t, "honest/unsafe", &assertNeCircuit{Unsafe: true},
		&assertNeCircuit{In: pPlusSmallR, Unsafe: true})

	withEvilHint(t, func() {
		// THE HAZARD. With ReduceSlow on both sides the prover gets p+r on the left and r on
		// the right and the circuit certifies "p+r != r", i.e. x != x. This is the concrete
		// reason AssertNotEqualF must not use ReduceSlow.
		mustSolve(t, "evil/unsafe certifies x != x", &assertNeCircuit{Unsafe: true},
			&assertNeCircuit{In: pPlusSmallR, Unsafe: true})

		// The shipped AssertNotEqualF closes it.
		mustReject(t, "evil/safe", &assertNeCircuit{}, &assertNeCircuit{In: pPlusSmallR})
	})
}

// toBinaryCircuit asserts that bit 0 of In equals Bit0. smallR is odd and p + smallR is even
// (p is odd), so a non-canonical representative flips the answer.
type toBinaryCircuit struct {
	In     frontend.Variable
	Bit0   frontend.Variable
	Unsafe bool
}

func (c *toBinaryCircuit) Define(api frontend.API) error {
	chip := NewChip(api)
	v := Variable{Value: c.In, UpperBound: new(big.Int).Set(wideBound)}
	var bits []frontend.Variable
	if c.Unsafe {
		bits = api.ToBinary(chip.ReduceSlow(v).Value, 31)
	} else {
		bits = chip.ToBinary(v)
	}
	api.AssertIsEqual(bits[0], c.Bit0)
	return nil
}

func TestHazardIsReal_ToBinary(t *testing.T) {
	// p + smallR reduces to smallR, which is odd.
	mustSolve(t, "honest/safe bit0=1", &toBinaryCircuit{},
		&toBinaryCircuit{In: pPlusSmallR, Bit0: 1})
	mustReject(t, "honest/safe bit0=0", &toBinaryCircuit{},
		&toBinaryCircuit{In: pPlusSmallR, Bit0: 0})

	withEvilHint(t, func() {
		// THE HAZARD: the unsafe shape decomposes p + smallR, whose low bit is 0, and so
		// certifies that the felt is even when it is odd.
		mustSolve(t, "evil/unsafe certifies the wrong parity", &toBinaryCircuit{Unsafe: true},
			&toBinaryCircuit{In: pPlusSmallR, Bit0: 0, Unsafe: true})

		// Chip.ToBinary (the Num2BitsF opcode) closes it: neither parity is satisfiable,
		// because the canonicalisation itself rejects the witness.
		mustReject(t, "evil/safe bit0=0", &toBinaryCircuit{},
			&toBinaryCircuit{In: pPlusSmallR, Bit0: 0})
		mustReject(t, "evil/safe bit0=1", &toBinaryCircuit{},
			&toBinaryCircuit{In: pPlusSmallR, Bit0: 1})
	})
}

// ---------------------------------------------------------------------------
// 4. AssertIsEqualF is deliberately NOT canonicalised. Its safety argument is that a
//    non-canonical representative can only make it fail, never let a false claim through.
//    Both halves of that are checked here.
// ---------------------------------------------------------------------------

type assertEqCircuit struct {
	A frontend.Variable
	B frontend.Variable
}

func (c *assertEqCircuit) Define(api frontend.API) error {
	chip := NewChip(api)
	wide := func(v frontend.Variable) Variable {
		return Variable{Value: v, UpperBound: new(big.Int).Set(wideBound)}
	}
	chip.AssertIsEqualF(wide(c.A), wide(c.B))
	return nil
}

func TestAssertIsEqualFStaysSoundWithoutCanonicality(t *testing.T) {
	// Equal mod p, honest hint: both sides canonicalise to the same wire.
	mustSolve(t, "honest equal", &assertEqCircuit{},
		&assertEqCircuit{A: pPlusSmallR, B: new(big.Int).Add(new(big.Int).Mul(modulus, big.NewInt(3)), big.NewInt(smallR))})
	// Different mod p: rejected.
	mustReject(t, "honest different", &assertEqCircuit{},
		&assertEqCircuit{A: pPlusSmallR, B: big.NewInt(smallR + 1)})

	withEvilHint(t, func() {
		// Still cannot certify a false equality: the misbehaving hint shifts BOTH sides by
		// the same p, so unequal field elements stay unequal as integers.
		mustReject(t, "evil different", &assertEqCircuit{},
			&assertEqCircuit{A: pPlusSmallR, B: big.NewInt(smallR + 1)})
	})
}

// TestLeverCIsActuallyOn fails loudly if someone re-enables the canonicality lookup on every
// reduction, which would leave the measured constraint count silently back at the old number.
func TestLeverCIsActuallyOn(t *testing.T) {
	c := &reduceCircuit{Canonical: false}
	a := &reduceCircuit{In: pPlusSmallR, Out: pPlusSmallR, Canonical: false}
	withEvilHint(t, func() {
		if err := solve(t, c, a); err != nil {
			t.Fatalf("Lever C appears to be OFF: the lazy reduce rejected a non-canonical "+
				"remainder, which means the rem < p lookup is still being emitted on every "+
				"reduction. Error: %v", err)
		}
	})
}
