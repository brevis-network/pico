package koalabear

// The quintic extension's arithmetic against a reference written from Plonky3's
// trinomial_quintic_mul, and the inverse against Plonky3's own, which the field FFI calls: the
// circuit's InvE solves only if the hint's inverse times its operand is one under MulE, so the two
// agree on the field only if MulE reduces by Plonky3's modulus.

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type ext = [ExtDegree]*big.Int

// referenceMul is a*b in F_p[X]/(X^5 + X^2 - 1), written out as Plonky3's trinomial_quintic_mul
// does rather than through quinticFold, so that a wrong row there does not repeat here.
func referenceMul(a, b ext) ext {
	var c [productLen]*big.Int
	for k := range c {
		c[k] = new(big.Int)
	}
	for i := 0; i < ExtDegree; i++ {
		for j := 0; j < ExtDegree; j++ {
			c[i+j].Add(c[i+j], new(big.Int).Mul(a[i], b[j]))
		}
	}
	add := func(terms ...*big.Int) *big.Int {
		s := new(big.Int)
		for _, t := range terms {
			s.Add(s, t)
		}
		return s.Mod(s, modulus)
	}
	neg := func(x *big.Int) *big.Int { return new(big.Int).Neg(x) }
	return ext{
		add(c[0], c[5], neg(c[8])),
		add(c[1], c[6]),
		add(c[2], neg(c[5]), c[7], c[8]),
		add(c[3], neg(c[6]), c[8]),
		add(c[4], neg(c[7])),
	}
}

// referenceInverse is a^(p^5 - 2) by square and multiply over referenceMul: an inverse that owes
// nothing to Plonky3.
func referenceInverse(a ext) ext {
	exponent := new(big.Int).Exp(modulus, big.NewInt(ExtDegree), nil)
	exponent.Sub(exponent, big.NewInt(2))
	result := ext{big.NewInt(1), new(big.Int), new(big.Int), new(big.Int), new(big.Int)}
	for i := exponent.BitLen() - 1; i >= 0; i-- {
		result = referenceMul(result, result)
		if exponent.Bit(i) == 1 {
			result = referenceMul(result, a)
		}
	}
	return result
}

func reduced(a ext) ext {
	var out ext
	for i := range a {
		out[i] = new(big.Int).Mod(a[i], modulus)
	}
	return out
}

func randomExt(rng *rand.Rand, below *big.Int) ext {
	var e ext
	for i := range e {
		e[i] = new(big.Int).Rand(rng, below)
	}
	return e
}

func uniform(v int64) ext {
	return ext{big.NewInt(v), big.NewInt(v), big.NewInt(v), big.NewInt(v), big.NewInt(v)}
}

func toVariables(e ext) [ExtDegree]frontend.Variable {
	var out [ExtDegree]frontend.Variable
	for i := range e {
		out[i] = e[i]
	}
	return out
}

// mulCircuit asserts that a*b is Want, for operands whose wires carry Bound, by the path Path
// names: MulE's own choice, or one of the two forms it chooses between.
type mulCircuit struct {
	A, B, Want [ExtDegree]frontend.Variable
	Bound      *big.Int `gnark:"-"`
	Path       string   `gnark:"-"`
}

func operand(limbs [ExtDegree]frontend.Variable, bound *big.Int) ExtensionVariable {
	var e ExtensionVariable
	for i := range limbs {
		e.Value[i] = Variable{Value: limbs[i], UpperBound: new(big.Int).Set(bound)}
	}
	return e
}

func (c *mulCircuit) Define(api frontend.API) error {
	chip := NewChip(api)
	a, b := operand(c.A, c.Bound), operand(c.B, c.Bound)
	var got ExtensionVariable
	switch c.Path {
	case "interpolated":
		got = chip.foldProduct(a, b, chip.mulEInterpolated(a, b))
	case "schoolbook":
		got = chip.foldProduct(a, b, chip.mulESchoolbook(a, b))
	default:
		got = chip.MulE(a, b)
	}
	chip.AssertIsEqualE(got, chip.RangeCheckWitnessE(operand(c.Want, modulus_sub_1)))
	return nil
}

func solveMul(t *testing.T, path string, bound *big.Int, a, b, want ext) error {
	t.Helper()
	shape := &mulCircuit{Bound: bound, Path: path}
	assignment := &mulCircuit{A: toVariables(a), B: toVariables(b), Want: toVariables(want), Bound: bound, Path: path}
	return test.IsSolved(shape, assignment, ecc.BN254.ScalarField())
}

var paths = []string{"MulE", "interpolated", "schoolbook"}

func TestTheEvaluationMatrixIsInverted(t *testing.T) {
	for i := 0; i < productLen; i++ {
		for k := 0; k < productLen; k++ {
			// Row i of the evaluation matrix times column k of its inverse.
			s := new(big.Rat)
			for j := 0; j < productLen; j++ {
				var e *big.Rat
				if i == productLen-1 {
					e = big.NewRat(0, 1)
					if j == productLen-1 {
						e = big.NewRat(1, 1)
					}
				} else {
					e = new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(interpolationPoints[i]), big.NewInt(int64(j)), nil))
				}
				s.Add(s, new(big.Rat).Mul(e, interpolationWeights[j][k]))
			}
			want := new(big.Rat)
			if i == k {
				want.SetInt64(1)
			}
			if s.Cmp(want) != 0 {
				t.Fatalf("evaluation row %d times weight column %d is %s, not %s", i, k, s, want)
			}
		}
	}
}

func TestMulEMatchesTheReference(t *testing.T) {
	rng := rand.New(rand.NewSource(1552))
	pMinus1 := new(big.Int).Set(modulus_sub_1)
	cases := [][2]ext{
		{uniform(0), uniform(0)},
		{uniform(1), uniform(1)},
		{uniform(2130706432), uniform(2130706432)},
		// X * X^4 = X^5 = 1 - X^2.
		{ext{big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
			ext{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(1)}},
	}
	for i := 0; i < 24; i++ {
		cases = append(cases, [2]ext{randomExt(rng, modulus), randomExt(rng, modulus)})
	}
	for _, path := range paths {
		for _, c := range cases {
			want := referenceMul(c[0], c[1])
			if err := solveMul(t, path, pMinus1, c[0], c[1], want); err != nil {
				t.Fatalf("%s: %v * %v is not %v: %v", path, c[0], c[1], want, err)
			}
			// The control: the assertion is live.
			wrong := want
			wrong[ExtDegree-1] = new(big.Int).Mod(new(big.Int).Add(want[ExtDegree-1], big.NewInt(1)), modulus)
			if err := solveMul(t, path, pMinus1, c[0], c[1], wrong); err == nil {
				t.Fatalf("%s: %v * %v also gave %v", path, c[0], c[1], wrong)
			}
		}
	}
	x5 := referenceMul(cases[3][0], cases[3][1])
	if want := (ext{big.NewInt(1), big.NewInt(0), new(big.Int).Sub(modulus, big.NewInt(1)), big.NewInt(0), big.NewInt(0)}); !equal(x5, want) {
		t.Fatalf("the reference has X^5 = %v, not 1 - X^2", x5)
	}
}

// Operands far from reduced, as reduceFast leaves them (it reduces only from 2^120): the products
// are then about 2^240, which is where interpolation's exactness argument has to hold.
func TestMulEIsExactOnUnreducedOperands(t *testing.T) {
	rng := rand.New(rand.NewSource(15520))
	bound := new(big.Int).Lsh(big.NewInt(1), 119)
	for _, path := range paths {
		for i := 0; i < 8; i++ {
			a, b := randomExt(rng, bound), randomExt(rng, bound)
			if i == 0 {
				a, b = uniform(0), uniform(0)
				for j := range a {
					a[j] = new(big.Int).Sub(bound, big.NewInt(1))
					b[j] = new(big.Int).Sub(bound, big.NewInt(1))
				}
			}
			want := referenceMul(reduced(a), reduced(b))
			if err := solveMul(t, path, bound, a, b, want); err != nil {
				t.Fatalf("%s: unreduced %v * %v is not %v: %v", path, a, b, want, err)
			}
		}
	}
}

// Past productCap, MulE reduces its operands before it multiplies.
func TestMulEReducesOperandsPastTheCap(t *testing.T) {
	rng := rand.New(rand.NewSource(155200))
	bound := new(big.Int).Lsh(big.NewInt(1), 130)
	if productFits(operand(toVariables(uniform(0)), bound), operand(toVariables(uniform(0)), bound)) {
		t.Fatalf("operands bounded by 2^130 fit productCap: the test no longer reaches the guard")
	}
	a, b := randomExt(rng, bound), randomExt(rng, bound)
	if err := solveMul(t, "MulE", bound, a, b, referenceMul(reduced(a), reduced(b))); err != nil {
		t.Fatal(err)
	}
}

// invCircuit asserts that InvE(A) is Want. InvE itself asserts A * InvE(A) = 1 under MulE.
type invCircuit struct {
	A, Want [ExtDegree]frontend.Variable
}

func (c *invCircuit) Define(api frontend.API) error {
	chip := NewChip(api)
	inverse := chip.InvE(chip.RangeCheckWitnessE(operand(c.A, modulus_sub_1)))
	chip.AssertIsEqualE(inverse, chip.RangeCheckWitnessE(operand(c.Want, modulus_sub_1)))
	return nil
}

func TestInvEIsPlonky3sInverse(t *testing.T) {
	rng := rand.New(rand.NewSource(1552000))
	cases := []ext{uniform(1), uniform(2130706432), {big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(1)}}
	for i := 0; i < 8; i++ {
		cases = append(cases, randomExt(rng, modulus))
	}
	for _, a := range cases {
		want := referenceInverse(a)
		if got := referenceMul(a, want); !equal(got, uniformOne()) {
			t.Fatalf("the reference inverse of %v is wrong: the product is %v", a, got)
		}
		assignment := &invCircuit{A: toVariables(a), Want: toVariables(want)}
		if err := test.IsSolved(&invCircuit{}, assignment, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("InvE(%v) is not %v: %v", a, want, err)
		}
	}
}

// Zero has no inverse: the hint gives zero, and the circuit does not solve rather than the process
// aborting.
func TestInvEOfZeroDoesNotSolve(t *testing.T) {
	assignment := &invCircuit{A: toVariables(uniform(0)), Want: toVariables(uniform(0))}
	if err := test.IsSolved(&invCircuit{}, assignment, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("InvE(0) solved")
	}
}

// costCircuit is one MulE of operands of which only the limbs AWire and BWire mark are wires; the
// rest are constants. Nothing else is in it, so its constraints are the multiplications MulE spends.
type costCircuit struct {
	A, B         [ExtDegree]frontend.Variable
	AWire, BWire [ExtDegree]bool `gnark:"-"`
}

func (c *costCircuit) Define(api frontend.API) error {
	chip := NewChip(api)
	pick := func(limbs [ExtDegree]frontend.Variable, wire [ExtDegree]bool) ExtensionVariable {
		var e ExtensionVariable
		for i := range limbs {
			if wire[i] {
				e.Value[i] = Variable{Value: limbs[i], UpperBound: new(big.Int).Set(modulus_sub_1)}
			} else {
				e.Value[i] = NewFConst("7")
			}
		}
		return e
	}
	chip.MulE(pick(c.A, c.AWire), pick(c.B, c.BWire))
	return nil
}

func TestMulECost(t *testing.T) {
	all := [ExtDegree]bool{true, true, true, true, true}
	none := [ExtDegree]bool{}
	low3 := [ExtDegree]bool{true, true, true}
	for _, c := range []struct {
		name         string
		aWire, bWire [ExtDegree]bool
		want         int
	}{
		{"two wire operands: interpolated", all, all, interpolationMuls},
		{"a felt lifted into the extension: schoolbook", [ExtDegree]bool{true}, all, ExtDegree},
		// The product at infinity is of the leading coefficients, and a's is a constant.
		{"wires at 0 and 1 against five: interpolated, infinity free", [ExtDegree]bool{true, true}, all, interpolationMuls - 1},
		{"wires at 0 and 4 against five: interpolated", [ExtDegree]bool{true, false, false, false, true}, all, interpolationMuls},
		// Nine pairs of wires, against seven nonzero points and the one at 0.
		{"three low wires each: interpolated beats nine pairs", low3, low3, interpolationMuls - 1},
		{"a constant operand: free", none, all, 0},
	} {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &costCircuit{AWire: c.aWire, BWire: c.bWire})
		if err != nil {
			t.Fatal(err)
		}
		if n := ccs.GetNbConstraints(); n != c.want {
			t.Errorf("%s: %d constraints, not %d", c.name, n, c.want)
		}
	}
}

func equal(a, b ext) bool {
	for i := range a {
		if a[i].Cmp(b[i]) != 0 {
			return false
		}
	}
	return true
}

func uniformOne() ext {
	return ext{big.NewInt(1), new(big.Int), new(big.Int), new(big.Int), new(big.Int)}
}
