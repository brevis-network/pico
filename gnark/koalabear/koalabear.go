package koalabear

/*
#cgo LDFLAGS: -L. -lfield_ffi
#include "koalabear_ffi.h"
*/
import "C"

import (
	"fmt"
	"math"
	"math/big"
	"os"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

var modulus = new(big.Int).SetUint64(2130706433)
var modulus_sub_1 = new(big.Int).SetUint64(2130706432)

// twoPow31 and twoPow31_sub_1 are the bound a bare 31-bit range check justifies. Under lazy
// canonicality (see reduceVar) a reduced wire is only known to be < 2^31, not < p, so this
// is the honest post-reduction UpperBound on the lookup branch.
var twoPow31 = new(big.Int).SetUint64(2147483648)
var twoPow31_sub_1 = new(big.Int).SetUint64(2147483647)

// canonShift = 2^24 - 1. Since p = 2^31 - 2^24 + 1, for any v already known to be < 2^31,
//
//	v < p  <=>  v <= 2^31 - 2^24  <=>  v + canonShift < 2^31.
//
// So one extra 31-bit lookup upgrades "31 bits" to "canonical". The "already < 2^31" premise
// is load-bearing: without it a v near -(2^24 - 1) would make the shifted form wrap into range.
const canonShift = uint64(1)<<24 - 1

func init() {
	// These functions must be public so Gnark's hint system can access them.
	solver.RegisterHint(InvFHint)
	solver.RegisterHint(InvEHint)
	solver.RegisterHint(ReduceHint)
	solver.RegisterHint(SplitLimbsHint)
}

type Variable struct {
	Value      frontend.Variable
	UpperBound *big.Int
}

type ExtensionVariable struct {
	Value [4]Variable
}

type Chip struct {
	api          frontend.API
	RangeChecker frontend.Rangechecker
}

func NewChip(api frontend.API) *Chip {
	return &Chip{
		api:          api,
		RangeChecker: rangecheck.New(api),
	}
}

func Zero() Variable {
	return Variable{
		Value:      frontend.Variable("0"),
		UpperBound: new(big.Int).SetUint64(0),
	}
}

func One() Variable {
	return Variable{
		Value:      frontend.Variable("1"),
		UpperBound: new(big.Int).SetUint64(1),
	}
}

func NewFConst(value string) Variable {
	int_value, success := new(big.Int).SetString(value, 10)
	if !success {
		panic("string to int conversion failed")
	}
	// Reject negatives, and only negatives. A negative literal produces a negative UpperBound,
	// which compares BELOW the modulus and therefore takes ReduceCanonical's free path -- the
	// wire crosses the felt -> integer boundary with nothing proved about it. That is the whole
	// hazard.
	//
	// Literals at or above p are deliberately allowed: the bound then honestly exceeds the
	// modulus, ReduceCanonical routes them to reduceVar and they are reduced properly. The
	// Poseidon2-KoalaBear round-constant tables are stored unreduced (e.g. 3964964605 =
	// p + 1834258172), so rejecting them breaks package init for no soundness gain -- which is
	// exactly what a first, over-broad version of this guard did.
	if int_value.Sign() < 0 {
		panic("koalabear.NewFConst: negative literal " + value)
	}
	return Variable{
		Value:      frontend.Variable(value),
		UpperBound: int_value,
	}
}

// RangeCheckWitness emits the entry range checks for a raw witness felt -- one that arrives
// from outside the circuit with no constraints on it at all -- and returns it carrying the
// bound those checks justify.
//
// This is the canonical-witness tightening, and the reason it is one function rather than
// two is lazy canonicality. On the lookup branch it emits the pair
//
//	Check(v, 31)  and  Check(v + canonShift, 31)
//
// which together prove v < p, and only then hands back the canonical bound. Under lazy
// canonicality almost every canonicalisation in the circuit is discharged by this bound (see
// ReduceCanonical's first guard, which returns the wire unproved when UpperBound < p), so a
// version of this that tightened the bound without emitting the checks would silently
// unsound the felt -> integer boundary everywhere. The tightened bound is therefore produced
// BY the routine that emits the proof (see proveCanonicalBound), and freepath_audit_test.go
// is what actually holds the line.
func (c *Chip) RangeCheckWitness(v Variable) Variable {
	return Variable{Value: v.Value, UpperBound: c.proveCanonicalBound(v.Value)}
}

// proveCanonicalBound emits the pair of lookups that prove `v < p` and returns the bound they
// justify. The bound is the return value of the proof, so a mutation that deletes the proof
// deletes the bound with it and the caller stops compiling.
//
// That is a guard rail, not a guarantee: someone can still edit inside this function. The
// actual enforcement is freepath_audit_test.go, which plants exactly that mutation and fails.
// It is worth naming, because an earlier version of this code carried a comment asserting the
// two were inseparable while they were three ordinary statements, and all nine canonicality
// tests passed with the shifted lookup deleted.
//
// p = 2^31 - 2^24 + 1, so `v < p  <=>  v + (2^24 - 1) < 2^31`; the first check bounds v itself
// (without it a large field element near -(2^24-1) would let the shifted form wrap into range).
func (c *Chip) proveCanonicalBound(v frontend.Variable) *big.Int {
	c.RangeChecker.Check(v, 31)
	c.RangeChecker.Check(c.api.Add(v, frontend.Variable(canonShift)), 31)
	return new(big.Int).Set(modulus_sub_1)
}

// RangeCheckWitnessE is RangeCheckWitness over an extension element's four coefficients.
func (c *Chip) RangeCheckWitnessE(e ExtensionVariable) ExtensionVariable {
	for j := 0; j < 4; j++ {
		e.Value[j] = c.RangeCheckWitness(e.Value[j])
	}
	return e
}

func NewF(value string) Variable {
	return Variable{
		Value:      frontend.Variable(value),
		UpperBound: new(big.Int).SetUint64(uint64(math.Pow(2, 32))),
	}
}

func NewE(value []string) ExtensionVariable {
	a := NewF(value[0])
	b := NewF(value[1])
	c := NewF(value[2])
	d := NewF(value[3])
	return ExtensionVariable{Value: [4]Variable{a, b, c, d}}
}

func NewEConst(value []string) ExtensionVariable {
	a := NewFConst(value[0])
	b := NewFConst(value[1])
	c := NewFConst(value[2])
	d := NewFConst(value[3])
	return ExtensionVariable{Value: [4]Variable{a, b, c, d}}
}

func Felts2Ext(a, b, c, d Variable) ExtensionVariable {
	return ExtensionVariable{Value: [4]Variable{a, b, c, d}}
}

func (c *Chip) AddF(a, b Variable, forceReduce ...bool) Variable {
	result := Variable{
		Value:      c.api.Add(a.Value, b.Value),
		UpperBound: new(big.Int).Add(a.UpperBound, b.UpperBound),
	}
	if len(forceReduce) > 0 && !forceReduce[0] {
		return result
	}
	return c.reduceFast(result)
}

func (c *Chip) SubF(a, b Variable) Variable {
	negB := c.negF(b)
	return c.AddF(a, negB)
}

func (c *Chip) MulF(a, b Variable, forceReduce ...bool) Variable {
	result := Variable{
		Value:      c.api.Mul(a.Value, b.Value),
		UpperBound: new(big.Int).Mul(a.UpperBound, b.UpperBound),
	}
	if len(forceReduce) > 0 && !forceReduce[0] {
		return result
	}
	return c.reduceFast(result)
}

func (c *Chip) MulFConst(a Variable, b int, forceReduce ...bool) Variable {
	result := Variable{
		Value:      c.api.Mul(a.Value, b),
		UpperBound: new(big.Int).Mul(a.UpperBound, new(big.Int).SetUint64(uint64(b))),
	}
	if len(forceReduce) > 0 && !forceReduce[0] {
		return result
	}
	return c.reduceFast(result)
}

func (c *Chip) negF(a Variable) Variable {
	divisor := new(big.Int).Div(a.UpperBound, modulus)
	divisorPlusOne := new(big.Int).Add(divisor, big.NewInt(1))
	liftedModulus := new(big.Int).Mul(divisorPlusOne, modulus)

	return c.reduceFast(Variable{
		Value:      c.api.Sub(liftedModulus, a.Value),
		UpperBound: liftedModulus,
	})
}

func (c *Chip) invF(in Variable) Variable {
	result, err := c.api.Compiler().NewHint(InvFHint, 1, in.Value)
	if err != nil {
		panic(err)
	}

	// 2^31 - 1, not 2^31: both branches below prove 31 bits, so the value is at most
	// 2^31 - 1. The distinction matters because ReduceCanonical's cheap path is gated on
	// UpperBound < 2^31.
	xinv := Variable{
		Value:      result[0],
		UpperBound: new(big.Int).Set(twoPow31_sub_1),
	}
	c.RangeChecker.Check(result[0], 31)
	product := c.MulF(in, xinv)
	c.AssertIsEqualF(product, NewFConst("1"))

	return xinv
}

func (c *Chip) DivF(a, b Variable) Variable {
	bInv := c.invF(b)
	return c.MulF(a, bInv)
}

// AssertIsEqualF does NOT need canonical representatives, and deliberately does not pay for
// them.
//
// Write a2 = va + ka*p and b2 = vb + kb*p with va, vb in [0, p) the true field values and
// ka, kb in {0, 1} (ReduceSlow proves both sides < 2^31 < 2p, so no third representative
// exists). a2 == b2 over the integers gives va - vb = (kb - ka)*p with |va - vb| < p, hence
// kb = ka and va = vb. So a non-canonical representative can only make this assert FAIL --
// it can never let a false claim through -- and ReduceHint always returns the canonical
// remainder, so honest provers are unaffected.
func (c *Chip) AssertIsEqualF(a, b Variable) {
	a2 := c.ReduceSlow(a)
	b2 := c.ReduceSlow(b)
	c.api.AssertIsEqual(a2.Value, b2.Value)
}

// AssertNotEqualF is the mirror image of AssertIsEqualF and is genuinely unsound without
// canonicality: v and v + p are the same field element but different integers, so
// AssertIsDifferent on non-canonical representatives would certify a disequality that is
// false mod p. Both sides must be canonical.
func (c *Chip) AssertNotEqualF(a, b Variable) {
	a2 := c.ReduceCanonical(a)
	b2 := c.ReduceCanonical(b)
	c.api.AssertIsDifferent(a2.Value, b2.Value)
}

func (c *Chip) AssertIsEqualE(a, b ExtensionVariable) {
	c.AssertIsEqualF(a.Value[0], b.Value[0])
	c.AssertIsEqualF(a.Value[1], b.Value[1])
	c.AssertIsEqualF(a.Value[2], b.Value[2])
	c.AssertIsEqualF(a.Value[3], b.Value[3])
}

func (c *Chip) SelectF(cond frontend.Variable, a, b Variable) Variable {
	var UpperBound *big.Int
	if a.UpperBound.Cmp(b.UpperBound) == -1 {
		UpperBound = b.UpperBound
	} else {
		UpperBound = a.UpperBound
	}
	return Variable{
		Value:      c.api.Select(cond, a.Value, b.Value),
		UpperBound: UpperBound,
	}
}

func (c *Chip) SelectE(cond frontend.Variable, a, b ExtensionVariable) ExtensionVariable {
	return ExtensionVariable{
		Value: [4]Variable{
			c.SelectF(cond, a.Value[0], b.Value[0]),
			c.SelectF(cond, a.Value[1], b.Value[1]),
			c.SelectF(cond, a.Value[2], b.Value[2]),
			c.SelectF(cond, a.Value[3], b.Value[3]),
		},
	}
}

func (c *Chip) AddEF(a ExtensionVariable, b Variable) ExtensionVariable {
	v1 := c.AddF(a.Value[0], b)
	return ExtensionVariable{Value: [4]Variable{v1, a.Value[1], a.Value[2], a.Value[3]}}
}

func (c *Chip) AddE(a, b ExtensionVariable) ExtensionVariable {
	v1 := c.AddF(a.Value[0], b.Value[0])
	v2 := c.AddF(a.Value[1], b.Value[1])
	v3 := c.AddF(a.Value[2], b.Value[2])
	v4 := c.AddF(a.Value[3], b.Value[3])
	return ExtensionVariable{Value: [4]Variable{v1, v2, v3, v4}}
}

func (c *Chip) SubE(a, b ExtensionVariable) ExtensionVariable {
	v1 := c.SubF(a.Value[0], b.Value[0])
	v2 := c.SubF(a.Value[1], b.Value[1])
	v3 := c.SubF(a.Value[2], b.Value[2])
	v4 := c.SubF(a.Value[3], b.Value[3])
	return ExtensionVariable{Value: [4]Variable{v1, v2, v3, v4}}
}

func (c *Chip) SubEF(a ExtensionVariable, b Variable) ExtensionVariable {
	v1 := c.SubF(a.Value[0], b)
	return ExtensionVariable{Value: [4]Variable{v1, a.Value[1], a.Value[2], a.Value[3]}}
}

// reduceFastThresholdBits mirrors the guard inside reduceFast: below it, reduceFast
// is a no-op, so additions, constant scalings and modulus lifts are all free in R1CS.
const reduceFastThresholdBits = 120

// karatsubaHeadroomBits bounds the blow-up of mulEKaratsuba's coefficients relative to
// max(a)*max(b). The worst coefficient is out0 = p0 + 3*(q2 + r0), which propagates to
// ~112*max(a)*max(b); 2^7 = 128 is the next power of two above that.
const karatsubaHeadroomBits = 7

// subLifted returns a - b without ever invoking reduceFast.
//
// negF always calls reduceFast, which is harmless while bounds stay small but turns into a
// real ~25-30 constraint reduction once they do not. Karatsuba needs twelve subtractions
// where schoolbook needs none, so routing them through negF would trade seven saved
// multiplications for twelve possible reductions. Here the modulus lift is applied directly:
// api.Sub against a constant is a linear combination, hence free.
func (c *Chip) subLifted(a, b Variable) Variable {
	divisor := new(big.Int).Div(b.UpperBound, modulus)
	lifted := new(big.Int).Mul(new(big.Int).Add(divisor, big.NewInt(1)), modulus)
	return Variable{
		Value:      c.api.Add(a.Value, c.api.Sub(lifted, b.Value)),
		UpperBound: new(big.Int).Add(a.UpperBound, lifted),
	}
}

// karatsuba2 multiplies two degree-1 polynomials with three multiplications instead of
// four, returning the three coefficients of the degree-2 product.
func (c *Chip) karatsuba2(u0, u1, v0, v1 Variable) (Variable, Variable, Variable) {
	m0 := c.MulF(u0, v0, false)
	m2 := c.MulF(u1, v1, false)
	t := c.MulF(c.AddF(u0, u1, false), c.AddF(v0, v1, false), false)
	// m1 = u0*v1 + u1*v0 = t - m0 - m2
	m1 := c.subLifted(c.subLifted(t, m0), m2)
	return m0, m1, m2
}

// karatsubaFits reports whether mulEKaratsuba can run without any coefficient crossing the
// reduceFast threshold. When it cannot, the extra modulus lifts would each widen a value that
// is about to be reduced anyway, so the schoolbook form is the cheaper shape.
func karatsubaFits(a, b ExtensionVariable) bool {
	maxBits := func(e ExtensionVariable) int {
		m := 0
		for i := 0; i < 4; i++ {
			if n := e.Value[i].UpperBound.BitLen(); n > m {
				m = n
			}
		}
		return m
	}
	return maxBits(a)+maxBits(b)+karatsubaHeadroomBits < reduceFastThresholdBits
}

// MulE multiplies in KoalaBear's quartic extension F_p[X]/(X^4 - 3).
//
// Additions and constant scalings are free in R1CS (they are linear combinations), so the
// only cost that matters is the number of api.Mul calls: Karatsuba needs 9 where schoolbook
// needs 16.
func (c *Chip) MulE(a, b ExtensionVariable) ExtensionVariable {
	if karatsubaFits(a, b) {
		return c.mulEKaratsuba(a, b)
	}
	return c.mulESchoolbook(a, b)
}

// mulEKaratsuba is the 9-multiplication form.
//
//	A0 = a0 + a1*X   A1 = a2 + a3*X      B0 = b0 + b1*X   B1 = b2 + b3*X
//	P  = A0*B0       R  = A1*B1          Q  = (A0+A1)*(B0+B1) - P - R = A0*B1 + A1*B0
//	a*b = P + Q*X^2 + R*X^4, and X^4 = 3, so
//	  out0 = p0 + 3*(q2 + r0)      out2 = p2 + q0 + 3*r2
//	  out1 = p1 + 3*r1             out3 = q1
func (c *Chip) mulEKaratsuba(a, b ExtensionVariable) ExtensionVariable {
	a0, a1, a2, a3 := a.Value[0], a.Value[1], a.Value[2], a.Value[3]
	b0, b1, b2, b3 := b.Value[0], b.Value[1], b.Value[2], b.Value[3]

	p0, p1, p2 := c.karatsuba2(a0, a1, b0, b1)
	r0, r1, r2 := c.karatsuba2(a2, a3, b2, b3)
	n0, n1, n2 := c.karatsuba2(
		c.AddF(a0, a2, false), c.AddF(a1, a3, false),
		c.AddF(b0, b2, false), c.AddF(b1, b3, false),
	)

	q0 := c.subLifted(c.subLifted(n0, p0), r0)
	q1 := c.subLifted(c.subLifted(n1, p1), r1)
	q2 := c.subLifted(c.subLifted(n2, p2), r2)

	v2 := [4]Variable{
		c.AddF(p0, c.MulFConst(c.AddF(q2, r0, false), 3, false), false),
		c.AddF(p1, c.MulFConst(r1, 3, false), false),
		c.AddF(c.AddF(p2, q0, false), c.MulFConst(r2, 3, false), false),
		q1,
	}
	for i := 0; i < 4; i++ {
		v2[i] = c.reduceFast(v2[i])
	}
	return ExtensionVariable{Value: v2}
}

// mulESchoolbook is the original 16-multiplication form, kept as the fallback for operands
// whose bounds leave Karatsuba no headroom.
func (c *Chip) mulESchoolbook(a, b ExtensionVariable) ExtensionVariable {
	v2 := [4]Variable{
		Zero(),
		Zero(),
		Zero(),
		Zero(),
	}

	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			if i+j >= 4 {
				v2[i+j-4] = c.AddF(v2[i+j-4], c.MulFConst(c.MulF(a.Value[i], b.Value[j], false), 3, false), false)
			} else {
				v2[i+j] = c.AddF(v2[i+j], c.MulF(a.Value[i], b.Value[j], false), false)
			}
		}
	}
	v2[0] = c.reduceFast(v2[0])
	v2[1] = c.reduceFast(v2[1])
	v2[2] = c.reduceFast(v2[2])
	v2[3] = c.reduceFast(v2[3])
	return ExtensionVariable{Value: v2}
}

func (c *Chip) MulEF(a ExtensionVariable, b Variable) ExtensionVariable {
	v1 := c.MulF(a.Value[0], b)
	v2 := c.MulF(a.Value[1], b)
	v3 := c.MulF(a.Value[2], b)
	v4 := c.MulF(a.Value[3], b)
	return ExtensionVariable{Value: [4]Variable{v1, v2, v3, v4}}
}

func (c *Chip) InvE(in ExtensionVariable) ExtensionVariable {
	result, err := c.api.Compiler().NewHint(InvEHint, 4, in.Value[0].Value, in.Value[1].Value, in.Value[2].Value, in.Value[3].Value)
	if err != nil {
		panic(err)
	}

	// 2^31 - 1 for the same reason as in invF.
	xinv := Variable{Value: result[0], UpperBound: new(big.Int).Set(twoPow31_sub_1)}
	yinv := Variable{Value: result[1], UpperBound: new(big.Int).Set(twoPow31_sub_1)}
	zinv := Variable{Value: result[2], UpperBound: new(big.Int).Set(twoPow31_sub_1)}
	linv := Variable{Value: result[3], UpperBound: new(big.Int).Set(twoPow31_sub_1)}
	c.RangeChecker.Check(result[0], 31)
	c.RangeChecker.Check(result[1], 31)
	c.RangeChecker.Check(result[2], 31)
	c.RangeChecker.Check(result[3], 31)
	out := ExtensionVariable{Value: [4]Variable{xinv, yinv, zinv, linv}}

	product := c.MulE(in, out)
	c.AssertIsEqualE(product, NewEConst([]string{"1", "0", "0", "0"}))

	return out
}

func (c *Chip) Ext2Felt(in ExtensionVariable) [4]Variable {
	return in.Value
}

func (c *Chip) DivE(a, b ExtensionVariable) ExtensionVariable {
	bInv := c.InvE(b)
	return c.MulE(a, bInv)
}

func (c *Chip) DivEF(a ExtensionVariable, b Variable) ExtensionVariable {
	bInv := c.invF(b)
	return c.MulEF(a, bInv)
}

func (c *Chip) NegE(a ExtensionVariable) ExtensionVariable {
	v1 := c.negF(a.Value[0])
	v2 := c.negF(a.Value[1])
	v3 := c.negF(a.Value[2])
	v4 := c.negF(a.Value[3])
	return ExtensionVariable{Value: [4]Variable{v1, v2, v3, v4}}
}

// ToBinary reads the felt as an integer -- the 31 bits of v and of v + p differ -- so it
// must canonicalise first. This is the Num2BitsF opcode's implementation.
func (c *Chip) ToBinary(in Variable) []frontend.Variable {
	return c.api.ToBinary(c.ReduceCanonical(in).Value, 31)
}

func (p *Chip) reduceFast(x Variable) Variable {
	if x.UpperBound.BitLen() >= 120 {
		return p.reduceVar(x, false)
	}
	return x
}

// ReduceSlow returns a representative of x mod p that is constrained to fit in 31 bits.
//
// It does NOT promise canonicality. On the lookup branch (lazy canonicality) the returned
// wire may be either r or r + p, whichever the prover chose; both are < 2^31 and congruent to
// x mod p. That is sufficient for every consumer that stays inside mod-p arithmetic, and for
// AssertIsEqualF (see the argument there). Anything that reads the wire as an INTEGER must
// call ReduceCanonical instead.
func (p *Chip) ReduceSlow(x Variable) Variable {
	if x.UpperBound.Cmp(modulus) == -1 {
		return x
	}
	return p.reduceVar(x, false)
}

// ReduceCanonical returns THE canonical representative of x mod p: the returned wire is
// constrained to be < p, so reading it as an integer is meaningful.
//
// Call it at every site where a felt leaves mod-p arithmetic. On the current tape those are:
//   - Chip.ToBinary            (the Num2BitsF opcode)
//   - AssertNotEqualF          (the AssertNeF opcode)
//   - Felt2Var                 (the CircuitFelt2Var / PrintF / PrintE opcodes and
//     poseidon2.ConvertKoalaBear; CircuitFelt2Var feeds the Poseidon2-BN254 sponge and
//     ultimately the VkeyHash / CommittedValuesDigest public inputs)
//
// The middle branch is what makes lazy canonicality nearly free at these sites: a wire that
// is already proved < 2^31 does not need a fresh hint + quotient check + recomposition assert
// to become canonical. It needs exactly the one shifted lookup that reduceVar skipped, and
// nothing else.
func (p *Chip) ReduceCanonical(x Variable) Variable {
	if x.UpperBound.Cmp(modulus) == -1 {
		// The tracked bound already forces canonicality; there is nothing to prove.
		if kbReduceStats {
			fmt.Fprintf(os.Stderr, "KBCANON free\n")
		}
		return x
	}
	// There used to be a shortcut here for bounds already under 2^31: emit one shifted lookup
	// and call it canonical. It was incomplete. A bound under 2^31 does NOT imply the runtime
	// value is under p, and for a value honestly in [p, 2^31) the shifted lookup has no
	// satisfying assignment -- the circuit becomes unprovable rather than the proof becoming
	// invalid, which no honest prover can recover from. The bound cannot distinguish the two
	// cases, so the shortcut was a bet on the witness. It fired zero times on the tape it was
	// written against (measured: all 64,900 ReduceCanonical calls take the free path above),
	// so it bought nothing and is gone. reduceVar handles every remaining case for any value.
	return p.reduceVar(x, true)
}

// Felt2Var is the ONE sanctioned way to turn a felt into a raw BN254 wire, and exists so that
// the felt-read-as-integer boundary has a name that can be grepped for.
//
// Reading Variable.Value directly is fine inside mod-p arithmetic -- that is what the whole
// gadget does -- but the moment a wire leaves for something that is not mod-p arithmetic
// (a hash absorbing it, a bit decomposition, an integer comparison, a public input) it must
// be canonical, or the prover gets to choose between v and v + p and the two give different
// answers. Route every such exit through here.
func (p *Chip) Felt2Var(x Variable) frontend.Variable {
	return p.ReduceCanonical(x).Value
}

// kbReduceStats, when KB_REDUCE_STATS=1, emits one line per real reduction so the
// call count and the maxNbBits distribution can be histogrammed off the stderr stream.
// Reductions are the dominant residual cost in this circuit and were previously only
// estimable by subtracting the explicit opcode costs from the total.
var kbReduceStats = os.Getenv("KB_REDUCE_STATS") == "1"

// reduceVar emits a modular reduction of x and returns the reduced wire together with the
// UpperBound that the constraints it just emitted actually justify.
//
// Value and bound leave through the same return statement. That is the whole design: the
// dangerous combination -- skip the canonicality proof but keep the < p bound -- is not
// expressible in this function, and no caller can construct it because no caller sets the
// bound itself.
//
// LAZY CANONICALITY (canonical == false, lookup branch only). Because p = 2^31 - 2^24 + 1, a
// remainder proved only "< 2^31" is one of at most two representatives of x mod p: r, or
// r + p when r < 2^24 - 1. Everything downstream that only does mod-p arithmetic treats the
// two identically, so the second lookup is owed only where a felt is read as an integer. See
// ReduceCanonical for that list.
func (p *Chip) reduceVar(x Variable, canonical bool) Variable {
	maxNbBits := uint64(x.UpperBound.BitLen())
	if maxNbBits <= 30 {
		// Below 2^30 < p the value is canonical already, whatever the caller asked for.
		return x
	}
	if kbReduceStats {
		fmt.Fprintf(os.Stderr, "KBREDUCE %d canonical=%v\n", maxNbBits, canonical)
	}

	result, err := p.api.Compiler().NewHint(ReduceHint, 2, x.Value)
	if err != nil {
		panic(err)
	}

	quotient := result[0]
	remainder := result[1]

	p.RangeChecker.Check(quotient, int(maxNbBits-30))

	// Canonicality via a second range check instead of a limb split.
	//
	//     rem < p  <=>  rem <= 2^31 - 2^24  <=>  rem + (2^24 - 1) < 2^31.
	// Both sides are pure lookup queries, which displaces the recomposition assert, the
	// IsZero on the high limb and the guarded product that the split-limb form needs.
	//
	// The FIRST check is load-bearing and is never skipped: without a bound on `rem` itself
	// a large field element near -(2^24 - 1) would make the shifted form wrap into range,
	// and the two-representative argument above would collapse.
	p.RangeChecker.Check(remainder, 31)
	bound := twoPow31_sub_1
	if canonical {
		p.RangeChecker.Check(p.api.Add(remainder, frontend.Variable(canonShift)), 31)
		bound = modulus_sub_1
	}
	p.api.AssertIsEqual(x.Value, p.api.Add(p.api.Mul(quotient, modulus), remainder))
	return Variable{Value: remainder, UpperBound: new(big.Int).Set(bound)}
}

// debugNonCanonicalRemainder makes ReduceHint hand back the NON-canonical representative
// r + p whenever that still fits in 31 bits (i.e. whenever r < 2^24 - 1).
//
// It exists because the usual verification is structurally blind to lazy canonicality.
// ReduceHint always returns the canonical remainder, so the honest witness satisfies the
// dropped canonicality check whether or not that check is constrained -- test.IsSolved
// therefore passes identically on a circuit that proves rem < p and on one that does not,
// and says nothing about either. The only way to get evidence is to make the prover
// misbehave in exactly the way the dropped check was supposed to prevent.
//
// It is unexported and written only by canonicality_test.go (same package). No other
// package can reach it, and nothing reads it from the environment.
var debugNonCanonicalRemainder bool

// The hint used to compute Reduce.
func ReduceHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		panic("reduceHint expects 1 input operand")
	}
	input := inputs[0]
	quotient := new(big.Int).Div(input, modulus)
	remainder := new(big.Int).Rem(input, modulus)
	if debugNonCanonicalRemainder && quotient.Sign() > 0 {
		if alt := new(big.Int).Add(remainder, modulus); alt.Cmp(twoPow31) < 0 {
			quotient = new(big.Int).Sub(quotient, big.NewInt(1))
			remainder = alt
		}
	}
	results[0] = quotient
	results[1] = remainder
	return nil
}

func (p *Chip) ReduceE(x ExtensionVariable) ExtensionVariable {
	for i := 0; i < 4; i++ {
		x.Value[i] = p.ReduceSlow(x.Value[i])
	}
	return x
}

func InvFHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	a := C.uint(new(big.Int).Mod(inputs[0], modulus).Uint64())
	ainv := C.koalabearinv(a)
	results[0].SetUint64(uint64(ainv))
	return nil
}

// The hint used to split a KoalaBear Variable into a 7 bit limb (the most significant bits) and a
// 24 bit limb.
func SplitLimbsHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != 1 {
		panic("SplitLimbsHint expects 1 input operand")
	}

	// The KoalaBear field element
	input := inputs[0]

	if input.Cmp(modulus) == 0 || input.Cmp(modulus) == 1 {
		return fmt.Errorf("input is not in the field")
	}

	two_24 := big.NewInt(int64(math.Pow(2, 24)))

	// The least significant bits
	results[0] = new(big.Int).Rem(input, two_24)
	// The most significant bits
	results[1] = new(big.Int).Quo(input, two_24)

	return nil
}

func InvEHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	a := C.uint(new(big.Int).Mod(inputs[0], modulus).Uint64())
	b := C.uint(new(big.Int).Mod(inputs[1], modulus).Uint64())
	c := C.uint(new(big.Int).Mod(inputs[2], modulus).Uint64())
	d := C.uint(new(big.Int).Mod(inputs[3], modulus).Uint64())
	ainv := C.koalabearextinv(a, b, c, d, 0)
	binv := C.koalabearextinv(a, b, c, d, 1)
	cinv := C.koalabearextinv(a, b, c, d, 2)
	dinv := C.koalabearextinv(a, b, c, d, 3)
	results[0].SetUint64(uint64(ainv))
	results[1].SetUint64(uint64(binv))
	results[2].SetUint64(uint64(cinv))
	results[3].SetUint64(uint64(dinv))
	return nil
}
