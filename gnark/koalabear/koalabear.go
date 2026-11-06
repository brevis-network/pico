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

// ExtDegree is the degree of KoalaBear's extension F_p[X]/(X^5 + X^2 - 1), Plonky3's
// QuinticTrinomialExtensionField<KoalaBear> (mle-core's EF). An extension element is its five
// coefficients, lowest first, in the order the Rust side writes them: ImmE's literals, Ext2Felt's
// and CircuitFelts2Ext's limbs, and each row of the witness's exts.
const ExtDegree = 5

type ExtensionVariable struct {
	Value [ExtDegree]Variable
}

type Chip struct {
	api          frontend.API
	RangeChecker frontend.Rangechecker
	// interpolation is interpolationWeights reduced into the circuit's field, made on first use.
	interpolation *[productLen][productLen]*big.Int
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

// RangeCheckWitnessE is RangeCheckWitness over an extension element's five coefficients.
func (c *Chip) RangeCheckWitnessE(e ExtensionVariable) ExtensionVariable {
	for j := 0; j < ExtDegree; j++ {
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

// NewE takes exactly ExtDegree coefficients. Any other count is a writer on another extension
// degree, so it panics rather than drop or invent a coefficient.
func NewE(value []string) ExtensionVariable {
	checkExtDegree("NewE", len(value))
	var e ExtensionVariable
	for i := range e.Value {
		e.Value[i] = NewF(value[i])
	}
	return e
}

// NewEConst is NewE for a literal: each coefficient is bounded exactly, as NewFConst does.
func NewEConst(value []string) ExtensionVariable {
	checkExtDegree("NewEConst", len(value))
	var e ExtensionVariable
	for i := range e.Value {
		e.Value[i] = NewFConst(value[i])
	}
	return e
}

func checkExtDegree(what string, n int) {
	if n != ExtDegree {
		panic(fmt.Sprintf("koalabear.%s: %d coefficients, not KoalaBear^%d's %d", what, n, ExtDegree, ExtDegree))
	}
}

func Felts2Ext(limbs [ExtDegree]Variable) ExtensionVariable {
	return ExtensionVariable{Value: limbs}
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
	for i := 0; i < ExtDegree; i++ {
		c.AssertIsEqualF(a.Value[i], b.Value[i])
	}
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
	var out ExtensionVariable
	for i := 0; i < ExtDegree; i++ {
		out.Value[i] = c.SelectF(cond, a.Value[i], b.Value[i])
	}
	return out
}

func (c *Chip) AddEF(a ExtensionVariable, b Variable) ExtensionVariable {
	a.Value[0] = c.AddF(a.Value[0], b)
	return a
}

func (c *Chip) AddE(a, b ExtensionVariable) ExtensionVariable {
	var out ExtensionVariable
	for i := 0; i < ExtDegree; i++ {
		out.Value[i] = c.AddF(a.Value[i], b.Value[i])
	}
	return out
}

func (c *Chip) SubE(a, b ExtensionVariable) ExtensionVariable {
	var out ExtensionVariable
	for i := 0; i < ExtDegree; i++ {
		out.Value[i] = c.SubF(a.Value[i], b.Value[i])
	}
	return out
}

func (c *Chip) SubEF(a ExtensionVariable, b Variable) ExtensionVariable {
	a.Value[0] = c.SubF(a.Value[0], b)
	return a
}

// productLen is the number of coefficients of the product of two extension elements before it is
// reduced: two degree-4 polynomials multiply to degree 8.
const productLen = 2*ExtDegree - 1

// quinticFold reduces the product's coefficients c_0..c_8 to five, under X^5 = 1 - X^2 and so
// X^6 = X - X^3, X^7 = X^2 - X^4, X^8 = X^3 + X^2 - 1. Row j is res[j] of Plonky3's
// trinomial_quintic_mul:
//
//	res0 = c0 + c5 - c8          res3 = c3 - c6 + c8
//	res1 = c1 + c6               res4 = c4 - c7
//	res2 = c2 - c5 + c7 + c8
var quinticFold = [ExtDegree][productLen]int{
	{1, 0, 0, 0, 0, 1, 0, 0, -1},
	{0, 1, 0, 0, 0, 0, 1, 0, 0},
	{0, 0, 1, 0, 0, -1, 0, 1, 1},
	{0, 0, 0, 1, 0, 0, -1, 0, 1},
	{0, 0, 0, 0, 1, 0, 0, -1, 0},
}

// interpolationMuls is the most mulEInterpolated costs: one multiplication per evaluation.
const interpolationMuls = productLen

// interpolationPoints are the finite points mulEInterpolated evaluates at. The ninth evaluation is
// at infinity, the product of the leading coefficients. Any nine distinct points determine a
// product of degree 8; small integers keep each evaluation a short linear combination.
var interpolationPoints = [productLen - 1]int64{0, 1, -1, 2, -2, 3, -3, 4}

// interpolationWeights[k][i] is the weight of evaluation i (infinity last) in coefficient c_k: the
// inverse of the matrix that evaluates a degree-8 polynomial at those points, over the rationals.
var interpolationWeights = invertEvaluationMatrix()

// productCap is how large a reduced product's coefficient may be. Every coefficient is a wire in
// BN254's scalar field, of modulus r ~ 2^253.6, and stands for an integer only while it stays
// under r; the interpolated form gives back the integer only then. Operands leave reduceFast under
// 2^120, so products of operands stay near 2^244 and MulE's check never fires on a tape: it is
// there for an operand that has not been through a reduction.
var productCap = new(big.Int).Lsh(big.NewInt(1), 250)

// invertEvaluationMatrix inverts the matrix that takes a degree-8 polynomial's nine coefficients to
// its values at interpolationPoints and at infinity, by Gauss-Jordan elimination over the
// rationals.
func invertEvaluationMatrix() [productLen][productLen]*big.Rat {
	var m, inv [productLen][productLen]*big.Rat
	for i := 0; i < productLen; i++ {
		for k := 0; k < productLen; k++ {
			m[i][k] = new(big.Rat)
			inv[i][k] = new(big.Rat)
		}
		inv[i][i].SetInt64(1)
	}
	for i, x := range interpolationPoints {
		power := big.NewInt(1)
		for k := 0; k < productLen; k++ {
			m[i][k].SetInt(power)
			power.Mul(power, big.NewInt(x))
		}
	}
	// At infinity a polynomial's value is its leading coefficient.
	m[productLen-1][productLen-1].SetInt64(1)
	for col := 0; col < productLen; col++ {
		pivot := col
		for pivot < productLen && m[pivot][col].Sign() == 0 {
			pivot++
		}
		if pivot == productLen {
			panic("koalabear: the interpolation points are not distinct")
		}
		m[col], m[pivot] = m[pivot], m[col]
		inv[col], inv[pivot] = inv[pivot], inv[col]
		scale := new(big.Rat).Inv(m[col][col])
		for k := 0; k < productLen; k++ {
			m[col][k].Mul(m[col][k], scale)
			inv[col][k].Mul(inv[col][k], scale)
		}
		for row := 0; row < productLen; row++ {
			if row == col || m[row][col].Sign() == 0 {
				continue
			}
			factor := new(big.Rat).Set(m[row][col])
			for k := 0; k < productLen; k++ {
				m[row][k].Sub(m[row][k], new(big.Rat).Mul(factor, m[col][k]))
				inv[row][k].Sub(inv[row][k], new(big.Rat).Mul(factor, inv[col][k]))
			}
		}
	}
	return inv
}

// interpolationInField is interpolationWeights in the circuit's field, each n/d as n * d^-1 mod r.
func (c *Chip) interpolationInField() *[productLen][productLen]*big.Int {
	if c.interpolation == nil {
		field := c.api.Compiler().Field()
		var weights [productLen][productLen]*big.Int
		for k := range weights {
			for i := range weights[k] {
				w := interpolationWeights[k][i]
				inverse := new(big.Int).ModInverse(w.Denom(), field)
				weights[k][i] = inverse.Mul(inverse, w.Num()).Mod(inverse, field)
			}
		}
		c.interpolation = &weights
	}
	return c.interpolation
}

// sum adds terms in one linear combination.
func sum(api frontend.API, terms []frontend.Variable) frontend.Variable {
	switch len(terms) {
	case 0:
		return frontend.Variable(0)
	case 1:
		return terms[0]
	default:
		return api.Add(terms[0], terms[1], terms[2:]...)
	}
}

// evaluate is e's coefficient polynomial at x: a linear combination of the coefficients, so free.
func (c *Chip) evaluate(e ExtensionVariable, x int64) frontend.Variable {
	field := c.api.Compiler().Field()
	terms := make([]frontend.Variable, 0, ExtDegree)
	power := big.NewInt(1)
	for i := 0; i < ExtDegree; i++ {
		if power.Sign() != 0 {
			terms = append(terms, c.api.Mul(e.Value[i].Value, new(big.Int).Mod(power, field)))
		}
		power.Mul(power, big.NewInt(x))
	}
	return sum(c.api, terms)
}

// wireLimbs marks e's coefficients that are wires rather than constants. A product costs a
// multiplication only when both of its sides are wires.
func (c *Chip) wireLimbs(e ExtensionVariable) (wires [ExtDegree]bool, n int) {
	for i := range e.Value {
		if _, constant := c.api.Compiler().ConstantValue(e.Value[i].Value); !constant {
			wires[i] = true
			n++
		}
	}
	return wires, n
}

// mulCosts is what each of MulE's two forms costs for a*b, in multiplications.
//
// mulESchoolbook multiplies each pair of coefficients: one per pair of wires. mulEInterpolated
// multiplies each pair of evaluations: at a nonzero point an operand with any wire coefficient
// evaluates to a wire, so each of those seven costs one whenever both operands have a wire; at 0
// the evaluations are the constant coefficients and at infinity the leading ones, so those two
// cost one only when both of theirs are wires.
func (c *Chip) mulCosts(a, b ExtensionVariable) (schoolbook, interpolated int) {
	wa, na := c.wireLimbs(a)
	wb, nb := c.wireLimbs(b)
	schoolbook = na * nb
	if schoolbook == 0 {
		return 0, 0
	}
	for _, x := range interpolationPoints {
		if x != 0 || (wa[0] && wb[0]) {
			interpolated++
		}
	}
	if wa[ExtDegree-1] && wb[ExtDegree-1] {
		interpolated++
	}
	return schoolbook, interpolated
}

// productBounds bounds the product's coefficients: c_k is the sum of a_i*b_j over i+j = k, so it is
// at most the same sum over the operands' bounds.
func productBounds(a, b ExtensionVariable) [productLen]*big.Int {
	var bounds [productLen]*big.Int
	for k := range bounds {
		bounds[k] = new(big.Int)
	}
	for i := 0; i < ExtDegree; i++ {
		for j := 0; j < ExtDegree; j++ {
			bounds[i+j].Add(bounds[i+j], new(big.Int).Mul(a.Value[i].UpperBound, b.Value[j].UpperBound))
		}
	}
	return bounds
}

// foldLift returns the multiple of p that reduced coefficient j adds, and the bound that coefficient
// then has. The fold subtracts, and a wire has to stay a non-negative integer, so a row with a
// negative entry adds the least multiple of p above its negative part's bound: the result is the
// same mod p and cannot go below zero. The bound is the positive part's bound plus that multiple.
func foldLift(j int, bounds [productLen]*big.Int) (lift, bound *big.Int) {
	positive, negative := new(big.Int), new(big.Int)
	for k, sign := range quinticFold[j] {
		switch sign {
		case 1:
			positive.Add(positive, bounds[k])
		case -1:
			negative.Add(negative, bounds[k])
		}
	}
	lift = new(big.Int)
	if negative.Sign() > 0 {
		lift.Div(negative, modulus)
		lift.Add(lift, big.NewInt(1)).Mul(lift, modulus)
	}
	return lift, positive.Add(positive, lift)
}

// productFits reports whether every reduced coefficient of a*b stays under productCap.
func productFits(a, b ExtensionVariable) bool {
	bounds := productBounds(a, b)
	for j := 0; j < ExtDegree; j++ {
		if _, bound := foldLift(j, bounds); bound.Cmp(productCap) >= 0 {
			return false
		}
	}
	return true
}

// MulE multiplies in KoalaBear's quintic extension F_p[X]/(X^5 + X^2 - 1).
//
// Additions and constant scalings are free in R1CS (they are linear combinations), so the only
// cost that matters is the number of api.Mul calls between two wires. A product is the nine
// coefficients c_0..c_8 of the product of the two coefficient polynomials, reduced to five by
// quinticFold. MulE gets the nine whichever way multiplies less (mulCosts):
//
//   - mulEInterpolated evaluates both operands at nine points, multiplies the evaluations and
//     interpolates: at most nine multiplications, for any operands.
//   - mulESchoolbook multiplies every pair of coefficients, and a pair with a constant side costs
//     nothing: five for a felt lifted into the extension, nothing when either operand is constant.
//
// The two give the same nine integers, and share the fold and its bounds.
func (c *Chip) MulE(a, b ExtensionVariable) ExtensionVariable {
	if !productFits(a, b) {
		a, b = c.ReduceE(a), c.ReduceE(b)
	}
	if schoolbook, interpolated := c.mulCosts(a, b); schoolbook <= interpolated {
		return c.foldProduct(a, b, c.mulESchoolbook(a, b))
	}
	return c.foldProduct(a, b, c.mulEInterpolated(a, b))
}

// mulESchoolbook is the product's nine coefficients as sums of the 25 products of a coefficient of
// a and one of b. A product with a constant side is a linear combination, so only the pairs of
// non-constant coefficients cost a multiplication.
func (c *Chip) mulESchoolbook(a, b ExtensionVariable) [productLen]frontend.Variable {
	var terms [productLen][]frontend.Variable
	for i := 0; i < ExtDegree; i++ {
		for j := 0; j < ExtDegree; j++ {
			terms[i+j] = append(terms[i+j], c.api.Mul(a.Value[i].Value, b.Value[j].Value))
		}
	}
	var coeffs [productLen]frontend.Variable
	for k := range coeffs {
		coeffs[k] = sum(c.api, terms[k])
	}
	return coeffs
}

// mulEInterpolated is the product's nine coefficients from nine multiplications: the operands'
// values at interpolationPoints and at infinity, multiplied pairwise, then taken back to
// coefficients by interpolationWeights. The evaluations and the interpolation are linear, so the
// nine products are the whole cost.
//
// The coefficients are exact, not merely right mod r. Each product is constrained, so it is the
// integer product of the two evaluations mod r; interpolation is a fixed invertible linear map, so
// the nine results are the integer coefficients c_k mod r, and so is the fold of them. The true
// fold is a non-negative integer under r (foldLift, productCap), so the wire is that integer:
// negative points and fractional weights cannot leave a trace, because only the end result has to
// lie in [0, r).
func (c *Chip) mulEInterpolated(a, b ExtensionVariable) [productLen]frontend.Variable {
	var evaluations [productLen]frontend.Variable
	for i, x := range interpolationPoints {
		evaluations[i] = c.api.Mul(c.evaluate(a, x), c.evaluate(b, x))
	}
	evaluations[productLen-1] = c.api.Mul(a.Value[ExtDegree-1].Value, b.Value[ExtDegree-1].Value)
	weights := c.interpolationInField()
	var coeffs [productLen]frontend.Variable
	for k := range coeffs {
		terms := make([]frontend.Variable, 0, productLen)
		for i, e := range evaluations {
			if weights[k][i].Sign() != 0 {
				terms = append(terms, c.api.Mul(e, weights[k][i]))
			}
		}
		coeffs[k] = sum(c.api, terms)
	}
	return coeffs
}

// foldProduct reduces a*b's nine coefficients to five by quinticFold, each one bounded and lifted
// by foldLift, and reduces whichever crosses reduceFast's threshold.
func (c *Chip) foldProduct(a, b ExtensionVariable, coeffs [productLen]frontend.Variable) ExtensionVariable {
	bounds := productBounds(a, b)
	var out ExtensionVariable
	for j := 0; j < ExtDegree; j++ {
		lift, bound := foldLift(j, bounds)
		terms := []frontend.Variable{lift}
		for k, sign := range quinticFold[j] {
			switch sign {
			case 1:
				terms = append(terms, coeffs[k])
			case -1:
				terms = append(terms, c.api.Neg(coeffs[k]))
			}
		}
		out.Value[j] = c.reduceFast(Variable{Value: sum(c.api, terms), UpperBound: bound})
	}
	return out
}

func (c *Chip) MulEF(a ExtensionVariable, b Variable) ExtensionVariable {
	var out ExtensionVariable
	for i := 0; i < ExtDegree; i++ {
		out.Value[i] = c.MulF(a.Value[i], b)
	}
	return out
}

func (c *Chip) InvE(in ExtensionVariable) ExtensionVariable {
	inputs := make([]frontend.Variable, ExtDegree)
	for i := range inputs {
		inputs[i] = in.Value[i].Value
	}
	result, err := c.api.Compiler().NewHint(InvEHint, ExtDegree, inputs...)
	if err != nil {
		panic(err)
	}

	// 2^31 - 1 for the same reason as in invF.
	var out ExtensionVariable
	for i := 0; i < ExtDegree; i++ {
		out.Value[i] = Variable{Value: result[i], UpperBound: new(big.Int).Set(twoPow31_sub_1)}
		c.RangeChecker.Check(result[i], 31)
	}

	product := c.MulE(in, out)
	c.AssertIsEqualE(product, NewEConst([]string{"1", "0", "0", "0", "0"}))

	return out
}

func (c *Chip) Ext2Felt(in ExtensionVariable) [ExtDegree]Variable {
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
	var out ExtensionVariable
	for i := 0; i < ExtDegree; i++ {
		out.Value[i] = c.negF(a.Value[i])
	}
	return out
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
	for i := 0; i < ExtDegree; i++ {
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

// InvEHint is the inverse of the extension element whose ExtDegree coefficients are its inputs, by
// Plonky3's QuinticTrinomialExtensionField<KoalaBear>::try_inverse over the field FFI; zero gives
// zero, which InvE's product check then rejects.
func InvEHint(_ *big.Int, inputs []*big.Int, results []*big.Int) error {
	if len(inputs) != ExtDegree || len(results) != ExtDegree {
		return fmt.Errorf("InvEHint: %d coefficients in and %d out, not %d and %d", len(inputs), len(results), ExtDegree, ExtDegree)
	}
	var in, out [ExtDegree]C.uint32_t
	for i := range in {
		in[i] = C.uint32_t(new(big.Int).Mod(inputs[i], modulus).Uint64())
	}
	C.koalabearquinticinv(&in[0], &out[0])
	for i := range out {
		results[i].SetUint64(uint64(out[i]))
	}
	return nil
}
