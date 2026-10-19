package poseidon2

import (
	"github.com/brevis-network/pico/gnark/koalabear"
	"github.com/consensys/gnark/frontend"
	"math/big"
)

const KOALABEAR_WIDTH = 16
const koalabearNumExternalRounds = 8
const koalabearNumInternalRounds = 20

type Poseidon2KoalaBearChip struct {
	// Round constants this chip permutes with. The FRI on-chain circuit and the MLE wrap circuit
	// use DIFFERENT tables, so the chip must carry its own rather than read a package global —
	// see constants_koalabear_mle.go.
	rc          *[30][KOALABEAR_WIDTH]koalabear.Variable
	State       [16]koalabear.Variable
	bufferCount int

	api      frontend.API
	fieldApi *koalabear.Chip
}

// NewKoalaBearChip builds the chip with the legacy pico round constants — the table the FRI
// on-chain circuit's own hashing was generated against.
func NewKoalaBearChip(api frontend.API) *Poseidon2KoalaBearChip {
	return newKoalaBearChipWithRc(api, &rc16_koalabear)
}

// NewKoalaBearMleChip builds the chip with the MLE/WHIR backend's round constants. Only the wrap
// circuit may use this: the MLE recursion proof's in-circuit PV digest is computed with these, and
// the legacy table makes that assert unsatisfiable.
func NewKoalaBearMleChip(api frontend.API) *Poseidon2KoalaBearChip {
	return newKoalaBearChipWithRc(api, &rc16_koalabear_mle)
}

func newKoalaBearChipWithRc(
	api frontend.API,
	rc *[30][KOALABEAR_WIDTH]koalabear.Variable,
) *Poseidon2KoalaBearChip {
	return &Poseidon2KoalaBearChip{
		rc: rc,
		State: [16]koalabear.Variable{
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
			koalabear.Zero(),
		},
		api:      api,
		fieldApi: koalabear.NewChip(api),
	}
}

func (p *Poseidon2KoalaBearChip) Update(input koalabear.Variable) {
	p.State[p.bufferCount] = p.fieldApi.AddF(p.State[p.bufferCount], input)
	p.bufferCount = p.bufferCount + 1

	if p.bufferCount == 15 {
		p.PermuteMut(&p.State)
		p.bufferCount = 0
	}
}

func (p *Poseidon2KoalaBearChip) Finalize() [16]koalabear.Variable {
	if p.bufferCount > 0 {
		p.State[p.bufferCount] = p.fieldApi.AddF(p.State[p.bufferCount], koalabear.One())
	} else {
		p.State[0] = p.fieldApi.AddF(p.State[0], koalabear.One())
	}
	p.PermuteMut(&p.State)

	res := [16]koalabear.Variable{}
	for i := 0; i < 16; i++ {
		res[i] = p.State[i]
	}
	return res
}

func (p *Poseidon2KoalaBearChip) PermuteMut(state *[KOALABEAR_WIDTH]koalabear.Variable) {
	// The initial linear layer.
	p.externalLinearLayer(state)

	// The first half of the external rounds.
	rounds := koalabearNumExternalRounds + koalabearNumInternalRounds
	roundsFBeginning := koalabearNumExternalRounds / 2
	for r := 0; r < roundsFBeginning; r++ {
		p.addRc(state, p.rc[r])
		p.sbox(state)
		p.externalLinearLayer(state)
	}

	// The internal rounds.
	p_end := roundsFBeginning + koalabearNumInternalRounds
	for r := roundsFBeginning; r < p_end; r++ {
		state[0] = p.fieldApi.AddF(state[0], p.rc[r][0])
		state[0] = p.sboxP(state[0])
		p.diffusionPermuteMut(state)
	}

	// The second half of the external rounds.
	for r := p_end; r < rounds; r++ {
		p.addRc(state, p.rc[r])
		p.sbox(state)
		p.externalLinearLayer(state)
	}
}

func (p *Poseidon2KoalaBearChip) addRc(state *[KOALABEAR_WIDTH]koalabear.Variable, rc [KOALABEAR_WIDTH]koalabear.Variable) {
	for i := 0; i < KOALABEAR_WIDTH; i++ {
		state[i] = p.fieldApi.AddF(state[i], rc[i])
	}
}

// sboxP cubes a felt. It reaches past the field gadget into raw api.Mul, which is safe
// because cubing is a mod-p operation: if ReduceSlow handed back v + p instead of v, then
// (v + p)^3 = v^3 (mod p) and the trailing reduction lands on the same field element. Only
// the BOUND changes, and the bound is what the code below is careful about.
func (p *Poseidon2KoalaBearChip) sboxP(input koalabear.Variable) koalabear.Variable {
	zero := koalabear.NewFConst("0")
	inputCpy := p.fieldApi.AddF(input, zero)
	inputCpy = p.fieldApi.ReduceSlow(inputCpy)
	inputValue := inputCpy.Value
	i2 := p.api.Mul(inputValue, inputValue)
	i3 := p.api.Mul(i2, inputValue)
	// Derived from the reduced input's ACTUAL bound, not hard-coded to p^3. Under lazy
	// canonicality ReduceSlow only promises < 2^31, so p^3 was a bound the wire no longer
	// satisfies; it escaped notice because p^3 and (2^31 - 1)^3 share BitLen 93 and BitLen is
	// all that reduceVar consumes. Deriving it removes the coincidence.
	i3bb := p.fieldApi.ReduceSlow(koalabear.Variable{
		Value:      i3,
		UpperBound: new(big.Int).Exp(inputCpy.UpperBound, big.NewInt(3), nil),
	})
	return i3bb
}

func (p *Poseidon2KoalaBearChip) sbox(state *[KOALABEAR_WIDTH]koalabear.Variable) {
	for i := 0; i < KOALABEAR_WIDTH; i++ {
		state[i] = p.sboxP(state[i])
	}
}

func (p *Poseidon2KoalaBearChip) mdsLightPermutation4x4(state []koalabear.Variable) {
	t01 := p.fieldApi.AddF(state[0], state[1])
	t23 := p.fieldApi.AddF(state[2], state[3])
	t0123 := p.fieldApi.AddF(t01, t23)
	t01123 := p.fieldApi.AddF(t0123, state[1])
	t01233 := p.fieldApi.AddF(t0123, state[3])
	state[3] = p.fieldApi.AddF(t01233, p.fieldApi.MulFConst(state[0], 2))
	state[1] = p.fieldApi.AddF(t01123, p.fieldApi.MulFConst(state[2], 2))
	state[0] = p.fieldApi.AddF(t01123, t01)
	state[2] = p.fieldApi.AddF(t01233, t23)
}

func (p *Poseidon2KoalaBearChip) externalLinearLayer(state *[KOALABEAR_WIDTH]koalabear.Variable) {
	for i := 0; i < KOALABEAR_WIDTH; i += 4 {
		p.mdsLightPermutation4x4(state[i : i+4])
	}

	sums := [4]koalabear.Variable{
		state[0],
		state[1],
		state[2],
		state[3],
	}
	for i := 4; i < KOALABEAR_WIDTH; i += 4 {
		sums[0] = p.fieldApi.AddF(sums[0], state[i])
		sums[1] = p.fieldApi.AddF(sums[1], state[i+1])
		sums[2] = p.fieldApi.AddF(sums[2], state[i+2])
		sums[3] = p.fieldApi.AddF(sums[3], state[i+3])
	}

	for i := 0; i < KOALABEAR_WIDTH; i++ {
		state[i] = p.fieldApi.AddF(state[i], sums[i%4])
	}
}

func (p *Poseidon2KoalaBearChip) diffusionPermuteMut(state *[KOALABEAR_WIDTH]koalabear.Variable) {
	matInternalDiagM1 := [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("2130706431"),
		koalabear.NewFConst("1"),
		koalabear.NewFConst("2"),
		koalabear.NewFConst("1065353217"),
		koalabear.NewFConst("3"),
		koalabear.NewFConst("4"),
		koalabear.NewFConst("1065353216"),
		koalabear.NewFConst("2130706430"),
		koalabear.NewFConst("2130706429"),
		koalabear.NewFConst("2122383361"),
		koalabear.NewFConst("1864368129"),
		koalabear.NewFConst("2130706306"),
		koalabear.NewFConst("8323072"),
		koalabear.NewFConst("266338304"),
		koalabear.NewFConst("133169152"),
		koalabear.NewFConst("127"),
	}
	p.matmulInternal(state, &matInternalDiagM1)
}

func (p *Poseidon2KoalaBearChip) matmulInternal(
	state *[KOALABEAR_WIDTH]koalabear.Variable,
	matInternalDiagM1 *[KOALABEAR_WIDTH]koalabear.Variable,
) {
	sum := koalabear.NewFConst("0")
	for i := 0; i < KOALABEAR_WIDTH; i++ {
		sum = p.fieldApi.AddF(sum, state[i])
	}

	for i := 0; i < KOALABEAR_WIDTH; i++ {
		state[i] = p.fieldApi.MulF(state[i], matInternalDiagM1[i])
		state[i] = p.fieldApi.AddF(state[i], sum)
	}
}
