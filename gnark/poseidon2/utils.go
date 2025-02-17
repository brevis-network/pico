package poseidon2

import (
	"github.com/brevis-network/pico/gnark/koalabear"
	"github.com/consensys/gnark/frontend"
)

func (p *Poseidon2Chip) diffusionPermuteMut(state *[width]frontend.Variable) {
	sum := p.zero
	for i := 0; i < width; i++ {
		sum = p.api.Add(sum, state[i])
	}

	for i := 0; i < width; i++ {
		state[i] = p.api.Mul(state[i], p.internal_linear_layer[i])
		state[i] = p.api.Add(state[i], sum)
	}
}

func (p *Poseidon2Chip) matrixPermuteMut(state *[width]frontend.Variable) {
	sum := p.api.Add(state[0], state[1])
	sum = p.api.Add(sum, state[2])
	state[0] = p.api.Add(state[0], sum)
	state[1] = p.api.Add(state[1], sum)
	state[2] = p.api.Add(state[2], sum)
}

func ConvertKoalaBear(api frontend.API, state *[16]koalabear.Variable) [16]frontend.Variable {
	var res [16]frontend.Variable
	chip := koalabear.NewChip(api)
	for i := 0; i < 16; i++ {
		res[i] = chip.ReduceSlow(state[i]).Value
	}
	return res
}
