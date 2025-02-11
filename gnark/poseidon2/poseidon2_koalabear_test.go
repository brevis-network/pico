package poseidon2

import (
	"github.com/brevis-network/pico/gnark/koalabear"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/test"
	"github.com/rs/zerolog"
	"os"
	"testing"
)

type TestPoseidon2KoalaBearCircuit struct {
	Input, ExpectedOutput [KOALABEAR_WIDTH]koalabear.Variable `gnark:",public"`
}

func (circuit *TestPoseidon2KoalaBearCircuit) Define(api frontend.API) error {
	poseidon2Chip := NewKoalaBearChip(api)

	input := [KOALABEAR_WIDTH]koalabear.Variable{}
	for i := 0; i < KOALABEAR_WIDTH; i++ {
		input[i] = circuit.Input[i]
	}
	poseidon2Chip.PermuteMut(&input)

	for i := 0; i < KOALABEAR_WIDTH; i++ {
		poseidon2Chip.fieldApi.AssertIsEqualF(circuit.ExpectedOutput[i], input[i])
	}

	//fmt.Printf("out input: %v", ConvertKoalaBear(api, &input))
	return nil
}

func TestPoseidon2KoalaBear(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	assert := test.NewAssert(t)

	var circuit, witness *TestPoseidon2KoalaBearCircuit

	input := [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
		koalabear.NewFConst("0"),
	}

	//[1330215056, 1388930081, 1337212159, 2038180411, 1881671374, 164509734, 498654582, 1841854018, 82116708,
	// 1571428065, 117003252, 1678395592, 2088326992, 1852522451, 1063576961, 1871812444]
	expected_output := [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("1330215056"),
		koalabear.NewFConst("1388930081"),
		koalabear.NewFConst("1337212159"),
		koalabear.NewFConst("2038180411"),
		koalabear.NewFConst("1881671374"),
		koalabear.NewFConst("164509734"),
		koalabear.NewFConst("498654582"),
		koalabear.NewFConst("1841854018"),
		koalabear.NewFConst("82116708"),
		koalabear.NewFConst("1571428065"),
		koalabear.NewFConst("117003252"),
		koalabear.NewFConst("1678395592"),
		koalabear.NewFConst("2088326992"),
		koalabear.NewFConst("1852522451"),
		koalabear.NewFConst("1063576961"),
		koalabear.NewFConst("1871812444"),
	}

	circuit = &TestPoseidon2KoalaBearCircuit{Input: input, ExpectedOutput: expected_output}
	witness = &TestPoseidon2KoalaBearCircuit{Input: input, ExpectedOutput: expected_output}

	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
