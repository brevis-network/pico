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

// ── MLE/WHIR backend table ────────────────────────────────────────────────────────────────────
//
// A SECOND pin, against the other KoalaBear-Poseidon2 constant table. Both tables ship, and each
// circuit shape must permute with its own: the legacy FRI on-chain circuit's honest witness is
// unsatisfiable under the MLE table and vice versa (measured — the FRI circuit fails at
// `assertIsEqual`). Keeping both tests is what stops a future change from "unifying" them.
//
// The expected vector is the same one `pico_mle_core`'s `kb_poseidon2_permutation_vector_matches_gnark`
// asserts on the Rust side, for the same all-zero input.

type TestPoseidon2KoalaBearMleCircuit struct {
	Input, ExpectedOutput [KOALABEAR_WIDTH]koalabear.Variable `gnark:",public"`
}

func (circuit *TestPoseidon2KoalaBearMleCircuit) Define(api frontend.API) error {
	poseidon2Chip := NewKoalaBearMleChip(api)

	input := [KOALABEAR_WIDTH]koalabear.Variable{}
	for i := 0; i < KOALABEAR_WIDTH; i++ {
		input[i] = circuit.Input[i]
	}
	poseidon2Chip.PermuteMut(&input)

	for i := 0; i < KOALABEAR_WIDTH; i++ {
		poseidon2Chip.fieldApi.AssertIsEqualF(circuit.ExpectedOutput[i], input[i])
	}

	return nil
}

func TestPoseidon2KoalaBearMle(t *testing.T) {
	assert := test.NewAssert(t)

	input := [KOALABEAR_WIDTH]koalabear.Variable{}
	for i := 0; i < KOALABEAR_WIDTH; i++ {
		input[i] = koalabear.NewFConst("0")
	}

	expectedOutput := [KOALABEAR_WIDTH]koalabear.Variable{
		koalabear.NewFConst("1467453764"),
		koalabear.NewFConst("68262570"),
		koalabear.NewFConst("2085334433"),
		koalabear.NewFConst("1711169726"),
		koalabear.NewFConst("869537427"),
		koalabear.NewFConst("698494029"),
		koalabear.NewFConst("1998923102"),
		koalabear.NewFConst("727938840"),
		koalabear.NewFConst("1236421175"),
		koalabear.NewFConst("857433239"),
		koalabear.NewFConst("1995651691"),
		koalabear.NewFConst("1526804549"),
		koalabear.NewFConst("968729910"),
		koalabear.NewFConst("15322618"),
		koalabear.NewFConst("1511105384"),
		koalabear.NewFConst("1900792116"),
	}

	// Both sides carry values: `koalabear.Variable` is not a gnark leaf type, so a nil in the
	// circuit struct is not filled in from the assignment — it panics in the first linear layer.
	circuit := &TestPoseidon2KoalaBearMleCircuit{Input: input, ExpectedOutput: expectedOutput}
	witness := &TestPoseidon2KoalaBearMleCircuit{Input: input, ExpectedOutput: expectedOutput}

	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// The two tables must actually differ; if a refactor ever pointed both constructors at the same
// array, both pin tests above would still pass while the FRI path silently broke.
func TestKoalaBearTablesAreDistinct(t *testing.T) {
	same := true
	for r := 0; r < 30 && same; r++ {
		for i := 0; i < KOALABEAR_WIDTH; i++ {
			if rc16_koalabear[r][i].Value != rc16_koalabear_mle[r][i].Value {
				same = false
				break
			}
		}
	}
	if same {
		t.Fatal("the FRI and MLE KoalaBear-Poseidon2 tables are identical — one has overwritten the other")
	}
}
