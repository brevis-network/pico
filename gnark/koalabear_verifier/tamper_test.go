package koalabear_verifier

// Two checks on whatever wrap circuit and witness sit beside the test as constraints.json and
// groth16_witness.json, as the Wrap proof CI job puts them: every witness value the circuit reads
// is bound, and the circuit fits the Groth16 domain its keys are sized for. Both skip when the
// files are not there.

import (
	"encoding/json"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"testing"

	"github.com/brevis-network/pico/gnark/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

// 2^31 - 2^24 + 1.
var koalaBearModulus = big.NewInt(2130706433)

// The domain a Groth16 key for this circuit is sized for. One constraint past it doubles the FFT
// domain, the setup and prove time, and the proving key.
const maxConstraints = 1 << 23

func readWrapWitness(t *testing.T) utils.WitnessInput {
	t.Helper()
	data, err := os.ReadFile("groth16_witness.json")
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("no groth16_witness.json here: put a wrap witness and its constraints.json beside the test")
	}
	if err != nil {
		t.Fatal(err)
	}
	var witness utils.WitnessInput
	if err := json.Unmarshal(data, &witness); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONSTRAINTS_JSON", "./constraints.json")
	return witness
}

// plusOne adds one to a decimal field element, modulo its field.
func plusOne(value string, modulus *big.Int) string {
	v, ok := new(big.Int).SetString(value, 10)
	if !ok {
		panic("not a decimal field element: " + value)
	}
	return v.Add(v, big.NewInt(1)).Mod(v, modulus).String()
}

// A deep copy, so that each case changes one value of the honest witness and nothing else.
func cloneWitness(w utils.WitnessInput) utils.WitnessInput {
	c := w
	c.Vars = append([]string(nil), w.Vars...)
	c.Felts = append([]string(nil), w.Felts...)
	c.Exts = make([][]string, len(w.Exts))
	for i, ext := range w.Exts {
		c.Exts[i] = append([]string(nil), ext...)
	}
	return c
}

// Every witness value the circuit reads is bound by some constraint, so changing any one of them
// must leave the circuit unsatisfiable; one that still solves is an unconstrained value. The cases
// are test_mle_e2e's WRAP_TAMPER kinds, applied to the written witness instead of before writing
// it, so they need no proof per case: vars hold commitments at the head and transcript remainders
// at the tail, felts the public values, opened rows and transcript digits, exts the GKR claims,
// sumcheck and stacking values and the WHIR final polynomial. WRAP_TAMPER's rem_over_bound is not
// here: it needs the squeeze count, which only the Rust side has.
//
// "last" is the last value the circuit reads, one before the end: GnarkWitness::new appends a 999
// to each of the three arrays, and no opcode reads it. WRAP_TAMPER changes the witness before that
// sentinel exists, so its "last" is this one too.
func TestTamperedWitnessIsUnsatisfiable(t *testing.T) {
	honest := readWrapWitness(t)
	scalar := ecc.BN254.ScalarField()
	// The sentinel, checked so that a writer that stops appending it moves "last" here too.
	lastExt := honest.Exts[len(honest.Exts)-1]
	if honest.Vars[len(honest.Vars)-1] != "999" || honest.Felts[len(honest.Felts)-1] != "999" ||
		len(lastExt) == 0 || lastExt[0] != "999" {
		t.Fatalf("the witness does not end in GnarkWitness::new's 999 sentinel, so the last value read is not one before the end")
	}
	solves := func(w utils.WitnessInput) error {
		return test.IsSolved(NewCircuit(w), NewCircuit(w), scalar)
	}
	// The control: without it, a witness that solves nothing would pass every case below.
	if err := solves(honest); err != nil {
		t.Fatalf("the honest witness does not solve, so nothing below would mean anything: %v", err)
	}

	mid := func(n int) int { return n / 2 }
	last := func(n int) int { return n - 2 }
	cases := map[string]func(w *utils.WitnessInput){
		"var_first":  func(w *utils.WitnessInput) { w.Vars[0] = plusOne(w.Vars[0], scalar) },
		"var_mid":    func(w *utils.WitnessInput) { i := mid(len(w.Vars)); w.Vars[i] = plusOne(w.Vars[i], scalar) },
		"var_last":   func(w *utils.WitnessInput) { i := last(len(w.Vars)); w.Vars[i] = plusOne(w.Vars[i], scalar) },
		"felt_first": func(w *utils.WitnessInput) { w.Felts[0] = plusOne(w.Felts[0], koalaBearModulus) },
		"felt_mid": func(w *utils.WitnessInput) {
			i := mid(len(w.Felts))
			w.Felts[i] = plusOne(w.Felts[i], koalaBearModulus)
		},
		"felt_last": func(w *utils.WitnessInput) {
			i := last(len(w.Felts))
			w.Felts[i] = plusOne(w.Felts[i], koalaBearModulus)
		},
		"ext_first": func(w *utils.WitnessInput) { w.Exts[0][0] = plusOne(w.Exts[0][0], koalaBearModulus) },
		"ext_mid": func(w *utils.WitnessInput) {
			i := mid(len(w.Exts))
			w.Exts[i][0] = plusOne(w.Exts[i][0], koalaBearModulus)
		},
		"ext_last": func(w *utils.WitnessInput) {
			i := last(len(w.Exts))
			w.Exts[i][0] = plusOne(w.Exts[i][0], koalaBearModulus)
		},
		"vkey_hash": func(w *utils.WitnessInput) { w.VkeyHash = plusOne(w.VkeyHash, scalar) },
		"cvd": func(w *utils.WitnessInput) {
			w.CommittedValuesDigest = plusOne(w.CommittedValuesDigest, scalar)
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			w := cloneWitness(honest)
			tamper(&w)
			if err := solves(w); err == nil {
				t.Fatalf("the witness with %s changed still solves: that value is not bound", name)
			}
		})
	}
}

// The circuit fits the Groth16 domain: at most 2^23 constraints. It compiles the circuit, which
// the solve tests do not.
func TestCircuitFitsGroth16Domain(t *testing.T) {
	witness := readWrapWitness(t)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, NewCircuit(witness))
	if err != nil {
		t.Fatal(err)
	}
	n := ccs.GetNbConstraints()
	t.Logf("%d constraints: %d (%.1f%%) under 2^23", n, maxConstraints-n, 100*float64(maxConstraints-n)/maxConstraints)
	if n > maxConstraints {
		t.Fatalf("%d constraints is past 2^23: the Groth16 domain doubles to 2^24, and the proving key with it", n)
	}
}
