package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// VerifyInputs is what PicoVerifier.verifyPicoProof is called with, as `cargo pico prove --evm`
// writes it to inputs.json: the program's vkey and the bytes its guest committed.
type VerifyInputs struct {
	RiscvVKey    string `json:"riscvVKey"`
	PublicValues string `json:"publicValues"`
}

// ReadVerifyInputs reads an inputs.json.
func ReadVerifyInputs(path string) (VerifyInputs, error) {
	var in VerifyInputs
	data, err := os.ReadFile(path)
	if err != nil {
		return in, fmt.Errorf("failed to read the inputs: %v", err)
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return in, fmt.Errorf("%s is not an inputs.json: %v", path, err)
	}
	return in, nil
}

// WrapPublicInputs computes the wrap circuit's two public inputs the way
// PicoVerifier.verifyPicoProof does, from what the verifier is handed rather than from the proof:
// the program vkey read as a big-endian word, and SHA-256 of the public values with its top three
// bits cleared (`hashPublicValues`), so that it fits one BN254 scalar.
func WrapPublicInputs(in VerifyInputs) (bn254_fr.Vector, error) {
	vkey, err := decodeWord(in.RiscvVKey)
	if err != nil {
		return nil, fmt.Errorf("riscvVKey: %v", err)
	}
	if vkey.Cmp(bn254_fr.Modulus()) >= 0 {
		return nil, fmt.Errorf("riscvVKey is not a canonical scalar-field element")
	}
	digits, ok := strings.CutPrefix(strings.TrimSpace(in.PublicValues), "0x")
	if !ok {
		return nil, fmt.Errorf("publicValues %q is not 0x-prefixed hex", in.PublicValues)
	}
	publicValues, err := hex.DecodeString(digits)
	if err != nil {
		return nil, fmt.Errorf("publicValues: %v", err)
	}
	digest := sha256.Sum256(publicValues)
	digest[0] &= 0x1f
	inputs := make(bn254_fr.Vector, 2)
	inputs[0].SetBigInt(vkey)
	inputs[1].SetBigInt(new(big.Int).SetBytes(digest[:]))
	return inputs, nil
}

// CheckProofInputs compares the public inputs a proof file carries with the ones computed from
// the verifier's own inputs. The file's are only a convenience copy: a proof is checked against
// the computed ones, and a file that disagrees is refused rather than believed.
func CheckProofInputs(carried, computed bn254_fr.Vector) error {
	names := []string{"the program vkey", "the public-values digest"}
	if len(carried) != len(computed) {
		return fmt.Errorf("the wrap circuit has %d public inputs, and the proof file carries %d",
			len(computed), len(carried))
	}
	for i := range computed {
		if !carried[i].Equal(&computed[i]) {
			return fmt.Errorf("the proof file's public input %d (%s) is not the one computed from the inputs",
				i, names[i])
		}
	}
	return nil
}
