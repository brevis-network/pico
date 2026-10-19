package utils

import (
	"fmt"
	"math/big"
	"strings"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
)

// ProofWords is how many 32-byte words GetAggOnChainProof writes before the public inputs: A,
// B and C, then the Pedersen commitment and its proof of knowledge. They are, in order, the
// first three arguments of the exported verifier's verifyProof.
const ProofWords = 12

// ParseAggOnChainProof reads back what GetAggOnChainProof writes: ProofWords words of proof,
// then one word per public input. Every field has to be a 0x-prefixed 32-byte word holding a
// canonical element, so a file GetAggOnChainProof did not write is refused rather than reduced
// into some other proof.
func ParseAggOnChainProof(data string) (*groth16_bn254.Proof, bn254_fr.Vector, error) {
	fields := strings.Split(strings.TrimSpace(data), ",")
	if len(fields) <= ProofWords {
		return nil, nil, fmt.Errorf("expected %d proof words and at least one public input, got %d fields",
			ProofWords, len(fields))
	}
	words := make([]*big.Int, len(fields))
	for i, field := range fields {
		w, err := decodeWord(field)
		if err != nil {
			return nil, nil, fmt.Errorf("field %d: %v", i, err)
		}
		words[i] = w
	}

	var coords [ProofWords]fp.Element
	for i := range coords {
		if words[i].Cmp(fp.Modulus()) >= 0 {
			return nil, nil, fmt.Errorf("field %d is not a canonical base-field element", i)
		}
		coords[i].SetBigInt(words[i])
	}
	var proof groth16_bn254.Proof
	proof.Ar = curve.G1Affine{X: coords[0], Y: coords[1]}
	// ExportProof writes each coordinate of B with its A1 half first.
	proof.Bs.X.A1, proof.Bs.X.A0 = coords[2], coords[3]
	proof.Bs.Y.A1, proof.Bs.Y.A0 = coords[4], coords[5]
	proof.Krs = curve.G1Affine{X: coords[6], Y: coords[7]}
	proof.Commitments = []curve.G1Affine{{X: coords[8], Y: coords[9]}}
	proof.CommitmentPok = curve.G1Affine{X: coords[10], Y: coords[11]}

	inputs := make(bn254_fr.Vector, len(fields)-ProofWords)
	for i := range inputs {
		w := words[ProofWords+i]
		if w.Cmp(bn254_fr.Modulus()) >= 0 {
			return nil, nil, fmt.Errorf("public input %d is not a canonical scalar-field element", i)
		}
		inputs[i].SetBigInt(w)
	}
	return &proof, inputs, nil
}

func decodeWord(field string) (*big.Int, error) {
	digits, ok := strings.CutPrefix(strings.TrimSpace(field), "0x")
	if !ok || len(digits) != 64 {
		return nil, fmt.Errorf("%q is not a 0x-prefixed 32-byte word", field)
	}
	w, ok := new(big.Int).SetString(digits, 16)
	if !ok {
		return nil, fmt.Errorf("%q is not hex", field)
	}
	return w, nil
}
