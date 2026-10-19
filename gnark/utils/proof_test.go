package utils

import (
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/rangecheck"
	"golang.org/x/crypto/sha3"
)

// A circuit with the wrap circuit's proof shape: its log-derivative range check puts one Pedersen
// commitment in every proof, and it has two public inputs.
type committedCircuit struct {
	X frontend.Variable
	A frontend.Variable `gnark:",public"`
	B frontend.Variable `gnark:",public"`
}

func (c *committedCircuit) Define(api frontend.API) error {
	rangecheck.New(api).Check(c.X, 16)
	api.AssertIsEqual(api.Mul(c.X, c.X), c.A)
	api.AssertIsEqual(api.Add(c.X, 1), c.B)
	return nil
}

// proveCommitted proves X = 3 and returns the on-chain encoding with its verifying key.
func proveCommitted(t *testing.T) (string, *groth16_bn254.VerifyingKey, bn254_fr.Vector) {
	t.Helper()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &committedCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	full, err := frontend.NewWitness(&committedCircuit{X: 3, A: 9, B: 4}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	public, err := full.Public()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(ccs, pk, full, backend.WithProverHashToFieldFunction(sha3.NewLegacyKeccak256()))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(proof.(*groth16_bn254.Proof).Commitments); n != 1 {
		t.Fatalf("the fixture circuit has %d commitments, not the wrap circuit's one", n)
	}
	text, err := GetAggOnChainProof(proof, public)
	if err != nil {
		t.Fatal(err)
	}
	return text, vk.(*groth16_bn254.VerifyingKey), public.Vector().(bn254_fr.Vector)
}

func verifyOnChain(text string, vk *groth16_bn254.VerifyingKey) error {
	proof, inputs, err := ParseAggOnChainProof(text)
	if err != nil {
		return err
	}
	return groth16_bn254.Verify(proof, vk, inputs, backend.WithVerifierHashToFieldFunction(sha3.NewLegacyKeccak256()))
}

// The file `prove` writes is the proof: read back, it verifies against the key, with the public
// inputs it carries.
func TestAnOnChainProofReadsBackAndVerifies(t *testing.T) {
	text, vk, public := proveCommitted(t)
	fields := strings.Split(text, ",")
	if len(fields) != ProofWords+2 {
		t.Fatalf("expected %d fields, got %d: %s", ProofWords+2, len(fields), text)
	}
	_, inputs, err := ParseAggOnChainProof(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != len(public) {
		t.Fatalf("%d public inputs read back, %d proved", len(inputs), len(public))
	}
	for i := range inputs {
		if !inputs[i].Equal(&public[i]) {
			t.Fatalf("public input %d read back as %v, proved as %v", i, inputs[i].String(), public[i].String())
		}
	}
	if err := verifyOnChain(text, vk); err != nil {
		t.Fatalf("the proof read back does not verify: %v", err)
	}

	// Each word the verifier reads has to matter: one bit changed anywhere, in the proof, its
	// commitment, the commitment's proof of knowledge or a public input, and it must not verify.
	for i := range fields {
		tampered := append([]string(nil), fields...)
		last := tampered[i][len(tampered[i])-1]
		flipped := "0"
		if last == '0' {
			flipped = "1"
		}
		tampered[i] = tampered[i][:len(tampered[i])-1] + flipped
		if err := verifyOnChain(strings.Join(tampered, ","), vk); err == nil {
			t.Errorf("a proof with field %d changed still verifies", i)
		}
	}
}

// A file ParseAggOnChainProof did not write is refused rather than read as some other proof.
func TestAMalformedOnChainProofIsRefused(t *testing.T) {
	text, _, _ := proveCommitted(t)
	fields := strings.Split(text, ",")
	word := func(hex string) string { return "0x" + strings.Repeat("0", 64-len(hex)) + hex }
	for name, bad := range map[string]string{
		"no public input":  strings.Join(fields[:ProofWords], ","),
		"no 0x":            strings.Join(append([]string{fields[0][2:]}, fields[1:]...), ","),
		"a short word":     strings.Join(append([]string{"0x01"}, fields[1:]...), ","),
		"not hex":          strings.Join(append([]string{"0x" + strings.Repeat("z", 64)}, fields[1:]...), ","),
		"a coordinate ≥ p": strings.Join(append([]string{word("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")}, fields[1:]...), ","),
		"an input ≥ r":     strings.Join(append(append([]string(nil), fields[:ProofWords]...), word("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), fields[ProofWords+1]), ","),
	} {
		if _, _, err := ParseAggOnChainProof(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
