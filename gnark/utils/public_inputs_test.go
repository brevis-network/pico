package utils

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// The committed contract fixtures: what PicoVerifier.verifyPicoProof is called with in
// contracts/test/PicoVerifier.t.sol, and the digest `hashPublicValues` gives for them there.
type fixture struct {
	VerifyInputs
	CommittedValuesDigest string   `json:"committedValuesDigest"`
	Proof                 []string `json:"proof"`
}

func readFixture(t *testing.T, name string) fixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "contracts", "test", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func element(t *testing.T, word string) bn254_fr.Element {
	t.Helper()
	w, err := decodeWord(word)
	if err != nil {
		t.Fatal(err)
	}
	var e bn254_fr.Element
	e.SetBigInt(w)
	return e
}

// The inputs computed here are the contract's: on every fixture the vkey is the one the contract
// passes and the digest equals the contract's `hashPublicValues` (the fixtures' leading digest bytes
// between them exercise all three cleared bits).
func TestWrapPublicInputsMatchTheContract(t *testing.T) {
	for _, name := range []string{"fib.json", "poseidon2.json", "ed25519.json"} {
		f := readFixture(t, name)
		inputs, err := WrapPublicInputs(f.VerifyInputs)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if want := element(t, f.RiscvVKey); !inputs[0].Equal(&want) {
			t.Fatalf("%s: vkey input %s, contract %s", name, inputs[0].String(), want.String())
		}
		if want := element(t, f.CommittedValuesDigest); !inputs[1].Equal(&want) {
			t.Fatalf("%s: digest input %s, contract %s", name, inputs[1].String(), want.String())
		}
	}
}

// Changed public values or a changed vkey give other inputs, and a proof file carrying the old
// ones is refused against them.
func TestChangedInputsAreRefused(t *testing.T) {
	f := readFixture(t, "fib.json")
	honest, err := WrapPublicInputs(f.VerifyInputs)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckProofInputs(honest, honest); err != nil {
		t.Fatalf("the honest inputs are refused: %v", err)
	}
	pv := f.PublicValues
	for _, changed := range []VerifyInputs{
		{RiscvVKey: f.RiscvVKey, PublicValues: pv[:len(pv)-2] + flipHex(pv[len(pv)-2:])},
		{RiscvVKey: f.RiscvVKey, PublicValues: pv[:2] + flipHex(pv[2:4]) + pv[4:]},
		{RiscvVKey: f.RiscvVKey, PublicValues: pv + "00"},
		{RiscvVKey: f.RiscvVKey[:65] + flipHex(f.RiscvVKey[65:]), PublicValues: pv},
	} {
		inputs, err := WrapPublicInputs(changed)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckProofInputs(honest, inputs); err == nil {
			t.Fatalf("a proof file's inputs are accepted against changed inputs %+v", changed)
		}
	}
}

// A word that is not the right width, or not canonical, is refused rather than reduced.
func TestMalformedInputsAreRefused(t *testing.T) {
	f := readFixture(t, "fib.json")
	modulus := "0x" + strings.Repeat("0", 64-len(bn254_fr.Modulus().Text(16))) + bn254_fr.Modulus().Text(16)
	for _, bad := range []VerifyInputs{
		{RiscvVKey: "0x1234", PublicValues: f.PublicValues},
		{RiscvVKey: modulus, PublicValues: f.PublicValues},
		{RiscvVKey: f.RiscvVKey, PublicValues: strings.TrimPrefix(f.PublicValues, "0x")},
		{RiscvVKey: f.RiscvVKey, PublicValues: "0xzz"},
	} {
		if _, err := WrapPublicInputs(bad); err == nil {
			t.Fatalf("malformed inputs accepted: %+v", bad)
		}
	}
}

// flipHex flips the low bit of a two-digit hex byte.
func flipHex(b string) string {
	v, _ := new(big.Int).SetString(b, 16)
	v.Xor(v, big.NewInt(1))
	s := v.Text(16)
	if len(s) < len(b) {
		s = strings.Repeat("0", len(b)-len(s)) + s
	}
	return s
}
