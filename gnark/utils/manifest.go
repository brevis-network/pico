package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

// Manifest records what a Groth16 setup was made from and what it wrote. `prove` reads it to
// refuse a witness for another circuit before it loads gigabytes of keys, and a published key
// set is checked against it: the same wrap_constraints.json gives the same circuit_sha256, the
// file hashes say which pk, vk and verifier contract that setup produced, and vk_root says which
// whitelist they accept.
type Manifest struct {
	// SHA-256 of the wrap_constraints.json the circuit was compiled from.
	CircuitSha256 string `json:"circuit_sha256"`
	// R1CS constraints: a Groth16 key for more than 2^23 needs the 2^24 FFT domain.
	NbConstraints int `json:"nb_constraints"`
	// Public inputs, not counting the constant wire: vkey_hash and committed_values_digest.
	NbPublicInputs int `json:"nb_public_inputs"`
	// The gnark module the setup ran with, as the build recorded it.
	Gnark string `json:"gnark"`
	// SHA-256 of each file the setup wrote, by role: pk, vk, ccs and solidity.
	Files map[string]string `json:"files"`
	// The whitelist root the circuit pins, as the eight canonical KoalaBear limbs of its
	// AssertVkRoot op: the root a deployment of these keys accepts. Absent for a circuit that
	// pins none, which only a setup with the unpinned override, or of a FRI circuit, writes.
	VkRoot []uint32 `json:"vk_root,omitempty"`
}

// Sha256File hashes a file without reading it into memory: a proving key is gigabytes.
func Sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %v", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// GnarkVersion is the gnark module version this binary was built with, "unknown" when the build
// carries no module information.
func GnarkVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/consensys/gnark" {
			return dep.Version
		}
	}
	return "unknown"
}

func WriteManifest(path string, m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func ReadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %v", path, err)
	}
	if m.CircuitSha256 == "" {
		return nil, fmt.Errorf("%s names no circuit_sha256", path)
	}
	return &m, nil
}

// CheckCircuit refuses a constraints file other than the one the keys were set up for. A key
// set is bound to one circuit, and the wrap circuit bakes in the whitelist root, so a witness
// from a prover with another whitelist is exactly what this catches.
func (m *Manifest) CheckCircuit(constraintsPath string) error {
	got, err := Sha256File(constraintsPath)
	if err != nil {
		return err
	}
	if got != m.CircuitSha256 {
		return fmt.Errorf("the keys were set up for circuit %s, and %s is circuit %s: it needs a setup of its own",
			m.CircuitSha256, constraintsPath, got)
	}
	return nil
}
