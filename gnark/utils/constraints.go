package utils

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"math/big"
	"os"
	"strconv"
)

type WitnessInput struct {
	Vars                  []string   `json:"vars"`
	Felts                 []string   `json:"felts"`
	Exts                  [][]string `json:"exts"`
	VkeyHash              string     `json:"vkey_hash"`
	CommittedValuesDigest string     `json:"committed_values_digest"`
	// Which proving backend produced this witness. "mle" selects the MLE KoalaBear-Poseidon2
	// round-constant table; absent means the legacy FRI table. Both circuits have the same two
	// public inputs, so the witness is the only thing that can tell them apart.
	Backend string `json:"backend"`
}

// ConstraintsPath is the constraints file the circuit is compiled from: CONSTRAINTS_JSON, or
// constraints.json when it is unset. Everything that reads the circuit's file resolves it here,
// so a check on it is a check on what Define compiles.
func ConstraintsPath() string {
	if path := os.Getenv("CONSTRAINTS_JSON"); path != "" {
		return path
	}
	return "constraints.json"
}

// AllowUnpinnedSetupEnv names the variable that lets a Groth16 setup run on MLE wrap constraints
// that pin no whitelist root. For tests only.
const AllowUnpinnedSetupEnv = "PICO_GNARK_ALLOW_UNPINNED_SETUP"

// AssertVkRootOpcode asserts the vk_root public-value limbs, args[0], equal the whitelist root,
// args[1], given as canonical decimals.
const AssertVkRootOpcode = "AssertVkRoot"

// ConstraintsVkRoot returns the whitelist root the constraints file at path pins: the constant
// side of its one AssertVkRoot op, or nil when it has none. A second op is an error: no file
// the prover writes has one, and a setup should not have to decide which root it attests.
func ConstraintsVkRoot(path string) ([]uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Streamed, so that a file of millions of ops is never held whole, and only the AssertVkRoot
	// arguments are decoded.
	dec := json.NewDecoder(f)
	if tok, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("parse %s: %v", path, err)
	} else if tok != json.Delim('[') {
		return nil, fmt.Errorf("%s is not a json array of constraints", path)
	}
	var root []uint32
	for dec.More() {
		var op struct {
			Opcode string          `json:"opcode"`
			Args   json.RawMessage `json:"args"`
		}
		if err := dec.Decode(&op); err != nil {
			return nil, fmt.Errorf("parse %s: %v", path, err)
		}
		if op.Opcode != AssertVkRootOpcode {
			continue
		}
		if root != nil {
			return nil, fmt.Errorf("%s has more than one %s op", path, AssertVkRootOpcode)
		}
		if root, err = parseVkRootArgs(op.Args); err != nil {
			return nil, fmt.Errorf("%s: %s: %v", path, AssertVkRootOpcode, err)
		}
	}
	return root, nil
}

func parseVkRootArgs(raw json.RawMessage) ([]uint32, error) {
	var args [][]string
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, err
	}
	if len(args) != 2 || len(args[0]) != 8 || len(args[1]) != 8 {
		return nil, fmt.Errorf("want 8 felts and 8 root limbs")
	}
	root := make([]uint32, 8)
	for i, limb := range args[1] {
		v, err := strconv.ParseUint(limb, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("root limb %d: %v", i, err)
		}
		root[i] = uint32(v)
	}
	return root, nil
}

// SetupVkRoot is the whitelist root a Groth16 setup over the MLE wrap constraints at path
// attests. Constraints that pin none are refused unless allowUnpinned is set: keys made from them
// verify a wrap of a recursion tree of any program with the same layout, since every in-circuit
// membership check is then against a root the prover chose.
func SetupVkRoot(path string, allowUnpinned bool) ([]uint32, error) {
	root, err := ConstraintsVkRoot(path)
	if err != nil || root != nil {
		return root, err
	}
	if allowUnpinned {
		fmt.Printf("WARNING: the wrap constraints %s pin no whitelist root; %s=1, so setting up "+
			"anyway. These keys accept any program of the same layout: never deploy them.\n",
			path, AllowUnpinnedSetupEnv)
		return nil, nil
	}
	return nil, fmt.Errorf("the wrap constraints %s pin no whitelist root, and keys made from "+
		"them would accept any program of the same layout. Prove in whitelist mode "+
		"(VK_VERIFICATION=true with MLE_VK_MAP and MLE_VK_ROOT), or set %s=1 for a test setup",
		path, AllowUnpinnedSetupEnv)
}

type Groth16Proof struct {
	A             [2]string    `json:"a"`
	B             [2][2]string `json:"b"`
	C             [2]string    `json:"c"`
	Commitment    [2]string    `json:"commitment"`
	CommitmentPok [2]string    `json:"commitment_pok"`
}

func ReadProvingKey(filename string, pk groth16.ProvingKey) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = pk.UnsafeReadFrom(f)
	return err
}

func ReadVerifyingKey(filename string, vk groth16.VerifyingKey) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = vk.UnsafeReadFrom(f)
	return err
}

func WriteProvingKey(filename string, pk groth16.ProvingKey) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	_, err = pk.WriteTo(f)
	if err != nil {
		return err
	}
	return nil
}

func WriteVerifyingKey(filename string, vk groth16.VerifyingKey) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}

	_, err = vk.WriteTo(f)
	if err != nil {
		return err
	}
	return nil
}

func GetAggOnChainProof(proof groth16.Proof, pubWitness witness.Witness) (string, error) {
	a, b, c, commitment, commitmentPok := ExportProof(proof)
	var A [2]string
	for i := 0; i < 2; i++ {
		A[i] = Encode(a[i].FillBytes(make([]byte, 32)))
	}

	var B [2][2]string
	for i := 0; i < 2; i++ {
		for j := 0; j < 2; j++ {
			B[i][j] = Encode(b[i][j].FillBytes(make([]byte, 32)))
		}
	}

	var C [2]string
	for i := 0; i < 2; i++ {
		C[i] = Encode(c[i].FillBytes(make([]byte, 32)))
	}

	var Commitment [2]string
	var CommitmentPok [2]string
	for i := 0; i < 2; i++ {
		Commitment[i] = Encode(commitment[i].FillBytes(make([]byte, 32)))
		CommitmentPok[i] = Encode(commitmentPok[i].FillBytes(make([]byte, 32)))
	}

	proofData := Groth16Proof{
		A:             A,
		B:             B,
		C:             C,
		Commitment:    Commitment,
		CommitmentPok: CommitmentPok,
	}

	var result = ""
	result += proofData.A[0] + ","
	result += proofData.A[1] + ","
	result += proofData.B[0][0] + ","
	result += proofData.B[0][1] + ","
	result += proofData.B[1][0] + ","
	result += proofData.B[1][1] + ","
	result += proofData.C[0] + ","
	result += proofData.C[1] + ","
	result += proofData.Commitment[0] + ","
	result += proofData.Commitment[1] + ","
	result += proofData.CommitmentPok[0] + ","
	result += proofData.CommitmentPok[1] + ","

	// Then the public inputs, in the circuit's order: vkey_hash, committed_values_digest.
	swVector := pubWitness.Vector().(bn254_fr.Vector)
	for i := 0; i < len(swVector); i++ {
		var data [32]byte
		swVector[i].BigInt(new(big.Int)).FillBytes(data[:])
		if i == len(swVector)-1 {
			result += Encode(data[:])
		} else {
			result += Encode(data[:]) + ","
		}
	}
	return result, nil
}

// only for bn254
func ExportProof(proof groth16.Proof) (a [2]*big.Int, b [2][2]*big.Int, c [2]*big.Int, commitment [2]*big.Int, commitmentPok [2]*big.Int) {
	bn254Proof := proof.(*groth16_bn254.Proof)
	// proof.Ar, proof.Bs, proof.Krs
	a[0] = bn254Proof.Ar.X.BigInt(new(big.Int))
	a[1] = bn254Proof.Ar.Y.BigInt(new(big.Int))

	b[0][0] = bn254Proof.Bs.X.A1.BigInt(new(big.Int))
	b[0][1] = bn254Proof.Bs.X.A0.BigInt(new(big.Int))
	b[1][0] = bn254Proof.Bs.Y.A1.BigInt(new(big.Int))
	b[1][1] = bn254Proof.Bs.Y.A0.BigInt(new(big.Int))

	c[0] = bn254Proof.Krs.X.BigInt(new(big.Int))
	c[1] = bn254Proof.Krs.Y.BigInt(new(big.Int))

	// The log-derivative range checker puts exactly one Pedersen commitment in every proof,
	// and gnark's exported verifier takes it and its proof of knowledge as two extra calldata
	// arguments. There is no commitment-free shape in this tree any more, so this is
	// unconditional; a proof arriving here without one is a bug worth crashing on.
	commitment[0] = bn254Proof.Commitments[0].X.BigInt(new(big.Int))
	commitment[1] = bn254Proof.Commitments[0].Y.BigInt(new(big.Int))

	commitmentPok[0] = bn254Proof.CommitmentPok.X.BigInt(new(big.Int))
	commitmentPok[1] = bn254Proof.CommitmentPok.Y.BigInt(new(big.Int))
	return
}

// Encode hex-encodes b with an 0x prefix. It does NOT pad: callers are responsible for
// handing it a fixed-width buffer. Every BN254 coordinate emitted by GetAggOnChainProof goes
// through big.Int.FillBytes(make([]byte, 32)) for exactly that reason -- big.Int.Bytes()
// strips leading zeros, which silently produced short fields whenever a coordinate's top byte
// was zero.
func Encode(b []byte) string {
	enc := make([]byte, len(b)*2+2)
	copy(enc, "0x")
	hex.Encode(enc[2:], b)
	return string(enc)
}

func ReadCcs(filename string, ccs constraint.ConstraintSystem) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = ccs.ReadFrom(f)
	return err
}

func WriteCcs(filename string, css constraint.ConstraintSystem) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	_, err = css.WriteTo(f)
	if err != nil {
		return err
	}
	return nil
}
