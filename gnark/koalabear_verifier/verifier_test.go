package koalabear_verifier

import (
	"encoding/json"
	"fmt"
	"github.com/brevis-network/pico/gnark/utils"
	"github.com/consensys/gnark-crypto/ecc"
	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/sha3"
	"log"
	"os"
	"testing"
)

func TestSolveVerifierCircuit(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	assert := test.NewAssert(t)

	os.Setenv("WITNESS_JSON", "./groth16_witness.json")
	os.Setenv("CONSTRAINTS_JSON", "./constraints.json")
	os.Setenv("GROTH16", "1")

	doSolve(assert)
	fmt.Printf("done koala bear verify \n")
}

func TestSetupVerifierCircuit(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	assert := test.NewAssert(t)

	os.Setenv("WITNESS_JSON", "./groth16_witness.json")
	os.Setenv("CONSTRAINTS_JSON", "./constraints.json")
	os.Setenv("GROTH16", "1")

	circuit, assigment := doSolve(assert)

	doSetUp(assert, circuit, assigment)
}

func doSolve(assert *test.Assert) (circuit *Circuit, assigment *Circuit) {
	data, err := os.ReadFile("./groth16_witness.json")
	assert.NoError(err)

	// Deserialize the JSON data into a slice of Instruction structs
	var inputs utils.WitnessInput
	err = json.Unmarshal(data, &inputs)
	assert.NoError(err)
	assigment = NewCircuit(inputs)
	circuit = NewCircuit(inputs)

	err = test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	assert.NoError(err)
	fmt.Println("solve done")

	return circuit, assigment
}

func doSetUp(assert *test.Assert, circuit *Circuit, assigment *Circuit) {
	fullWitness, err := frontend.NewWitness(assigment, ecc.BN254.ScalarField())
	assert.NoError(err)
	pubWitness, err := fullWitness.Public()
	assert.NoError(err)
	fmt.Printf("fullWitness: %v \n", pubWitness)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	assert.NoError(err)
	fmt.Printf("ccs: %d \n", ccs.GetNbConstraints())

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalln(err)
	}

	pf, err := groth16.Prove(ccs, pk, fullWitness, backend.WithProverHashToFieldFunction(sha3.NewLegacyKeccak256()))
	assert.NoError(err)

	err = groth16.Verify(pf, vk, pubWitness, backend.WithVerifierHashToFieldFunction(sha3.NewLegacyKeccak256()))
	assert.NoError(err)

	err = utils.WriteProvingKey("vm_pk", pk)
	assert.NoError(err)

	err = utils.WriteVerifyingKey("vm_vk", vk)
	assert.NoError(err)

	err = utils.WriteCcs("vm_ccs", ccs)
	assert.NoError(err)

	f, err := os.Create("Groth16Verifier.sol")
	defer f.Close()
	assert.NoError(err)

	err = vk.ExportSolidity(f)
	assert.NoError(err)
}

func TestVerifyProof(t *testing.T) {
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())
	assert := test.NewAssert(t)

	var bn254Vk groth16_bn254.VerifyingKey
	err := utils.ReadVerifyingKey("vm_vk", &bn254Vk)
	assert.NoError(err)

	var bn254Proof groth16_bn254.Proof
	var pubWitness bn254_fr.Vector
	var pub1, pub2 bn254_fr.Element

	bn254Proof.Ar.X.SetBytes(common.HexToHash("0x13d502e6bb33187b8251eff8f388a2ebb7edab3c428fdfe22ca135b8cad3292d").Bytes())
	bn254Proof.Ar.Y.SetBytes(common.HexToHash("0x2181025631aef5ee919f15c71cf54c3de6ee92b9fec721234a75d8d442680439").Bytes())
	bn254Proof.Bs.X.A1.SetBytes(common.HexToHash("0x139a44d54695192467e225331ff838c2a132f0684af3fd1f2cc711cf98a9c1dd").Bytes())
	bn254Proof.Bs.X.A0.SetBytes(common.HexToHash("0x1090f329df3a95a3e20076589e395267808e1bd5a676c8fc3e0ca724588482d3").Bytes())
	bn254Proof.Bs.Y.A1.SetBytes(common.HexToHash("0x1ad808833daa58bfaecc57fbc9c0a26e473abad3843f6b8a11c82d43fb6b7046").Bytes())
	bn254Proof.Bs.Y.A0.SetBytes(common.HexToHash("0x1aeb2fa095ca05d471367670792004d755af298da88a874ec2e8293739ad5d01").Bytes())
	bn254Proof.Krs.X.SetBytes(common.HexToHash("0x2d4b8f5e2ed555ea2e81d3cf8c196108b4f017cf0e2e891dbcaef4696546f63a").Bytes())
	bn254Proof.Krs.Y.SetBytes(common.HexToHash("0x2268cde4f532bb060ed569ff9db9543e30120239796f10a2bd678f7007ea1d94").Bytes())
	pub1.SetBytes(common.HexToHash("0x0026bc8aa9c7eb428f1d55142dfebd9e63d7de7922da83f36bbc205e50814af2").Bytes())
	pub2.SetBytes(common.HexToHash("0x03b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").Bytes())
	pubWitness = append(pubWitness, pub1, pub2)

	err = groth16_bn254.Verify(&bn254Proof, &bn254Vk, pubWitness)
	assert.NoError(err)
}
