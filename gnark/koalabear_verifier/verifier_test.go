package koalabear_verifier

import (
	"encoding/json"
	"fmt"
	"github.com/brevis-network/pico/gnark/utils"
	"github.com/celer-network/goutils/log"
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

	res, err := utils.GetAggOnChainProof(pf, pubWitness)
	assert.NoError(err)
	log.Infof("res: %+v", res)

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

func TestVerify(t *testing.T) {
	assert := test.NewAssert(t)

	// load vk
	vk := &groth16_bn254.VerifyingKey{}
	err := utils.ReadVerifyingKey("./vm_vk", vk)
	assert.NoError(err)

	var pubWitnessVector bn254_fr.Vector
	/*
		witness_0: 0x0024c5ed2607a793fc6417f00e797e8a2fa6f3b164968e06d9ac45139c52af1e
		witness_1: 0x03b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	*/
	w1 := common.HexToHash("0x0024c5ed2607a793fc6417f00e797e8a2fa6f3b164968e06d9ac45139c52af1e")
	w2 := common.HexToHash("0x03b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

	var one, two bn254_fr.Element
	one.SetBytes(w1[:])
	two.SetBytes(w2[:])
	pubWitnessVector = append(pubWitnessVector, one, two)

	/*
		proofData.A[0]: 0x0589dc0bb97a050e1195e8fb1553c7d7eba9a9ea86c1e6fae6e3a9911984093c
		proofData.A[1]: 0x2118692f49d428305d9a855ba0168212e264892a079dd107238892c527de9e80
		proofData.B[0][0]: 0x24f9daff30c2f868716d9d05f680f845e8c301eb41d69a0c57e31a0936f43881
		proofData.B[0][1]: 0x0d69635321e9f16eabe9310ad2895ef2acb175fcf943e4e824ef6751e74711bc
		proofData.B[1][0]: 0x247f0e801c8bd1daa4399f633aca30d749bf4b78ada6fef9e698ad88aa60d818
		proofData.B[1][1]: 0x0eeff499c9a0773a1e18e05d0a30dd5cd6e0411f9dc11040530173a521b3076e
		proofData.C[0]: 0x077f7fde2ba663ea781b5a99168d5df0b5de28fac1dd515dd6b34e74c1d53c37
		proofData.C[1]: 0x072e55103a031969a1d8ed0b582e7e17316c46e254c33d428a6f6586ecd8fd7d
	*/
	pa0 := common.HexToHash("0x0589dc0bb97a050e1195e8fb1553c7d7eba9a9ea86c1e6fae6e3a9911984093c")
	pa1 := common.HexToHash("0x2118692f49d428305d9a855ba0168212e264892a079dd107238892c527de9e80")
	pb00 := common.HexToHash("0x24f9daff30c2f868716d9d05f680f845e8c301eb41d69a0c57e31a0936f43881")
	pb01 := common.HexToHash("0x0d69635321e9f16eabe9310ad2895ef2acb175fcf943e4e824ef6751e74711bc")
	pb10 := common.HexToHash("0x247f0e801c8bd1daa4399f633aca30d749bf4b78ada6fef9e698ad88aa60d818")
	pb11 := common.HexToHash("0x0eeff499c9a0773a1e18e05d0a30dd5cd6e0411f9dc11040530173a521b3076e")
	pc0 := common.HexToHash("0x077f7fde2ba663ea781b5a99168d5df0b5de28fac1dd515dd6b34e74c1d53c37")
	pc1 := common.HexToHash("0x072e55103a031969a1d8ed0b582e7e17316c46e254c33d428a6f6586ecd8fd7d")
	var proof groth16_bn254.Proof
	proof.Ar.X.SetBytes(pa0[:])
	proof.Ar.Y.SetBytes(pa1[:])
	proof.Bs.X.A1.SetBytes(pb00[:])
	proof.Bs.X.A0.SetBytes(pb01[:])
	proof.Bs.Y.A1.SetBytes(pb10[:])
	proof.Bs.Y.A0.SetBytes(pb11[:])
	proof.Krs.X.SetBytes(pc0[:])
	proof.Krs.Y.SetBytes(pc1[:])

	// verify
	err = groth16_bn254.Verify(&proof, vk, pubWitnessVector)
	assert.NoError(err)
}
