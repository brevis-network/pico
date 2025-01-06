package sdk

import (
	"encoding/json"
	"fmt"
	"github.com/brevis-network/brevis-vm/gnark/utils"
	"github.com/brevis-network/brevis-vm/gnark/vm_verifier"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	bn254cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/sha3"
	"io/ioutil"
	"os"
	"sync"
)

var (
	Pk  = groth16.NewProvingKey(ecc.BN254)
	Vk  = groth16.NewVerifyingKey(ecc.BN254)
	Ccs = new(bn254cs.R1CS)

	loadLock sync.WaitGroup
)

type PicoGroth16Proof struct {
	VkeyHash              string
	CommittedValuesDigest string
	Proof                 string // hex
}

func DoSolve() (circuit *vm_verifier.Circuit, assigment *vm_verifier.Circuit, err error) {
	witnessFile := os.Getenv("WITNESS_JSON")

	data, err := os.ReadFile(witnessFile)
	if err != nil {
		return nil, nil, fmt.Errorf("fail to read witness file: %v\n", err)
	}

	var inputs vm_verifier.WitnessInput
	err = json.Unmarshal(data, &inputs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse witness json: %v\n", err)
	}
	assigment = vm_verifier.NewCircuit(inputs)
	circuit = vm_verifier.NewCircuit(inputs)

	err = test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to solve: %v\n", err)
	}
	fmt.Println("solved with success")

	return circuit, assigment, nil
}

func Setup() error {
	circuit, assigment, err := DoSolve()
	if err != nil {
		return fmt.Errorf("fail to solve: %v\n", err)
	}
	fullWitness, err := frontend.NewWitness(assigment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("fail to gen full witness: %v", err)
	}
	pubWitness, err := fullWitness.Public()
	if err != nil {
		return fmt.Errorf("fail to gen public witness: %v", err)
	}
	//fmt.Printf("fullWitness: %v \n", pubWitness)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return fmt.Errorf("fail to compile frontend: %v", err)
	}
	Ccs = ccs.(*bn254cs.R1CS)
	fmt.Printf("ccs: %d \n", ccs.GetNbConstraints())

	Pk, Vk, err = groth16.Setup(Ccs)
	if err != nil {
		return fmt.Errorf("fail to setup groth16: %v", err)
	}

	pf, err := groth16.Prove(Ccs, Pk, fullWitness, backend.WithProverHashToFieldFunction(sha3.NewLegacyKeccak256()))
	if err != nil {
		return fmt.Errorf("fail to prove groth16: %v", err)
	}

	err = groth16.Verify(pf, Vk, pubWitness, backend.WithVerifierHashToFieldFunction(sha3.NewLegacyKeccak256()))
	if err != nil {
		return fmt.Errorf("fail to verify: %v", err)
	}

	err = utils.WriteProvingKey(os.Getenv("PK_PATH"), Pk)
	if err != nil {
		return fmt.Errorf("fail to write pk: %v", err)
	}

	err = utils.WriteVerifyingKey(os.Getenv("VK_PATH"), Vk)
	if err != nil {
		return fmt.Errorf("fail to write vk: %v", err)
	}
	return nil
}

func Prove() error {
	loadLock.Add(2) // 1 for load pk, 1 for compile ccs

	var reafProveKeyErr, compileCcsErr error
	go func() {
		defer loadLock.Done()
		reafProveKeyErr = utils.ReadProvingKey(os.Getenv("PK_PATH"), Pk)
	}()

	err := utils.ReadVerifyingKey(os.Getenv("VK_PATH"), Vk)
	if err != nil {
		return fmt.Errorf("failed to read verifing key: %v", err)
	}

	witnessFile := os.Getenv("WITNESS_JSON")

	data, err := os.ReadFile(witnessFile)
	if err != nil {
		return fmt.Errorf("fail to read witness file: %v\n", err)
	}

	var inputs vm_verifier.WitnessInput
	err = json.Unmarshal(data, &inputs)
	if err != nil {
		return fmt.Errorf("failed to parse witness json: %v", err)
	}
	assigment := vm_verifier.NewCircuit(inputs)
	circuit := vm_verifier.NewCircuit(inputs)

	err = test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("failed to solve: %v", err)
	}

	fullWitness, err := frontend.NewWitness(assigment, ecc.BN254.ScalarField())
	if err != nil {
		return fmt.Errorf("failed to get full witness: %v", err)
	}
	pubWitness, err := fullWitness.Public()
	if err != nil {
		return fmt.Errorf("failed to get public witness: %v", err)
	}
	fmt.Printf("fullWitness: %v \n", pubWitness)

	go func() {
		defer loadLock.Done()
		ccs, ccsErr := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
		if ccsErr != nil {
			compileCcsErr = ccsErr
			return
		}
		Ccs = ccs.(*bn254cs.R1CS)
		fmt.Printf("ccs: %d \n", ccs.GetNbConstraints())
	}()

	loadLock.Wait()

	if compileCcsErr != nil {
		return fmt.Errorf("fail to compile compiler: %v", compileCcsErr)
	}
	if reafProveKeyErr != nil {
		return fmt.Errorf("fail to read reproving key: %v", reafProveKeyErr)
	}

	pf, err := groth16.Prove(Ccs, Pk, fullWitness, backend.WithProverHashToFieldFunction(sha3.NewLegacyKeccak256()))
	if err != nil {
		return fmt.Errorf("failed to prove: %v", err)
	}

	err = groth16.Verify(pf, Vk, pubWitness, backend.WithVerifierHashToFieldFunction(sha3.NewLegacyKeccak256()))
	if err != nil {
		return fmt.Errorf("failed to verify proof: %v", err)
	}

	res, err := utils.GetAggOnChainProof(pf, pubWitness)
	if err != nil {
		return fmt.Errorf("failed to get OnChainProof: %v\n", err)
	}

	err = ioutil.WriteFile(os.Getenv("PROOF_PATH"), []byte(res), 0644)
	if err != nil {
		return fmt.Errorf("failed to write res, err: %v", err)
	}
	fmt.Println("proof written successfully")

	bn254Proof := pf.(*groth16_bn254.Proof)
	fmt.Printf("bn254Proof Commitments: %v \n", bn254Proof.Commitments)
	fmt.Printf("bn254Proof CommitmentPok: %v \n", bn254Proof.CommitmentPok)

	return nil
}

func ExportSolidify() error {
	err := utils.ReadVerifyingKey(os.Getenv("VK_PATH"), Vk)
	if err != nil {
		return fmt.Errorf("failed to read verifiing key: %v", err)
	}

	f, err := os.Create(os.Getenv("SOLIDITY_PATH"))
	defer f.Close()
	if err != nil {
		return fmt.Errorf("fail to solidify file: %v", err)
	}

	err = Vk.ExportSolidity(f)
	if err != nil {
		return fmt.Errorf("fail to export solidity: %v", err)
	}
	return nil
}
