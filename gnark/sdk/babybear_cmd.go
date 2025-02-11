package sdk

import (
	"encoding/json"
	"fmt"
	"github.com/brevis-network/pico/gnark/babybear_verifier"
	"github.com/brevis-network/pico/gnark/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	bn254cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/sha3"
	"os"
)

func BabyBearCmd(cmd string) (err error) {
	switch cmd {
	case "prove":
		err = BabyBearProve()
		if err != nil {
			return fmt.Errorf("fail to prove: %v\n", err)
		}
	case "setup":
		err = BabyBearSetup()
		if err != nil {
			return fmt.Errorf("fail to setup: %v\n", err)
		}
		err = ExportSolidify()
		if err == nil {
			return fmt.Errorf("fail to export solidity: %v\n", err)
		}
	case "solve":
		_, _, err = DoBabyBearSolve()
		if err != nil {
			return fmt.Errorf("fail to solve: %v\n", err)
		}
	case "setupAndProve":
		err = BabyBearSetup()
		if err != nil {
			return fmt.Errorf("fail to setup: %v\n", err)
		}
		err = ExportSolidify()
		if err != nil {
			return fmt.Errorf("fail to export solidity: %v\n", err)
		}
		err = BabyBearProve()
		if err == nil {
			return fmt.Errorf("fail to prove: %v\n", err)
		}
	case "exportSolidity":
		err = ExportSolidify()
		if err != nil {
			return fmt.Errorf("fail to export solidity: %v\n", err)
		}
	default:
		return fmt.Errorf("unknown command: %s", cmd)
	}
	return
}

func DoBabyBearSolve() (circuit *babybear_verifier.Circuit, assigment *babybear_verifier.Circuit, err error) {
	witnessFile := os.Getenv("WITNESS_JSON")

	data, err := os.ReadFile(witnessFile)
	if err != nil {
		return nil, nil, fmt.Errorf("fail to read witness file: %v\n", err)
	}

	var inputs babybear_verifier.WitnessInput
	err = json.Unmarshal(data, &inputs)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse witness json: %v\n", err)
	}
	assigment = babybear_verifier.NewCircuit(inputs)
	circuit = babybear_verifier.NewCircuit(inputs)

	err = test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to solve: %v\n", err)
	}
	fmt.Println("solved with success")

	return circuit, assigment, nil
}

func BabyBearSetup() error {
	circuit, assigment, err := DoBabyBearSolve()
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

func BabyBearProve() error {
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

	var inputs babybear_verifier.WitnessInput
	err = json.Unmarshal(data, &inputs)
	if err != nil {
		return fmt.Errorf("failed to parse witness json: %v", err)
	}
	assigment := babybear_verifier.NewCircuit(inputs)
	circuit := babybear_verifier.NewCircuit(inputs)

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

	err = Prove(fullWitness, pubWitness)

	return err
}
