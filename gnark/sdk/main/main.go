package main

import (
	"flag"
	"fmt"
	"github.com/brevis-network/brevis-vm/gnark/sdk"
	"os"
)

var (
	cmd             = flag.String("cmd", "prove", "cmd to choose: prove(default)/setup/solve")
	pkPath          = flag.String("pk", "./data/vm_pk", "path of proving key")
	vkPath          = flag.String("vk", "./data/vm_vk", "path of verifying key")
	useGroth16      = flag.Bool("groth16", true, "use groth16")
	witnessFile     = flag.String("witness", "./data/groth16_witness.json", "path of witness json file")
	constraintsFile = flag.String("constraints", "./data/constraints.json", "path of constraint json file")
	proofPath       = flag.String("proof", "./data/proof.data", "path of proof file")
	solidifyPath    = flag.String("sol", "./data/pico_vm_verifier.sol", "path of solidify file")
)

func main() {
	flag.Parse()
	if *useGroth16 {
		err := os.Setenv("GROTH16", "1")
		if err != nil {
			fmt.Printf("failed to set env var: %v\n", err)
			return
		}
	}
	err := os.Setenv("PK_PATH", *pkPath)
	if err != nil {
		fmt.Printf("failed to set pk env var: %v\n", err)
		return
	}

	err = os.Setenv("VK_PATH", *vkPath)
	if err != nil {
		fmt.Printf("failed to set vk env var: %v\n", err)
		return
	}

	err = os.Setenv("WITNESS_JSON", *witnessFile)
	if err != nil {
		fmt.Printf("failed to set witness env var: %v\n", err)
		return
	}

	err = os.Setenv("CONSTRAINTS_JSON", *constraintsFile)
	if err != nil {
		fmt.Printf("failed to set constrains env var: %v\n", err)
		return
	}

	err = os.Setenv("PROOF_PATH", *proofPath)
	if err != nil {
		fmt.Printf("failed to set proof path env var: %v\n", err)
		return
	}

	err = os.Setenv("SOLIDITY_PATH", *solidifyPath)
	if err != nil {
		fmt.Printf("failed to set solidify path env var: %v\n", err)
		return
	}

	switch *cmd {
	case "prove":
		err = sdk.Prove()
		if err != nil {
			fmt.Printf("fail to prove: %v\n", err)
		}
	case "setup":
		err = sdk.Setup()
		if err != nil {
			fmt.Printf("fail to setup: %v\n", err)
		}
		err = sdk.ExportSolidify()
		if err == nil {
			fmt.Printf("fail to export solidity: %v\n", err)
		}
	case "solve":
		_, _, err = sdk.DoSolve()
		if err != nil {
			fmt.Printf("fail to solve: %v\n", err)
		}
	case "setupAndProve":
		err = sdk.Setup()
		if err == nil {
			fmt.Printf("fail to setup: %v\n", err)
		}
		err = sdk.ExportSolidify()
		if err == nil {
			fmt.Printf("fail to export solidity: %v\n", err)
		}
		err = sdk.Prove()
		if err == nil {
			fmt.Printf("fail to prove: %v\n", err)
		}
	case "exportSolidity":
		err = sdk.ExportSolidify()
		if err != nil {
			fmt.Printf("fail to export solidity: %v\n", err)
		}
	default:
		fmt.Printf("unknown command: %s \n", *cmd)
		return
	}
}
