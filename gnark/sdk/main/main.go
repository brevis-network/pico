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
	field           = flag.String("field", "babybear", "field for proving, support babybear and koala bear")
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

	switch *field {
	case "babybear":
		err = sdk.BabyBearCmd(*cmd)
		if err != nil {
			fmt.Printf("failed to babybear: %v\n", err)
			return
		}
	case "koalabear":
		err = sdk.KoalaBearCmd(*cmd)
		if err != nil {
			fmt.Printf("failed to koalabear: %v\n", err)
			return
		}
	default:
		fmt.Printf("field %s not supported\n", *field)
		return
	}

}
