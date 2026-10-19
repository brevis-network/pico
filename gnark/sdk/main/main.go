package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/brevis-network/pico/gnark/sdk"
)

var (
	cmd             = flag.String("cmd", "prove", "cmd to choose: prove(default)/setup/solve/verify/setupAndProve/exportSolidity")
	pkPath          = flag.String("pk", "./data/vm_pk", "path of proving key")
	ccsPath         = flag.String("ccs", "./data/vm_ccs", "path of ccs")
	vkPath          = flag.String("vk", "./data/vm_vk", "path of verifying key")
	witnessFile     = flag.String("witness", "./data/groth16_witness.json", "path of witness json file")
	field           = flag.String("field", "kb", "field for proving; only kb is supported")
	constraintsFile = flag.String("constraints", "./data/constraints.json", "path of constraint json file")
	proofPath       = flag.String("proof", "./data/proof.data", "path of proof file")
	solidifyPath    = flag.String("sol", "./data/Groth16Verifier.sol", "path of solidify file")
	manifestPath    = flag.String("manifest", "./data/manifest.json", "path of the setup manifest: setup writes it, prove checks -constraints against it")
)

// The `-groth16` switch is deliberately absent. It selected koalabear.go's `api.ToBinary`
// range-check branch, and the MLE circuit's canonical-witness reduction is only sound on the
// log-derivative branch -- the compensating shifted check exists nowhere else. It also defaulted
// to true, so the shipped CLI compiled the branch the deployed verifier did not expect and
// produced a proof that could not verify, from a command that exited 0.
func main() {
	flag.Parse()
	err := os.Setenv("PK_PATH", *pkPath)
	if err != nil {
		fmt.Printf("failed to set pk env var: %v\n", err)
		return
	}

	err = os.Setenv("CCS_PATH", *ccsPath)
	if err != nil {
		fmt.Printf("failed to set ccs env var: %v\n", err)
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

	err = os.Setenv("MANIFEST_PATH", *manifestPath)
	if err != nil {
		fmt.Printf("failed to set manifest path env var: %v\n", err)
		return
	}

	switch *field {
	case "kb":
		if err = sdk.KoalaBearCmd(*cmd); err != nil {
			fmt.Printf("failed to koalabear: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Printf("field %s not supported\n", *field)
		os.Exit(1)
	}

}
