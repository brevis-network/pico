package sdk

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"

	"github.com/brevis-network/pico/gnark/koalabear_verifier"
	"github.com/brevis-network/pico/gnark/utils"
	"github.com/consensys/gnark-crypto/ecc"
	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	bn254cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/sha3"
)

// KoalaBearCmd runs one command. Each parses the witness file at most once: it is the largest
// input after the keys.
func KoalaBearCmd(cmd string) (err error) {
	var inputs utils.WitnessInput
	switch cmd {
	case "prove":
		if err = KoalaBearProve(nil); err != nil {
			return fmt.Errorf("fail to prove: %v", err)
		}
	case "setup":
		if inputs, err = readWitnessInput(os.Getenv("WITNESS_JSON")); err != nil {
			return fmt.Errorf("fail to setup: %v", err)
		}
		if err = KoalaBearSetup(inputs); err != nil {
			return fmt.Errorf("fail to setup: %v", err)
		}
	case "solve":
		if inputs, err = readWitnessInput(os.Getenv("WITNESS_JSON")); err != nil {
			return fmt.Errorf("fail to solve: %v", err)
		}
		if _, _, err = DoKoalaBearSolve(inputs); err != nil {
			return fmt.Errorf("fail to solve: %v", err)
		}
	case "verify":
		if err = KoalaBearVerify(); err != nil {
			return fmt.Errorf("fail to verify: %v", err)
		}
	case "setupAndProve":
		if inputs, err = readWitnessInput(os.Getenv("WITNESS_JSON")); err != nil {
			return fmt.Errorf("fail to setup: %v", err)
		}
		if err = KoalaBearSetup(inputs); err != nil {
			return fmt.Errorf("fail to setup: %v", err)
		}
		if err = KoalaBearProve(&inputs); err != nil {
			return fmt.Errorf("fail to prove: %v", err)
		}
	case "exportSolidity":
		if err = ExportSolidify(); err != nil {
			return fmt.Errorf("fail to export solidity: %v", err)
		}
	default:
		return fmt.Errorf("unknown command: %s", cmd)
	}
	return
}

func readWitnessInput(path string) (inputs utils.WitnessInput, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return inputs, err
	}
	if err = json.Unmarshal(data, &inputs); err != nil {
		return inputs, fmt.Errorf("parse %s: %v", path, err)
	}
	return inputs, nil
}

func DoKoalaBearSolve(inputs utils.WitnessInput) (circuit *koalabear_verifier.Circuit, assigment *koalabear_verifier.Circuit, err error) {
	assigment = koalabear_verifier.NewCircuit(inputs)
	circuit = koalabear_verifier.NewCircuit(inputs)

	err = test.IsSolved(circuit, assigment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to solve: %v\n", err)
	}
	fmt.Println("solved with success")

	return circuit, assigment, nil
}

// KoalaBearSetup compiles the circuit, runs a Groth16 setup for it, proves and verifies the
// witness once as a check, and writes pk, vk and ccs, the verifier contract and the manifest.
//
// groth16.Setup samples its toxic waste in this process, so whoever runs it can forge proofs
// that verify under these keys. Keys made here are for testing; the keys behind a deployed
// verifier need a setup whose provenance is settled.
//
// On an MLE witness it reads the whitelist root from the constraints file, refuses constraints
// that pin none (see utils.SetupVkRoot) unless PICO_GNARK_ALLOW_UNPINNED_SETUP=1, and records
// the root in the manifest.
func KoalaBearSetup(inputs utils.WitnessInput) error {
	var vkRoot []uint32
	if inputs.Backend == "mle" {
		var err error
		allowUnpinned := os.Getenv(utils.AllowUnpinnedSetupEnv) == "1"
		if vkRoot, err = utils.SetupVkRoot(utils.ConstraintsPath(), allowUnpinned); err != nil {
			return err
		}
	}
	circuit, assigment, err := DoKoalaBearSolve(inputs)
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

	err = utils.WriteCcs(os.Getenv("CCS_PATH"), ccs)
	if err != nil {
		return fmt.Errorf("fail to write ccs: %v", err)
	}

	if err = ExportSolidify(); err != nil {
		return fmt.Errorf("fail to export solidity: %v", err)
	}
	return writeSetupManifest(len(pubWitness.Vector().(bn254_fr.Vector)), vkRoot)
}

// writeSetupManifest records the circuit the keys were made for, the whitelist root it pins, and a
// hash of every file the setup wrote. It hashes the files as written, so it runs after all of them
// are.
func writeSetupManifest(nbPublicInputs int, vkRoot []uint32) error {
	path := os.Getenv("MANIFEST_PATH")
	if path == "" {
		return nil
	}
	circuit, err := utils.Sha256File(utils.ConstraintsPath())
	if err != nil {
		return fmt.Errorf("fail to hash the constraints file: %v", err)
	}
	files := map[string]string{}
	for role, env := range map[string]string{"pk": "PK_PATH", "vk": "VK_PATH", "ccs": "CCS_PATH", "solidity": "SOLIDITY_PATH"} {
		if files[role], err = utils.Sha256File(os.Getenv(env)); err != nil {
			return fmt.Errorf("fail to hash the %s: %v", role, err)
		}
	}
	manifest := &utils.Manifest{
		CircuitSha256:  circuit,
		NbConstraints:  Ccs.GetNbConstraints(),
		NbPublicInputs: nbPublicInputs,
		Gnark:          utils.GnarkVersion(),
		Files:          files,
		VkRoot:         vkRoot,
	}
	if err := utils.WriteManifest(path, manifest); err != nil {
		return fmt.Errorf("fail to write the manifest: %v", err)
	}
	fmt.Printf("manifest: %s\n", path)
	return nil
}

// KoalaBearProve proves a witness with the keys a setup wrote: inputs when given, else the
// WITNESS_JSON file, read while the keys load.
//
// The circuit is the ccs that setup saved, not a fresh compile of the constraints file: compiling
// is most of a prove's wall time, and the saved ccs is the circuit pk was made for. With a
// manifest beside the keys, the constraints file the witness came with must be that circuit, so a
// witness from another circuit is refused before gigabytes of keys are read. The prover solves
// the constraint system itself and fails on an unsatisfied constraint, so no separate solve runs.
func KoalaBearProve(inputs *utils.WitnessInput) error {
	if err := checkCircuitAgainstManifest(); err != nil {
		return err
	}

	// Fresh objects, never the package-level ones: a `setupAndProve` run has already filled
	// those, and gnark's VerifyingKey.readFrom appends commitment keys rather than resetting them
	// (see ExportSolidify).
	pk := groth16.NewProvingKey(ecc.BN254)
	vk := groth16.NewVerifyingKey(ecc.BN254)
	ccs := new(bn254cs.R1CS)
	var wg sync.WaitGroup
	var pkErr, ccsErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		pkErr = utils.ReadProvingKey(os.Getenv("PK_PATH"), pk)
	}()
	go func() {
		defer wg.Done()
		ccsErr = utils.ReadCcs(os.Getenv("CCS_PATH"), ccs)
	}()
	vkErr := utils.ReadVerifyingKey(os.Getenv("VK_PATH"), vk)
	var fullWitness, pubWitness witness.Witness
	var witnessErr error
	if inputs != nil {
		fullWitness, pubWitness, witnessErr = newWitness(*inputs)
	} else {
		fullWitness, pubWitness, witnessErr = readWitness(os.Getenv("WITNESS_JSON"))
	}
	wg.Wait()
	for _, e := range []struct {
		what string
		err  error
	}{{"proving key", pkErr}, {"ccs", ccsErr}, {"verifying key", vkErr}, {"witness", witnessErr}} {
		if e.err != nil {
			return fmt.Errorf("failed to read the %s: %v", e.what, e.err)
		}
	}
	return Prove(ccs, pk, vk, fullWitness, pubWitness)
}

func readWitness(path string) (full witness.Witness, public witness.Witness, err error) {
	inputs, err := readWitnessInput(path)
	if err != nil {
		return nil, nil, err
	}
	return newWitness(inputs)
}

func newWitness(inputs utils.WitnessInput) (full witness.Witness, public witness.Witness, err error) {
	full, err = frontend.NewWitness(koalabear_verifier.NewCircuit(inputs), ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, err
	}
	public, err = full.Public()
	return full, public, err
}

// checkCircuitAgainstManifest refuses a constraints file whose hash is not the manifest's. Keys
// with no manifest beside them predate it; they are used with a warning.
func checkCircuitAgainstManifest() error {
	path := os.Getenv("MANIFEST_PATH")
	if path == "" {
		return nil
	}
	manifest, err := utils.ReadManifest(path)
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "warning: no manifest at %s: the witness is not checked against the circuit the keys were set up for\n", path)
		return nil
	}
	if err != nil {
		return err
	}
	constraints := os.Getenv("CONSTRAINTS_JSON")
	if _, err := os.Stat(constraints); err != nil {
		return fmt.Errorf("the manifest at %s binds the keys to one circuit: pass the witness's constraints file with -constraints (%v)", path, err)
	}
	return manifest.CheckCircuit(constraints)
}

// KoalaBearVerify checks a proof file against a verifying key, as the exported contract does: the
// proof, its commitment and proof of knowledge, and the two public inputs the file carries.
func KoalaBearVerify() error {
	vk := new(groth16_bn254.VerifyingKey)
	if err := utils.ReadVerifyingKey(os.Getenv("VK_PATH"), vk); err != nil {
		return fmt.Errorf("failed to read the verifying key: %v", err)
	}
	data, err := os.ReadFile(os.Getenv("PROOF_PATH"))
	if err != nil {
		return fmt.Errorf("failed to read the proof: %v", err)
	}
	proof, inputs, err := utils.ParseAggOnChainProof(string(data))
	if err != nil {
		return err
	}
	if len(inputs) != 2 {
		return fmt.Errorf("the wrap circuit has two public inputs, and the proof file carries %d", len(inputs))
	}
	if err := groth16_bn254.Verify(proof, vk, inputs, backend.WithVerifierHashToFieldFunction(sha3.NewLegacyKeccak256())); err != nil {
		return err
	}
	fmt.Println("proof verified")
	return nil
}
