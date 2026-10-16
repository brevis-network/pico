package koalabear_verifier

import (
	"encoding/json"
	"fmt"
	"github.com/brevis-network/pico/gnark/koalabear"
	"github.com/brevis-network/pico/gnark/poseidon2"
	"github.com/brevis-network/pico/gnark/utils"
	"github.com/consensys/gnark/frontend"
	"os"
	"strconv"
)

type Circuit struct {
	VkeyHash              frontend.Variable `gnark:",public"`
	CommittedValuesDigest frontend.Variable `gnark:",public"`
	Vars                  []frontend.Variable
	Felts                 []koalabear.Variable
	Exts                  []koalabear.ExtensionVariable
	// Plain Go config, not a witness value: the MLE and FRI paths permute with DIFFERENT
	// KoalaBear-Poseidon2 tables and each one's honest witness is unsatisfiable under the other's,
	// so the chip has to be chosen per proof. Both shapes expose the same two public inputs, so
	// this cannot be inferred from the circuit's signature.
	UseMleKoalaBearConstants bool
}

func NewCircuit(witnessInput utils.WitnessInput) *Circuit {
	vars := make([]frontend.Variable, len(witnessInput.Vars))
	felts := make([]koalabear.Variable, len(witnessInput.Felts))
	exts := make([]koalabear.ExtensionVariable, len(witnessInput.Exts))
	for i := 0; i < len(witnessInput.Vars); i++ {
		vars[i] = frontend.Variable(witnessInput.Vars[i])
	}
	for i := 0; i < len(witnessInput.Felts); i++ {
		felts[i] = koalabear.NewF(witnessInput.Felts[i])
	}
	for i := 0; i < len(witnessInput.Exts); i++ {
		exts[i] = koalabear.NewE(witnessInput.Exts[i])
	}
	return &Circuit{
		VkeyHash:                 witnessInput.VkeyHash,
		CommittedValuesDigest:    witnessInput.CommittedValuesDigest,
		UseMleKoalaBearConstants: witnessInput.Backend == "mle",
		Vars:                     vars,
		Felts:                    felts,
		Exts:                     exts,
	}
}

type Constraint struct {
	Opcode string     `json:"opcode"`
	Args   [][]string `json:"args"`
}

type Proof struct {
	PublicInputs [2]string `json:"public_inputs"`
	EncodedProof string    `json:"encoded_proof"`
	RawProof     string    `json:"raw_proof"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	// Read the file.
	data, err := os.ReadFile(utils.ConstraintsPath())
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Deserialize the JSON data into a slice of Instruction structs.
	var constraints []Constraint
	err = json.Unmarshal(data, &constraints)
	if err != nil {
		return fmt.Errorf("error deserializing JSON: %v", err)
	}

	hashAPI := poseidon2.NewChip(api)
	hashKoalaBearAPI := poseidon2.NewKoalaBearChip(api)
	if circuit.UseMleKoalaBearConstants {
		hashKoalaBearAPI = poseidon2.NewKoalaBearMleChip(api)
	}
	fieldAPI := koalabear.NewChip(api)
	vars := make(map[string]frontend.Variable)
	felts := make(map[string]koalabear.Variable)
	exts := make(map[string]koalabear.ExtensionVariable)

	// Canonical witness felts. Each one is range checked on entry anyway, so the 2^32 bound
	// that NewF hands out is pure waste: it is wider than p, so a reduction fires on every
	// single raw witness purely to canonicalise an input we are already constraining. One
	// extra lookup on the shifted value turns "< 2^31" into "< p", which is far cheaper than
	// the reduction it removes.
	//
	// The checks and the tightened bound both come out of Chip.RangeCheckWitness, which is
	// the only way to get either. Lazy canonicality leans on this: with the bound tightened to
	// p - 1 here, ReduceCanonical at the felt -> integer boundaries has nothing left to prove,
	// which is why lazy canonicality costs nothing at those boundaries on this tape.
	witnessFelts := make([]koalabear.Variable, len(circuit.Felts))
	for i := 0; i < len(circuit.Felts); i++ {
		witnessFelts[i] = fieldAPI.RangeCheckWitness(circuit.Felts[i])
	}
	witnessExts := make([]koalabear.ExtensionVariable, len(circuit.Exts))
	for i := 0; i < len(circuit.Exts); i++ {
		witnessExts[i] = fieldAPI.RangeCheckWitnessE(circuit.Exts[i])
	}

	// Iterate through the instructions and handle each opcode.
	for _, cs := range constraints {
		//fmt.Printf("cs: %s \n", cs.Opcode)
		switch cs.Opcode {
		case "ImmV":
			vars[cs.Args[0][0]] = frontend.Variable(cs.Args[1][0])
		case "ImmF":
			// The literal is known at compile time, so bound it exactly instead of
			// assuming 2^32. An inflated bound is not merely imprecise -- it propagates through
			// every downstream operation and forces reductions that the literal never needed.
			felts[cs.Args[0][0]] = koalabear.NewFConst(cs.Args[1][0])
		case "ImmE":
			exts[cs.Args[0][0]] = koalabear.NewEConst(cs.Args[1])
		case "AddV":
			vars[cs.Args[0][0]] = api.Add(vars[cs.Args[1][0]], vars[cs.Args[2][0]])
		case "AddF":
			felts[cs.Args[0][0]] = fieldAPI.AddF(felts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "AddE":
			exts[cs.Args[0][0]] = fieldAPI.AddE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "AddEF":
			exts[cs.Args[0][0]] = fieldAPI.AddEF(exts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "SubV":
			vars[cs.Args[0][0]] = api.Sub(vars[cs.Args[1][0]], vars[cs.Args[2][0]])
		case "SubF":
			felts[cs.Args[0][0]] = fieldAPI.SubF(felts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "DivF":
			felts[cs.Args[0][0]] = fieldAPI.DivF(felts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "SubE":
			exts[cs.Args[0][0]] = fieldAPI.SubE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "SubEF":
			exts[cs.Args[0][0]] = fieldAPI.SubEF(exts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "MulV":
			vars[cs.Args[0][0]] = api.Mul(vars[cs.Args[1][0]], vars[cs.Args[2][0]])
		case "MulF":
			felts[cs.Args[0][0]] = fieldAPI.MulF(felts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "MulE":
			exts[cs.Args[0][0]] = fieldAPI.MulE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "MulEF":
			exts[cs.Args[0][0]] = fieldAPI.MulEF(exts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "DivE":
			exts[cs.Args[0][0]] = fieldAPI.DivE(exts[cs.Args[1][0]], exts[cs.Args[2][0]])
		case "DivEF":
			exts[cs.Args[0][0]] = fieldAPI.DivEF(exts[cs.Args[1][0]], felts[cs.Args[2][0]])
		case "NegE":
			exts[cs.Args[0][0]] = fieldAPI.NegE(exts[cs.Args[1][0]])
		case "InvE":
			exts[cs.Args[0][0]] = fieldAPI.InvE(exts[cs.Args[1][0]])
		case "Num2BitsV":
			numBits, err := strconv.Atoi(cs.Args[2][0])
			if err != nil {
				return fmt.Errorf("error converting number of bits to int: %v", err)
			}
			bits := api.ToBinary(vars[cs.Args[1][0]], numBits)
			for i := 0; i < len(cs.Args[0]); i++ {
				vars[cs.Args[0][i]] = bits[i]
			}
		case "Num2BitsF":
			bits := fieldAPI.ToBinary(felts[cs.Args[1][0]])
			for i := 0; i < len(cs.Args[0]); i++ {
				vars[cs.Args[0][i]] = bits[i]
			}
		case "Permute":
			state := [3]frontend.Variable{vars[cs.Args[0][0]], vars[cs.Args[1][0]], vars[cs.Args[2][0]]}
			hashAPI.PermuteMut(&state)
			vars[cs.Args[0][0]] = state[0]
			vars[cs.Args[1][0]] = state[1]
			vars[cs.Args[2][0]] = state[2]
		case "PermuteKoalaBear":
			var state [16]koalabear.Variable
			for i := 0; i < 16; i++ {
				state[i] = felts[cs.Args[i][0]]
			}
			hashKoalaBearAPI.PermuteMut(&state)
			for i := 0; i < 16; i++ {
				felts[cs.Args[i][0]] = state[i]
			}
		case "SelectV":
			vars[cs.Args[0][0]] = api.Select(vars[cs.Args[1][0]], vars[cs.Args[2][0]], vars[cs.Args[3][0]])
		case "SelectF":
			felts[cs.Args[0][0]] = fieldAPI.SelectF(vars[cs.Args[1][0]], felts[cs.Args[2][0]], felts[cs.Args[3][0]])
		case "SelectE":
			exts[cs.Args[0][0]] = fieldAPI.SelectE(vars[cs.Args[1][0]], exts[cs.Args[2][0]], exts[cs.Args[3][0]])
		case "Ext2Felt":
			out := fieldAPI.Ext2Felt(exts[cs.Args[4][0]])
			for i := 0; i < 4; i++ {
				felts[cs.Args[i][0]] = out[i]
			}
		case "AssertEqV":
			api.AssertIsEqual(vars[cs.Args[0][0]], vars[cs.Args[1][0]])
		case "AssertEqF":
			fieldAPI.AssertIsEqualF(felts[cs.Args[0][0]], felts[cs.Args[1][0]])
		case "AssertNeF":
			fieldAPI.AssertNotEqualF(felts[cs.Args[0][0]], felts[cs.Args[1][0]])
		case "AssertEqE":
			fieldAPI.AssertIsEqualE(exts[cs.Args[0][0]], exts[cs.Args[1][0]])
		case "PrintV":
			api.Println(vars[cs.Args[0][0]])
		case "PrintF":
			// Canonical, so that what gets printed is the field element and not an
			// arbitrary 31-bit representative of it.
			api.Println(fieldAPI.Felt2Var(felts[cs.Args[0][0]]))
		case "PrintE":
			// Same reasoning as PrintF: ReduceE only promises a 31-bit representative.
			e := exts[cs.Args[0][0]]
			for j := 0; j < 4; j++ {
				api.Println(fieldAPI.Felt2Var(e.Value[j]))
			}
		case "WitnessV":
			i, err := strconv.Atoi(cs.Args[1][0])
			if err != nil {
				panic(err)
			}
			vars[cs.Args[0][0]] = circuit.Vars[i]
		case "WitnessF":
			i, err := strconv.Atoi(cs.Args[1][0])
			if err != nil {
				panic(err)
			}
			felts[cs.Args[0][0]] = witnessFelts[i]
		case "WitnessE":
			i, err := strconv.Atoi(cs.Args[1][0])
			if err != nil {
				panic(err)
			}
			exts[cs.Args[0][0]] = witnessExts[i]
		case "CommitVkeyHash":
			element := vars[cs.Args[0][0]]
			api.AssertIsEqual(circuit.VkeyHash, element)
		case "CommitCommitedValuesDigest":
			element := vars[cs.Args[0][0]]
			api.AssertIsEqual(circuit.CommittedValuesDigest, element)
		case utils.AssertVkRootOpcode:
			if len(cs.Args) != 2 || len(cs.Args[0]) != 8 || len(cs.Args[1]) != 8 {
				return fmt.Errorf("%s takes 8 felts and 8 root limbs", cs.Opcode)
			}
			for i := 0; i < 8; i++ {
				fieldAPI.AssertIsEqualF(felts[cs.Args[0][i]], koalabear.NewFConst(cs.Args[1][i]))
			}
		case "CircuitFelts2Ext":
			exts[cs.Args[0][0]] = koalabear.Felts2Ext(felts[cs.Args[1][0]], felts[cs.Args[2][0]], felts[cs.Args[3][0]], felts[cs.Args[4][0]])
		case "CircuitFelt2Var":
			// Lazy canonicality: this is the boundary where a felt stops being a mod-p value and
			// becomes a BN254 integer -- it goes on to be hashed by the Poseidon2-BN254
			// sponge and compared against VkeyHash / CommittedValuesDigest. v and v + p are
			// the same felt but different digests, so the canonical form is required here.
			vars[cs.Args[0][0]] = fieldAPI.Felt2Var(felts[cs.Args[1][0]])
		case "ReduceE":
			exts[cs.Args[0][0]] = fieldAPI.ReduceE(exts[cs.Args[0][0]])
		default:
			return fmt.Errorf("unhandled opcode: %s", cs.Opcode)
		}
	}

	return nil
}
