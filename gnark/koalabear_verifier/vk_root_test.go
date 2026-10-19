package koalabear_verifier

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brevis-network/pico/gnark/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

// A circuit of eight witness felts and one AssertVkRoot over them, with no wrap artifacts needed.
func vkRootCircuit(t *testing.T, root []string) {
	t.Helper()
	var ops, ids []string
	for i := range root {
		ops = append(ops, fmt.Sprintf(`{"opcode":"WitnessF","args":[["f%d"],["%d"]]}`, i, i))
		ids = append(ids, fmt.Sprintf(`"f%d"`, i))
	}
	ops = append(ops, fmt.Sprintf(`{"opcode":"%s","args":[[%s],["%s"]]}`,
		utils.AssertVkRootOpcode, strings.Join(ids, ","), strings.Join(root, `","`)))
	path := filepath.Join(t.TempDir(), "constraints.json")
	if err := os.WriteFile(path, []byte("["+strings.Join(ops, ",")+"]"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONSTRAINTS_JSON", path)
}

func solvesWithFelts(felts []string) error {
	w := utils.WitnessInput{Felts: felts, VkeyHash: "0", CommittedValuesDigest: "0", Backend: "mle"}
	return test.IsSolved(NewCircuit(w), NewCircuit(w), ecc.BN254.ScalarField())
}

// Every limb is asserted: the root itself solves, and a witness one off in any limb does not. The
// last limb is p - 1, where a one-off witness wraps to 0.
func TestAssertVkRootPinsEveryLimb(t *testing.T) {
	root := []string{"1728898831", "861353444", "150357242", "1832012952", "466770237", "393984475", "847093963", "2130706432"}
	vkRootCircuit(t, root)
	if err := solvesWithFelts(root); err != nil {
		t.Fatalf("the pinned root does not solve: %v", err)
	}
	for i := range root {
		felts := append([]string(nil), root...)
		felts[i] = plusOne(felts[i], koalaBearModulus)
		if err := solvesWithFelts(felts); err == nil {
			t.Errorf("limb %d one off still solves", i)
		}
	}
}

func TestAShortAssertVkRootIsRefused(t *testing.T) {
	root := []string{"1", "2", "3", "4", "5", "6", "7"}
	vkRootCircuit(t, root)
	if err := solvesWithFelts(root); err == nil || !strings.Contains(err.Error(), "8 felts") {
		t.Fatalf("an AssertVkRoot of seven limbs: %v", err)
	}
}
