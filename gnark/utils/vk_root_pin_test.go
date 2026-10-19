package utils

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The op as the wrap compiler emits it: the eight vk_root limb felts, then the root's limbs.
const assertVkRootOp = `{"opcode":"AssertVkRoot","args":[` +
	`["backend1","backend2","backend3","backend4","backend5","backend6","backend7","backend8"],` +
	`["1728898831","861353444","150357242","1832012952","466770237","393984475","847093963","2130706432"]]}`

var pinnedRoot = []uint32{1728898831, 861353444, 150357242, 1832012952, 466770237, 393984475, 847093963, 2130706432}

func writeConstraints(t *testing.T, ops ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "constraints.json")
	body := append([]string{`{"opcode":"ImmF","args":[["backend0"],["7"]]}`}, ops...)
	if err := os.WriteFile(path, []byte("["+strings.Join(body, ",")+"]"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheSetupTakesThePinnedRootFromTheConstraints(t *testing.T) {
	path := writeConstraints(t, assertVkRootOp)
	for _, allowUnpinned := range []bool{false, true} {
		root, err := SetupVkRoot(path, allowUnpinned)
		if err != nil {
			t.Fatalf("pinned constraints refused (override %v): %v", allowUnpinned, err)
		}
		if !reflect.DeepEqual(root, pinnedRoot) {
			t.Fatalf("read root %v, the constraints pin %v", root, pinnedRoot)
		}
	}
}

func TestTheSetupRefusesUnpinnedConstraintsWithoutTheOverride(t *testing.T) {
	path := writeConstraints(t)
	root, err := ConstraintsVkRoot(path)
	if err != nil || root != nil {
		t.Fatalf("constraints with no AssertVkRoot read as root %v, error %v", root, err)
	}
	_, err = SetupVkRoot(path, false)
	if err == nil {
		t.Fatal("unpinned constraints accepted without the override")
	}
	if !strings.Contains(err.Error(), "pin no whitelist root") || !strings.Contains(err.Error(), AllowUnpinnedSetupEnv) {
		t.Fatalf("the refusal does not say why or how to override: %v", err)
	}
	if root, err := SetupVkRoot(path, true); err != nil || root != nil {
		t.Fatalf("with the override: root %v, error %v", root, err)
	}
}

// Two roots are refused even with the override: the override admits a circuit that pins no root,
// not one whose root the setup would have to pick.
func TestConstraintsWithTwoRootsAreRefused(t *testing.T) {
	path := writeConstraints(t, assertVkRootOp, assertVkRootOp)
	for _, allowUnpinned := range []bool{false, true} {
		if _, err := SetupVkRoot(path, allowUnpinned); err == nil || !strings.Contains(err.Error(), "more than one") {
			t.Fatalf("two AssertVkRoot ops (override %v): %v", allowUnpinned, err)
		}
	}
}

func TestAMalformedAssertVkRootIsRefused(t *testing.T) {
	for name, op := range map[string]string{
		"seven limbs": `{"opcode":"AssertVkRoot","args":[["a","b","c","d","e","f","g"],["1","2","3","4","5","6","7"]]}`,
		"not decimal": strings.Replace(assertVkRootOp, `"1728898831"`, `"0x1"`, 1),
		"past u32":    strings.Replace(assertVkRootOp, `"1728898831"`, `"4294967296"`, 1),
	} {
		if _, err := ConstraintsVkRoot(writeConstraints(t, op)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
