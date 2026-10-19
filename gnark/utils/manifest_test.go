package utils

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestTheManifestBindsTheKeysToOneCircuit(t *testing.T) {
	dir := t.TempDir()
	circuit := filepath.Join(dir, "wrap_constraints.json")
	other := filepath.Join(dir, "other_constraints.json")
	if err := os.WriteFile(circuit, []byte(`[{"opcode":"ImmV","args":[["0"]]}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte(`[{"opcode":"ImmV","args":[["1"]]}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	hash, err := Sha256File(circuit)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "manifest.json")
	written := &Manifest{
		CircuitSha256:  hash,
		NbConstraints:  7,
		NbPublicInputs: 2,
		Gnark:          GnarkVersion(),
		Files:          map[string]string{"pk": "00", "vk": "11"},
	}
	if err := WriteManifest(path, written); err != nil {
		t.Fatal(err)
	}
	read, err := ReadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if read.CircuitSha256 != hash || read.NbConstraints != 7 || read.NbPublicInputs != 2 || read.Files["vk"] != "11" {
		t.Fatalf("read back %+v, wrote %+v", read, written)
	}

	if err := read.CheckCircuit(circuit); err != nil {
		t.Fatalf("the circuit the keys were made for is refused: %v", err)
	}
	err = read.CheckCircuit(other)
	if err == nil {
		t.Fatal("another circuit is accepted")
	}
	if !strings.Contains(err.Error(), hash) {
		t.Fatalf("the refusal does not name the keys' circuit: %v", err)
	}
}

func TestAManifestWithoutACircuitIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte(`{"nb_constraints": 1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(path); err == nil {
		t.Fatal("a manifest that binds no circuit is accepted")
	}
}

// vk_root is written as eight numbers when the setup pinned one and left out when it did not, and
// a manifest written before the field existed still loads.
func TestTheManifestRecordsTheRootTheSetupPinned(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	base := Manifest{CircuitSha256: "00", NbConstraints: 1, NbPublicInputs: 2, Gnark: "v", Files: map[string]string{}}

	pinned := base
	pinned.VkRoot = pinnedRoot
	if err := WriteManifest(path, &pinned); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"vk_root": [`) {
		t.Fatalf("the root is not an array under vk_root:\n%s", data)
	}
	read, err := ReadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(read.VkRoot, pinnedRoot) {
		t.Fatalf("read back root %v, wrote %v", read.VkRoot, pinnedRoot)
	}

	if err := WriteManifest(path, &base); err != nil {
		t.Fatal(err)
	}
	if data, _ = os.ReadFile(path); strings.Contains(string(data), "vk_root") {
		t.Fatalf("an unpinned setup's manifest names a vk_root:\n%s", data)
	}

	if err := os.WriteFile(path, []byte(`{"circuit_sha256":"00","nb_constraints":1,"nb_public_inputs":2,"gnark":"v","files":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if read, err = ReadManifest(path); err != nil || read.VkRoot != nil {
		t.Fatalf("a manifest without vk_root: %+v, %v", read, err)
	}
}
