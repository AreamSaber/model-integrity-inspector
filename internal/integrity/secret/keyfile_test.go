package secret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyFileCreateLoadAndNeverOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	created, err := CreateKeyFile(path, "v1")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadKeyFile(path, "v1")
	if err != nil {
		t.Fatal(err)
	}
	testRoot, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal("could not open test fixture root")
	}
	defer func() { _ = testRoot.Close() }()
	before, err := testRoot.ReadFile("master.key")
	if err != nil {
		t.Fatal("could not inspect synthetic test key")
	}
	defer clear(before)
	if len(before) != 32 || bytes.Equal(before, make([]byte, 32)) {
		t.Fatal("created key is not a 32-byte random value")
	}
	message := []byte("keyfile roundtrip")
	one, err := created.AuditMAC("v1", message)
	if err != nil {
		t.Fatal(err)
	}
	two, err := loaded.AuditMAC("v1", message)
	if err != nil || !bytes.Equal(one, two) {
		t.Fatal("loaded key derives different material")
	}
	if _, err := CreateKeyFile(path, "v2"); !errors.Is(err, ErrKeyFileExists) {
		t.Fatalf("create overwrote existing key: %v", err)
	}
	after, err := testRoot.ReadFile("master.key")
	if err != nil {
		t.Fatal("could not inspect synthetic test key")
	}
	defer clear(after)
	if !bytes.Equal(before, after) {
		t.Fatal("existing key changed")
	}
	if _, err := json.Marshal(loaded); !errors.Is(err, ErrSensitive) {
		t.Fatal("key ring serialization allowed")
	}
	if strings.Contains(fmt.Sprintf("%#v", loaded), string(before)) {
		t.Fatal("master bytes leaked through formatting")
	}
}

func TestKeyFileLengthVersionAndErrorRedaction(t *testing.T) {
	for _, size := range []int{0, 1, 31, 33, 64, 4096} {
		path := filepath.Join(t.TempDir(), "private-path-canary.key")
		if _, err := CreateKeyFile(path, "v1"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, bytes.Repeat([]byte{0xA7}, size), 0o600); err != nil {
			t.Fatal("could not resize test fixture")
		}
		if _, err := LoadKeyFile(path, "v1"); !errors.Is(err, ErrKeyFileInvalid) {
			t.Fatalf("invalid size %d accepted: %v", size, err)
		}
	}
	for _, version := range []string{"", "bad/version", strings.Repeat("a", 65)} {
		path := filepath.Join(t.TempDir(), "must-not-exist.key")
		if _, err := CreateKeyFile(path, version); !errors.Is(err, ErrKeyFileInvalid) {
			t.Fatal("bad version accepted")
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("bad version created a file")
		}
	}
	path := filepath.Join(t.TempDir(), "error-path-canary.key")
	_, err := LoadKeyFile(path, "v1")
	if err == nil || strings.Contains(err.Error(), "canary") || strings.Contains(err.Error(), path) {
		t.Fatal("keyfile errors leak source path")
	}
	if _, err := LoadKeyFile(t.TempDir(), "v1"); err == nil {
		t.Fatal("directory accepted as key")
	}
}

func TestKeyFileRejectsLinks(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "master.key")
	if _, err := CreateKeyFile(path, "v1"); err != nil {
		t.Fatal(err)
	}
	hardLink := filepath.Join(directory, "hard.key")
	if err := os.Link(path, hardLink); err != nil {
		t.Fatal("hardlink fixture could not be created")
	}
	if _, err := LoadKeyFile(hardLink, "v1"); !errors.Is(err, ErrKeyFileUnsafe) {
		t.Fatal("multiply-linked master accepted")
	}
	if err := os.Remove(hardLink); err != nil {
		t.Fatal("could not remove test hardlink")
	}
	link := filepath.Join(directory, "link.key")
	if err := os.Symlink(path, link); err != nil {
		t.Skip("OS does not permit this test user to create symlinks")
	}
	if _, err := LoadKeyFile(link, "v1"); err == nil {
		t.Fatal("symbolic link accepted")
	}
	if _, err := CreateKeyFile(link, "v2"); err == nil {
		t.Fatal("create followed symbolic link")
	}
	parentLink := filepath.Join(directory, "alias")
	if err := os.Symlink(directory, parentLink); err != nil {
		t.Fatal("could not create ancestor symlink fixture")
	}
	if _, err := LoadKeyFile(filepath.Join(parentLink, "master.key"), "v1"); err == nil {
		t.Fatal("ancestor symlink accepted")
	}
	if _, err := CreateKeyFile(filepath.Join(parentLink, "new.key"), "v1"); err == nil {
		t.Fatal("create traversed ancestor symlink")
	}
	if _, err := os.Stat(filepath.Join(directory, "new.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unsafe create wrote through ancestor link")
	}
}
