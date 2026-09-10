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

	"go.yaml.in/yaml/v3"
)

func TestKeyRingFilesLoadsActiveAndHistoricalVersions(t *testing.T) {
	dir := t.TempDir()
	refs := []KeyFileReference{{Version: "old.1", File: filepath.Join(dir, "old.key")}, {Version: "new.2", File: filepath.Join(dir, "new.key")}}
	originals := make(map[string]*KeyRing)
	for _, ref := range refs {
		key, err := CreateKeyFile(ref.File, ref.Version)
		if err != nil {
			t.Fatal(err)
		}
		originals[ref.Version] = key
	}
	ring, err := LoadKeyFiles("new.2", refs)
	if err != nil || ring.ActiveVersion() != "new.2" {
		t.Fatal("multiple restricted files not loaded")
	}
	for _, ref := range refs {
		want, err := originals[ref.Version].AuditMAC(ref.Version, []byte("historical audit fixture"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := ring.AuditMAC(ref.Version, []byte("historical audit fixture"))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("historical audit derivation changed")
		}
	}
	scope, oldRecord := testRecord(t, originals["old.1"])
	if err := ring.WithCredentialsForWorker(scope, oldRecord, func(c Credentials) error {
		return c.Use(func(key []byte, headers map[string][]byte) error {
			if string(key) != canary || string(headers["x-custom"]) != "private-header" {
				t.Fatal("historical credential changed")
			}
			return nil
		})
	}); err != nil {
		t.Fatal("historical AAD/key could not decrypt")
	}
	_, currentRecord := testRecord(t, ring)
	if currentRecord.KeyVersion != "new.2" || currentRecord.PayloadKeyVersion != "new.2" {
		t.Fatal("new writes did not use active version")
	}
	// A missing historical file is fatal; the valid active key is not a fallback.
	missing := append([]KeyFileReference(nil), refs...)
	missing[0].File = filepath.Join(dir, "missing-private-path-canary.key")
	if got, err := LoadKeyFiles("new.2", missing); got != nil || err == nil || strings.Contains(err.Error(), "canary") {
		t.Fatal("missing historical key accepted or path exposed")
	}
	// Invalid bytes in any version likewise prevent publishing a partial ring.
	if err := os.WriteFile(refs[0].File, []byte("invalid-private-key-canary"), 0600); err != nil {
		t.Fatal("resize synthetic historical key")
	}
	if got, err := LoadKeyFiles("new.2", refs); got != nil || !errors.Is(err, ErrKeyFileInvalid) {
		t.Fatal("partial ring escaped after historical failure")
	}
	// Also read/derive the valid active file first, then encounter bad history.
	if got, err := LoadKeyFiles("new.2", []KeyFileReference{refs[1], refs[0]}); got != nil || !errors.Is(err, ErrKeyFileInvalid) {
		t.Fatal("valid active key escaped after a later historical read failure")
	}
}

func TestKeyRingFileReferencesFailBeforeOpening(t *testing.T) {
	valid := KeyFileReference{Version: "one", File: filepath.Join(t.TempDir(), "never-created.key")}
	cases := []struct {
		active string
		refs   []KeyFileReference
	}{
		{"one", nil}, {"", []KeyFileReference{valid}}, {"two", []KeyFileReference{valid}},
		{"one", []KeyFileReference{valid, valid}},
		{"one", []KeyFileReference{valid, {Version: "bad/version", File: valid.File}}},
		{"one", make([]KeyFileReference, MaxMasterKeyFiles+1)},
	}
	for i, test := range cases {
		if key, err := LoadKeyFiles(test.active, test.refs); key != nil || !errors.Is(err, ErrKeyFileInvalid) {
			t.Fatalf("invalid references %d not rejected before I/O", i)
		}
	}
	for _, path := range []string{"", "path\x00canary"} {
		if key, err := LoadKeyFiles("one", []KeyFileReference{{Version: "one", File: path}}); key != nil || !errors.Is(err, ErrKeyFileUnsafe) {
			t.Fatal("invalid path not rejected")
		}
	}
}

func TestKeyRingFileReferenceSerializationAndCopies(t *testing.T) {
	ref := KeyFileReference{Version: "version-canary", File: "private-path-canary"}
	for _, value := range []any{ref, &ref, []KeyFileReference{ref}, struct{ References []KeyFileReference }{[]KeyFileReference{ref}}} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, value), "canary") {
				t.Fatal("reference formatted private input")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrSensitive) {
			t.Fatal("private references serialized as JSON")
		}
		if _, err := yaml.Marshal(value); !errors.Is(err, ErrSensitive) {
			t.Fatal("private references serialized as YAML")
		}
	}
}
