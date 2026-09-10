package templates

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestBuiltinBundleCanonicalImmutableAndDetached(t *testing.T) {
	b := Builtin()
	data, hash, err := b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Templates) != 20 || hash != BuiltinHash {
		t.Fatal("builtin catalog shape changed")
	}
	t.Logf("builtin bundle %s SHA256 %s", b.Version, hash)
	if _, err := VerifiedBuiltin(); err != nil {
		t.Fatal(err)
	}
	restored, err := Decode(data, hash)
	if err != nil {
		t.Fatal(err)
	}
	data2, hash2, err := restored.Canonical()
	if err != nil || hash != hash2 || !bytes.Equal(data, data2) {
		t.Fatal("bundle reproduction differs")
	}
	registry := NewRegistry()
	if _, err := registry.Add(b); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Add(b); err != nil {
		t.Fatal("same hash retry not idempotent")
	}
	b.Templates[0].Prompt = "different-content"
	if _, err := registry.Add(b); !errors.Is(err, ErrImmutable) {
		t.Fatal("same version mutated")
	}
	read, readHash, err := registry.Get(BuiltinVersion)
	if err != nil || readHash != hash {
		t.Fatal("registered content changed")
	}
	read.Templates[0].Assertions[0] = "different"
	read.Templates[0].Prompt = "changed-copy"
	read, readHash, err = registry.Get(BuiltinVersion)
	if err != nil || readHash != hash || read.Templates[0].Assertions[0] == "different" {
		t.Fatal("registry leaked mutable storage")
	}
	if strings.Contains(fmt.Sprintf("%+v", read), "Generate") || strings.Contains(fmt.Sprint(read.Templates[0]), "生成") {
		t.Fatal("ordinary logging exposes prompt body")
	}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if _, _, err := registry.Get(BuiltinVersion); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
}

func TestBundleRejectsDriftUnknownFieldsAndRenderingSyntax(t *testing.T) {
	b := Builtin()
	raw, hash, err := b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{append(bytes.Clone(raw), ' '), append(bytes.Clone(raw), []byte(" {}")...), bytes.Replace(raw, []byte(`"version":`), []byte(`"unknown":"x","version":`), 1), bytes.Replace(raw, []byte(`"version":`), []byte(`"version":"0.0.0","version":`), 1)} {
		if _, err := Decode(data, hash); err == nil {
			t.Fatal("ambiguous/drifted artifact accepted")
		}
	}
	for _, change := range []func(*Bundle){
		func(v *Bundle) { v.Templates[0].Prompt = "[[INCLUDE]]" },
		func(v *Bundle) { v.Templates[0].ID = "../file" },
		func(v *Bundle) { v.Templates[1].ID = v.Templates[0].ID },
		func(v *Bundle) { v.Templates[0].Prompt = string([]byte{0xff}) },
		func(v *Bundle) { v.Templates[9].AuxiliaryOnly = false },
		func(v *Bundle) { v.Version = "1.0.0-" + strings.Repeat("a", 128) },
		func(v *Bundle) { v.Templates[0].Version = "1.0.0-" + strings.Repeat("a", 128) },
	} {
		mutated := Builtin()
		change(&mutated)
		if mutated.Validate() == nil {
			t.Fatal("invalid bundle accepted")
		}
	}
	for _, template := range b.Templates {
		out, err := Render(template, map[string]string{"NONCE": "synthetic_nonce_01", "COUNT": "10000", "LABEL": "item", "STYLE": "concise"})
		if err != nil || strings.Contains(out, "[[") || !strings.Contains(out, "synthetic_nonce_01") {
			t.Fatal("valid builtin not fully expanded")
		}
	}
	if _, err := Render(b.Templates[0], map[string]string{}); err == nil {
		t.Fatal("missing variable accepted")
	}
	if _, err := Render(b.Templates[0], map[string]string{"NONCE": "[[COUNT]]", "COUNT": "12"}); err == nil {
		t.Fatal("recursive placeholder accepted")
	}
}

func FuzzDecodeBundle(f *testing.F) {
	data, hash, _ := Builtin().Canonical()
	f.Add(data)
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			t.Skip()
		}
		_, _ = Decode(raw, hash)
	})
}
