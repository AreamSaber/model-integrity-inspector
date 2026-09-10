package bundle

import (
	"encoding/json"
	"testing"
)

func TestBuiltinRuntimeArtifactFrozenAndDetached(t *testing.T) {
	raw, err := builtinBytes()
	if err != nil {
		t.Fatal(err)
	}
	if got := digest(raw); got != BuiltinHash {
		t.Fatalf("runtime artifact changed: %s", got)
	}
	artifacts, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if json.Unmarshal(artifacts.RuleBytes(), &manifest) != nil || manifest.Status != "development_uncalibrated" || manifest.Version != BuiltinVersion || len(manifest.PairedMetrics) != 4 || manifest.PairedAlpha != .05 {
		t.Fatal("runtime artifact falsely promoted or incomplete")
	}
	copy := artifacts.RuleBytes()
	copy[0] = 'x'
	if digest(artifacts.RuleBytes()) != BuiltinHash {
		t.Fatal("caller changed shared rules")
	}
	copy = artifacts.TemplateBytes()
	copy[0] = 'x'
	if artifacts.TemplateBytes()[0] == 'x' {
		t.Fatal("caller changed shared templates")
	}
}
