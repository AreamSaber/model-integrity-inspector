package bundle

import (
	"context"
	"encoding/json"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func TestBackupDependenciesBindingsRequireActualExactHashRoles(t *testing.T) {
	installed, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if json.Unmarshal(installed.RuleBytes(), &m) != nil {
		t.Fatal("rule fixture")
	}
	engine, err := tokenizer.NewBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	carrier, err := engine.InstalledArtifact(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"exact", "carrier_hash_not_configuration", "old_version", "wrong_hash", "nil_actual", "zero_actual"} {
		t.Run(mode, func(t *testing.T) {
			original := m
			actual := carrier
			switch mode {
			case "carrier_hash_not_configuration":
				original.Tokenizer.SHA256 = carrier.Ref().SHA256
			case "old_version":
				original.Tokenizer.Version = "0.1.0"
			case "wrong_hash":
				original.Tokenizer.SHA256 = BuiltinHash
			case "nil_actual":
				actual = nil
			case "zero_actual":
				actual = &tokenizer.InstalledArtifact{}
			}
			raw := backupDependencyTestMarshal(t, original)
			rule := backupDependencyTestObserve(t, backupDependencyTestSource("rule", original.Version, 1, 2, raw), raw)
			got, err := MatchBackupTokenizerDependency(t.Context(), rule, actual)
			if mode == "exact" {
				if err != nil || got.Dependency.HashRole != BackupDependencyTokenizerConfiguration || got.CarrierSHA256 != carrier.Ref().SHA256 {
					t.Fatal("actual installed configuration not mapped", err)
				}
			} else if err == nil || got != (BackupDependencyBinding{}) {
				t.Fatal("wrong namespace/version/capability silently satisfied missing dependency")
			}
		})
	}
}

func TestBackupDependenciesMemberIdentityAndOpaqueContainer(t *testing.T) {
	b := templates.Builtin()
	data, hash, err := b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	observed := backupDependencyTestObserve(t, backupDependencyTestSource("template", b.Version, 1, 2, data), data)
	member := observed.Members()[0]
	for _, mode := range []string{"organization", "container_version", "container_hash", "member_id", "member_version", "canceled", "nil_context"} {
		t.Run(mode, func(t *testing.T) {
			want := member
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch mode {
			case "organization":
				want.OrganizationID++
			case "container_version":
				want.ContainerVersion = "0.1.0"
			case "container_hash":
				want.ContainerSHA256 = BuiltinHash
			case "member_id":
				want.ID = "unknown-member"
			case "member_version":
				want.Version = "0.1.0"
			case "canceled":
				cancel()
			case "nil_context":
				ctx = nil
			}
			got, err := MatchBackupTemplateMember(ctx, observed, want)
			if err == nil || got != (BackupTemplateMember{}) {
				t.Fatal("inexact template member binding accepted")
			}
		})
	}
	altered := observed.Members()
	altered[0].ID = "mutated"
	if observed.Members()[0] != member {
		t.Fatal("returned member inventory shares mutable slice")
	}
	if hash != member.ContainerSHA256 {
		t.Fatal("member lost original container hash")
	}
	// An exact opaque template's bytes can be retained, but NO member identity
	// can be proved from it. This is explicitly incomplete semantic closure.
	opaqueData := []byte(`{"future_schema":"unknown-template","version":"old","members":[{"version":"not-a-recognized-codec"}]}`)
	opaque := backupDependencyTestObserve(t, backupDependencyTestSource("template", "old", 1, 3, opaqueData), opaqueData)
	installed, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if json.Unmarshal(installed.RuleBytes(), &m) != nil {
		t.Fatal("rule fixture")
	}
	m.Template = ArtifactRef{"old", digest(opaqueData)}
	raw := backupDependencyTestMarshal(t, m)
	rule := backupDependencyTestObserve(t, backupDependencyTestSource("rule", m.Version, 1, 4, raw), raw)
	binding, err := MatchBackupTemplateDependency(t.Context(), rule, opaque)
	if err != nil || binding.ResourceSource != opaque.Source() || opaque.Classification() != BackupDependenciesOpaque {
		t.Fatal("opaque original byte identity lost", err)
	}
	member.ContainerVersion, member.ContainerSHA256 = "old", digest(opaqueData)
	if got, err := MatchBackupTemplateMember(t.Context(), opaque, member); err == nil || got != (BackupTemplateMember{}) {
		t.Fatal("opaque content promoted to member semantics")
	}
}

func TestBackupDependenciesKnownRawFieldsDoNotGrantTodayExecution(t *testing.T) {
	installed, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if json.Unmarshal(installed.RuleBytes(), &m) != nil {
		t.Fatal("rule fixture")
	}
	m.Status = "published"
	m.Version = "9.0.0"
	m.GeneratorVersion = "historical.generator.7"
	m.FeatureVersion = "historical.features.3"
	m.Scoring.NoBaselineFactor = 42 // Finite original field, unsupported TODAY.
	raw := backupDependencyTestMarshal(t, m)
	observed := backupDependencyTestObserve(t, backupDependencyTestSource("rule", m.Version, 1, 2, raw), raw)
	if observed.Classification() != BackupDependenciesExplained || len(observed.Dependencies()) != 8 {
		t.Fatal("finite old original data was erased by today's runtime policy")
	}
	for _, d := range observed.Dependencies() {
		if d.Category == "generator" && (d.Version != "historical.generator.7" || d.HashRole != BackupDependencyImplementation || d.SHA256 != "") {
			t.Fatal("historical implementation identity silently defaulted")
		}
		if d.Category == "scoring" && d.Basis != BackupDependencyDerived {
			t.Fatal("derived original parameters misrepresented as historical execution evidence")
		}
	}
	// There is deliberately no Execute/Verified/Complete method or mutable
	// caller assertion capable of turning these declarations into a Runtime.
}
