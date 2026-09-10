package repository_test

import (
	"bytes"
	"errors"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

func TestSnapshotKeyInventoryActualRewrapAndDeletion(t *testing.T) {
	repository.SnapshotKeyInventoryCryptoBridge(t, func(org, id int64) (repository.SecretRecord, repository.SecretRecord, func(repository.SecretRecord) error) {
		ring, err := secret.NewKeyRing("actual-old", map[string][]byte{"actual-old": bytes.Repeat([]byte{11}, 32), "actual-new": bytes.Repeat([]byte{27}, 32)})
		if err != nil {
			t.Fatal(err)
		}
		newOnly, err := secret.NewKeyRing("actual-new", map[string][]byte{"actual-new": bytes.Repeat([]byte{27}, 32)})
		if err != nil {
			t.Fatal(err)
		}
		credentials, err := secret.NewCredentials([]byte("real-rewrap-private-canary"), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer credentials.Destroy()
		scope := secret.Scope{OrganizationID: org, SecretID: id, SecretVersion: 1}
		old, err := ring.Encrypt(scope, credentials)
		if err != nil {
			t.Fatal(err)
		}
		next, err := ring.Rewrap(scope, old, "actual-new")
		if err != nil {
			t.Fatal(err)
		}
		convert := func(v secret.Record) repository.SecretRecord {
			return repository.SecretRecord{ID: id, OrganizationID: org, SecretVersion: 1, KeyVersion: v.KeyVersion, PayloadKeyVersion: v.PayloadKeyVersion, Fingerprint: v.Fingerprint, LastFour: v.LastFour, EncryptedDataKey: v.EncryptedDataKey, Nonce: v.Nonce, Ciphertext: v.Ciphertext}
		}
		open := func(v repository.SecretRecord) error {
			return newOnly.WithCredentialsForWorker(scope, secret.Record{KeyVersion: v.KeyVersion, PayloadKeyVersion: v.PayloadKeyVersion, Fingerprint: v.Fingerprint, LastFour: v.LastFour, EncryptedDataKey: v.EncryptedDataKey, Nonce: v.Nonce, Ciphertext: v.Ciphertext}, func(c secret.Credentials) error {
				return c.Use(func(key []byte, _ map[string][]byte) error {
					if string(key) != "real-rewrap-private-canary" {
						return errors.New("wrong restored credentials")
					}
					return nil
				})
			})
		}
		return convert(old), convert(next), open
	})
}

func TestSnapshotKeyInventoryActualGeneratorOriginalManifest(t *testing.T) {
	repository.SnapshotKeyInventoryGeneratorBridge(t, func(org int64, target repository.TargetState) domain.ExecutionPlan {
		raw, hash, err := templates.Builtin().Canonical()
		if err != nil {
			t.Fatal(err)
		}
		engine, err := tokenizer.NewBuiltin()
		if err != nil {
			t.Fatal(err)
		}
		ring, err := secret.NewKeyRing("actual-plan-old", map[string][]byte{"actual-plan-old": bytes.Repeat([]byte{37}, 32)})
		if err != nil {
			t.Fatal(err)
		}
		compiler, err := generator.New(raw, hash, engine, ring)
		if err != nil {
			t.Fatal(err)
		}
		options := generator.Options{OrganizationID: org, Target: domain.ExecutionTarget{ID: target.Target.ID, Version: target.Target.Version, SecretID: target.Secret.ID, SecretVersion: target.Secret.Version, Model: target.Target.Model, Endpoint: target.Target.Endpoint, Protocol: target.Target.Protocol, MaxOutputParameter: "max_tokens"}, Package: "quick", Budget: domain.ExecutionBudget{MaxRequests: 150, MaxTokens: 1000000, TimeoutSeconds: 600}, RuleVersion: "1.0.0-dev.1", ScoringVersion: "1.0.0-dev.1", ContextWindow: 128000, MaxOutputTokens: 4096, SupportsSeed: true, SupportsStream: true, Concurrency: 3, MaxRetries: 2}
		manifest, err := compiler.Generate(options)
		if err != nil {
			t.Fatal(err)
		}
		data, digest, err := manifest.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		plan, err := compiler.ExecutionPlan(data, digest, org)
		if err != nil {
			t.Fatal("real signed manifest verification", err)
		}
		return plan
	})
}
