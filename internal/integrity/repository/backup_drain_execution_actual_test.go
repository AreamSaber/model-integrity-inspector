package repository_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/features"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/safehttp"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
	"model-integrity-inspector.local/mii/internal/integrity/worker"
)

type backupDrainTLSResolver struct{}

func (backupDrainTLSResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

func TestBackupDrainExecutionActualTLSAndPurposeMAC(t *testing.T) {
	artifact, hash, err := templates.Builtin().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := tokenizer.NewBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := secret.NewKeyRing("BACKUP-PREPARE.v1", map[string][]byte{"BACKUP-PREPARE.v1": bytes.Repeat([]byte{0x57}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := generator.New(artifact, hash, tokens, ring)
	if err != nil {
		t.Fatal(err)
	}
	builder, err := features.New(features.Config{Verifier: compiler, Tokenizer: tokens, TemplateArtifact: artifact, TrustedTemplateHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	mac, err := ring.NewDerivedSourceMAC()
	if err != nil {
		t.Fatal(err)
	}
	sealer, verifier, err := features.NewDerivedCapabilitiesWithMAC("BACKUP-PREPARE.v1", mac)
	if err != nil {
		t.Fatal(err)
	}
	prepare, err := worker.NewRunRecoveryPreparer(builder, sealer)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" {
			t.Error("request did not use actual owned TLS adapter")
		}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
		}
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"owned-request","choices":[{"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}]}`)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := safehttp.NewClient(safehttp.Config{Endpoint: "https://upstream.example.com/v1", RootCAs: roots, Resolver: backupDrainTLSResolver{}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "8.8.8.8:443" {
			t.Error("TLS bypassed validated address")
		}
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	var before int64
	repository.BackupDrainExecutionActualTLSBridge(t,
		func(org int64, target repository.TargetState) domain.ExecutionPlan {
			before = requests.Load()
			options := generator.Options{OrganizationID: org, AnalysisSourceVersion: domain.AnalysisSourceDerivedV1, Target: domain.ExecutionTarget{ID: target.Target.ID, Version: target.Target.Version, SecretID: target.Secret.ID, SecretVersion: target.Secret.Version, Endpoint: target.Target.Endpoint, Model: target.Target.Model, Protocol: target.Target.Protocol, MaxOutputParameter: "max_tokens", AuthType: "bearer", TimeoutSeconds: 180}, Package: "custom", Custom: &generator.Custom{Families: []string{"neutral"}, Repetitions: 1, Languages: []string{"en-US"}}, Budget: domain.ExecutionBudget{MaxRequests: 20, MaxTokens: 50000, TimeoutSeconds: 600}, RuleVersion: "1.0.0-dev.1", ScoringVersion: "1.0.0-dev.1", ContextWindow: 128000, MaxOutputTokens: 4096, SupportsSeed: true, SupportsStream: true, Concurrency: 1, MaxRetries: 2}
			manifest, err := compiler.Generate(options)
			if err != nil {
				t.Fatal(err)
			}
			raw, hash, err := manifest.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			plan, err := compiler.ExecutionPlan(raw, hash, org)
			if err != nil {
				t.Fatal(err)
			}
			return plan
		},
		func(ctx context.Context, plan domain.ExecutionPlan) (domain.RequestSnapshot, func() error) {
			adapter, err := openaichat.New(openaichat.Config{Endpoint: plan.Target.Endpoint, MaxOutputParameter: "max_tokens", Doer: client})
			if err != nil {
				t.Fatal(err)
			}
			request, snapshot, err := adapter.BuildRequest(ctx, plan.Probes[0].Samples[0].Request)
			if err != nil {
				t.Fatal(err)
			}
			return snapshot, func() error {
				response, err := client.Do(request)
				if err != nil {
					return err
				}
				defer func() { _ = response.Body.Close() }()
				_, err = io.Copy(io.Discard, response.Body)
				return err
			}
		},
		func(ctx context.Context, source *repository.BackupExecutionSource) (*repository.AttemptDerivedCandidates, error) {
			return prepare(ctx, source)
		},
		func(ctx context.Context, data repository.ExecutionReconciliationData, record repository.DerivedRecord) {
			row := features.SampleBinding{OrganizationID: data.Sample.OrganizationID, RunID: data.Sample.RunID, ID: data.Sample.ID, ProbeInstanceID: data.Sample.ProbeInstanceID, Ordinal: data.Sample.Ordinal, ExecutionOrdinal: data.Sample.ExecutionOrdinal}
			if data.Sample.PairID != nil {
				row.PairID = *data.Sample.PairID
			}
			if err := json.Unmarshal([]byte(data.Sample.RequestPlan), &row.RequestPlan); err != nil {
				t.Fatal(err)
			}
			a := data.Attempt
			attempt := features.AttemptBinding{OrganizationID: a.OrganizationID, RunID: a.RunID, SampleID: a.LogicalSampleID, ID: a.ID, JobID: a.JobID, Number: a.AttemptNo, Status: a.Status, Validity: a.Validity, RequestHash: a.RequestHash}
			if a.ErrorCode != nil {
				attempt.ErrorCode = *a.ErrorCode
			}
			if err := json.Unmarshal([]byte(a.RequestSnapshot), &attempt.Snapshot); err != nil {
				t.Fatal(err)
			}
			run := features.RunBinding{OrganizationID: data.Run.OrganizationID, ID: data.Run.ID, Plan: data.Plan}
			actual := features.DerivedRecord{Version: record.Version, KeyVersion: record.KeyVersion, Payload: record.Payload, MAC: record.MAC}
			if err := builder.VerifyDerivedRecord(ctx, run, row, attempt, actual, verifier); err != nil {
				t.Fatal("persisted original outcome does not authenticate", err)
			}
			actual.MAC = append([]byte(nil), actual.MAC...)
			actual.MAC[0] ^= 1
			if err := builder.VerifyDerivedRecord(ctx, run, row, attempt, actual, verifier); err == nil {
				t.Fatal("real verifier accepted same-length MAC corruption")
			}
			if requests.Load() != before+1 {
				t.Fatal("drain redispatched actual request")
			}
		})
}
