package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

type forbiddenExecutionDoer struct{ t *testing.T }

func (d forbiddenExecutionDoer) Do(*http.Request) (*http.Response, error) {
	d.t.Error("repository test attempted network access")
	return nil, errors.New("test outbound forbidden")
}

func TestExecutionSnapshotAcceptsRealAdapterAndRejectsDuplicateKeys(t *testing.T) {
	seed := int64(9007199254740993)
	temperature := 0.7
	topP := 0.9
	for _, parameter := range []string{"max_tokens", "max_completion_tokens"} {
		for _, stream := range []bool{false, true} {
			plan := domain.SamplePlan{Request: domain.NormalizedRequest{Model: "model", Messages: []domain.NormalizedMessage{{Role: "system", Content: "System"}, {Role: "user", Content: "OK"}}, Seed: &seed, Temperature: &temperature, TopP: &topP, MaxOutputTokens: 20, Stream: stream, Stop: []string{"END"}, ResponseFormat: &domain.ResponseFormat{Type: "json_object"}, ExtraAllowedParams: map[string]any{"frequency_penalty": 0.5, "presence_penalty": -0.5}}}
			adapter, err := openaichat.New(openaichat.Config{Endpoint: "https://upstream.example/v1", MaxOutputParameter: parameter, Doer: forbiddenExecutionDoer{t}})
			if err != nil {
				t.Fatal(err)
			}
			request, snapshot, err := adapter.BuildRequest(t.Context(), plan.Request)
			if err != nil {
				t.Fatal(err)
			}
			if err := request.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if !validDispatchSnapshot(plan, snapshot) {
				t.Fatal("real adapter snapshot rejected")
			}
			// A parser that only compared decoded maps would overlook the first key;
			// exact canonical bytes reject secret-bearing duplicate-key payloads.
			bad := snapshot
			bad.Payload = append([]byte(`{"model":"credential-canary",`), snapshot.Payload[1:]...)
			bad.PayloadBytes = len(bad.Payload)
			hash := sha256.Sum256(bad.Payload)
			bad.RequestHash = hex.EncodeToString(hash[:])
			if validDispatchSnapshot(plan, bad) {
				t.Fatal("duplicate key payload accepted")
			}
			changed := plan
			otherSeed := seed + 1
			changed.Request.Seed = &otherSeed
			if validDispatchSnapshot(changed, snapshot) {
				t.Fatal("64-bit seed precision collision")
			}
		}
	}
}

func TestExecutionParameterAndOutcomeClassificationFailClosed(t *testing.T) {
	for _, request := range []domain.NormalizedRequest{{Temperature: ptrExecution(math.NaN())}, {Temperature: ptrExecution(3)}, {TopP: ptrExecution(-1)}, {ResponseFormat: &domain.ResponseFormat{Type: "unsupported"}}, {Stop: []string{""}}, {ExtraAllowedParams: map[string]any{"frequency_penalty": "secret"}}, {ExtraAllowedParams: map[string]any{"presence_penalty": 3}}} {
		if validExecutionParameters(request) {
			t.Fatal("invalid frozen parameter accepted")
		}
	}
	for _, outcome := range []domain.AttemptOutcome{{Validity: "VALID", HTTPStatus: 401}, {Validity: "INVALID_RETRYABLE", HTTPStatus: 401, ErrorCode: "MI_RATE_LIMITED"}, {Validity: "INVALID_RETRYABLE", HTTPStatus: 501, ErrorCode: "MI_SERVICE_UNAVAILABLE"}, {Validity: "INVALID_RETRYABLE", HTTPStatus: 401, ErrorCode: "MI_AUTH_FAILED"}, {Validity: "INVALID_PROTOCOL", HTTPStatus: 400, ErrorCode: "raw upstream body"}, {Validity: "VALID", HTTPStatus: 200, LocalCompletionTokens: -1}} {
		if validAttemptOutcome(outcome) {
			t.Fatal("unsafe result/retry classification accepted")
		}
	}
}

func ptrExecution(v float64) *float64 { return &v }

func TestExecutionManifestHashAndStableSnapshotEncoding(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		manifest, err := json.Marshal(map[string]any{"seed": "fixture", "order": []int{2, 1}, "template_hash": "fixture", "nonce": "fixture", "note": "<reproduce>"})
		if err != nil {
			t.Fatal(err)
		}
		plan.Manifest = manifest
		hash := sha256.Sum256(manifest)
		plan.ManifestHash = hex.EncodeToString(hash[:])
		if !validateExecutionPlan(plan) {
			t.Fatal("valid compact object/hash rejected")
		}
		run, err := tenant.CreateRun(plan, policy, "manifest-run")
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := tenant.GetExecutionPlan(run.ID)
		if err != nil || !validateExecutionPlan(loaded) || string(loaded.Manifest) != string(manifest) {
			t.Fatal("manifest hash/bytes drifted on persistence")
		}
		for _, raw := range []string{`{"changed":true}`, `[]`, `null`, `{ "seed":1 }`, `{"note":"<raw>"}`} {
			bad := plan
			bad.Manifest = json.RawMessage(raw)
			if raw != `{"changed":true}` {
				sum := sha256.Sum256(bad.Manifest)
				bad.ManifestHash = hex.EncodeToString(sum[:])
			}
			if validateExecutionPlan(bad) {
				t.Fatal("mismatched/nonobject/noncanonical manifest accepted")
			}
		}
	})
}
