package worker

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/safehttp"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/target"
)

const PrecheckMaxOutputTokens = 16
const PrecheckMaxResponseBytes = 64 << 10

type PrecheckConfig struct {
	Store       *repository.Store
	Secrets     *secret.Service
	URLPolicy   safehttp.URLPolicy
	Resolver    safehttp.Resolver
	DialContext safehttp.DialContextFunc
	RootCAs     *x509.CertPool
	// Administrator/test ceiling, never a target/request-controlled override.
	ExecutionTimeout time.Duration
}

func NewPrecheckHandler(config PrecheckConfig) (Handler, error) {
	if config.Store == nil || config.Secrets == nil {
		return nil, ErrConfiguration
	}
	if config.ExecutionTimeout == 0 {
		config.ExecutionTimeout = repository.PrecheckExecutionLimit
	}
	if config.ExecutionTimeout <= 0 || config.ExecutionTimeout > repository.PrecheckExecutionLimit {
		return nil, ErrConfiguration
	}
	if _, err := safehttp.ValidateEndpoint("https://validation.invalid/v1", config.URLPolicy); err != nil {
		return nil, ErrConfiguration
	}
	config.URLPolicy.PrivateCIDRAllowlist = append([]string(nil), config.URLPolicy.PrivateCIDRAllowlist...)
	config.URLPolicy.BlockedCIDRs = append([]string(nil), config.URLPolicy.BlockedCIDRs...)
	if config.RootCAs != nil {
		config.RootCAs = config.RootCAs.Clone()
	}
	return func(ctx context.Context, execution Execution) (Completion, error) {
		return executePrecheck(ctx, execution, config)
	}, nil
}

func failedPrecheck(code, name string) repository.PrecheckOutcome {
	checks := []repository.PrecheckCheck{}
	if name != "" {
		checks = append(checks, repository.PrecheckCheck{Name: name, Status: "failed", ErrorCode: code})
	}
	return repository.PrecheckOutcome{Status: "failed", ErrorCode: code, Checks: checks}
}

func completePrecheck(record repository.PrecheckRecord, outcome repository.PrecheckOutcome) Completion {
	return func(tx *repository.TenantTransaction) error {
		return tx.FinishPrecheck(record.ID, *record.JobID, outcome)
	}
}

func executePrecheck(ctx context.Context, execution Execution, config PrecheckConfig) (Completion, error) {
	if execution.Queue == nil || repository.JobType(execution.Lease.Job.Type) != repository.JobTargetPrecheck {
		return nil, repository.ErrJobInvalid
	}
	tenant, err := config.Store.WithOrganization(ctx, execution.Lease.Job.OrganizationID)
	if err != nil {
		return nil, err
	}
	record, err := tenant.GetPrecheckForWorker(execution.Lease.Job.ObjectID)
	if err != nil {
		return nil, err
	}
	if record.JobID == nil || *record.JobID != execution.Lease.Job.ID {
		return nil, repository.ErrJobInvalid
	}
	finish := func(code string) (Completion, error) { return completePrecheck(record, failedPrecheck(code, "")), nil }
	if record.Status == "passed" || record.Status == "failed" {
		var checks []repository.PrecheckCheck
		if json.Unmarshal([]byte(record.ResultJSON), &checks) != nil {
			return nil, repository.ErrUnavailable
		}
		return completePrecheck(record, repository.PrecheckOutcome{Status: record.Status, Checks: checks, ErrorCode: record.ErrorCode, MaxOutputParameter: record.MaxOutputParameter}), nil
	}
	if record.RequestCount > 0 {
		return finish("MI_UNCERTAIN_ATTEMPT")
	}
	if time.Now().After(record.CreatedAt.Add(repository.PrecheckLifetime)) {
		return finish("MI_PRECHECK_EXPIRED")
	}
	if err := execution.Queue.CheckLease(ctx, execution.Lease); err != nil {
		if errors.Is(err, repository.ErrJobCancelled) {
			return finish("MI_PRECHECK_CANCELLED")
		}
		if errors.Is(err, repository.ErrPrecheckStale) {
			return finish("MI_PRECHECK_STALE")
		}
		return nil, err
	}
	err = execution.Queue.WithLease(ctx, execution.Lease, func(tx *repository.TenantTransaction) error {
		var err error
		record, err = tx.BeginPrecheck(record.ID, execution.Lease.Job.ID)
		return err
	})
	if err != nil {
		cause := context.Cause(ctx)
		if cause == nil && errors.Is(err, repository.ErrJobLeaseLost) {
			cause = execution.Queue.CheckLease(ctx, execution.Lease)
		}
		if errors.Is(cause, repository.ErrJobCancelled) {
			return finish("MI_PRECHECK_CANCELLED")
		}
		if errors.Is(cause, repository.ErrPrecheckStale) {
			return finish("MI_PRECHECK_STALE")
		}
		return nil, err
	}
	if record.StartedAt == nil {
		return nil, repository.ErrUnavailable
	}
	remaining := min(config.ExecutionTimeout, time.Until(record.StartedAt.Add(repository.PrecheckExecutionLimit)))
	if remaining <= 0 {
		return finish("MI_TIMEOUT")
	}
	callCtx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	snapshot, err := decodePrecheckSnapshot(record)
	if err != nil {
		return finish("MI_PROTOCOL_UNSUPPORTED")
	}
	outcome := failedPrecheck("MI_SECRET_UNAVAILABLE", "")
	err = config.Secrets.WithCredentialsForWorker(callCtx, secret.Scope{OrganizationID: record.OrganizationID, SecretID: record.SecretID, SecretVersion: record.SecretVersion}, func(credentials secret.Credentials) error {
		return credentials.Use(func(key []byte, headers map[string][]byte) error {
			outcome = callPrecheck(callCtx, execution, config, record, snapshot, key, headers)
			return nil // Preserve only typed outcome; never propagate upstream diagnostics through Secret.
		})
	})
	if err != nil {
		outcome = failedPrecheck("MI_SECRET_UNAVAILABLE", "")
	}
	if cause := context.Cause(ctx); cause != nil {
		code := precheckErrorCode(cause)
		if errors.Is(cause, context.Canceled) {
			code = "MI_PRECHECK_CANCELLED"
		}
		outcome = failedPrecheck(code, "")
	} else if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
		outcome = failedPrecheck("MI_TIMEOUT", "")
	}
	return completePrecheck(record, outcome), nil
}

func decodePrecheckSnapshot(record repository.PrecheckRecord) (target.Snapshot, error) {
	var snapshot target.Snapshot
	if len(record.SnapshotJSON) > 32<<10 {
		return snapshot, ErrConfiguration
	}
	decoder := json.NewDecoder(bytes.NewBufferString(record.SnapshotJSON))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&snapshot) != nil {
		return snapshot, ErrConfiguration
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) {
		return snapshot, ErrConfiguration
	}
	if snapshot.OrganizationID != record.OrganizationID || snapshot.TargetID != record.TargetID || snapshot.TargetVersion != record.TargetVersion || snapshot.SecretID != record.SecretID || snapshot.SecretVersion != record.SecretVersion || snapshot.Protocol != "openai_chat" || snapshot.Options.TLSVerify == nil || !*snapshot.Options.TLSVerify ||
		(snapshot.AuthType != "bearer" && snapshot.AuthType != "custom_header") {
		return snapshot, ErrConfiguration
	}
	return snapshot, nil
}

type precheckDoer struct {
	client     *safehttp.Client
	execution  Execution
	record     repository.PrecheckRecord
	guardError error
}

func (client *precheckDoer) Do(request *http.Request) (*http.Response, error) {
	if err := request.Context().Err(); err != nil {
		client.guardError = err
		return nil, err
	}
	err := client.execution.Queue.WithLease(request.Context(), client.execution.Lease, func(tx *repository.TenantTransaction) error {
		return tx.ReservePrecheckRequest(client.record.ID, client.execution.Lease.Job.ID)
	})
	if err != nil {
		if errors.Is(err, repository.ErrJobLeaseLost) && request.Context().Err() == nil {
			if checked := client.execution.Queue.CheckLease(request.Context(), client.execution.Lease); errors.Is(checked, repository.ErrJobCancelled) || errors.Is(checked, repository.ErrPrecheckStale) {
				err = checked
			}
		}
		client.guardError = err
		return nil, err
	}
	return client.client.Do(request)
}

func callPrecheck(ctx context.Context, execution Execution, config PrecheckConfig, record repository.PrecheckRecord, snapshot target.Snapshot, key []byte, headers map[string][]byte) repository.PrecheckOutcome {
	validation := make(http.Header, len(headers)+1)
	allowed := make([]string, 0, len(headers)+1)
	for name, value := range headers {
		validation[name] = []string{string(value)}
		allowed = append(allowed, name)
	}
	defer clear(validation)
	if snapshot.AuthType == "custom_header" {
		validation[snapshot.AuthHeaderName] = []string{"validation"}
		allowed = append(allowed, snapshot.AuthHeaderName)
	}
	if err := safehttp.ValidateCustomHeaders(validation); err != nil {
		return failedPrecheck("MI_SECRET_UNAVAILABLE", "")
	}
	timeout := min(20*time.Second, config.ExecutionTimeout)
	if snapshot.Options.TimeoutSeconds > 0 {
		timeout = min(timeout, time.Duration(snapshot.Options.TimeoutSeconds)*time.Second)
	}
	client, err := safehttp.NewClient(safehttp.Config{Endpoint: snapshot.Endpoint, Policy: config.URLPolicy, Resolver: config.Resolver, DialContext: config.DialContext, RootCAs: config.RootCAs, AllowedRequestHeaders: allowed,
		ConnectTimeout: min(5*time.Second, timeout), TLSHandshakeTimeout: min(5*time.Second, timeout), ResponseHeaderTimeout: min(10*time.Second, timeout), StreamIdleTimeout: min(10*time.Second, timeout), RequestTotalTimeout: timeout,
		MaxRequestBodyBytes: 4096, MaxResponseBodyBytes: PrecheckMaxResponseBytes, MaxErrorBodyBytes: PrecheckMaxResponseBytes})
	if err != nil {
		return failedPrecheck(precheckErrorCode(err), "network")
	}
	defer client.CloseIdleConnections()
	doer := &precheckDoer{client: client, execution: execution, record: record}
	parameter := snapshot.Options.MaxOutputParameter
	automatic := parameter == "auto" || parameter == ""
	if automatic {
		parameter = "max_tokens"
	}
	adapter, err := openaichat.New(openaichat.Config{Endpoint: snapshot.Endpoint, MaxOutputParameter: parameter, Doer: doer, URLPolicy: config.URLPolicy, RequestTimeout: timeout, FirstEventTimeout: timeout, StreamIdleTimeout: min(10*time.Second, timeout), MaxResponseBytes: PrecheckMaxResponseBytes, MaxEventBytes: PrecheckMaxResponseBytes})
	if err != nil {
		return failedPrecheck(precheckErrorCode(err), "parameters")
	}
	var requests []*http.Request
	defer func() {
		for _, request := range requests {
			clear(request.Header)
		}
	}()
	prepare := func(request *http.Request) error {
		requests = append(requests, request)
		if snapshot.AuthType == "bearer" {
			request.Header.Set("Authorization", "Bearer "+string(key))
		} else {
			request.Header.Set(snapshot.AuthHeaderName, string(key))
		}
		for name, value := range headers {
			request.Header.Set(name, string(value))
		}
		return nil
	}
	input := domain.NormalizedRequest{Model: snapshot.Model, Messages: []domain.NormalizedMessage{{Role: "user", Content: "Reply with OK."}}, MaxOutputTokens: PrecheckMaxOutputTokens}
	var nonstream domain.NormalizedResponse
	if automatic {
		result, callErr := adapter.Precheck(ctx, input, prepare)
		nonstream, err, parameter = result.Response, callErr, result.MaxOutputParameter
	} else {
		nonstream, _, err = adapter.Call(ctx, input, prepare, nil)
	}
	if err != nil {
		return precheckCallFailure(err, doer.guardError, "nonstream")
	}
	if nonstream.ParseStatus != "valid" {
		return failedPrecheck("MI_PROTOCOL_UNSUPPORTED", "nonstream")
	}
	outcome := repository.PrecheckOutcome{Status: "passed", MaxOutputParameter: parameter, Checks: []repository.PrecheckCheck{}}
	for _, name := range []string{"network", "authentication", "model", "parameters", "nonstream"} {
		outcome.Checks = append(outcome.Checks, repository.PrecheckCheck{Name: name, Status: "passed"})
	}
	nonstream = domain.NormalizedResponse{} // Do not retain response text/metadata in the result or snapshot.
	input.Stream = true
	stream, _, err := adapter.Call(ctx, input, prepare, nil)
	if err != nil {
		failure := precheckCallFailure(err, doer.guardError, "stream")
		outcome.Status, outcome.ErrorCode = "failed", failure.ErrorCode
		outcome.Checks = append(outcome.Checks, repository.PrecheckCheck{Name: "stream", Status: "failed", ErrorCode: failure.ErrorCode})
		return outcome
	}
	if stream.ParseStatus != "valid" || !stream.StreamTerminated {
		outcome.Status, outcome.ErrorCode = "failed", "MI_PROTOCOL_UNSUPPORTED"
		outcome.Checks = append(outcome.Checks, repository.PrecheckCheck{Name: "stream", Status: "unsupported", ErrorCode: outcome.ErrorCode})
		return outcome
	}
	outcome.Checks = append(outcome.Checks, repository.PrecheckCheck{Name: "stream", Status: "passed"})
	return outcome
}

func precheckCallFailure(err, guard error, stage string) repository.PrecheckOutcome {
	if guard != nil {
		return failedPrecheck(precheckErrorCode(guard), "")
	}
	code := precheckErrorCode(err)
	switch code {
	case "MI_AUTH_FAILED":
		stage = "authentication"
	case "MI_MODEL_NOT_FOUND":
		stage = "model"
	case "MI_NETWORK_FAILED", "MI_TARGET_BLOCKED_ADDRESS", "MI_TIMEOUT":
		stage = "network"
	}
	return failedPrecheck(code, stage)
}

func precheckErrorCode(err error) string {
	for _, mapping := range []struct {
		err  error
		code string
	}{
		{repository.ErrPrecheckStale, "MI_PRECHECK_STALE"}, {repository.ErrPrecheckExpired, "MI_PRECHECK_EXPIRED"}, {repository.ErrPrecheckBudget, "MI_PRECHECK_BUDGET_EXCEEDED"}, {repository.ErrJobCancelled, "MI_PRECHECK_CANCELLED"},
		{context.Canceled, "MI_PRECHECK_CANCELLED"}, {context.DeadlineExceeded, "MI_TIMEOUT"}, {safehttp.ErrBlockedAddress, "MI_TARGET_BLOCKED_ADDRESS"}, {safehttp.ErrInvalidEndpoint, "MI_TARGET_BLOCKED_ADDRESS"},
		{safehttp.ErrTimeout, "MI_TIMEOUT"}, {safehttp.ErrDNS, "MI_NETWORK_FAILED"}, {safehttp.ErrNetwork, "MI_NETWORK_FAILED"}, {safehttp.ErrSafetyLimit, "MI_PRECHECK_BUDGET_EXCEEDED"},
	} {
		if errors.Is(err, mapping.err) {
			return mapping.code
		}
	}
	var upstream *openaichat.Error
	if errors.As(err, &upstream) {
		switch upstream.Code {
		case "MI_UPSTREAM_AUTHENTICATION_FAILED":
			return "MI_AUTH_FAILED"
		case "MI_UPSTREAM_MODEL_NOT_FOUND":
			return "MI_MODEL_NOT_FOUND"
		case "MI_UPSTREAM_RATE_LIMITED":
			return "MI_RATE_LIMITED"
		case "MI_HTTP_TIMEOUT":
			return "MI_TIMEOUT"
		case "MI_HTTP_CANCELED":
			return "MI_PRECHECK_CANCELLED"
		case "MI_TARGET_BLOCKED_ADDRESS", "MI_TARGET_INVALID_ENDPOINT", "MI_HTTP_REDIRECT_BLOCKED":
			return "MI_TARGET_BLOCKED_ADDRESS"
		case "MI_HTTP_DNS_FAILED", "MI_HTTP_NETWORK_FAILED", "MI_HTTP_TLS_FAILED":
			return "MI_NETWORK_FAILED"
		case "CLIENT_SAFETY_LIMIT":
			return "MI_PRECHECK_BUDGET_EXCEEDED"
		case "MI_PROTOCOL_INVALID", "MI_UPSTREAM_INVALID_PARAMETERS", "MI_UPSTREAM_UNSUPPORTED_PARAMETER", "MI_REQUEST_INVALID", "MI_ADAPTER_INVALID_CONFIG":
			return "MI_PROTOCOL_UNSUPPORTED"
		default:
			return "MI_SERVICE_UNAVAILABLE"
		}
	}
	return "MI_SERVICE_UNAVAILABLE"
}
