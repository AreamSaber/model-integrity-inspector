package worker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net/http"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/safehttp"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

type runCallResult struct {
	attempt    repository.AttemptRecord
	response   domain.NormalizedResponse
	display    repository.DisplayEvidenceRecord
	bodies     *repository.AttemptBodyCapture
	outcome    domain.AttemptOutcome
	guardError error
	jitter     int
}

type executionDoer struct {
	client     *safehttp.Client
	execution  Execution
	sample     repository.LogicalSampleRecord
	plan       domain.SamplePlan
	parameter  string
	attempt    repository.AttemptRecord
	guardError error
}

func (d *executionDoer) Do(request *http.Request) (*http.Response, error) {
	if d.attempt.ID != 0 || request.GetBody == nil {
		d.guardError = repository.ErrConfiguration
		return nil, d.guardError
	}
	body, err := request.GetBody()
	if err != nil {
		d.guardError = repository.ErrConfiguration
		return nil, d.guardError
	}
	encoded, err := io.ReadAll(io.LimitReader(body, openaichat.MaxRequestBytes+1))
	_ = body.Close()
	defer clear(encoded)
	if err != nil || len(encoded) > openaichat.MaxRequestBytes {
		d.guardError = repository.ErrConfiguration
		return nil, d.guardError
	}
	digest := sha256.Sum256(encoded)
	snapshot := domain.RequestSnapshot{Model: d.plan.Request.Model, Stream: d.plan.Request.Stream, MaxOutputTokens: d.plan.Request.MaxOutputTokens, MaxOutputParameter: d.parameter, Payload: encoded, PayloadBytes: len(encoded), RequestHash: hex.EncodeToString(digest[:])}
	err = d.execution.Queue.WithLease(request.Context(), d.execution.Lease, func(tx *repository.TenantTransaction) error {
		var err error
		d.attempt, err = tx.ReserveAttempt(d.sample.ID, snapshot)
		return err
	})
	if err != nil {
		d.guardError = err
		return nil, err
	}
	return d.client.Do(request)
}

func callRunSample(ctx context.Context, execution Execution, config RunConfig, plan domain.ExecutionPlan, sample repository.LogicalSampleRecord, samplePlan domain.SamplePlan, key []byte, headers map[string][]byte) runCallResult {
	result := runCallResult{}
	validation := make(http.Header, len(headers)+1)
	allowed := make([]string, 0, len(headers)+1)
	for name, value := range headers {
		validation[name] = []string{string(value)}
		allowed = append(allowed, name)
	}
	defer clear(validation)
	if plan.Target.AuthType == "custom_header" {
		validation[plan.Target.AuthHeaderName] = []string{"validation"}
		allowed = append(allowed, plan.Target.AuthHeaderName)
	}
	if safehttp.ValidateCustomHeaders(validation) != nil {
		return result
	}
	timeout := min(config.RequestTimeout, time.Duration(plan.Target.TimeoutSeconds)*time.Second)
	client, err := safehttp.NewClient(safehttp.Config{Endpoint: plan.Target.Endpoint, Policy: config.URLPolicy, Resolver: config.Resolver, DialContext: config.DialContext, RootCAs: config.RootCAs, AllowedRequestHeaders: allowed, ConnectTimeout: min(10*time.Second, timeout), TLSHandshakeTimeout: min(10*time.Second, timeout), ResponseHeaderTimeout: min(30*time.Second, timeout), StreamIdleTimeout: min(30*time.Second, timeout), RequestTotalTimeout: timeout, MaxRequestBodyBytes: openaichat.MaxRequestBytes, MaxResponseBodyBytes: 1 << 20, MaxErrorBodyBytes: 64 << 10})
	if err != nil {
		return result
	}
	defer client.CloseIdleConnections()
	doer := &executionDoer{client: client, execution: execution, sample: sample, plan: samplePlan, parameter: plan.Target.MaxOutputParameter}
	adapter, err := openaichat.New(openaichat.Config{Endpoint: plan.Target.Endpoint, MaxOutputParameter: plan.Target.MaxOutputParameter, Doer: doer, URLPolicy: config.URLPolicy, RequestTimeout: timeout, FirstEventTimeout: min(60*time.Second, timeout), StreamIdleTimeout: min(30*time.Second, timeout), MaxResponseBytes: 1 << 20, MaxEventBytes: 1 << 20})
	if err != nil {
		return result
	}
	var outbound *http.Request
	defer func() {
		if outbound != nil {
			clear(outbound.Header)
		}
	}()
	response, _, callError := adapter.Call(ctx, samplePlan.Request, func(request *http.Request) error {
		outbound = request
		for name, value := range headers {
			request.Header.Set(name, string(value))
		}
		if plan.Target.AuthType == "bearer" {
			request.Header.Set("Authorization", "Bearer "+string(key))
		} else {
			request.Header.Set(plan.Target.AuthHeaderName, string(key))
		}
		return nil
	}, nil)
	result.attempt, result.response, result.guardError = doer.attempt, response, doer.guardError
	result.outcome = classifyExecutionResponse(response, callError)
	estimate, countErr := config.Tokenizer.CountOutput(response.Content, tokenizer.Selection{ReportedModel: response.ModelReported, RequestedModel: samplePlan.Request.Model})
	result.outcome.TokenizerID = estimate.TokenizerID
	result.outcome.TokenizerQuality = string(estimate.Quality)
	if estimate.Tokens != nil {
		result.outcome.LocalCompletionTokens = *estimate.Tokens
	}
	if countErr != nil {
		result.outcome.Validity = "INVALID_SAFETY_LIMIT"
		result.outcome.ErrorCode = "MI_CLIENT_SAFETY_LIMIT"
	} else if estimate.Quality == tokenizer.Heuristic || estimate.Quality == tokenizer.Unavailable {
		result.response.ParseWarnings = append(result.response.ParseWarnings, "LOCAL_TOKENIZER_APPROXIMATE")
		if result.outcome.Validity == "VALID" {
			result.outcome.Validity = "VALID_WITH_WARNING"
		}
	}
	if random, e := rand.Int(rand.Reader, big.NewInt(1001)); e == nil {
		result.jitter = int(random.Int64())
	}
	return result
}

func classifyExecutionResponse(response domain.NormalizedResponse, err error) domain.AttemptOutcome {
	outcome := domain.AttemptOutcome{HTTPStatus: response.HTTPStatus, PromptTokens: response.PromptTokens, CompletionTokens: response.CompletionTokens, DurationMillis: response.DurationMs}
	if err == nil && response.HTTPStatus == 200 && (response.ParseStatus == "valid" || response.ParseStatus == "partial") {
		outcome.Validity = "VALID"
		if response.ParseStatus == "partial" || len(response.ParseWarnings) > 0 {
			outcome.Validity = "VALID_WITH_WARNING"
		}
		if response.Refusal {
			outcome.Validity = "NOT_APPLICABLE"
			outcome.ErrorCode = "MI_SAFETY_REFUSAL"
		}
		return outcome
	}
	outcome.Validity = "INVALID_PROTOCOL"
	outcome.ErrorCode = "MI_PROTOCOL_UNSUPPORTED"
	var upstream *openaichat.Error
	if !errors.As(err, &upstream) {
		return outcome
	}
	if upstream.HTTPStatus != 0 {
		outcome.HTTPStatus = upstream.HTTPStatus
	}
	switch upstream.Code {
	case "MI_UPSTREAM_AUTHENTICATION_FAILED":
		outcome.ErrorCode = "MI_AUTH_FAILED"
	case "MI_UPSTREAM_MODEL_NOT_FOUND":
		outcome.ErrorCode = "MI_MODEL_NOT_FOUND"
	case "MI_UPSTREAM_RATE_LIMITED":
		outcome.Validity = "INVALID_RETRYABLE"
		outcome.ErrorCode = "MI_RATE_LIMITED"
	case "MI_UPSTREAM_UNAVAILABLE":
		outcome.Validity = "INVALID_RETRYABLE"
		outcome.ErrorCode = "MI_SERVICE_UNAVAILABLE"
	case "MI_HTTP_TIMEOUT":
		outcome.Validity = "INVALID_RETRYABLE"
		outcome.ErrorCode = "MI_TIMEOUT"
		if outcome.HTTPStatus != 408 {
			outcome.HTTPStatus = 0
		}
	case "MI_HTTP_DNS_FAILED", "MI_HTTP_NETWORK_FAILED":
		outcome.Validity = "INVALID_RETRYABLE"
		outcome.ErrorCode = "MI_NETWORK_TEMPORARY"
		outcome.HTTPStatus = 0
	case "CLIENT_SAFETY_LIMIT":
		outcome.Validity = "INVALID_SAFETY_LIMIT"
		outcome.ErrorCode = "MI_CLIENT_SAFETY_LIMIT"
	case "MI_HTTP_CANCELED":
		outcome.Validity = "NOT_APPLICABLE"
		outcome.ErrorCode = "MI_EXECUTION_CANCELLED"
	}
	if upstream.RetryAfter > 0 {
		// Preserve the upstream wait. The scheduler refuses delays above its
		// one-hour policy ceiling; truncating here would retry prematurely.
		outcome.RetryAfterSeconds = int64((upstream.RetryAfter + time.Second - 1) / time.Second)
	}
	return outcome
}
