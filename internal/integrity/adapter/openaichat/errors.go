package openaichat

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/safehttp"
)

// Error contains classifications only. It must never retain an upstream body,
// URL, auth header, parser diagnostic, secret callback error or wrapped cause.
type Error struct {
	Code                 string
	HTTPStatus           int
	Retryable            bool
	RetryAfter           time.Duration
	UnsupportedParameter string
}

func (err *Error) Error() string { return err.Code }
func failure(code string) *Error { return &Error{Code: code} }

func transportFailure(err error) *Error {
	for _, item := range []struct {
		value     error
		retryable bool
	}{
		{safehttp.ErrSafetyLimit, false}, {safehttp.ErrBlockedAddress, false}, {safehttp.ErrInvalidEndpoint, false},
		{safehttp.ErrInvalidHeader, false}, {safehttp.ErrTLS, false}, {safehttp.ErrRedirect, false}, {safehttp.ErrEncoding, false},
		{safehttp.ErrDNS, true}, {safehttp.ErrNetwork, true}, {safehttp.ErrTimeout, true}, {safehttp.ErrCanceled, false},
	} {
		if errors.Is(err, item.value) {
			return &Error{Code: item.value.Error(), Retryable: item.retryable}
		}
	}
	if errors.Is(err, context.Canceled) {
		return failure("MI_HTTP_CANCELED")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &Error{Code: "MI_HTTP_TIMEOUT", Retryable: true}
	}
	return &Error{Code: "MI_HTTP_NETWORK_FAILED", Retryable: true}
}

func transportEnd(err error) string {
	switch transportFailure(err).Code {
	case "CLIENT_SAFETY_LIMIT":
		return "client_safety_limit"
	case "MI_HTTP_TIMEOUT":
		return "timeout"
	case "MI_HTTP_CANCELED":
		return "canceled"
	case "MI_TARGET_BLOCKED_ADDRESS", "MI_TARGET_INVALID_ENDPOINT":
		return "blocked"
	default:
		return "network"
	}
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	if len(value) == 0 || len(value) > 128 || strings.ContainsAny(value, "\r\n\x00") {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds < 0 || seconds > 86400 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	date, err := http.ParseTime(value)
	if err != nil {
		return 0
	}
	wait := date.Sub(now)
	if wait < 0 || wait > 24*time.Hour {
		return 0
	}
	return wait
}

func (a *Adapter) httpError(response *http.Response) *Error {
	code := "MI_UPSTREAM_HTTP_ERROR"
	retryable := false
	switch response.StatusCode {
	case 400:
		code = "MI_UPSTREAM_INVALID_PARAMETERS"
	case 401, 403:
		code = "MI_UPSTREAM_AUTHENTICATION_FAILED"
	case 404:
		code = "MI_UPSTREAM_MODEL_NOT_FOUND"
	case 408:
		code = "MI_HTTP_TIMEOUT"
		retryable = true
	case 409:
		code = "MI_UPSTREAM_CONFLICT"
	case 429:
		code = "MI_UPSTREAM_RATE_LIMITED"
		retryable = true
	case 500, 502, 503, 504:
		code = "MI_UPSTREAM_UNAVAILABLE"
		retryable = true
	}
	result := &Error{Code: code, HTTPStatus: response.StatusCode, Retryable: retryable, RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"), a.config.Now())}
	data, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if len(data) > 64*1024 || errors.Is(err, safehttp.ErrSafetyLimit) {
		return &Error{Code: "CLIENT_SAFETY_LIMIT", HTTPStatus: response.StatusCode}
	}
	if err != nil {
		return transportFailure(err)
	}
	if response.StatusCode != http.StatusBadRequest {
		return result
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Type    string `json:"type"`
			Param   string `json:"param"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if checkJSON(data) != nil || json.Unmarshal(data, &body) != nil {
		return result
	}
	message := strings.ToLower(body.Error.Message)
	explicit := body.Error.Code == "unsupported_parameter" && body.Error.Param == "max_tokens"
	unsupported := strings.Contains(message, "not supported") || strings.Contains(message, "unsupported")
	explicitMessage := strings.HasPrefix(message, "unsupported parameter: 'max_tokens'") || strings.HasPrefix(message, "unsupported parameter: \"max_tokens\"")
	compatible := (body.Error.Code == "invalid_request_error" || body.Error.Type == "invalid_request_error") &&
		(body.Error.Param == "max_tokens" || explicitMessage) && strings.Contains(message, "max_completion_tokens") && unsupported
	if explicit || compatible {
		result.Code = "MI_UPSTREAM_UNSUPPORTED_PARAMETER"
		result.UnsupportedParameter = "max_tokens"
	}
	return result
}
