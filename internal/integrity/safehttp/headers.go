package safehttp

import (
	"net/http"
	"strings"
)

var standardHeaders = []string{"Authorization", "Content-Type", "Accept", "User-Agent", "X-Api-Key", "Idempotency-Key", "Openai-Organization", "Openai-Project", "X-Request-Id"}

func validHeaderName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, character := range name {
		allowed := (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", character)
		if !allowed {
			return false
		}
	}
	return true
}

func reservedTransportHeader(name string) bool {
	name = strings.ToLower(name)
	if strings.HasPrefix(name, "proxy-") || strings.HasPrefix(name, "x-forwarded") {
		return true
	}
	switch name {
	case "host", "connection", "keep-alive", "transfer-encoding", "content-length", "trailer", "te", "upgrade",
		"cookie", "set-cookie", "forwarded", "forwarded-for", "via", "x-host", "x-original-host", "x-http-method-override",
		"x-original-url", "x-rewrite-url", "expect", "accept-encoding", "content-encoding":
		return true
	}
	return false
}

func validateHeaderValues(headers http.Header) error {
	total := 0
	seen := make(map[string]bool)
	for name, values := range headers {
		canonical := http.CanonicalHeaderKey(name)
		if !validHeaderName(name) || reservedTransportHeader(name) || seen[canonical] || len(values) != 1 {
			return ErrInvalidHeader
		}
		seen[canonical] = true
		value := values[0]
		if hasControl(value) || len(value) > 8192 {
			return ErrInvalidHeader
		}
		total += len(name) + len(value)
		if total > 32*1024 {
			return ErrInvalidHeader
		}
	}
	return nil
}

// ValidateCustomHeaders checks user-configured overrides, not the final adapter
// request. Authorization/Content-Type/Accept are owned by the adapter; transport
// routing, framing and proxy headers cannot be overridden under any spelling.
func ValidateCustomHeaders(headers http.Header) error {
	if err := validateHeaderValues(headers); err != nil {
		return err
	}
	for name := range headers {
		switch http.CanonicalHeaderKey(name) {
		case "Authorization", "Content-Type", "Accept", "User-Agent", "Idempotency-Key":
			return ErrInvalidHeader
		}
	}
	return nil
}

func responseHeaders(headers http.Header) http.Header {
	clean := make(http.Header)
	for _, name := range []string{"Content-Type", "Retry-After", "X-Request-Id", "Request-Id", "Openai-Processing-Ms"} {
		values := headers.Values(name)
		if len(values) != 1 || len(values[0]) > 512 || hasControl(values[0]) {
			continue
		}
		clean.Set(name, values[0])
	}
	return clean
}
