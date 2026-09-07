package safehttp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultMaxBodyBytes      int64 = 8 * 1024 * 1024
	DefaultMaxErrorBodyBytes int64 = 64 * 1024
)

// Resolver and DialContextFunc are trusted infrastructure/test seams, not target
// options. DialContext receives only a validated numeric IP and the target port.
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type DialContextFunc func(context.Context, string, string) (net.Conn, error)

type Config struct {
	Endpoint              string
	Policy                URLPolicy
	AllowedRequestHeaders []string
	Resolver              Resolver
	DialContext           DialContextFunc
	RootCAs               *x509.CertPool
	ConnectTimeout        time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	StreamIdleTimeout     time.Duration
	RequestTotalTimeout   time.Duration
	MaxRequestBodyBytes   int64
	MaxResponseBodyBytes  int64
	MaxErrorBodyBytes     int64
}

// Client owns a separate connection pool for one target. Do not share it across
// targets or expose its configuration to request authors. It has no cookie jar,
// proxy hook, redirect option, secret access, logging or analysis dependencies.
type Client struct {
	endpoint  *url.URL
	policy    addressPolicy
	config    Config
	headers   map[string]bool
	client    *http.Client
	transport *http.Transport
}

func NewClient(config Config) (*Client, error) {
	if err := defaults(&config); err != nil {
		return nil, err
	}
	policy, err := compilePolicy(config.Policy)
	if err != nil {
		return nil, err
	}
	endpoint, err := policy.validateEndpoint(config.Endpoint)
	if err != nil {
		return nil, err
	}
	c := &Client{endpoint: endpoint, policy: policy, config: config, headers: make(map[string]bool)}
	for _, name := range append(append([]string(nil), standardHeaders...), config.AllowedRequestHeaders...) {
		if !validHeaderName(name) || reservedTransportHeader(name) {
			return nil, ErrInvalidConfig
		}
		c.headers[http.CanonicalHeaderKey(name)] = true
	}
	var roots *x509.CertPool
	if config.RootCAs != nil {
		roots = config.RootCAs.Clone()
	}
	c.transport = &http.Transport{
		Proxy:                  nil, // Never inherit HTTP_PROXY/HTTPS_PROXY/ALL_PROXY.
		DialContext:            c.dial,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, ServerName: endpoint.Hostname(), RootCAs: roots},
		TLSHandshakeTimeout:    config.TLSHandshakeTimeout,
		ResponseHeaderTimeout:  config.ResponseHeaderTimeout,
		MaxResponseHeaderBytes: 64 * 1024,
		DisableCompression:     true, // Apply both wire and decompressed byte limits ourselves.
		MaxIdleConns:           16,
		MaxIdleConnsPerHost:    16,
		MaxConnsPerHost:        64,
		IdleConnTimeout:        60 * time.Second,
		// HTTP/1.1 keeps per-connection stream-idle deadlines isolated. Do not
		// multiplex HTTP/2 streams over a socket with a shared read deadline.
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	c.client = &http.Client{
		Transport: c.transport,
		Timeout:   config.RequestTotalTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return c, nil
}

func defaults(config *Config) error {
	for _, item := range []struct {
		value    *time.Duration
		fallback time.Duration
	}{
		{&config.ConnectTimeout, 10 * time.Second}, {&config.TLSHandshakeTimeout, 10 * time.Second},
		{&config.ResponseHeaderTimeout, 30 * time.Second}, {&config.StreamIdleTimeout, 30 * time.Second},
		{&config.RequestTotalTimeout, 180 * time.Second},
	} {
		if *item.value < 0 || *item.value > 24*time.Hour {
			return ErrInvalidConfig
		}
		if *item.value == 0 {
			*item.value = item.fallback
		}
	}
	for _, size := range []*int64{&config.MaxRequestBodyBytes, &config.MaxResponseBodyBytes} {
		if *size < 0 || *size > DefaultMaxBodyBytes {
			return ErrInvalidConfig
		}
		if *size == 0 {
			*size = DefaultMaxBodyBytes
		}
	}
	if config.MaxErrorBodyBytes < 0 || config.MaxErrorBodyBytes > DefaultMaxErrorBodyBytes {
		return ErrInvalidConfig
	}
	if config.MaxErrorBodyBytes == 0 {
		config.MaxErrorBodyBytes = DefaultMaxErrorBodyBytes
	}
	config.MaxErrorBodyBytes = min(config.MaxErrorBodyBytes, config.MaxResponseBodyBytes)
	if config.Resolver == nil {
		config.Resolver = net.DefaultResolver
	}
	if config.DialContext == nil {
		dialer := &net.Dialer{Timeout: config.ConnectTimeout, KeepAlive: 30 * time.Second}
		config.DialContext = dialer.DialContext
	}
	return nil
}

func (c *Client) dial(parent context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, ErrBlockedAddress
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || !strings.EqualFold(host, c.endpoint.Hostname()) || port != effectivePort(c.endpoint) {
		return nil, ErrBlockedAddress
	}
	ctx, cancel := context.WithTimeout(parent, c.config.ConnectTimeout)
	defer cancel()
	var addresses []netip.Addr
	if literal, parseErr := netip.ParseAddr(host); parseErr == nil {
		addresses = []netip.Addr{literal}
	} else {
		addresses, err = c.config.Resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			if ctx.Err() != nil {
				return nil, sanitized(ctx.Err())
			}
			return nil, ErrDNS
		}
	}
	if len(addresses) == 0 || len(addresses) > 64 {
		return nil, ErrDNS
	}
	// Validate the complete answer set BEFORE dialing any answer. A mixed public
	// and private set is forbidden even if the first connection would succeed.
	for _, addr := range addresses {
		if err := c.policy.validateIP(addr); err != nil {
			return nil, err
		}
	}
	for _, addr := range addresses {
		conn, dialErr := c.config.DialContext(ctx, "tcp", net.JoinHostPort(addr.Unmap().String(), port))
		if dialErr == nil && conn != nil {
			return &idleConn{Conn: conn, timeout: c.config.StreamIdleTimeout}, nil
		}
		if conn != nil {
			_ = conn.Close()
		}
		if ctx.Err() != nil {
			return nil, sanitized(ctx.Err())
		}
	}
	return nil, ErrNetwork
}

func effectivePort(endpoint *url.URL) string {
	if endpoint.Port() != "" {
		return endpoint.Port()
	}
	if endpoint.Scheme == "https" {
		return "443"
	}
	return "80"
}

func (c *Client) validateRequest(request *http.Request) error {
	if request == nil || request.URL == nil || request.RequestURI != "" || len(request.Trailer) != 0 || len(request.TransferEncoding) != 0 {
		return ErrInvalidRequest
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead && request.Method != http.MethodPost {
		return ErrInvalidRequest
	}
	endpoint, err := c.policy.validateEndpoint(request.URL.String())
	if err != nil {
		return err
	}
	if endpoint.Scheme != c.endpoint.Scheme || endpoint.Hostname() != c.endpoint.Hostname() || effectivePort(endpoint) != effectivePort(c.endpoint) {
		return ErrBlockedAddress
	}
	base := strings.TrimSuffix(c.endpoint.Path, "/")
	if base != "" && endpoint.Path != base && !strings.HasPrefix(endpoint.Path, base+"/") {
		return ErrBlockedAddress
	}
	if request.Host != "" && !strings.EqualFold(request.Host, request.URL.Host) {
		return ErrInvalidHeader
	}
	if err := validateHeaderValues(request.Header); err != nil {
		return err
	}
	for name := range request.Header {
		if !c.headers[http.CanonicalHeaderKey(name)] {
			return ErrInvalidHeader
		}
	}
	return nil
}

// Do preserves response streaming while enforcing request, wire-response and
// decompressed-response limits. Callers must close Body; exceeding a read limit
// returns ErrSafetyLimit (never a silently truncated successful EOF).
func (c *Client) Do(request *http.Request) (*http.Response, error) {
	if err := c.validateRequest(request); err != nil {
		if request != nil && request.Body != nil {
			_ = request.Body.Close()
		}
		return nil, err
	}
	ctx, cancel := context.WithTimeout(request.Context(), c.config.RequestTotalTimeout)
	sent := request.Clone(ctx)
	if sent.Header == nil {
		sent.Header = make(http.Header)
	}
	if err := c.prepareBody(sent); err != nil {
		cancel()
		return nil, err
	}
	sent.Header.Set("Accept-Encoding", "gzip")
	response, err := c.client.Do(sent)
	if err != nil {
		cancel()
		return nil, sanitized(err)
	}
	if response.StatusCode >= 300 && response.StatusCode <= 399 && response.StatusCode != http.StatusNotModified {
		_ = response.Body.Close()
		cancel()
		return nil, ErrRedirect
	}
	body, err := c.responseBody(response, ctx, cancel)
	if err != nil {
		_ = response.Body.Close()
		cancel()
		return nil, err
	}
	response.Body = body
	response.Request = nil // Never return an internal copy carrying auth headers.
	response.Trailer = nil
	response.Header = responseHeaders(response.Header)
	response.Status = strconv.Itoa(response.StatusCode) + " " + http.StatusText(response.StatusCode)
	return response, nil
}

func (c *Client) prepareBody(request *http.Request) error {
	if request.ContentLength > c.config.MaxRequestBodyBytes {
		if request.Body != nil {
			_ = request.Body.Close()
		}
		return ErrSafetyLimit
	}
	if request.Body == nil {
		request.ContentLength = 0
		return nil
	}
	body := request.Body
	stop := context.AfterFunc(request.Context(), func() { _ = body.Close() })
	defer stop()
	defer func() { _ = body.Close() }()
	data, err := io.ReadAll(io.LimitReader(body, c.config.MaxRequestBodyBytes+1))
	if request.Context().Err() != nil {
		return sanitized(request.Context().Err())
	}
	if err != nil {
		return sanitized(err)
	}
	if int64(len(data)) > c.config.MaxRequestBodyBytes {
		return ErrSafetyLimit
	}
	request.Body = io.NopCloser(bytes.NewReader(data))
	request.ContentLength = int64(len(data))
	request.GetBody = nil // Do not automatically replay credentials or billable requests.
	return nil
}

func (c *Client) responseBody(response *http.Response, ctx context.Context, cancel context.CancelFunc) (io.ReadCloser, error) {
	limit := c.config.MaxResponseBodyBytes
	if response.StatusCode >= 400 {
		limit = c.config.MaxErrorBodyBytes
	}
	if response.ContentLength > limit {
		return nil, ErrSafetyLimit
	}
	raw := &limitedBody{reader: response.Body, closer: response.Body, remaining: limit, cancel: cancel, ctx: ctx}
	if len(response.Header.Values("Content-Encoding")) > 1 {
		return nil, ErrEncoding
	}
	encoding := strings.TrimSpace(strings.ToLower(response.Header.Get("Content-Encoding")))
	switch encoding {
	case "", "identity":
		return raw, nil
	case "gzip":
		// The decoder can read the wire EOF before returning its last buffered
		// plaintext bytes. Only the outer reader ends the request in that case.
		raw.cancel = func() {}
		decoder, err := gzip.NewReader(raw)
		if err != nil {
			return nil, sanitized(err)
		}
		response.Uncompressed = true
		response.ContentLength = -1
		return &limitedBody{reader: decoder, closer: &gzipBody{Reader: decoder, raw: raw}, remaining: limit, cancel: cancel, ctx: ctx}, nil
	default:
		return nil, ErrEncoding
	}
}

func (c *Client) CloseIdleConnections() {
	c.transport.CloseIdleConnections()
}

func sanitized(err error) error {
	if err == nil {
		return nil
	}
	for _, safe := range []error{ErrInvalidEndpoint, ErrBlockedAddress, ErrSafetyLimit, ErrRedirect, ErrDNS, ErrTLS, ErrTimeout, ErrCanceled, ErrNetwork, ErrEncoding} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	if errors.Is(err, context.Canceled) {
		return ErrCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return ErrTimeout
	}
	var certificate *tls.CertificateVerificationError
	if errors.As(err, &certificate) {
		return ErrTLS
	}
	return ErrNetwork
}
