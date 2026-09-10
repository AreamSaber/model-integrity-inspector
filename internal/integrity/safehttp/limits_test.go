package safehttp

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

type errorBody struct {
	closed atomic.Bool
}

func (body *errorBody) Read([]byte) (int, error) { return 0, errors.New("CANARY_READER_SECRET") }
func (body *errorBody) Close() error {
	body.closed.Store(true)
	return errors.New("CANARY_CLOSE_SECRET")
}

func TestReaderErrorsNeverExposeUpstreamData(t *testing.T) {
	t.Parallel()
	original := &errorBody{}
	var canceled atomic.Bool
	body := &limitedBody{reader: original, closer: original, remaining: 8, cancel: func() { canceled.Store(true) }}
	if n, err := body.Read(nil); n != 0 || err != nil {
		t.Fatal("empty read should not advance body")
	}
	_, err := io.ReadAll(body)
	if !errors.Is(err, ErrNetwork) || strings.Contains(err.Error(), "CANARY") || !original.closed.Load() || !canceled.Load() {
		t.Fatalf("body read error was not safely handled: %v", err)
	}
	if err := body.Close(); err != nil {
		t.Fatal("close exposes underlying transport error")
	}
}

func TestCanceledStreamEOFIsNotSuccessfulCompletion(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	reader := io.NopCloser(strings.NewReader(""))
	body := &limitedBody{reader: reader, closer: reader, remaining: 8, cancel: cancel, ctx: ctx}
	cancel()
	if _, err := io.ReadAll(body); !errors.Is(err, ErrCanceled) {
		t.Fatalf("cancellation racing upstream EOF appeared successful: %v", err)
	}
}

func TestRequestReadErrorIsSanitizedAndClosed(t *testing.T) {
	t.Parallel()
	client, err := NewClient(Config{Endpoint: "https://api.example.com/v1"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	body := &errorBody{}
	req := request(t, http.MethodPost, "https://api.example.com/v1", body)
	_, err = client.Do(req)
	if !errors.Is(err, ErrNetwork) || !body.closed.Load() || strings.Contains(err.Error(), "CANARY") {
		t.Fatalf("request reader error leaked: %v", err)
	}
}

func TestDirectPrivateDialAndMappedPublicPinning(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		endpoint string
		policy   URLPolicy
		address  string
	}{
		{"http://10.20.1.2:8080/v1", URLPolicy{AllowHTTP: true, PrivateCIDRAllowlist: []string{"10.20.0.0/16"}}, "10.20.1.2:8080"},
		{"https://[::ffff:8.8.8.8]/v1", URLPolicy{}, "8.8.8.8:443"},
		{"https://[2606:4700:4700::1111]/v1", URLPolicy{}, "[2606:4700:4700::1111]:443"},
	} {
		t.Run(test.endpoint, func(t *testing.T) {
			var called atomic.Bool
			client, err := NewClient(Config{
				Endpoint: test.endpoint, Policy: test.policy,
				Resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
					t.Error("literal address must not be reinterpreted by DNS")
					return nil, nil
				}),
				DialContext: func(_ context.Context, network, address string) (net.Conn, error) {
					called.Store(true)
					if network != "tcp" || address != test.address {
						t.Error("IP literal was not pinned canonically")
					}
					return nil, ErrNetwork
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			_, err = client.Do(request(t, http.MethodGet, test.endpoint, nil))
			if !errors.Is(err, ErrNetwork) || !called.Load() {
				t.Fatalf("allowed literal did not reach scoped dialer: %v", err)
			}
		})
	}
}

func TestUnknownMethodFramingAndAuthorityNeverDial(t *testing.T) {
	t.Parallel()
	var called atomic.Bool
	client, err := NewClient(Config{Endpoint: "https://api.example.com/v1", DialContext: func(context.Context, string, string) (net.Conn, error) {
		called.Store(true)
		return nil, ErrNetwork
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	for _, mutate := range []func(*http.Request){
		func(req *http.Request) { req.Method = http.MethodConnect },
		func(req *http.Request) { req.RequestURI = "https://169.254.169.254" },
		func(req *http.Request) { req.TransferEncoding = []string{"chunked"} },
		func(req *http.Request) { req.Trailer = http.Header{"Host": {"127.0.0.1"}} },
		func(req *http.Request) { req.URL = nil },
	} {
		req := request(t, http.MethodGet, "https://api.example.com/v1", nil)
		mutate(req)
		if _, err := client.Do(req); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("invalid request framing accepted: %v", err)
		}
	}
	if _, err := client.Do(nil); !errors.Is(err, ErrInvalidRequest) {
		t.Error("nil request accepted")
	}
	if called.Load() {
		t.Fatal("invalid request performed network I/O")
	}
}
