package safehttp

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestValidateEndpoint(t *testing.T) {
	t.Parallel()
	for _, endpoint := range []string{
		"https://api.example.com/v1", "https://api.example.com:8443/v1/", "https://8.8.8.8/v1/chat/completions",
		"https://[2606:4700:4700::1111]/v1", "https://[::ffff:8.8.8.8]/v1", "https://API.EXAMPLE.COM/v1",
	} {
		t.Run(endpoint, func(t *testing.T) {
			if _, err := ValidateEndpoint(endpoint, URLPolicy{}); err != nil {
				t.Fatalf("valid endpoint rejected: %v", err)
			}
		})
	}
	for _, endpoint := range []string{
		"", "/relative", "http://api.example.com", "ftp://api.example.com", "file:///etc/passwd", "unix:///var/run/docker.sock",
		"https://user:CANARY_PASSWORD@api.example.com", "https://api.example.com?api_key=CANARY_SECRET", "https://api.example.com?api-version=v1",
		"https://api.example.com?", "https://api.example.com/#fragment", "https://api.example.com/#",
		"https://api.example.com\r\nX-Key:CANARY_SECRET", "https://api.example.com/%0d%0aHeader",
		"https://api.example.com/../admin", "https://api.example.com/./v1", "https://api.example.com/%2e%2e/admin",
		"https://api.example.com/%252e%252e/admin", "https://api.example.com//v1", "https://api.example.com\\@127.0.0.1/",
		"https://api.example.com:", "https://api.example.com:0", "https://api.example.com:65536", "https://api.example.com:0443",
		"https://api.example.com.", "https://-api.example.com", "https://api..example.com", "https://例子.com",
		"https://127.0.0.1", "https://127.1", "https://2130706433", "https://0177.0.0.1", "https://0x7f000001",
		"https://0x7f.0.0.1", "https://1.2.3", "https://[::1]", "https://[::ffff:127.0.0.1]", "https://[fe80::1%25eth0]",
		"https://0.0.0.0", "https://169.254.169.254", "https://169.254.170.2", "https://100.100.100.200", "https://168.63.129.16",
		"https://10.1.2.3", "https://172.16.1.2", "https://192.168.1.1", "https://[fd00:ec2::254]", "https://[fc00::1]",
		"https://192.0.2.1", "https://198.18.0.1", "https://198.51.100.1", "https://203.0.113.1", "https://224.0.0.1", "https://255.255.255.255",
		"https://[2001:db8::1]", "https://[2002:7f00:1::]", "https://[64:ff9b::7f00:1]", "https://[3fff::1]",
		"https://localhost", "https://sub.localhost", "https://metadata.google.internal", "https://instance-data.ec2.internal", "https://kubernetes.default.svc",
	} {
		t.Run(endpoint, func(t *testing.T) {
			if _, err := ValidateEndpoint(endpoint, URLPolicy{}); err == nil {
				t.Fatal("unsafe endpoint accepted")
			} else if strings.Contains(err.Error(), "CANARY") || strings.Contains(err.Error(), endpoint) && endpoint != "" {
				t.Fatalf("error leaked endpoint data: %v", err)
			}
		})
	}
}

func TestPrivateAllowlistDoesNotOverridePermanentDeny(t *testing.T) {
	t.Parallel()
	policy := URLPolicy{AllowHTTP: true, PrivateCIDRAllowlist: []string{"10.20.0.0/16", "192.168.100.0/24", "fc00::/7"}, BlockedCIDRs: []string{"10.20.30.0/24"}}
	for _, endpoint := range []string{"http://10.20.1.2/v1", "https://192.168.100.2", "https://[fd12:3456::1]/v1"} {
		if _, err := ValidateEndpoint(endpoint, policy); err != nil {
			t.Fatalf("administrator-allowed private endpoint rejected: %v", err)
		}
	}
	for _, endpoint := range []string{"https://10.21.1.2", "https://10.20.30.1", "https://127.0.0.1", "https://169.254.169.254", "https://168.63.129.16", "https://[fd00:ec2::254]", "https://metadata.google.internal"} {
		if _, err := ValidateEndpoint(endpoint, policy); err == nil {
			t.Errorf("permanent/default block was overridden: %s", endpoint)
		}
	}
	for _, cidr := range []string{"0.0.0.0/0", "127.0.0.0/8", "169.254.0.0/16", "8.8.8.8/32", "::/0", "::1/128", "::ffff:10.0.0.0/104", "10.0.0.1/8", "invalid"} {
		if _, err := ValidateEndpoint("https://api.example.com", URLPolicy{PrivateCIDRAllowlist: []string{cidr}}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("unsafe allowlist entry %q: %v", cidr, err)
		}
	}
}

func TestIPPolicyRejectsZonesInvalidAndMappedPrivate(t *testing.T) {
	t.Parallel()
	policy, err := compilePolicy(URLPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []netip.Addr{{}, netip.MustParseAddr("2606:4700::1111%zone"), netip.MustParseAddr("::ffff:10.0.0.1"), netip.MustParseAddr("::"), netip.MustParseAddr("ff02::1")} {
		if !errors.Is(policy.validateIP(addr), ErrBlockedAddress) {
			t.Errorf("unsafe address accepted: %s", addr)
		}
	}
}

func TestCustomAndFinalHeaderBoundaries(t *testing.T) {
	t.Parallel()
	if err := ValidateCustomHeaders(http.Header{"X-Provider-Key": {"CANARY_KEY"}}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Authorization", "Content-Type", "Accept", "User-Agent", "Idempotency-Key", "Host", "Proxy-Authorization", "Connection", "Content-Length", "Transfer-Encoding", "TE", "Cookie", "X-Forwarded-Host", "X-Original-Host", "X-Original-Url", "Accept-Encoding", "Content-Encoding", "Bad Name", "X-Key\r\nInjected"} {
		if err := ValidateCustomHeaders(http.Header{name: {"CANARY_SECRET"}}); !errors.Is(err, ErrInvalidHeader) || strings.Contains(err.Error(), "CANARY") {
			t.Errorf("reserved/invalid custom header %q: %v", name, err)
		}
	}
	for _, headers := range []http.Header{
		{"X-Provider-Key": {"value\r\nHost:127.0.0.1"}}, {"X-Provider-Key": {"value\x00"}},
		{"X-Provider-Key": {"one", "two"}}, {"X-Provider-Key": {strings.Repeat("x", 8193)}},
		{"X-Key": {"one"}, "x-key": {"two"}},
	} {
		if err := ValidateCustomHeaders(headers); !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("unsafe header value accepted: %v", err)
		}
	}
	if err := validateHeaderValues(http.Header{"Authorization": {"Bearer CANARY_KEY"}, "Content-Type": {"application/json"}, "Accept": {"application/json"}}); err != nil {
		t.Fatalf("adapter-owned standard headers rejected: %v", err)
	}
}

func TestInvalidConfiguration(t *testing.T) {
	t.Parallel()
	for _, config := range []Config{
		{Endpoint: "https://api.example.com", MaxResponseBodyBytes: -1},
		{Endpoint: "https://api.example.com", MaxRequestBodyBytes: DefaultMaxBodyBytes + 1},
		{Endpoint: "https://api.example.com", MaxErrorBodyBytes: DefaultMaxErrorBodyBytes + 1},
		{Endpoint: "https://api.example.com", RequestTotalTimeout: -time.Second},
		{Endpoint: "https://api.example.com", StreamIdleTimeout: 25 * time.Hour},
		{Endpoint: "https://api.example.com", AllowedRequestHeaders: []string{"Proxy-Authorization"}},
		{Endpoint: "https://api.example.com", Policy: URLPolicy{BlockedCIDRs: []string{"invalid"}}},
	} {
		if _, err := NewClient(config); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("unsafe configuration accepted: %v", err)
		}
	}
}

func FuzzValidateEndpoint(f *testing.F) {
	for _, seed := range []string{"https://api.example.com/v1", "https://127.1", "https://[::ffff:127.0.0.1]", "https://example.com#", "https://user:secret@example.com", "https://api..example.com"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		endpoint, err := ValidateEndpoint(value, URLPolicy{})
		if err != nil {
			return
		}
		if endpoint.Scheme != "https" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || strings.ContainsAny(value, "\\%#") {
			t.Fatal("validated endpoint violates invariant")
		}
	})
}
