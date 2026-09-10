package safehttp

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

var (
	ErrInvalidEndpoint = errors.New("MI_TARGET_INVALID_ENDPOINT")
	ErrBlockedAddress  = errors.New("MI_TARGET_BLOCKED_ADDRESS")
	ErrInvalidConfig   = errors.New("MI_HTTP_INVALID_CONFIG")
	ErrInvalidHeader   = errors.New("MI_HTTP_INVALID_HEADER")
	ErrInvalidRequest  = errors.New("MI_HTTP_INVALID_REQUEST")
	ErrSafetyLimit     = errors.New("CLIENT_SAFETY_LIMIT")
	ErrRedirect        = errors.New("MI_HTTP_REDIRECT_BLOCKED")
	ErrDNS             = errors.New("MI_HTTP_DNS_FAILED")
	ErrTLS             = errors.New("MI_HTTP_TLS_FAILED")
	ErrTimeout         = errors.New("MI_HTTP_TIMEOUT")
	ErrCanceled        = errors.New("MI_HTTP_CANCELED")
	ErrNetwork         = errors.New("MI_HTTP_NETWORK_FAILED")
	ErrEncoding        = errors.New("MI_HTTP_UNSUPPORTED_ENCODING")
)

// URLPolicy is administrator-owned configuration, never request-supplied data.
// Allowlisting RFC1918/ULA does not override special-use or metadata exclusions.
type URLPolicy struct {
	AllowHTTP            bool
	PrivateCIDRAllowlist []string
	BlockedCIDRs         []string
}

type addressPolicy struct {
	allowHTTP bool
	private   []netip.Prefix
	blocked   []netip.Prefix
}

var privateRanges = prefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")

// Special-purpose ranges are conservatively denied even where individual anycast
// exceptions are globally reachable. Sources: IANA IPv4/IPv6 special registries.
// The Azure platform virtual IP and AWS IPv6 metadata IP are unconditional denies.
var deniedRanges = prefixes(
	"0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
	"192.88.99.0/24", "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "168.63.129.16/32",
	"2001::/23", "2001:db8::/32", "2002::/16", "2620:4f:8000::/48",
	"3fff::/20", "fd00:ec2::254/128",
)

func prefixes(values ...string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}

func compilePolicy(policy URLPolicy) (addressPolicy, error) {
	compiled := addressPolicy{allowHTTP: policy.AllowHTTP}
	for _, value := range policy.PrivateCIDRAllowlist {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
			return addressPolicy{}, ErrInvalidConfig
		}
		valid := false
		for _, private := range privateRanges {
			if private.Addr().BitLen() == prefix.Addr().BitLen() && private.Bits() <= prefix.Bits() && private.Contains(prefix.Addr()) {
				valid = true
			}
		}
		if !valid {
			return addressPolicy{}, ErrInvalidConfig
		}
		compiled.private = append(compiled.private, prefix)
	}
	for _, value := range policy.BlockedCIDRs {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Is4In6() || prefix != prefix.Masked() {
			return addressPolicy{}, ErrInvalidConfig
		}
		compiled.blocked = append(compiled.blocked, prefix)
	}
	return compiled, nil
}

func contains(ranges []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range ranges {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (policy addressPolicy) validateIP(addr netip.Addr) error {
	if !addr.IsValid() || addr.Zone() != "" {
		return ErrBlockedAddress
	}
	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || contains(deniedRanges, addr) || contains(policy.blocked, addr) {
		return ErrBlockedAddress
	}
	if addr.IsPrivate() {
		if !contains(policy.private, addr) {
			return ErrBlockedAddress
		}
		return nil
	}
	// Non-ULA IPv6 must be in the currently allocated global-unicast space.
	// This also rejects NAT64/translation encodings which can conceal IPv4 targets.
	if addr.Is6() && !netip.MustParsePrefix("2000::/3").Contains(addr) {
		return ErrBlockedAddress
	}
	return nil
}

// ValidateEndpoint performs pure URL/IP-literal validation without DNS or I/O.
// Endpoint query strings are intentionally unsupported: credentials cannot be
// moved into a query, logs, or redirects. Use scoped outbound headers instead.
func ValidateEndpoint(raw string, policy URLPolicy) (*url.URL, error) {
	compiled, err := compilePolicy(policy)
	if err != nil {
		return nil, err
	}
	return compiled.validateEndpoint(raw)
}

func (policy addressPolicy) validateEndpoint(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > 4096 || hasControl(raw) || strings.ContainsAny(raw, "\\%#") {
		return nil, ErrInvalidEndpoint
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return nil, ErrInvalidEndpoint
	}
	if u.Scheme != "https" && (!policy.allowHTTP || u.Scheme != "http") {
		return nil, ErrInvalidEndpoint
	}
	if u.Host == "" || strings.Contains(u.Host, "@") || strings.HasSuffix(u.Host, ":") {
		return nil, ErrInvalidEndpoint
	}
	if port := u.Port(); port != "" {
		number, parseErr := strconv.Atoi(port)
		if parseErr != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
			return nil, ErrInvalidEndpoint
		}
	}
	host := strings.ToLower(u.Hostname())
	if addr, parseErr := netip.ParseAddr(host); parseErr == nil {
		if err := policy.validateIP(addr); err != nil {
			return nil, err
		}
	} else if !validDNSName(host) {
		return nil, ErrInvalidEndpoint
	}
	if blockedHostname(host) {
		return nil, ErrBlockedAddress
	}
	if strings.Contains(u.Path, "//") || strings.Contains(u.Path, "%") {
		return nil, ErrInvalidEndpoint
	}
	for _, component := range strings.Split(u.Path, "/") {
		if component == "." || component == ".." {
			return nil, ErrInvalidEndpoint
		}
		for _, character := range component {
			allowed := (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || strings.ContainsRune("-._~", character)
			if !allowed {
				return nil, ErrInvalidEndpoint
			}
		}
	}
	u.Host = strings.ToLower(u.Host)
	return u, nil
}

func validDNSName(host string) bool {
	if len(host) == 0 || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	// A numeric or hexadecimal final label is never an ordinary DNS TLD; reject
	// legacy decimal/octal/hex and shortened IPv4 interpretations before lookup.
	last := labels[len(labels)-1]
	if (last[0] >= '0' && last[0] <= '9') || strings.HasPrefix(last, "0x") {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			allowed := (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-'
			if !allowed {
				return false
			}
		}
	}
	return true
}

func blockedHostname(host string) bool {
	for _, name := range []string{"localhost", "metadata", "metadata.google.internal", "instance-data.ec2.internal", "metadata.aws.internal", "kubernetes.default", "kubernetes.default.svc", "kubernetes.default.svc.cluster.local"} {
		if host == name || strings.HasSuffix(host, "."+name) {
			return true
		}
	}
	return false
}

func hasControl(value string) bool {
	for _, character := range value {
		if character < 32 || character == 127 {
			return true
		}
	}
	return false
}
