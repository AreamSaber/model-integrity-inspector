package secret

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

var ErrDerivedSourceUnavailable = errors.New("MI_DERIVED_SOURCE_UNAVAILABLE")

// DerivedSourceMAC owns only independent derived-S1 purpose keys. It never
// retains KeyRing, analysis/decryption keys, or a raw key accessor. The feature
// layer supplies the complete authenticated domain, version and canonical S1;
// secret deliberately does not import features or any analysis runtime.
type DerivedSourceMAC struct{ keys map[string][32]byte }

func (DerivedSourceMAC) String() string               { return "[derived-S1-only authenticator]" }
func (v DerivedSourceMAC) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (DerivedSourceMAC) MarshalJSON() ([]byte, error) { return nil, ErrSensitive }
func (v DerivedSourceMAC) LogValue() slog.Value       { return slog.StringValue(v.String()) }

// NewDerivedSourceMAC is a trusted startup factory. Historical versions remain
// available only when explicitly installed in the supplied KeyRing. Returned
// capability is immutable and can be shared by pure extraction and verification.
func (k *KeyRing) NewDerivedSourceMAC() (*DerivedSourceMAC, error) {
	if k == nil || !versionPattern.MatchString(k.active) {
		return nil, ErrDerivedSourceUnavailable
	}
	if _, ok := k.keys[k.active]; !ok {
		return nil, ErrDerivedSourceUnavailable
	}
	out := &DerivedSourceMAC{keys: make(map[string][32]byte, len(k.keys))}
	for version, set := range k.keys {
		if !versionPattern.MatchString(version) || len(set.derivedSource) != 32 {
			return nil, ErrDerivedSourceUnavailable
		}
		out.keys[version] = [32]byte(set.derivedSource)
	}
	return out, nil
}

// DerivedMAC accepts only the fixed feature-authentication domain and bounded
// nonempty payload. It authenticates bytes, not caller authority or database
// provenance: the real Worker/fenced transaction must supply those facts.
func (m *DerivedSourceMAC) DerivedMAC(version string, canonical []byte) ([]byte, error) {
	if m == nil || !versionPattern.MatchString(version) {
		return nil, ErrDerivedSourceUnavailable
	}
	prefix := []byte("mii/derived-s1/auth/v1\x00mii.derived-s1.v1\x00" + version + "\x00")
	if len(canonical) <= len(prefix) || len(canonical)-len(prefix) > 32<<10 || !bytes.HasPrefix(canonical, prefix) {
		return nil, ErrDerivedSourceUnavailable
	}
	key, ok := m.keys[version]
	if !ok {
		return nil, ErrDerivedSourceUnavailable
	}
	defer clear(key[:])
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(canonical)
	return mac.Sum(nil), nil
}
