package secret

import (
	"crypto/hmac"
	"crypto/sha256"
)

// ProbeMAC authenticates bounded canonical reproduction metadata, using a
// distinct HKDF purpose from wrapping, fingerprints, auditing and pagination.
// The generator binds organization, run nonce and artifact hash in its payload.
// Retain the named old key version while its S2 manifests must be replayable.
func (k *KeyRing) ProbeMAC(version string, payload []byte) ([]byte, error) {
	if k == nil || len(payload) == 0 || len(payload) > 4096 {
		return nil, ErrInvalid
	}
	keys, ok := k.keys[version]
	if !ok {
		return nil, ErrUnavailable
	}
	h := hmac.New(sha256.New, keys.probe)
	_, _ = h.Write(payload)
	return h.Sum(nil), nil
}
