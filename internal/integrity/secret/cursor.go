package secret

import (
	"crypto/hmac"
	"crypto/sha256"
)

// CursorMAC signs non-secret pagination state with a separate HKDF purpose.
// No raw key accessor; sharing a master across server replicas keeps cursors
// valid across load balancing without sharing any in-memory session registry.
func (k *KeyRing) CursorMAC(version string, payload []byte) ([]byte, error) {
	keys, ok := k.keys[version]
	if !ok || len(payload) > 2048 {
		return nil, ErrInvalid
	}
	h := hmac.New(sha256.New, keys.cursor)
	_, _ = h.Write(payload)
	return h.Sum(nil), nil
}
