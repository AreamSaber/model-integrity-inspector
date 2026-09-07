package secret

import (
	"crypto/hmac"
	"crypto/sha256"
)

// BaselineMAC authenticates an internal canonical baseline record. It does not
// decide source authenticity, human approval, calibration or scoring admission.
func (k *KeyRing) BaselineMAC(version string, canonical []byte) ([]byte, error) {
	if k == nil || len(canonical) < 1 || len(canonical) > 256<<10 {
		return nil, ErrUnavailable
	}
	key, ok := k.keys[version]
	if !ok {
		return nil, ErrUnavailable
	}
	h := hmac.New(sha256.New, key.baseline)
	_, _ = h.Write(canonical)
	return h.Sum(nil), nil
}
