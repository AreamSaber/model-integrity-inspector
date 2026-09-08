package secret

import (
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
)

// MaxMasterKeyFiles bounds operator-controlled startup I/O. It is not a data
// retention limit: needed historical versions must not be removed to fit it.
const MaxMasterKeyFiles = 64

// KeyFileReference is private operator configuration, never backup content or
// an API DTO. Only the version and a separately supplied restricted file occur
// here; inline master bytes, base64 values and environment expansion are absent.
type KeyFileReference struct {
	Version string `yaml:"version"`
	File    string `yaml:"file"`
}

func (KeyFileReference) String() string               { return "[private master-key reference]" }
func (v KeyFileReference) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (KeyFileReference) MarshalJSON() ([]byte, error) { return nil, ErrSensitive }
func (KeyFileReference) MarshalYAML() (any, error)    { return nil, ErrSensitive }
func (v KeyFileReference) LogValue() slog.Value       { return slog.StringValue(v.String()) }

// ValidateKeyFiles validates the whole closed configuration before any file is
// opened. Versions are case-sensitive, exactly as in existing ciphertext AAD.
func ValidateKeyFiles(active string, references []KeyFileReference) error {
	if !versionPattern.MatchString(active) || len(references) < 1 || len(references) > MaxMasterKeyFiles {
		return ErrKeyFileInvalid
	}
	seen := make(map[string]struct{}, len(references))
	for _, ref := range references {
		if !versionPattern.MatchString(ref.Version) {
			return ErrKeyFileInvalid
		}
		if _, exists := seen[ref.Version]; exists {
			return ErrKeyFileInvalid
		}
		seen[ref.Version] = struct{}{}
	}
	if _, exists := seen[active]; !exists {
		return ErrKeyFileInvalid
	}
	for _, ref := range references {
		if ref.File == "" || strings.ContainsRune(ref.File, 0) {
			return ErrKeyFileUnsafe
		}
	}
	return nil
}

// LoadKeyFiles derives one active-plus-historical ring, using the same native
// no-follow, ACL/mode, single-link and exact-32-byte checks as LoadKeyFile. Any
// unavailable/invalid file fails the entire operation; no partial ring escapes.
// No file is modified, and raw master buffers are cleared after derivation.
// This does not prove all database-referenced versions were supplied: the full
// restore inventory/cryptographic verifier must independently enforce that.
func LoadKeyFiles(active string, references []KeyFileReference) (*KeyRing, error) {
	refs := slices.Clone(references)
	if err := ValidateKeyFiles(active, refs); err != nil {
		return nil, err
	}
	masters := make(map[string][]byte, len(refs))
	defer func() {
		for _, master := range masters {
			clear(master)
		}
	}()
	for _, ref := range refs {
		master, err := readRestrictedMaster(ref.File)
		if err != nil {
			return nil, err
		}
		masters[ref.Version] = master
	}
	return NewKeyRing(active, masters)
}
