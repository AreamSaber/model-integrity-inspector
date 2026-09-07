package templates

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"
)

var ErrBundle = errors.New("MI_TEMPLATE_BUNDLE_INVALID")
var ErrImmutable = errors.New("MI_TEMPLATE_VERSION_IMMUTABLE")
var identifier = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,95}$`)
var version = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$`)

type Template struct {
	ID            string   `json:"id"`
	Version       string   `json:"version"`
	Family        string   `json:"family"`
	Category      string   `json:"category"`
	Language      string   `json:"language"`
	Variant       int      `json:"variant"`
	Prompt        string   `json:"prompt"`
	Assertions    []string `json:"assertions"`
	AuxiliaryOnly bool     `json:"auxiliary_only"`
}
type Bundle struct {
	Version   string     `json:"version"`
	Templates []Template `json:"templates"`
}

// Template contents are S2 material. Explicit canonical serialization is used
// only for persistence/reproduction, never ordinary structured logging.
func (Template) String() string               { return "[probe template]" }
func (v Template) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (Bundle) String() string                 { return "[probe template bundle]" }
func (v Bundle) Format(w fmt.State, _ rune)   { _, _ = io.WriteString(w, v.String()) }

func (b Bundle) Validate() error {
	if !version.MatchString(b.Version) || len(b.Templates) < 1 || len(b.Templates) > 256 {
		return ErrBundle
	}
	seen := map[string]bool{}
	for _, t := range b.Templates {
		if !identifier.MatchString(t.ID) || !version.MatchString(t.Version) || seen[t.ID] || (t.Language != "zh-CN" && t.Language != "en-US") || t.Variant < 1 || t.Variant > 32 || len(t.Prompt) == 0 || len(t.Prompt) > 8192 || !utf8.ValidString(t.Prompt) || strings.ContainsRune(t.Prompt, 0) || len(t.Assertions) == 0 || len(t.Assertions) > 8 {
			return ErrBundle
		}
		seen[t.ID] = true
		switch t.Family {
		case "sequence", "jsonl":
			if t.Category != "max_tokens" {
				return ErrBundle
			}
		case "format", "neutral", "differential", "style":
			if t.Category != "prompt_behavior" {
				return ErrBundle
			}
		case "self_report":
			if t.Category != "auxiliary" || !t.AuxiliaryOnly {
				return ErrBundle
			}
		default:
			return ErrBundle
		}
		if t.Family != "self_report" && t.AuxiliaryOnly {
			return ErrBundle
		}
		for _, assertion := range t.Assertions {
			if !identifier.MatchString(assertion) {
				return ErrBundle
			}
		}
		// Only data placeholders, never Go templates, expressions, includes or
		// file/network lookups. Unrecognized placeholders cannot be rendered.
		remaining := t.Prompt
		for _, key := range []string{"NONCE", "COUNT", "LABEL", "STYLE"} {
			remaining = strings.ReplaceAll(remaining, "[["+key+"]]", "")
		}
		if strings.Contains(remaining, "[[") || strings.Contains(remaining, "]]") {
			return ErrBundle
		}
	}
	return nil
}

func (b Bundle) Canonical() ([]byte, string, error) {
	if err := b.Validate(); err != nil {
		return nil, "", err
	}
	data, err := json.Marshal(b)
	if err != nil || len(data) > 1<<20 {
		return nil, "", ErrBundle
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}

// Decode requires the expected digest from trusted release/operator metadata.
// There is no fetch-from-URL path and no implicit acceptance of a new digest.
func Decode(data []byte, expectedHash string) (Bundle, error) {
	if len(data) > 1<<20 || len(expectedHash) != 64 || !utf8.Valid(data) {
		return Bundle{}, ErrBundle
	}
	var b Bundle
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&b) != nil {
		return Bundle{}, ErrBundle
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return Bundle{}, ErrBundle
	}
	canonical, hash, err := b.Canonical()
	// Require the unique canonical JSON bytes as well as their digest, ruling
	// out duplicate-key/whitespace representations of a trusted bundle.
	if err != nil || hash != expectedHash || !bytes.Equal(data, canonical) {
		return Bundle{}, ErrBundle
	}
	return b, nil
}

// Registry never replaces a registered version. Callers receive detached
// copies; changing their slice/prompt cannot mutate published process state.
// Durable publication/approval is a separate repository operation.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]registryEntry
}
type registryEntry struct {
	data []byte
	hash string
}

func NewRegistry() *Registry { return &Registry{entries: map[string]registryEntry{}} }
func (r *Registry) Add(b Bundle) (string, error) {
	data, hash, err := b.Canonical()
	if err != nil {
		return "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.entries[b.Version]; ok && old.hash != hash {
		return "", ErrImmutable
	}
	r.entries[b.Version] = registryEntry{data, hash}
	return hash, nil
}
func (r *Registry) Get(v string) (Bundle, string, error) {
	r.mu.RLock()
	entry, ok := r.entries[v]
	r.mu.RUnlock()
	if !ok {
		return Bundle{}, "", ErrBundle
	}
	b, err := Decode(entry.data, entry.hash)
	return b, entry.hash, err
}

func (b Bundle) Find(id string) (Template, bool) {
	for _, t := range b.Templates {
		if t.ID == id {
			t.Assertions = append([]string(nil), t.Assertions...)
			return t, true
		}
	}
	return Template{}, false
}

func Render(t Template, variables map[string]string) (string, error) {
	result := t.Prompt
	for _, key := range []string{"NONCE", "COUNT", "LABEL", "STYLE"} {
		value, ok := variables[key]
		if !ok {
			value = ""
		}
		if len(value) > 256 || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") || strings.Contains(value, "[[") || strings.Contains(value, "]]") {
			return "", ErrBundle
		}
		if strings.Contains(result, "[["+key+"]]") && value == "" {
			return "", ErrBundle
		}
		result = strings.ReplaceAll(result, "[["+key+"]]", value)
	}
	if len(result) > 16384 || strings.Contains(result, "[[") || strings.Contains(result, "]]") {
		return "", ErrBundle
	}
	return result, nil
}
