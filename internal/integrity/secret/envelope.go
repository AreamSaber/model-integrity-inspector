package secret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	ErrInvalid     = errors.New("MI_SECRET_INVALID")
	ErrUnavailable = errors.New("MI_SECRET_UNAVAILABLE")
	ErrSensitive   = errors.New("MI_SECRET_SERIALIZATION_FORBIDDEN")
	ErrConsumer    = errors.New("MI_SECRET_CONSUMER_FAILED")
)

const maxPayloadBytes = 64 << 10

// Scope is immutable across the lifetime of a credential version.
type Scope struct {
	OrganizationID int64 `json:"organization_id"`
	SecretID       int64 `json:"secret_id"`
	SecretVersion  int64 `json:"secret_version"`
}

// Record is a persistence value, never an API DTO. Each byte slice is owned by
// the record. Rewrap changes the wrapping key, not the original payload AAD.
type Record struct {
	KeyVersion        string `json:"-"`
	PayloadKeyVersion string `json:"-"`
	Fingerprint       string `json:"-"`
	LastFour          string `json:"-"`
	EncryptedDataKey  []byte `json:"-"`
	Nonce             []byte `json:"-"`
	Ciphertext        []byte `json:"-"`
}

func (Record) String() string               { return "[encrypted secret record]" }
func (r Record) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, r.String()) }
func (Record) MarshalJSON() ([]byte, error) { return nil, ErrSensitive }

type keySet struct{ wrap, fingerprint, audit, cursor, probe, evidence, baseline, display, derivedSource []byte }

// KeyRing holds derived purpose-separated keys, never the caller's master-key
// buffers. It is immutable after construction and safe for concurrent use.
type KeyRing struct {
	active string
	keys   map[string]keySet
}

func (*KeyRing) String() string               { return "[secret key ring]" }
func (k *KeyRing) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, k.String()) }
func (*KeyRing) MarshalJSON() ([]byte, error) { return nil, ErrSensitive }

var versionPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

func NewKeyRing(active string, masters map[string][]byte) (*KeyRing, error) {
	if !versionPattern.MatchString(active) || len(masters) == 0 {
		return nil, ErrInvalid
	}
	for version, master := range masters {
		if !versionPattern.MatchString(version) || len(master) != 32 {
			return nil, ErrInvalid
		}
	}
	if _, exists := masters[active]; !exists {
		return nil, ErrUnavailable
	}
	// Validate the complete set before deriving anything, avoiding partially
	// constructed purpose keys when a later map entry is invalid.
	k := &KeyRing{active: active, keys: make(map[string]keySet, len(masters))}
	for version, master := range masters {
		derive := func(purpose string) ([]byte, error) {
			return hkdf.Key(sha256.New, master, nil, "mii/v1/"+purpose+"/"+version, 32)
		}
		wrap, err := derive("secret-wrap")
		if err != nil {
			return nil, ErrUnavailable
		}
		fingerprint, err := derive("secret-fingerprint")
		if err != nil {
			return nil, ErrUnavailable
		}
		audit, err := derive("audit-integrity")
		if err != nil {
			return nil, ErrUnavailable
		}
		cursor, err := derive("pagination-cursor")
		if err != nil {
			return nil, ErrUnavailable
		}
		probe, err := derive("probe-reproduction")
		if err != nil {
			return nil, ErrUnavailable
		}
		evidence, err := derive("response-evidence")
		if err != nil {
			return nil, ErrUnavailable
		}
		baseline, err := derive("baseline-approval")
		if err != nil {
			return nil, ErrUnavailable
		}
		display, err := derive("evidence-display")
		if err != nil {
			return nil, ErrUnavailable
		}
		derivedSource, err := derive("derived-s1-authentication")
		if err != nil {
			return nil, ErrUnavailable
		}
		k.keys[version] = keySet{wrap: wrap, fingerprint: fingerprint, audit: audit, cursor: cursor, probe: probe, evidence: evidence, baseline: baseline, display: display, derivedSource: derivedSource}
	}
	return k, nil
}

// AuditMAC is deliberately not a raw key accessor. Old versions remain usable
// for chain verification until their documented audit retention expires.
func (k *KeyRing) AuditMAC(version string, canonicalEvent []byte) ([]byte, error) {
	keys, ok := k.keys[version]
	if !ok {
		return nil, ErrUnavailable
	}
	h := hmac.New(sha256.New, keys.audit)
	_, _ = h.Write(canonicalEvent)
	return h.Sum(nil), nil
}

func (k *KeyRing) ActiveVersion() string { return k.active }

// Credentials cannot be formatted or marshaled. Borrowed bytes must only be
// consumed by the outbound Worker scope. Destroy clears the original owned
// buffers even if a consumer modifies the header map; intentionally copied bytes
// or strings retained by a trusted consumer cannot be generally zeroized.
type Credentials struct {
	apiKey       []byte
	headers      map[string][]byte
	ownedHeaders [][]byte
}

func (Credentials) String() string               { return "[redacted credentials]" }
func (c Credentials) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, c.String()) }
func (Credentials) MarshalJSON() ([]byte, error) { return nil, ErrSensitive }

func NewCredentials(apiKey []byte, headers map[string]string) (Credentials, error) {
	if len(apiKey) == 0 || len(apiKey) > 8192 || !utf8.Valid(apiKey) || bytes.ContainsAny(apiKey, "\r\n\x00") || len(headers) > 32 {
		return Credentials{}, ErrInvalid
	}
	c := Credentials{apiKey: bytes.Clone(apiKey), headers: make(map[string][]byte, len(headers))}
	total := len(apiKey)
	for name, value := range headers {
		if !validHeaderName(name) || len(value) > 8192 || !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n\x00") {
			c.Destroy()
			return Credentials{}, ErrInvalid
		}
		normalized := strings.ToLower(name)
		if _, duplicate := c.headers[normalized]; duplicate {
			c.Destroy()
			return Credentials{}, ErrInvalid
		}
		total += len(name) + len(value)
		if total > maxPayloadBytes/2 {
			c.Destroy()
			return Credentials{}, ErrInvalid
		}
		buffer := []byte(value)
		c.headers[normalized] = buffer
		c.ownedHeaders = append(c.ownedHeaders, buffer)
	}
	return c, nil
}

func validHeaderName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for _, r := range name {
		allowed := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r)
		if !allowed {
			return false
		}
	}
	return true
}

func (c Credentials) Destroy() {
	clear(c.apiKey)
	for _, value := range c.ownedHeaders {
		clear(value)
	}
	for _, value := range c.headers {
		clear(value)
	}
}

func (c Credentials) Use(fn func(apiKey []byte, headers map[string][]byte) error) error {
	if fn == nil || len(c.apiKey) == 0 || bytes.ContainsAny(c.apiKey, "\x00") {
		return ErrInvalid
	}
	if err := fn(c.apiKey, c.headers); err != nil {
		return ErrConsumer
	}
	return nil
}

type payload struct {
	Version int               `json:"version"`
	APIKey  []byte            `json:"api_key"`
	Headers map[string][]byte `json:"headers"`
}
type wrappedKey struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	KeyVersion string `json:"key_version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}
type associatedData struct {
	Version           int    `json:"version"`
	Purpose           string `json:"purpose"`
	Scope             Scope  `json:"scope"`
	KeyVersion        string `json:"key_version"`
	PayloadKeyVersion string `json:"payload_key_version"`
	Fingerprint       string `json:"fingerprint"`
	LastFour          string `json:"last_four"`
}

func aad(scope Scope, record Record, purpose string) ([]byte, error) {
	version := record.KeyVersion
	if purpose == "payload" {
		version = record.PayloadKeyVersion
	}
	return json.Marshal(associatedData{Version: 1, Purpose: purpose, Scope: scope, KeyVersion: version, PayloadKeyVersion: record.PayloadKeyVersion, Fingerprint: record.Fingerprint, LastFour: record.LastFour})
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrUnavailable
	}
	return cipher.NewGCM(block)
}

func validScope(scope Scope) bool {
	return scope.OrganizationID > 0 && scope.SecretID > 0 && scope.SecretVersion > 0
}

func (k *KeyRing) Encrypt(scope Scope, credentials Credentials) (Record, error) {
	if !validScope(scope) || len(credentials.apiKey) == 0 || bytes.ContainsAny(credentials.apiKey, "\x00") {
		return Record{}, ErrInvalid
	}
	// #nosec G117 -- This private versioned payload is immediately AES-GCM encrypted, never returned/logged, and its buffer is cleared below. Public credential serialization is forbidden.
	encoded, err := json.Marshal(payload{Version: 1, APIKey: credentials.apiKey, Headers: credentials.headers})
	if err != nil {
		return Record{}, ErrInvalid
	}
	defer clear(encoded)
	if len(encoded) > maxPayloadBytes {
		return Record{}, ErrInvalid
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return Record{}, ErrUnavailable
	}
	defer clear(dek)
	keys := k.keys[k.active]
	fingerprint := hmac.New(sha256.New, keys.fingerprint)
	_, _ = fingerprint.Write(credentials.apiKey)
	lastFour := "" // Never expose the complete value of a short credential.
	runes := bytes.Runes(credentials.apiKey)
	if len(runes) > 8 {
		lastFour = string(runes[len(runes)-4:])
	}
	clear(runes)
	record := Record{KeyVersion: k.active, PayloadKeyVersion: k.active, Fingerprint: hex.EncodeToString(fingerprint.Sum(nil)), LastFour: lastFour}
	aead, err := gcm(dek)
	if err != nil {
		return Record{}, ErrUnavailable
	}
	record.Nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(record.Nonce); err != nil {
		return Record{}, ErrUnavailable
	}
	associated, err := aad(scope, record, "payload")
	if err != nil {
		return Record{}, ErrUnavailable
	}
	record.Ciphertext = aead.Seal(nil, record.Nonce, encoded, associated)
	if err := k.wrap(scope, &record, dek); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (k *KeyRing) wrap(scope Scope, record *Record, dek []byte) error {
	keys, ok := k.keys[record.KeyVersion]
	if !ok {
		return ErrUnavailable
	}
	aead, err := gcm(keys.wrap)
	if err != nil {
		return ErrUnavailable
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return ErrUnavailable
	}
	associated, err := aad(scope, *record, "wrap")
	if err != nil {
		return ErrUnavailable
	}
	envelope := wrappedKey{Version: 1, Algorithm: "AES-256-GCM", KeyVersion: record.KeyVersion, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, dek, associated)}
	record.EncryptedDataKey, err = json.Marshal(envelope)
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

func decode(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return ErrUnavailable
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrUnavailable
	}
	return nil
}

func (k *KeyRing) unwrap(scope Scope, record Record) ([]byte, error) {
	if !validScope(scope) || len(record.EncryptedDataKey) > 1024 || len(record.Ciphertext) > maxPayloadBytes+16 || len(record.Nonce) != 12 || !versionPattern.MatchString(record.PayloadKeyVersion) {
		return nil, ErrUnavailable
	}
	keys, ok := k.keys[record.KeyVersion]
	if !ok {
		return nil, ErrUnavailable
	}
	var envelope wrappedKey
	if err := decode(record.EncryptedDataKey, &envelope); err != nil {
		return nil, ErrUnavailable
	}
	if envelope.Version != 1 || envelope.Algorithm != "AES-256-GCM" || envelope.KeyVersion != record.KeyVersion || len(envelope.Nonce) != 12 || len(envelope.Ciphertext) != 48 {
		return nil, ErrUnavailable
	}
	aead, err := gcm(keys.wrap)
	if err != nil {
		return nil, ErrUnavailable
	}
	associated, err := aad(scope, record, "wrap")
	if err != nil {
		return nil, ErrUnavailable
	}
	dek, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, associated)
	if err != nil {
		return nil, ErrUnavailable
	}
	return dek, nil
}

// WithCredentialsForWorker is the only decryption entry point. Only the Worker
// composition layer may invoke it; Analyzer/Report/HTTP code must not import it.
// No consumer error text is propagated (it may contain an upstream credential).
func (k *KeyRing) WithCredentialsForWorker(scope Scope, record Record, fn func(Credentials) error) (result error) {
	defer func() {
		if recover() != nil {
			result = ErrConsumer
		}
	}()
	if fn == nil {
		return ErrInvalid
	}
	dek, err := k.unwrap(scope, record)
	if err != nil {
		return ErrUnavailable
	}
	defer clear(dek)
	aead, err := gcm(dek)
	if err != nil {
		return ErrUnavailable
	}
	associated, err := aad(scope, record, "payload")
	if err != nil {
		return ErrUnavailable
	}
	plaintext, err := aead.Open(nil, record.Nonce, record.Ciphertext, associated)
	if err != nil {
		return ErrUnavailable
	}
	defer clear(plaintext)
	var p payload
	if err := decode(plaintext, &p); err != nil {
		clear(p.APIKey)
		for _, v := range p.Headers {
			clear(v)
		}
		return ErrUnavailable
	}
	credentials := Credentials{apiKey: p.APIKey, headers: p.Headers}
	for _, value := range p.Headers {
		credentials.ownedHeaders = append(credentials.ownedHeaders, value)
	}
	defer credentials.Destroy()
	if p.Version != 1 || len(p.APIKey) == 0 || len(p.APIKey) > 8192 || len(p.Headers) > 32 {
		return ErrUnavailable
	}
	if err := fn(credentials); err != nil {
		return ErrConsumer
	}
	return nil
}

// Rewrap never decrypts credential payloads and does not need the old root after
// success. PayloadKeyVersion stays immutable so its original AAD still verifies.
func (k *KeyRing) Rewrap(scope Scope, record Record, newVersion string) (Record, error) {
	if _, ok := k.keys[newVersion]; !ok {
		return Record{}, ErrUnavailable
	}
	dek, err := k.unwrap(scope, record)
	if err != nil {
		return Record{}, ErrUnavailable
	}
	defer clear(dek)
	next := record
	next.KeyVersion = newVersion
	next.Nonce = bytes.Clone(record.Nonce)
	next.Ciphertext = bytes.Clone(record.Ciphertext)
	if err := k.wrap(scope, &next, dek); err != nil {
		return Record{}, ErrUnavailable
	}
	return next, nil
}
