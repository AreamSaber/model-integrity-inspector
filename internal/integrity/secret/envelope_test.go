package secret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const canary = "synthetic-test-canary-9e47-never-a-real-key"

func testRing(t testing.TB) *KeyRing {
	t.Helper()
	k, err := NewKeyRing("one", map[string][]byte{"one": bytes.Repeat([]byte{0x17}, 32), "two": bytes.Repeat([]byte{0x91}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testRecord(t testing.TB, k *KeyRing) (Scope, Record) {
	t.Helper()
	scope := Scope{OrganizationID: 1, SecretID: 2, SecretVersion: 3}
	c, err := NewCredentials([]byte(canary), map[string]string{"X-Custom": "private-header"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Destroy()
	r, err := k.Encrypt(scope, c)
	if err != nil {
		t.Fatal(err)
	}
	return scope, r
}

func TestEnvelopeRoundTripAndLifetime(t *testing.T) {
	k := testRing(t)
	scope, record := testRecord(t, k)
	var borrowed []byte
	var borrowedHeaders map[string][]byte
	err := k.WithCredentialsForWorker(scope, record, func(c Credentials) error {
		return c.Use(func(key []byte, headers map[string][]byte) error {
			if string(key) != canary || string(headers["x-custom"]) != "private-header" {
				t.Fatal("credential mismatch")
			}
			borrowed = key
			borrowedHeaders = headers
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) || !bytes.Equal(borrowedHeaders["x-custom"], make([]byte, len(borrowedHeaders["x-custom"]))) {
		t.Fatal("borrowed credential buffers were not cleared")
	}
	if bytes.Contains(record.Ciphertext, []byte(canary)) || bytes.Contains(record.EncryptedDataKey, []byte(canary)) {
		t.Fatal("plaintext in persistence record")
	}
	if record.LastFour != "-key" {
		t.Fatalf("mask suffix mismatch: %q", record.LastFour)
	}
}

func TestTenantAADAndTamperFailure(t *testing.T) {
	k := testRing(t)
	scope, record := testRecord(t, k)
	tests := map[string]func(*Scope, *Record){
		"organization":             func(s *Scope, _ *Record) { s.OrganizationID++ },
		"secret":                   func(s *Scope, _ *Record) { s.SecretID++ },
		"version":                  func(s *Scope, _ *Record) { s.SecretVersion++ },
		"unknown wrapping key":     func(_ *Scope, r *Record) { r.KeyVersion = "missing" },
		"known wrong wrapping key": func(_ *Scope, r *Record) { r.KeyVersion = "two" },
		"payload version":          func(_ *Scope, r *Record) { r.PayloadKeyVersion = "two" },
		"fingerprint":              func(_ *Scope, r *Record) { r.Fingerprint = "changed" },
		"mask":                     func(_ *Scope, r *Record) { r.LastFour = "xxxx" },
		"payload nonce":            func(_ *Scope, r *Record) { r.Nonce[0] ^= 1 },
		"payload tag":              func(_ *Scope, r *Record) { r.Ciphertext[len(r.Ciphertext)-1] ^= 1 },
		"wrapped key":              func(_ *Scope, r *Record) { r.EncryptedDataKey = []byte("{}") },
		"oversize envelope":        func(_ *Scope, r *Record) { r.EncryptedDataKey = make([]byte, 1025) },
		"oversize content":         func(_ *Scope, r *Record) { r.Ciphertext = make([]byte, maxPayloadBytes+17) },
		"short nonce":              func(_ *Scope, r *Record) { r.Nonce = []byte{1} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			s := scope
			r := record
			r.Nonce = bytes.Clone(record.Nonce)
			r.Ciphertext = bytes.Clone(record.Ciphertext)
			r.EncryptedDataKey = bytes.Clone(record.EncryptedDataKey)
			mutate(&s, &r)
			called := false
			err := k.WithCredentialsForWorker(s, r, func(Credentials) error { called = true; return nil })
			if !errors.Is(err, ErrUnavailable) || called {
				t.Fatalf("tampered record accepted: err=%v called=%v", err, called)
			}
		})
	}
}

func TestRewrapPreservesPayloadWithoutOldMaster(t *testing.T) {
	k := testRing(t)
	scope, record := testRecord(t, k)
	next, err := k.Rewrap(scope, record, "two")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(next.Ciphertext, record.Ciphertext) || !bytes.Equal(next.Nonce, record.Nonce) || next.PayloadKeyVersion != "one" || next.KeyVersion != "two" {
		t.Fatal("rewrap changed immutable payload")
	}
	onlyNew, err := NewKeyRing("two", map[string][]byte{"two": bytes.Repeat([]byte{0x91}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if err := onlyNew.WithCredentialsForWorker(scope, next, func(c Credentials) error {
		return c.Use(func(key []byte, _ map[string][]byte) error {
			if string(key) != canary {
				t.Fatal("rewrapped content mismatch")
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := onlyNew.WithCredentialsForWorker(scope, record, func(Credentials) error { return nil }); !errors.Is(err, ErrUnavailable) {
		t.Fatal("old record unexpectedly decryptable without old key")
	}
	if _, err := k.Rewrap(Scope{OrganizationID: 99, SecretID: 2, SecretVersion: 3}, record, "two"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cross-tenant rewrap accepted")
	}
	if _, err := k.Rewrap(scope, record, "absent"); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unknown new key accepted")
	}
}

func TestSensitiveValuesCannotBeSerializedOrFormatted(t *testing.T) {
	k := testRing(t)
	_, record := testRecord(t, k)
	c, err := NewCredentials([]byte(canary), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Destroy()
	for _, value := range []any{k, record, c} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if got := fmt.Sprintf(format, value); strings.Contains(got, canary) || strings.Contains(got, "private-header") || strings.Contains(got, record.Fingerprint) {
				t.Fatal("sensitive formatting leak")
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrSensitive) {
			t.Fatalf("sensitive serialization did not fail: %v", err)
		}
	}
}

func TestConsumerErrorAndPanicAreSanitized(t *testing.T) {
	k := testRing(t)
	scope, record := testRecord(t, k)
	for _, panicMode := range []bool{false, true} {
		var borrowed []byte
		err := k.WithCredentialsForWorker(scope, record, func(c Credentials) error {
			return c.Use(func(key []byte, _ map[string][]byte) error {
				borrowed = key
				if panicMode {
					panic(canary)
				}
				return errors.New(canary)
			})
		})
		if !errors.Is(err, ErrConsumer) || strings.Contains(err.Error(), canary) {
			t.Fatal("unsafe consumer error")
		}
		if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
			t.Fatal("error/panic did not clear credential")
		}
	}
}

func TestInputValidationAndShortMask(t *testing.T) {
	for _, masters := range []map[string][]byte{{}, {"one": []byte("short")}, {"bad/version": make([]byte, 32)}} {
		if _, err := NewKeyRing("one", masters); err == nil {
			t.Fatal("invalid master material accepted")
		}
	}
	for _, headers := range []map[string]string{{"Bad\rName": "v"}, {"X-Test": "a\nb"}, {"X-Test": "a", "x-test": "b"}, {"X": "\x00"}} {
		if _, err := NewCredentials([]byte(canary), headers); err == nil {
			t.Fatal("invalid headers accepted")
		}
	}
	for _, key := range [][]byte{nil, []byte("abc\rdef"), bytes.Repeat([]byte{1}, 8193)} {
		if _, err := NewCredentials(key, nil); err == nil {
			t.Fatal("invalid credential accepted")
		}
	}
	k := testRing(t)
	c, err := NewCredentials([]byte("short"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Destroy()
	if _, err := k.Encrypt(Scope{}, c); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero scope accepted")
	}
	r, err := k.Encrypt(Scope{OrganizationID: 1, SecretID: 2, SecretVersion: 3}, c)
	if err != nil {
		t.Fatal(err)
	}
	if r.LastFour != "" {
		t.Fatal("short secret exposed by mask")
	}
}

func TestDeletedAndReplacedHeadersStillCleared(t *testing.T) {
	for _, worker := range []bool{false, true} {
		var borrowed []byte
		consume := func(c Credentials) error {
			return c.Use(func(_ []byte, headers map[string][]byte) error {
				borrowed = headers["x-custom"]
				delete(headers, "x-custom")
				headers["x-custom"] = []byte("replacement")
				return nil
			})
		}
		if worker {
			k := testRing(t)
			scope, record := testRecord(t, k)
			if err := k.WithCredentialsForWorker(scope, record, consume); err != nil {
				t.Fatal(err)
			}
		} else {
			c, err := NewCredentials([]byte(canary), map[string]string{"X-Custom": "private-header"})
			if err != nil {
				t.Fatal(err)
			}
			if err := consume(c); err != nil {
				t.Fatal(err)
			}
			c.Destroy()
			if c.Use(func([]byte, map[string][]byte) error { return nil }) == nil {
				t.Fatal("destroyed credentials reused")
			}
			if _, err := testRing(t).Encrypt(Scope{1, 2, 3}, c); err == nil {
				t.Fatal("destroyed credentials encrypted")
			}
		}
		if len(borrowed) == 0 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
			t.Fatal("deleted original header buffer retained plaintext")
		}
	}
}

func TestNonceIndependenceAndPurposeSeparation(t *testing.T) {
	k := testRing(t)
	seen := map[string]bool{}
	for range 50 {
		_, r := testRecord(t, k)
		var wrap wrappedKey
		if err := json.Unmarshal(r.EncryptedDataKey, &wrap); err != nil {
			t.Fatal(err)
		}
		for _, nonce := range [][]byte{r.Nonce, wrap.Nonce} {
			if seen[string(nonce)] {
				t.Fatal("duplicate nonce")
			}
			seen[string(nonce)] = true
		}
	}
	s := k.keys["one"]
	if bytes.Equal(s.wrap, s.audit) || bytes.Equal(s.wrap, s.fingerprint) || bytes.Equal(s.audit, s.fingerprint) {
		t.Fatal("key purposes not isolated")
	}
	a, err := k.AuditMAC("one", []byte("event"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := k.AuditMAC("two", []byte("event"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("audit key versions not isolated")
	}
}

func FuzzEnvelopeRejectsMalformed(f *testing.F) {
	k := testRing(f)
	scope, record := testRecord(f, k)
	f.Add([]byte("{}"), []byte("short"), []byte("nonce"))
	f.Add(record.EncryptedDataKey, record.Ciphertext, record.Nonce)
	f.Fuzz(func(t *testing.T, wrapped, body, nonce []byte) {
		r := record
		r.EncryptedDataKey = wrapped
		r.Ciphertext = body
		r.Nonce = nonce
		if err := k.WithCredentialsForWorker(scope, r, func(Credentials) error { return nil }); err != nil && !errors.Is(err, ErrUnavailable) {
			t.Fatalf("unexpected failure: %v", err)
		}
	})
}
