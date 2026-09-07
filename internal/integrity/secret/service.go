package secret

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/safehttp"
)

// Input is write-only. The caller must discard/zero its input buffers after
// use. Service-owned copies are destroyed immediately after encryption.
type Input struct {
	Type       string
	APIKey     []byte
	HeaderName string
	Headers    map[string]string
}

func (Input) String() string                   { return "[write-only credentials]" }
func (input Input) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, input.String()) }
func (Input) MarshalJSON() ([]byte, error)     { return nil, ErrSensitive }

// Auth contains routing metadata only. It is internal, not an API response.
type Auth struct {
	Type       string
	HeaderName string
}

func ValidateInput(input Input) (Auth, error) {
	if (input.Type != "bearer" && input.Type != "custom_header") || len(input.Headers) > 32 {
		return Auth{}, ErrInvalid
	}
	headers := make(http.Header, len(input.Headers)+1)
	for name, value := range input.Headers {
		headers[name] = []string{value}
	}
	if err := safehttp.ValidateCustomHeaders(headers); err != nil {
		return Auth{}, ErrInvalid
	}
	auth := Auth{Type: input.Type}
	if input.Type == "bearer" {
		if input.HeaderName != "" {
			return Auth{}, ErrInvalid
		}
	} else {
		if input.HeaderName == "" {
			return Auth{}, ErrInvalid
		}
		for name := range input.Headers {
			if strings.EqualFold(name, input.HeaderName) {
				return Auth{}, ErrInvalid
			}
		}
		if err := safehttp.ValidateCustomHeaders(http.Header{input.HeaderName: []string{"validation"}}); err != nil {
			return Auth{}, ErrInvalid
		}
		auth.HeaderName = http.CanonicalHeaderKey(input.HeaderName)
	}
	credentials, err := NewCredentials(input.APIKey, input.Headers)
	if err != nil {
		return Auth{}, ErrInvalid
	}
	credentials.Destroy()
	return auth, nil
}

// Service persists no master key, plaintext cache, or generic secret-read API.
// Only WithCredentialsForWorker is a business decryption boundary.
type Service struct {
	store *repository.Store
	ring  *KeyRing
}

func NewService(store *repository.Store, ring *KeyRing) (*Service, error) {
	if store == nil || ring == nil || ring.ActiveVersion() == "" {
		return nil, ErrUnavailable
	}
	return &Service{store: store, ring: ring}, nil
}

func (*Service) String() string                     { return "[secret service]" }
func (service *Service) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, service.String()) }
func (*Service) MarshalJSON() ([]byte, error)       { return nil, ErrSensitive }

func (service *Service) PrepareCreate(orgID int64, input Input) (repository.SecretRecord, error) {
	if orgID <= 0 {
		return repository.SecretRecord{}, repository.ErrOrganizationScope
	}
	id, err := repository.NewID()
	if err != nil {
		return repository.SecretRecord{}, ErrUnavailable
	}
	return service.prepare(Scope{orgID, id, 1}, input)
}

// PrepareReplacement expects the new version. CAS of both the target and old
// Secret version occurs in the repository transaction, never in crypto code.
func (service *Service) PrepareReplacement(scope Scope, input Input) (repository.SecretRecord, error) {
	if scope.SecretVersion <= 1 {
		return repository.SecretRecord{}, ErrInvalid
	}
	return service.prepare(scope, input)
}

func (service *Service) prepare(scope Scope, input Input) (repository.SecretRecord, error) {
	if scope.OrganizationID <= 0 || scope.SecretID <= 0 || scope.SecretVersion <= 0 || scope.SecretVersion > math.MaxInt32 {
		return repository.SecretRecord{}, ErrInvalid
	}
	if _, err := ValidateInput(input); err != nil {
		return repository.SecretRecord{}, err
	}
	credentials, err := NewCredentials(input.APIKey, input.Headers)
	if err != nil {
		return repository.SecretRecord{}, err
	}
	defer credentials.Destroy()
	encrypted, err := service.ring.Encrypt(scope, credentials)
	if err != nil {
		return repository.SecretRecord{}, err
	}
	return repository.SecretRecord{ID: scope.SecretID, OrganizationID: scope.OrganizationID, SecretVersion: scope.SecretVersion,
		EncryptedDataKey: encrypted.EncryptedDataKey, Ciphertext: encrypted.Ciphertext, Nonce: encrypted.Nonce,
		KeyVersion: encrypted.KeyVersion, PayloadKeyVersion: encrypted.PayloadKeyVersion, Fingerprint: encrypted.Fingerprint, LastFour: encrypted.LastFour}, nil
}

// EndpointFingerprint uses a domain-separated HMAC, including tenant identity;
// URLs cannot be dictionary-tested with an unkeyed hash or correlated cross-org.
func (service *Service) EndpointFingerprint(orgID int64, endpoint string) (string, error) {
	if orgID <= 0 || endpoint == "" {
		return "", ErrInvalid
	}
	keys, ok := service.ring.keys[service.ring.active]
	if !ok {
		return "", ErrUnavailable
	}
	mac := hmac.New(sha256.New, keys.fingerprint)
	_, _ = io.WriteString(mac, "mii/v1/endpoint-fingerprint\x00"+strconv.FormatInt(orgID, 10)+"\x00"+endpoint)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// WithCredentialsForWorker must wrap the complete outbound adapter Call. Never
// return credentials or retain copies from the callback. Use expected version
// from a frozen run snapshot; changed/deleted credentials fail closed.
func (service *Service) WithCredentialsForWorker(ctx context.Context, scope Scope, consume func(Credentials) error) error {
	if consume == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	tenant, err := service.store.WithOrganization(ctx, scope.OrganizationID)
	if err != nil {
		return ErrUnavailable
	}
	record, err := tenant.GetSecretForWorker(scope.SecretID, scope.SecretVersion)
	if err != nil {
		return ErrUnavailable
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	return service.ring.WithCredentialsForWorker(scope, Record{KeyVersion: record.KeyVersion, PayloadKeyVersion: record.PayloadKeyVersion,
		Fingerprint: record.Fingerprint, LastFour: record.LastFour, EncryptedDataKey: record.EncryptedDataKey,
		Nonce: record.Nonce, Ciphertext: record.Ciphertext}, consume)
}
