package localfile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestDevelopmentTrustCanonicalRoundtrip(t *testing.T) {
	s, err := NewManifestSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()
	raw, err := EncodeDevelopmentManifestKey(s)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	parsed, err := ParseDevelopmentManifestKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	want, err := s.ProbeMAC(s.ActiveVersion(), []byte("development check"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := parsed.ProbeMAC(parsed.ActiveVersion(), []byte("development check"))
	if err != nil || !bytes.Equal(want, got) {
		t.Fatalf("roundtrip: %v", err)
	}
	if _, err := parsed.ProbeMAC("production-master", nil); !errors.Is(err, ErrTrust) {
		t.Fatal("unknown version accepted")
	}
	parsed.Destroy()
	if _, err := parsed.ProbeMAC(parsed.ActiveVersion(), nil); !errors.Is(err, ErrTrust) {
		t.Fatal("destroyed key accepted")
	}
	if _, err := EncodeDevelopmentManifestKey(parsed); !errors.Is(err, ErrTrust) {
		t.Fatal("destroyed key exported")
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicRaw, err := EncodeDevelopmentCapturePublicKey("dev-test", public)
	if err != nil {
		t.Fatal(err)
	}
	id, decoded, err := ParseDevelopmentCapturePublicKey(publicRaw)
	if err != nil || id != "dev-test" || !bytes.Equal(decoded, public) {
		t.Fatalf("public roundtrip: %v", err)
	}
	if _, err := EncodeDevelopmentCapturePublicKey("production", public); !errors.Is(err, ErrTrust) {
		t.Fatal("production id accepted")
	}
}

func TestTrustRejectsAliasesMasterAndMalformed(t *testing.T) {
	s, err := NewManifestSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()
	raw, err := EncodeDevelopmentManifestKey(s)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	cases := [][]byte{nil, bytes.Repeat([]byte("x"), 32), bytes.Repeat([]byte("x"), MaxTrustBytes+1), append(bytes.Clone(raw), '\n'), append(bytes.Clone(raw), 0xff), append(bytes.Clone(raw), []byte(`{}`)...), bytes.Replace(raw, []byte(`"purpose":`), []byte(`"Purpose":`), 1), bytes.Replace(raw, []byte(`"purpose":`), []byte(`"trusted":true,"purpose":`), 1), bytes.Replace(raw, []byte(`"purpose":`), []byte(`"purpose":"bad","purpose":`), 1), bytes.Replace(raw, []byte(ManifestKeyVersion), []byte("real-master-version"), 1), bytes.Replace(raw, []byte("development-only-probe-mac"), []byte("production"), 1)}
	for i, data := range cases {
		if _, err := ParseDevelopmentManifestKey(data); !errors.Is(err, ErrTrust) {
			t.Errorf("malformed %d accepted", i)
		}
		if _, _, err := ParseDevelopmentCapturePublicKey(data); !errors.Is(err, ErrTrust) {
			t.Errorf("wrong public type %d accepted", i)
		}
	}
}

func TestManifestSignerDiagnosticsAreRedacted(t *testing.T) {
	s, err := NewManifestSigner()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Destroy()
	secret := base64.StdEncoding.EncodeToString(s.key)
	for _, value := range []any{s, *s} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			got := fmt.Sprintf(format, value)
			if !strings.Contains(got, "REDACTED") || strings.Contains(got, secret) || strings.Contains(got, "[]uint8") {
				t.Fatal("format leak")
			}
		}
		if data, err := json.Marshal(value); !errors.Is(err, ErrSensitive) || len(data) != 0 {
			t.Fatal("implicit key serialization")
		}
		for _, jsonLog := range []bool{false, true} {
			var b bytes.Buffer
			var handler slog.Handler = slog.NewTextHandler(&b, nil)
			if jsonLog {
				handler = slog.NewJSONHandler(&b, nil)
			}
			slog.New(handler).Info("test", "direct", value, slog.Any("any", value))
			if strings.Contains(b.String(), secret) || !strings.Contains(b.String(), "REDACTED") {
				t.Fatal("slog leak")
			}
		}
	}
}
