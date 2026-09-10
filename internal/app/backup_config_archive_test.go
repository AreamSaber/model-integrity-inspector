package app

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

// Actual AEAD verifies framing and key identity; template semantics are a
// separate check. This uses a synthetic scope, NOT a full database manifest or
// production coordinator. No filesystem or restore/startup operation occurs.
func TestBackupConfigurationActualAuthenticatedArchive(t *testing.T) {
	a, err := newBackupConfigurationTemplate(t.Context(), backupConfigurationFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	ring, err := secret.NewKeyRing("v3", map[string][]byte{"v3": bytes.Repeat([]byte{0x37}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	seal, open, err := ring.NewBackupCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	limits := secret.BackupLimits{MaxBytes: 1 << 20, MaxEntries: 4, Timeout: time.Second}
	for _, mode := range []string{"valid", "authenticated_unsafe", "truncated_tail", "extra_tail", "wrong_key"} {
		t.Run(mode, func(t *testing.T) {
			plain := a.Bytes()
			if mode == "authenticated_unsafe" {
				plain = []byte(strings.Replace(string(plain), "./keys/master.key", "source-private-canary.key", 1))
			}
			expected := backupConfigurationDigest(plain)
			scope := secret.BackupScope{BackupID: 31, ManifestHash: expected}
			var archive bytes.Buffer
			_, err := seal.Seal(t.Context(), scope, limits, &archive, func(_ context.Context, w *secret.BackupArchiveWriter) error {
				return w.WriteEntry(secret.BackupEntry{Kind: "config", ID: "config-template"}, func(_ context.Context, out io.Writer) error {
					_, err := out.Write(plain)
					return err
				})
			})
			if err != nil {
				t.Fatal("actual encryption failed", err)
			}
			ciphertext := bytes.Clone(archive.Bytes())
			opener := open
			switch mode {
			case "truncated_tail":
				ciphertext = ciphertext[:len(ciphertext)-1]
			case "extra_tail":
				ciphertext = append(ciphertext, 1)
			case "wrong_key":
				wrong, err := secret.NewKeyRing("v3", map[string][]byte{"v3": bytes.Repeat([]byte{0x38}, 32)})
				if err != nil {
					t.Fatal(err)
				}
				_, opener, err = wrong.NewBackupCapabilities()
				if err != nil {
					t.Fatal(err)
				}
			}
			var tentative *backupConfigurationTemplate
			receipt, err := opener.Open(t.Context(), scope, limits, bytes.NewReader(ciphertext), func(ctx context.Context, entry secret.BackupEntry, r io.Reader) error {
				if tentative != nil || entry.Kind != "config" || entry.ID != "config-template" {
					return ErrConfig
				}
				raw, err := io.ReadAll(io.LimitReader(r, backupConfigurationMaxBytes+1))
				if err != nil {
					return err
				}
				tentative, err = verifyBackupConfigurationTemplate(ctx, raw, expected)
				return err
			})
			// Nothing may be published until the WHOLE authenticated archive has
			// completed, even if its config entry was already verified in memory.
			var published *backupConfigurationTemplate
			if err == nil {
				published = tentative
			}
			if mode == "valid" {
				if err != nil || published == nil || !bytes.Equal(published.Bytes(), a.Bytes()) {
					t.Fatal("valid carrier failed actual archive round trip", err)
				}
			} else if err == nil || published != nil {
				t.Fatal("unsafe/unauthenticated/incomplete archive authorized template")
			}
			if mode == "truncated_tail" || mode == "extra_tail" {
				if tentative == nil || !bytes.Equal(tentative.Bytes(), a.Bytes()) || receipt != (secret.BackupReceipt{}) {
					t.Fatal("tail failure did not exercise already-verified config with zero archive receipt")
				}
			}
		})
	}
}
