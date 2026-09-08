package backupmanifest

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

func TestManifestPreservesRealTemplateRegistryVersions(t *testing.T) {
	for _, length := range []int{66, 128} {
		b := templates.Builtin()
		b.Version = "1.0.0-" + strings.Repeat("a", length-6)
		registry := templates.NewRegistry()
		sha, err := registry.Add(b)
		if err != nil {
			t.Fatal("actual template version contract", err)
		}
		retained, gotHash, err := registry.Get(b.Version)
		if err != nil || gotHash != sha {
			t.Fatal("actual retained template lookup", err)
		}
		data, _, err := retained.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		m := fixture()
		m.Artifacts[2] = Artifact{"template", retained.Version, File{"template-v1", int64(len(data)), sha}}
		encoded, sum, err := Encode(m)
		if err != nil {
			t.Fatal("backup cannot retain a real supported version", err)
		}
		decoded, err := Decode(encoded, m.BackupID, sum)
		if err != nil || decoded.Artifacts[2].Version != retained.Version {
			t.Fatal("template version altered", err)
		}
	}
	m := fixture()
	m.Artifacts[0].Version = strings.Repeat("a", 129)
	if _, _, err := Encode(m); err == nil {
		t.Fatal("artifact version limit lost")
	}
	m = fixture()
	m.KeyVersions[1] = strings.Repeat("a", 65)
	if _, _, err := Encode(m); err == nil {
		t.Fatal("artifact fix expanded key version contract")
	}
}

// Synthetic file payloads exercise the actual archive crypto and every planned
// entry kind. These are not database snapshots or real audit-chain verification.
func TestManifestPlanBindsActualAuthenticatedArchive(t *testing.T) {
	m := fixture()
	payloads := map[string][]byte{}
	set := func(f *File) {
		payloads[f.EntryID] = []byte("synthetic-payload-for-" + f.EntryID)
		f.Bytes = int64(len(payloads[f.EntryID]))
		f.SHA256 = digest(payloads[f.EntryID])
	}
	set(&m.Database.File)
	set(&m.ConfigTemplate)
	for i := range m.Reports {
		set(&m.Reports[i].File)
	}
	for i := range m.Artifacts {
		set(&m.Artifacts[i].File)
	}
	data, sum, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	payloads["backup-manifest"] = data
	entries, err := Entries(m)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := secret.NewKeyRing("key-v2", map[string][]byte{"key-v2": bytes.Repeat([]byte{0x29}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	sealer, opener, err := ring.NewBackupCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	scope := secret.BackupScope{BackupID: m.BackupID, ManifestHash: sum}
	limits := secret.BackupLimits{MaxBytes: 1 << 20, MaxEntries: MaxEntries, Timeout: time.Second}
	for _, mode := range []string{"valid", "changed_payload", "missing_entry", "extra_entry", "wrong_kind"} {
		t.Run(mode, func(t *testing.T) {
			var archive bytes.Buffer
			_, err := sealer.Seal(t.Context(), scope, limits, &archive, func(_ context.Context, w *secret.BackupArchiveWriter) error {
				for _, entry := range entries {
					if mode == "missing_entry" && entry.Kind == "config" {
						continue
					}
					kind := entry.Kind
					payload := payloads[entry.File.EntryID]
					if mode == "changed_payload" && entry.Kind == "database" {
						payload = []byte("different-but-authenticated")
					}
					if mode == "wrong_kind" && entry.Kind == "database" {
						kind = "report"
					}
					if err := w.WriteEntry(secret.BackupEntry{Kind: kind, ID: entry.File.EntryID}, func(_ context.Context, out io.Writer) error { _, err := out.Write(payload); return err }); err != nil {
						return err
					}
				}
				if mode == "extra_entry" {
					return w.WriteEntry(secret.BackupEntry{Kind: "config", ID: "unlisted"}, func(_ context.Context, out io.Writer) error { _, err := out.Write([]byte("extra")); return err })
				}
				return nil
			})
			if err != nil {
				t.Fatal("actual encryption failed", err)
			}
			// The AEAD archive is deliberately valid in ALL cases: integrity of
			// archive framing alone cannot prove the manifest's exact file set.
			seen := map[string]bool{}
			mismatch := false
			_, err = opener.Open(t.Context(), scope, limits, bytes.NewReader(archive.Bytes()), func(_ context.Context, entry secret.BackupEntry, in io.Reader) error {
				plain, err := io.ReadAll(io.LimitReader(in, 1<<20))
				if err != nil {
					return err
				}
				var matched bool
				for _, want := range entries {
					if want.File.EntryID == entry.ID {
						matched = true
						if seen[entry.ID] || want.Kind != entry.Kind || want.File.Bytes != int64(len(plain)) || want.File.SHA256 != digest(plain) {
							mismatch = true
						}
					}
				}
				if !matched {
					mismatch = true
				}
				seen[entry.ID] = true
				if entry.Kind == "manifest" {
					if _, err := Decode(plain, m.BackupID, sum); err != nil {
						mismatch = true
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal("fixture should have authenticated complete framing", err)
			}
			if len(seen) != len(entries) {
				mismatch = true
			}
			if mismatch != (mode != "valid") {
				t.Fatal("manifest plan did not distinguish a valid archive from inconsistent inventory")
			}
		})
	}
}

func FuzzManifestDecode(f *testing.F) {
	valid, _, err := Encode(fixture())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"backup_id":91,"backup_id":91}`))
	f.Add(append(bytes.Clone(valid), ' '))
	f.Add([]byte(`{"backup_id":91,"reports":[` + strings.Repeat(`{},`, MaxEntries) + `{}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 256<<10 {
			t.Skip("bounded parser fuzz input")
		}
		got, err := Decode(data, 91, digest(data))
		if bytes.Equal(data, valid) && err != nil {
			t.Fatal("valid seed rejected", err)
		}
		if err != nil {
			if err != ErrInvalid && err != ErrLimit && err != ErrMismatch { //nolint:errorlint // Exact closed sentinel: no wrapped input or parser details.
				t.Fatal("unclassified error")
			}
			return
		}
		encoded, sum, err := Encode(got)
		if err != nil || !bytes.Equal(encoded, data) || sum != digest(data) {
			t.Fatal("successful decode is not canonical", err)
		}
		if _, err := Entries(got); err != nil {
			t.Fatal("accepted manifest cannot form a bounded archive", err)
		}
	})
}
