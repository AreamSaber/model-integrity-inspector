package backupmanifest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"testing"
	"time"
)

func scopedStreamFixture(t *testing.T) (Manifest, []Entry, map[string][]byte) {
	t.Helper()
	m := scopedFixture()
	payloads := make(map[string][]byte)
	set := func(f *File) {
		payload := []byte("actual-retained-scoped-bytes-" + f.EntryID)
		f.Bytes, f.SHA256 = int64(len(payload)), digest(payload)
		payloads[f.EntryID] = payload
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
	verified, err := Decode(data, m.BackupID, sum)
	if err != nil {
		t.Fatal(err)
	}
	payloads["backup-manifest"] = data
	entries, err := Entries(verified)
	if err != nil {
		t.Fatal(err)
	}
	return verified, entries, payloads
}

func TestManifestV2StreamBindsExactTenantPayloadSetAndClosesCapability(t *testing.T) {
	for _, mode := range []string{"valid", "reverse", "swapped_tenant_bytes", "missing_tenant", "duplicate_tenant", "changed_identity_manifest", "unknown", "short", "long", "callback_failure", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			m, entries, payloads := scopedStreamFixture(t)
			if mode == "reverse" {
				slices.Reverse(entries)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var retained func(string, string, io.Reader) error
			forbidden := inventoryReaderFunc(func([]byte) (int, error) {
				t.Error("unknown/failed/closed inventory accessed a new reader")
				return 0, io.EOF
			})
			err := VerifyStream(ctx, m, time.Second, func(_ context.Context, accept func(string, string, io.Reader) error) error {
				retained = accept
				// The verifier owns a file plan. Later changes to the caller's
				// identities cannot redirect already committed inventory bytes.
				m.Artifacts[0].OrganizationID, m.Artifacts[0].ID = 999, 888
				failed := false
				for _, e := range entries {
					if mode == "missing_tenant" && e.File.EntryID == "rule-org9" {
						continue
					}
					payload := payloads[e.File.EntryID]
					if e.File.EntryID == "rule-v1" {
						switch mode {
						case "swapped_tenant_bytes":
							payload = payloads["rule-org9"]
						case "short":
							payload = payload[:len(payload)-1]
						case "long":
							payload = append(bytes.Clone(payload), 'x')
						}
					}
					if mode == "changed_identity_manifest" && e.Kind == "manifest" {
						payload = bytes.Replace(payload, []byte(`"organization_id":5,"id":101`), []byte(`"organization_id":9,"id":101`), 1)
					}
					var in io.Reader = bytes.NewReader(payload)
					if failed {
						in = forbidden
					}
					if err := accept(e.Kind, e.File.EntryID, in); err != nil {
						failed = true // Deliberately swallow; failure must be sticky.
					}
					if mode == "duplicate_tenant" && e.File.EntryID == "rule-org9" {
						if err := accept(e.Kind, e.File.EntryID, forbidden); err != nil {
							failed = true
						}
					}
				}
				switch mode {
				case "unknown":
					_ = accept("rule", "invented-tenant-file", forbidden)
				case "callback_failure":
					return errors.New("untrusted scoped archive diagnostic")
				case "cancel":
					cancel()
				}
				return nil
			})
			want := ErrMismatch
			switch mode {
			case "valid", "reverse":
				want = nil
			case "callback_failure":
				want = ErrCallback
			case "cancel":
				want = ErrCanceled
			}
			if !errors.Is(err, want) {
				t.Fatal("wrong v2 exact-set outcome", err)
			}
			if retained == nil || !errors.Is(retained("rule", "rule-v1", forbidden), ErrClosed) {
				t.Fatal("v2 borrowed inventory capability survived completion")
			}
		})
	}
}
