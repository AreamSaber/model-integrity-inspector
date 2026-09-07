package reportstorage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "reports")
	store, err := Open(path)
	if err != nil {
		t.Fatal("restricted store open", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path
}
func TestStoreWriteReadRetryAndImmutableName(t *testing.T) {
	store, path := openTestStore(t)
	body := []byte(`{"content":"S1 synthetic"}`)
	ref, err := store.Put(t.Context(), 17, "json", body)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Hash != hashBytes(body) || ref.Name() != "org-17-"+hashBytes(body)+".json" {
		t.Fatal("wrong content address")
	}
	read, err := store.Read(t.Context(), ref)
	if err != nil || !bytes.Equal(read, body) {
		t.Fatal("read/hash check failed", err)
	}
	retry, err := store.Put(t.Context(), 17, "json", body)
	if err != nil || retry != ref {
		t.Fatal("idempotent retry failed", err)
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary files remain", err)
	}
	other, err := store.Put(t.Context(), 18, "json", body)
	if err != nil || other.Name() == ref.Name() {
		t.Fatal("cross-org name collision", err)
	}
	if _, err := store.Read(t.Context(), Reference{17, ref.Hash, "json", ref.Size + 1}); !errors.Is(err, ErrIntegrity) {
		t.Fatal("length mismatch accepted", err)
	}
	if err := os.WriteFile(filepath.Join(path, ref.Name()), bytes.Repeat([]byte("x"), len(body)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(t.Context(), ref); !errors.Is(err, ErrIntegrity) {
		t.Fatal("corruption accepted", err)
	}
	if _, err := store.Put(t.Context(), 17, "json", body); !errors.Is(err, ErrIntegrity) {
		t.Fatal("corruption silently overwritten", err)
	}
}
func TestStoreRejectLinksPathsAndCancellation(t *testing.T) {
	store, path := openTestStore(t)
	body := []byte("safe S1")
	ref, err := store.Put(t.Context(), 1, "html", body)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Link(filepath.Join(path, ref.Name()), alias); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(t.Context(), ref); !errors.Is(err, ErrUnsafe) {
		t.Fatal("hard-linked artifact accepted", err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	for _, v := range []Reference{{1, "../outside", "json", 3}, {1, strings.Repeat("a", 64), "../json", 3}, {0, ref.Hash, "html", ref.Size}, {1, ref.Hash, "html", MaxBytes + 1}} {
		if _, err := store.Read(t.Context(), v); !errors.Is(err, ErrUnsafe) {
			t.Fatal("unsafe reference", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.Read(ctx, ref); err == nil {
		t.Fatal("cancelled read continued")
	}
	if _, err := store.Put(ctx, 1, "json", body); err == nil {
		t.Fatal("cancelled write continued")
	}
	if _, err := store.Put(t.Context(), 1, "html", make([]byte, MaxBytes+1)); !errors.Is(err, ErrUnsafe) {
		t.Fatal("oversize write", err)
	}
	if _, err := Open("relative"); !errors.Is(err, ErrUnsafe) {
		t.Fatal("relative root")
	}
	if _, err := Open(filepath.VolumeName(path) + string(filepath.Separator)); !errors.Is(err, ErrUnsafe) {
		t.Fatal("volume root")
	}
}
func TestStoreRejectSymlinkDirectoryAndArtifact(t *testing.T) {
	store, path := openTestStore(t)
	body := []byte("S1")
	ref, err := store.Put(t.Context(), 3, "json", body)
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "linked-directory")
	if err := os.Symlink(path, link); err != nil {
		t.Skip("symlink creation unavailable")
	}
	if opened, err := Open(link); err == nil {
		_ = opened.Close()
		t.Fatal("symlink root accepted")
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(path, ref.Name())); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(path, ref.Name())); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(t.Context(), ref); !errors.Is(err, ErrUnsafe) {
		t.Fatal("artifact symlink accepted", err)
	}
}
