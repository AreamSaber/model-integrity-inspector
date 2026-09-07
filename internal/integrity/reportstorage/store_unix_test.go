//go:build !windows

package reportstorage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreActualUnixPermissionRevalidation(t *testing.T) {
	store, path := openTestStore(t)
	ref, err := store.Put(t.Context(), 4, "json", []byte("S1"))
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- deliberately broaden this isolated test artifact to verify rejection.
	if err := os.Chmod(filepath.Join(path, ref.Name()), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(t.Context(), ref); !errors.Is(err, ErrUnsafe) {
		t.Fatal("overpermissive artifact accepted", err)
	}
	// #nosec G302 -- deliberately executable isolated fixture must also fail closed.
	if err := os.Chmod(filepath.Join(path, ref.Name()), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(t.Context(), ref); !errors.Is(err, ErrUnsafe) {
		t.Fatal("executable artifact accepted", err)
	}
	// #nosec G302 -- deliberately broaden only the newly created test directory.
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(t.Context(), 4, "json", []byte("new")); !errors.Is(err, ErrUnsafe) {
		t.Fatal("overpermissive root accepted", err)
	}
}
