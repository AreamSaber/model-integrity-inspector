//go:build windows || linux

package localfile

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func privateDir(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	if err := protectTestDirectory(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAtomicWriteReadAndNoReplace(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "prediction.json")
	data := []byte(`{"complete":true}`)
	if err := WriteNew(t.Context(), path, data, 100); err != nil {
		t.Fatal(err)
	}
	got, err := Read(t.Context(), path, 100)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read: %v", err)
	}
	if err := WriteNew(t.Context(), path, []byte("different"), 100); !errors.Is(err, ErrExists) {
		t.Fatalf("replace: %v", err)
	}
	got, err = Read(t.Context(), path, 100)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("existing changed: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary leaked: %v/%d", err, len(entries))
	}
}

func TestAtomicCancelBeforePublicationLeavesNoFinal(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "canceled.json")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	err := writeNew(ctx, path, bytes.Repeat([]byte("sensitive-synthetic"), 65536), MaxFileBytes, cancel)
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("cancel: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed publication left files: %v/%d", err, len(entries))
	}
	if _, err := Read(ctx, path, 100); !errors.Is(err, ErrCanceled) {
		t.Fatalf("canceled read: %v", err)
	}
}

func TestAtomicConcurrentNoReplace(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "one.json")
	const count = 8
	var wg sync.WaitGroup
	results := make(chan error, count)
	for range count {
		wg.Go(func() { results <- WriteNew(t.Context(), path, []byte("complete"), 100) })
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
			continue
		}
		if !errors.Is(err, ErrExists) {
			t.Fatalf("race: %v", err)
		}
	}
	if success != 1 {
		t.Fatalf("success count: %d", success)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("race temporary leaked: %v/%d", err, len(entries))
	}
}

func TestFileInputBoundaries(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "input.json")
	if err := WriteNew(t.Context(), path, []byte("12345"), 100); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{-1, 0, 4, MaxFileBytes + 1} {
		if _, err := Read(t.Context(), path, limit); !errors.Is(err, ErrLimit) {
			t.Errorf("limit %d: %v", limit, err)
		}
	}
	for _, invalid := range []string{"", "relative.json", "https://example.invalid/data", path + "\x00", dir, filepath.Join(dir, "missing"), filepath.Join(dir, "..", "outside") + string(filepath.Separator) + ".."} {
		if _, err := Read(t.Context(), invalid, 100); err == nil || strings.Contains(err.Error(), dir) {
			t.Errorf("unsafe input accepted or leaked")
		}
	}
	if err := WriteNew(t.Context(), filepath.Join(dir, "empty"), nil, 100); !errors.Is(err, ErrLimit) {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "hardlink")
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(t.Context(), path, 100); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("hardlink: %v", err)
	}
	if err := WriteNew(t.Context(), link, []byte("do not replace"), 100); !errors.Is(err, ErrExists) {
		t.Fatalf("hardlink output: %v", err)
	}
}

func TestSymlinkInputAndParentRejected(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "plain")
	if err := WriteNew(t.Context(), path, []byte("safe"), 100); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "symlink")
	if err := os.Symlink(path, link); err != nil {
		t.Skip("OS does not permit unprivileged symlink creation")
	}
	if _, err := Read(t.Context(), link, 100); err == nil {
		t.Fatal("file symlink accepted")
	}
	if err := WriteNew(t.Context(), link, []byte("overwrite"), 100); err == nil {
		t.Fatal("file symlink replaced")
	}
	parent := filepath.Join(dir, "parent")
	if err := os.Symlink(dir, parent); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(t.Context(), filepath.Join(parent, "plain"), 100); err == nil {
		t.Fatal("parent symlink accepted")
	}
	if err := WriteNew(t.Context(), filepath.Join(parent, "new"), []byte("a"), 100); err == nil {
		t.Fatal("output parent symlink accepted")
	}
}
