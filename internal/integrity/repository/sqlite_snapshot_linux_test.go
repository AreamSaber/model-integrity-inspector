//go:build linux

package repository

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"model-integrity-inspector.local/mii/internal/integrity/privatefile"
)

func snapshotPrivateTestDir(t *testing.T) string {
	t.Helper()
	base := os.TempDir()
	var fs unix.Statfs_t
	if unix.Statfs(base, &fs) != nil {
		t.Fatal("snapshot fixture filesystem unavailable")
	}
	switch fs.Type {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC,
		unix.TMPFS_MAGIC, unix.RAMFS_MAGIC, unix.F2FS_SUPER_MAGIC:
	default:
		// Docker overlay is not silently admitted. Two live ~25 MiB databases
		// fit in a verified default 64 MiB tmpfs; these tests are not parallel.
		base = "/dev/shm"
		if unix.Statfs(base, &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
			t.Fatal("snapshot fixture has no supported local filesystem")
		}
	}
	path, err := os.MkdirTemp(base, "mii-snapshot-test-")
	if err != nil {
		t.Fatal("snapshot fixture private creation failed")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode().Perm() != 0o700 {
		t.Fatal("snapshot fixture private identity failed")
	}
	t.Cleanup(func() {
		after, err := os.Lstat(path)
		if err != nil || !os.SameFile(before, after) || !filepath.IsAbs(path) ||
			filepath.Dir(path) != filepath.Clean(base) || !strings.HasPrefix(filepath.Base(path), "mii-snapshot-test-") {
			t.Error("snapshot fixture cleanup identity failed")
			return
		}
		// Only this exact random test-owned directory is recursively reclaimed.
		if err := os.RemoveAll(path); err != nil {
			t.Error("snapshot fixture cleanup failed")
		}
	})
	built := false
	receipt, err := privatefile.WithSQLiteStaging(t.Context(), path,
		privatefile.SQLiteLimits{MaxDatabaseBytes: 1, MaxWorkspaceBytes: 2, Timeout: 5 * time.Second},
		func(context.Context, *privatefile.SQLiteTarget) error {
			built = true
			return errors.New("fixture admission abort")
		},
		func(context.Context, io.Reader) error { t.Error("fixture admission consumed bytes"); return nil })
	if !built || !errors.Is(err, privatefile.ErrCallback) || receipt != (privatefile.Receipt{}) {
		t.Fatal("snapshot fixture production admission failed")
	}
	return path
}
