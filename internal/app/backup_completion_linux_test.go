//go:build linux

package app

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func backupCompletionPrivateDirectory(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	var fs unix.Statfs_t
	if err := unix.Statfs(path, &fs); err != nil {
		t.Fatal("private fixture filesystem")
	}
	supported := false
	for _, kind := range []int64{unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.RAMFS_MAGIC, unix.F2FS_SUPER_MAGIC} {
		if fs.Type == kind {
			supported = true
		}
	}
	if !supported {
		if err := unix.Statfs("/dev/shm", &fs); err != nil || fs.Type != unix.TMPFS_MAGIC {
			t.Fatal("private fixture needs proven local filesystem")
		}
		var err error
		path, err = os.MkdirTemp("/dev/shm", "mii-backup-completion-test-")
		if err != nil {
			t.Fatal("private tmpfs fixture")
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(path); err != nil {
				t.Error("exact owned tmpfs fixture cleanup")
			}
		})
	}
	// #nosec G302 -- exact newly created owner-only fixture, never group/other access.
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal("private fixture mode")
	}
	return path
}
