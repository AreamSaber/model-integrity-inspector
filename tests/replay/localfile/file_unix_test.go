//go:build linux

package localfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// #nosec G302 -- directory traversal requires owner execute; no group/other access.
func protectTestDirectory(path string) error { return os.Chmod(path, 0o700) }

func TestLinuxFilesystemPolicy(t *testing.T) {
	for _, kind := range []int64{unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC, unix.RAMFS_MAGIC, unix.F2FS_SUPER_MAGIC} {
		if !supportedFilesystem(kind) {
			t.Fatal("supported local filesystem rejected")
		}
	}
	for _, kind := range []int64{0, unix.NFS_SUPER_MAGIC, unix.CIFS_SUPER_MAGIC, unix.FUSE_SUPER_MAGIC, unix.PROC_SUPER_MAGIC, unix.SYSFS_MAGIC} {
		if supportedFilesystem(kind) {
			t.Fatal("unknown/remote/pseudo filesystem accepted")
		}
	}
}

func TestUnixFIFOAndPermissions(t *testing.T) {
	dir := privateDir(t)
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(t.Context(), fifo, 100); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("fifo: %v", err)
	}
	path := filepath.Join(dir, "unsafe")
	if err := WriteNew(t.Context(), path, []byte("data"), 100); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- deliberately unsafe permissions in a rejection regression.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(t.Context(), path, 100); !errors.Is(err, ErrPermissions) {
		t.Fatalf("permissions: %v", err)
	}
	// #nosec G302 -- deliberately unsafe parent in a rejection regression.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(t.Context(), filepath.Join(dir, "rejected"), []byte("data"), 100); !errors.Is(err, ErrPermissions) {
		t.Fatalf("directory permissions: %v", err)
	}
}
