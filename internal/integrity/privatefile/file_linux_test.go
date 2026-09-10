//go:build linux

package privatefile

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// #nosec G302 -- owner-only directory traversal, never group/other access.
func protectTestDirectory(path string) error { return os.Chmod(path, 0o700) }

func newTestDirectory(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	var fs unix.Statfs_t
	if unix.Statfs(path, &fs) != nil {
		t.Fatal("could not inspect test filesystem")
	}
	if supportedFilesystem(fs.Type) {
		return path
	}
	// Docker build layers are often overlay. Do not relax the production
	// policy or skip tests: use a verified local tmpfs for the exact same cases.
	// Tests are intentionally not parallel; the largest file is ~32 MiB and
	// is removed by this test's Cleanup before the next case on a 64 MiB shm.
	if unix.Statfs("/dev/shm", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		t.Fatal("no supported local filesystem for mandatory private-file tests")
	}
	path, err := os.MkdirTemp("/dev/shm", "mii-privatefile-test-")
	if err != nil {
		t.Fatal("could not create private local test directory")
	}
	t.Cleanup(func() {
		// Remove only this exact random directory created above, never /dev/shm.
		if err := os.RemoveAll(path); err != nil {
			t.Error("private test directory cleanup failed")
		}
	})
	return path
}

func TestLinuxFilesystemPolicy(t *testing.T) {
	for _, kind := range []int64{unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.RAMFS_MAGIC, unix.F2FS_SUPER_MAGIC} {
		if !supportedFilesystem(kind) {
			t.Fatal("local filesystem rejected")
		}
	}
	for _, kind := range []int64{0, unix.NFS_SUPER_MAGIC, unix.CIFS_SUPER_MAGIC, unix.FUSE_SUPER_MAGIC, unix.PROC_SUPER_MAGIC, unix.SYSFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC} {
		if supportedFilesystem(kind) {
			t.Fatal("unproven local filesystem accepted")
		}
	}
}

func TestLinuxFIFOAndPermissionRejection(t *testing.T) {
	dir := privateDir(t)
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTestFile(t.Context(), fifo, 100); !errors.Is(err, ErrUnsafe) {
		t.Fatal("FIFO not rejected", err)
	}
	path := filepath.Join(dir, "source")
	if err := writeTestFile(t.Context(), path, []byte("source"), 100); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- deliberately unsafe regression fixture.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readTestFile(t.Context(), path, 100); !errors.Is(err, ErrPermissions) {
		t.Fatal("wide file mode accepted", err)
	}
	// #nosec G302 -- deliberately unsafe regression fixture.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeTestFile(t.Context(), filepath.Join(dir, "rejected"), []byte("new"), 100); !errors.Is(err, ErrPermissions) {
		t.Fatal("wide directory accepted", err)
	}
	assertEntries(t, dir, 2)
}

func TestLinuxSymlinkFileAndParentRejected(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "source")
	if err := writeTestFile(t.Context(), path, []byte("source"), 100); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readTestFile(t.Context(), link, 100); err == nil {
		t.Fatal("symlink source accepted")
	}
	if err := writeTestFile(t.Context(), link, []byte("new"), 100); !errors.Is(err, ErrExists) {
		t.Fatal("symlink destination replaced", err)
	}
	parent := filepath.Join(dir, "parent")
	if err := os.Symlink(dir, parent); err != nil {
		t.Fatal(err)
	}
	if _, err := readTestFile(t.Context(), filepath.Join(parent, "source"), 100); !errors.Is(err, ErrUnsafe) {
		t.Fatal("symlink parent read accepted", err)
	}
	if err := writeTestFile(t.Context(), filepath.Join(parent, "output"), []byte("new"), 100); !errors.Is(err, ErrUnsafe) {
		t.Fatal("symlink parent write accepted", err)
	}
	assertEntries(t, dir, 3)
}

func TestLinuxParentReplacementKeepsWritesConfined(t *testing.T) {
	for _, phase := range []string{"before", "after"} {
		t.Run(phase, func(t *testing.T) {
			root := privateDir(t)
			dir, moved := filepath.Join(root, "source"), filepath.Join(root, "moved")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			replace := func() {
				if err := os.Rename(dir, moved); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			hooks := &writeHooks{beforePublish: replace}
			if phase == "after" {
				hooks = &writeHooks{afterPublish: func(*os.File, *os.File) { replace() }}
			}
			result, err := writeNew(t.Context(), filepath.Join(dir, "result"), testLimits(100), testProduce([]byte("complete")), hooks)
			if !errors.Is(err, ErrUnsafe) || result.Published != (phase == "after") {
				t.Fatal("replacement did not fail closed", result, err)
			}
			assertEntries(t, dir, 0)
			count := 0
			if phase == "after" {
				count = 1
			}
			assertEntries(t, moved, count)
		})
	}
}

func TestLinuxReadDetectsMutationAndParentReplacement(t *testing.T) {
	for _, kind := range []string{"grow", "truncate", "parent"} {
		t.Run(kind, func(t *testing.T) {
			root := privateDir(t)
			dir := filepath.Join(root, "original")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "source")
			if err := writeTestFile(t.Context(), path, []byte("original"), 100); err != nil {
				t.Fatal(err)
			}
			_, err := Read(t.Context(), path, testLimits(100), func(_ context.Context, r io.Reader) error {
				if _, err := io.Copy(io.Discard, r); err != nil {
					return err
				}
				if kind == "parent" {
					if err := os.Rename(dir, filepath.Join(root, "moved")); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				} else {
					size := int64(2)
					if kind == "grow" {
						size = 20
					}
					if err := os.Truncate(path, size); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			})
			if !errors.Is(err, ErrUnsafe) {
				t.Fatal("mutation accepted", err)
			}
		})
	}
}

func TestLinuxDirectorySyncFailureKeepsPublishedOutput(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "complete")
	hooks := &writeHooks{afterPublish: func(parent, _ *os.File) {
		if err := parent.Close(); err != nil {
			t.Fatal(err)
		}
	}}
	result, err := writeNew(t.Context(), path, testLimits(100), testProduce([]byte("complete")), hooks)
	if !result.Published || !errors.Is(err, ErrUnavailable) {
		t.Fatal("directory sync failure receipt", result, err)
	}
	if data, err := readTestFile(t.Context(), path, 100); err != nil || string(data) != "complete" {
		t.Fatal("published file was removed", err)
	}
}

func TestLinuxReplacedStagingEntryIsNeverDeleted(t *testing.T) {
	dir := privateDir(t)
	var replaced string
	hooks := &writeHooks{beforePublish: func() {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 1 {
			t.Fatal("missing unique staging fixture")
		}
		replaced = filepath.Join(dir, entries[0].Name())
		if err := os.Rename(replaced, filepath.Join(dir, "original-moved")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(replaced, []byte("do not delete replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
	}}
	result, err := writeNew(t.Context(), filepath.Join(dir, "final"), testLimits(100), testProduce([]byte("original")), hooks)
	if !errors.Is(err, ErrUnsafe) || result.Published {
		t.Fatal("replacement published", result, err)
	}
	if content, err := readTestFile(t.Context(), replaced, 100); err != nil || string(content) != "do not delete replacement" {
		t.Fatal("cleanup removed another entry", err)
	}
	assertEntries(t, dir, 2)
}
