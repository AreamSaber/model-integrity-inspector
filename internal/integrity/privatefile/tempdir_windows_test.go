//go:build windows

package privatefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// This helper accepts only a directory just created by t.TempDir. It does not
// normalize an application input, and production still rejects short aliases.
func canonicalTestDirectory(t *testing.T, path string) string {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("privatefile fixture stage=directory_name")
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal("privatefile fixture stage=directory_handle")
	}
	f := os.NewFile(uintptr(handle), "privatefile-test-directory")
	if f == nil {
		_ = windows.CloseHandle(handle)
		t.Fatal("privatefile fixture stage=directory_file")
	}
	defer func() { _ = f.Close() }()
	var before windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &before); err != nil ||
		before.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		before.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		t.Fatal("privatefile fixture stage=directory_identity")
	}
	canonical, err := canonicalName(f)
	if err != nil || validatePath(canonical) != nil {
		t.Fatal("privatefile fixture stage=canonical_name")
	}
	canonicalPointer, err := windows.UTF16PtrFromString(canonical)
	if err != nil {
		t.Fatal("privatefile fixture stage=canonical_encoding")
	}
	verified, err := windows.CreateFile(canonicalPointer, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal("privatefile fixture stage=canonical_handle")
	}
	defer func() { _ = windows.CloseHandle(verified) }()
	var after windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(verified, &after); err != nil ||
		after.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		after.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		before.VolumeSerialNumber != after.VolumeSerialNumber ||
		before.FileIndexHigh != after.FileIndexHigh || before.FileIndexLow != after.FileIndexLow {
		t.Fatal("privatefile fixture stage=canonical_identity")
	}
	return canonical
}

func TestWindowsTempDirectoryShortBaseUsesCanonicalFixture(t *testing.T) {
	base := canonicalTestDirectory(t, t.TempDir())
	name, err := windows.UTF16PtrFromString(base)
	if err != nil {
		t.Fatal("privatefile fixture stage=short_base_encoding")
	}
	var buffer [4096]uint16
	n, err := windows.GetShortPathName(name, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || n >= uint32(len(buffer)) {
		t.Fatal("privatefile fixture stage=short_base_query")
	}
	short := windows.UTF16ToString(buffer[:n])
	allocated := !strings.EqualFold(short, base)
	t.Logf("privatefile fixture short_alias_allocated=%t", allocated)
	t.Setenv("TMP", short)
	t.Setenv("TEMP", short)
	// A caller's GOTMPDIR must not bypass this specific TMP/TEMP regression.
	t.Setenv("GOTMPDIR", "")
	t.Run("first_temp_directory", func(t *testing.T) {
		dir := privateDir(t) // This child's first TempDir, after TMP/TEMP changed.
		canonical := canonicalTestDirectory(t, dir)
		if !strings.EqualFold(dir, canonical) {
			t.Error("privatefile fixture stage=canonical_match matched=false")
		}
		path := filepath.Join(dir, "private.backup")
		if err := writeTestFile(t.Context(), path, []byte("synthetic private fixture"), 100); err != nil {
			t.Fatal("privatefile fixture stage=write_new unsafe=", errors.Is(err, ErrUnsafe))
		}
		data, err := readTestFile(t.Context(), path, 100)
		if err != nil || string(data) != "synthetic private fixture" {
			t.Fatal("privatefile fixture stage=read_back")
		}
		if allocated {
			relative, err := filepath.Rel(base, canonical)
			if err != nil || relative == "." || strings.HasPrefix(relative, "..") {
				t.Fatal("privatefile fixture stage=short_child_scope")
			}
			alias := filepath.Join(short, relative, "private.backup")
			if _, err := readTestFile(t.Context(), alias, 100); !errors.Is(err, ErrUnsafe) {
				t.Fatal("privatefile fixture stage=short_read_rejection")
			}
			if err := writeTestFile(t.Context(), filepath.Join(short, relative, "must-not-publish.backup"), []byte("synthetic"), 100); !errors.Is(err, ErrUnsafe) {
				t.Fatal("privatefile fixture stage=short_write_rejection")
			}
		}
		assertEntries(t, dir, 1)
	})
}
