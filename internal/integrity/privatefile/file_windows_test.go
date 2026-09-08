//go:build windows

package privatefile

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func newTestDirectory(t *testing.T) string { return t.TempDir() }

func protectTestDirectory(path string) error {
	sid, err := currentSID()
	if err != nil {
		return err
	}
	return setTestDACL(path, "D:P(A;OICI;FA;;;"+sid.String()+")(A;OICI;FA;;;SY)")
}

func setTestDACL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func TestWindowsAliasesAndPermissions(t *testing.T) {
	dir := privateDir(t)
	for _, path := range []string{`\\server\share\file`, `\\?\C:\file`, `\\.\pipe\test`, `C:\file:stream`, `C:\NUL`, `C:\CON.txt`, `C:\COM1`, `C:\COM¹`, `C:\LPT².txt`, `C:\file.`, `C:\file `, `C:/path/file`} {
		if _, err := readTestFile(t.Context(), path, 100); !errors.Is(err, ErrUnsafe) {
			t.Errorf("alias error: %v", err)
		}
	}
	path := filepath.Join(dir, "unsafe")
	if err := writeTestFile(t.Context(), path, []byte("data"), 100); err != nil {
		t.Fatal(err)
	}
	sid, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	if err := setTestDACL(path, "D:P(A;;FA;;;"+sid.String()+")(A;;FR;;;WD)"); err != nil {
		t.Fatal(err)
	}
	if _, err := readTestFile(t.Context(), path, 100); !errors.Is(err, ErrPermissions) {
		t.Fatalf("unsafe ACL: %v", err)
	}
	if err := setTestDACL(dir, "D:P(A;OICI;FA;;;"+sid.String()+")(A;OICI;FR;;;WD)"); err != nil {
		t.Fatal(err)
	}
	if err := writeTestFile(t.Context(), filepath.Join(dir, "rejected"), []byte("data"), 100); !errors.Is(err, ErrPermissions) {
		t.Fatalf("unsafe directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "rejected")); !os.IsNotExist(err) {
		t.Fatal("unsafe directory was mutated")
	}
}

func TestWindowsParentDeleteChildOnlyPermissionRejected(t *testing.T) {
	dir := privateDir(t)
	path, output := filepath.Join(dir, "existing.backup"), filepath.Join(dir, "must-not-publish.backup")
	if err := writeTestFile(t.Context(), path, []byte("existing-private-backup"), 100); err != nil {
		t.Fatal(err)
	}
	sid, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	// FILE_DELETE_CHILD alone grants namespace control over children despite
	// their private file DACL. No broad read/write/DELETE bit masks this case.
	if err := setTestDACL(dir, "D:P(A;;FA;;;"+sid.String()+")(A;;FA;;;SY)(A;;0x40;;;WD)"); err != nil {
		t.Fatal(err)
	}
	result, writeErr := WriteNew(t.Context(), output, testLimits(100), testProduce([]byte("must not publish")))
	if !errors.Is(writeErr, ErrPermissions) || result.Published {
		t.Error("parent allowing outsider delete-child accepted for publication", result, writeErr)
	}
	_, readErr := Read(t.Context(), path, testLimits(100), func(_ context.Context, r io.Reader) error {
		t.Error("parent allowing outsider delete-child reached private reader")
		_, err := io.Copy(io.Discard, r)
		return err
	})
	if !errors.Is(readErr, ErrPermissions) {
		t.Error("parent allowing outsider delete-child accepted for reading", readErr)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Error("unsafe parent write created an output")
	}
	if err := protectTestDirectory(dir); err != nil {
		t.Fatal(err)
	}
	content, err := readTestFile(t.Context(), path, 100)
	if err != nil || string(content) != "existing-private-backup" {
		t.Fatal("rejection changed the existing private input", err)
	}
	assertEntries(t, dir, 1)
}

func TestWindowsReadAndWriteHoldNonreplaceableHandles(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "locked")
	if _, err := WriteNew(t.Context(), path, testLimits(100), func(_ context.Context, w io.Writer) error {
		if err := os.Rename(dir, dir+"-moved"); err == nil {
			t.Fatal("pinned Windows directory was moved")
		}
		_, err := w.Write([]byte("complete"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(t.Context(), path, testLimits(100), func(_ context.Context, r io.Reader) error {
		if err := os.Rename(path, path+"-moved"); err == nil {
			t.Fatal("pinned Windows input was renamed")
		}
		if err := os.Truncate(path, 1); err == nil {
			t.Fatal("pinned Windows input allowed concurrent write")
		}
		_, err := io.Copy(io.Discard, r)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	assertEntries(t, dir, 1)
}

func TestWindowsShortNameAliasesRejectedWhenAllocated(t *testing.T) {
	dir := privateDir(t)
	path := filepath.Join(dir, "long private backup input filename.data")
	if err := writeTestFile(t.Context(), path, []byte("complete"), 100); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	var buffer [4096]uint16
	n, err := windows.GetShortPathName(name, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || n >= uint32(len(buffer)) {
		t.Fatal("short-name query failed")
	}
	short := windows.UTF16ToString(buffer[:n])
	if strings.EqualFold(short, path) {
		t.Log("NTFS did not allocate an 8.3 alias; device/ADS/UNC/junction rejection remains separately mandatory")
		return
	}
	if _, err := readTestFile(t.Context(), short, 100); !errors.Is(err, ErrUnsafe) {
		t.Fatal("short-name alias accepted", err)
	}
}

func TestWindowsDirectoryPermissionsRecheckedBeforePublication(t *testing.T) {
	dir := privateDir(t)
	sid, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	hooks := &writeHooks{beforePublish: func() {
		if err := setTestDACL(dir, "D:P(A;OICI;FA;;;"+sid.String()+")(A;OICI;FR;;;WD)"); err != nil {
			t.Fatal(err)
		}
	}}
	result, err := writeNew(t.Context(), filepath.Join(dir, "rejected"), testLimits(100), testProduce([]byte("private")), hooks)
	if !errors.Is(err, ErrPermissions) || result.Published {
		t.Fatal("broadened parent permissions accepted", result, err)
	}
	assertEntries(t, dir, 0)
}

// Junctions are available without the optional symbolic-link privilege. Exercise
// the actual native reparse boundary even when the portable symlink test skips.
func TestWindowsJunctionInputAndOutputRejected(t *testing.T) {
	dir := privateDir(t)
	target, junction := filepath.Join(dir, "target"), filepath.Join(dir, "junction")
	for _, path := range []string{target, junction} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal("could not create private junction fixture")
		}
	}
	if err := writeTestFile(t.Context(), filepath.Join(target, "source.json"), []byte("synthetic"), 100); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(junction)
	if err != nil {
		t.Fatal("invalid fixture path")
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal("could not open junction fixture")
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	substitute := append(utf16.Encode([]rune(`\??\`+target)), 0)
	printName := append(utf16.Encode([]rune(target)), 0)
	paths := append(substitute, printName...)
	if len(paths) > 10000 {
		t.Fatal("fixture path exceeds bounded reparse buffer")
	}
	buffer := make([]byte, 16+len(paths)*2)
	set16 := func(offset, value int) {
		if value < 0 || value > math.MaxUint16 {
			t.Fatal("fixture overflow")
		}
		// #nosec G115 -- value was explicitly checked against uint16 bounds.
		binary.LittleEndian.PutUint16(buffer[offset:], uint16(value))
	}
	binary.LittleEndian.PutUint32(buffer, windows.IO_REPARSE_TAG_MOUNT_POINT)
	set16(4, len(buffer)-8)
	set16(10, (len(substitute)-1)*2)
	set16(12, len(substitute)*2)
	set16(14, (len(printName)-1)*2)
	for i, unit := range paths {
		binary.LittleEndian.PutUint16(buffer[16+i*2:], unit)
	}
	var returned uint32
	// #nosec G115 -- buffer contains at most 10000 UTF-16 units plus 16 bytes.
	if err := windows.DeviceIoControl(handle, windows.FSCTL_SET_REPARSE_POINT, &buffer[0], uint32(len(buffer)), nil, 0, &returned, nil); err != nil {
		t.Fatal("could not install test-only junction")
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatal("could not close junction setup handle")
	}
	handle = windows.InvalidHandle
	if _, err := readTestFile(t.Context(), filepath.Join(junction, "source.json"), 100); !errors.Is(err, ErrUnsafe) {
		t.Fatal("junction input not rejected", err)
	}
	if err := writeTestFile(t.Context(), filepath.Join(junction, "output.json"), []byte("new"), 100); !errors.Is(err, ErrUnsafe) {
		t.Fatal("junction output not rejected", err)
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 1 || entries[0].Name() != "source.json" {
		t.Fatal("rejected junction write changed target directory")
	}
}
