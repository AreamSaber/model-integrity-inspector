//go:build windows

package reportstorage

import (
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func grantWorldRead(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestStoreRejectWindowsJunctionInPath(t *testing.T) {
	dir := t.TempDir()
	target, junction := filepath.Join(dir, "target"), filepath.Join(dir, "junction")
	for _, path := range []string{target, junction} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	name, err := windows.UTF16PtrFromString(junction)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	substitute := append(utf16.Encode([]rune(`\??\`+target)), 0)
	printName := append(utf16.Encode([]rune(target)), 0)
	paths := append(substitute, printName...)
	if len(paths) > 10000 {
		t.Fatal("fixture path too long")
	}
	buffer := make([]byte, 16+len(paths)*2)
	set16 := func(offset, value int) {
		if value < 0 || value > math.MaxUint16 {
			t.Fatal("fixture overflow")
		}
		// #nosec G115 -- the fixture rejects negative values and values above MaxUint16 immediately above.
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
	if uint64(len(buffer)) > math.MaxUint32 {
		t.Fatal("fixture overflow")
	}
	var returned uint32
	// #nosec G115 -- buffer length is checked against MaxUint32 immediately above and is built from at most 10000 UTF-16 units.
	err = windows.DeviceIoControl(handle, windows.FSCTL_SET_REPARSE_POINT, &buffer[0], uint32(len(buffer)), nil, 0, &returned, nil)
	_ = windows.CloseHandle(handle)
	if err != nil {
		t.Fatal("junction fixture", err)
	}
	for _, path := range []string{junction, filepath.Join(junction, "reports")} {
		opened, err := Open(path)
		if opened != nil {
			_ = opened.Close()
		}
		if !errors.Is(err, ErrUnsafe) {
			t.Fatal("junction accepted", err)
		}
	}
	if _, err := os.Stat(filepath.Join(target, "reports")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("followed junction")
	}
}
func TestStoreActualWindowsACLRevalidation(t *testing.T) {
	store, path := openTestStore(t)
	ref, err := store.Put(t.Context(), 4, "json", []byte("S1"))
	if err != nil {
		t.Fatal(err)
	}
	grantWorldRead(t, filepath.Join(path, ref.Name()))
	if _, err := store.Read(t.Context(), ref); !errors.Is(err, ErrUnsafe) {
		t.Fatal("overpermissive artifact accepted", err)
	}
	grantWorldRead(t, path)
	if _, err := store.Put(t.Context(), 4, "json", []byte("new")); !errors.Is(err, ErrUnsafe) {
		t.Fatal("overpermissive root accepted", err)
	}
	if opened, err := Open(path); err == nil {
		_ = opened.Close()
		t.Fatal("broad root reopened")
	}
}
