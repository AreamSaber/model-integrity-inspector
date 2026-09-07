//go:build windows

package secret

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

func setKeyTestDACL(t *testing.T, path, sddl string) {
	t.Helper()
	security, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal("invalid ACL fixture")
	}
	acl, _, err := security.DACL()
	if err != nil {
		t.Fatal("invalid ACL fixture")
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal("could not apply test-only ACL")
	}
}

func TestKeyFileWindowsReadCapablePrincipals(t *testing.T) {
	sid, err := currentKeyFileSID()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, extra string
		allowed     bool
	}{
		{"owner_only", "", true},
		{"system", "(A;;FA;;;SY)", true},
		{"trusted_administrators", "(A;;FA;;;BA)", true},
		{"everyone_read", "(A;;GR;;;WD)", false},
		{"users_read", "(A;;GR;;;BU)", false},
		{"everyone_write", "(A;;GW;;;WD)", false},
		{"everyone_change_acl", "(A;;WD;;;WD)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "master.key")
			if _, err := CreateKeyFile(path, "v1"); err != nil {
				t.Fatal(err)
			}
			setKeyTestDACL(t, path, "D:P(A;;FA;;;"+sid.String()+")"+tc.extra)
			_, err := LoadKeyFile(path, "v1")
			if tc.allowed && err != nil {
				t.Fatal(err)
			}
			if !tc.allowed && !errors.Is(err, ErrKeyFilePermissions) {
				t.Fatalf("unsafe ACL accepted: %v", err)
			}
		})
	}
}

func TestCreatedKeyACLPrecedesWriteAndUsesActualHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	file, err := openRestrictedKeyFile(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || info.Size() != 0 {
		t.Fatal("new key file has bytes before ACL validation")
	}
	if err := validateKeyHandle(file); err != nil {
		t.Fatal(err)
	}
	security, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal("could not inspect created test key ACL")
	}
	control, _, err := security.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("created key inherits parent ACL before writing")
	}
	// No write/delete sharing: another handle cannot replace bytes/name between
	// validating this handle and writing the generated master.
	testRoot, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal("could not open test fixture root")
	}
	defer func() { _ = testRoot.Close() }()
	other, err := testRoot.OpenFile("master.key", os.O_WRONLY, 0)
	if other != nil {
		_ = other.Close()
	}
	if err == nil {
		t.Fatal("key creation permitted a concurrent writer")
	}
}

func TestWindowsJunctionAncestorsRejected(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal("could not create junction target fixture")
	}
	path := filepath.Join(target, "master.key")
	if _, err := CreateKeyFile(path, "v1"); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(directory, "junction")
	if err := os.Mkdir(junction, 0o700); err != nil {
		t.Fatal("could not create junction fixture")
	}
	name, err := windows.UTF16PtrFromString(junction)
	if err != nil {
		t.Fatal("invalid junction fixture path")
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal("could not open junction fixture")
	}
	substitute := append(utf16.Encode([]rune(`\??\`+target)), 0)
	printName := append(utf16.Encode([]rune(target)), 0)
	paths := append(substitute, printName...)
	if len(paths) > 10000 {
		t.Fatal("junction fixture path exceeds bounded reparse buffer")
	}
	buffer := make([]byte, 16+len(paths)*2)
	binary.LittleEndian.PutUint32(buffer, windows.IO_REPARSE_TAG_MOUNT_POINT)
	binary.LittleEndian.PutUint16(buffer[4:], reparseUint16(t, len(buffer)-8))
	binary.LittleEndian.PutUint16(buffer[10:], reparseUint16(t, (len(substitute)-1)*2))
	binary.LittleEndian.PutUint16(buffer[12:], reparseUint16(t, len(substitute)*2))
	binary.LittleEndian.PutUint16(buffer[14:], reparseUint16(t, (len(printName)-1)*2))
	for index, unit := range paths {
		binary.LittleEndian.PutUint16(buffer[16+index*2:], unit)
	}
	var returned uint32
	bufferLength := len(buffer)
	if bufferLength < 0 || bufferLength > math.MaxUint32 {
		t.Fatal("invalid reparse fixture length")
		return
	}
	err = windows.DeviceIoControl(handle, windows.FSCTL_SET_REPARSE_POINT, &buffer[0], uint32(bufferLength), nil, 0, &returned, nil)
	_ = windows.CloseHandle(handle)
	if err != nil {
		t.Fatal("could not install test-only junction reparse data")
	}
	if _, err := LoadKeyFile(filepath.Join(junction, "master.key"), "v1"); !errors.Is(err, ErrKeyFileUnsafe) {
		t.Fatalf("junction ancestor accepted: %v", err)
	}
	if _, err := CreateKeyFile(filepath.Join(junction, "new.key"), "v1"); !errors.Is(err, ErrKeyFileUnsafe) {
		t.Fatalf("create followed junction: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "new.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("create wrote through junction")
	}
}

func reparseUint16(t *testing.T, size int) uint16 {
	t.Helper()
	if size < 0 || size > math.MaxUint16 {
		t.Fatal("invalid reparse fixture field length")
		return 0
	}
	return uint16(size)
}

func TestWindowsNullDACLRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "master.key")
	if _, err := CreateKeyFile(path, "v1"); err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil); err != nil {
		t.Fatal("could not create NULL ACL fixture")
	}
	if _, err := LoadKeyFile(path, "v1"); !errors.Is(err, ErrKeyFilePermissions) {
		t.Fatal("NULL DACL accepted")
	}
}

func TestWindowsNamespaceAndAlternateStreamRejected(t *testing.T) {
	for index, path := range []string{`\\.\NUL`, `\\?\C:\key`, `\\host\share\key`, `C:\key:stream`, "C:\\key.", "C:\\key "} {
		if _, err := LoadKeyFile(path, "v1"); !errors.Is(err, ErrKeyFileUnsafe) {
			t.Fatalf("unsafe Windows key path case %d did not fail closed: %v", index, err)
		}
	}
}
