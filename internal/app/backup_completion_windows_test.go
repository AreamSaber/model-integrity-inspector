//go:build windows

package app

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// Normalize ONLY this freshly created test directory. Production still rejects
// short names/reparse aliases and validates the actual DACL and NTFS identity.
func backupCompletionPrivateDirectory(t *testing.T) string {
	t.Helper()
	path := t.TempDir()
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("private fixture path")
	}
	h, err := windows.CreateFile(ptr, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal("private fixture handle")
	}
	defer func() {
		if err := windows.CloseHandle(h); err != nil {
			t.Error("private fixture close")
		}
	}()
	var original windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &original); err != nil || original.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || original.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		t.Fatal("private fixture identity")
	}
	var name [4096]uint16
	n, err := windows.GetFinalPathNameByHandle(h, &name[0], uint32(len(name)), 0)
	if err != nil || n == 0 || n >= uint32(len(name)) {
		t.Fatal("private fixture canonical name")
	}
	path = strings.TrimPrefix(windows.UTF16ToString(name[:n]), `\\?\`)
	if !strings.HasPrefix(path, `\\`) && len(path) > 3 && path[1] == ':' {
		canonical, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal("private fixture canonical encoding")
		}
		check, err := windows.CreateFile(canonical, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			t.Fatal("private fixture canonical reopen")
		}
		var actual windows.ByHandleFileInformation
		err = windows.GetFileInformationByHandle(check, &actual)
		closeErr := windows.CloseHandle(check)
		if err != nil || closeErr != nil || original.VolumeSerialNumber != actual.VolumeSerialNumber || original.FileIndexHigh != actual.FileIndexHigh || original.FileIndexLow != actual.FileIndexLow {
			t.Fatal("private fixture canonical identity mismatch")
		}
	} else {
		t.Fatal("private fixture unsupported canonical volume")
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal("private fixture owner")
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)")
	if err != nil {
		t.Fatal("private fixture DACL")
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal("private fixture DACL decode")
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal("private fixture DACL set")
	}
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		t.Fatal("private fixture vanished")
	}
	return path
}
