//go:build windows

package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// Windows Temp may allow other users to mutate an ancestor. Only this newly
// created random test child receives a private DACL; existing profile/Temp ACLs
// are never repaired. WithBackupWorkspace still validates the entire ancestry.
func backupPublicationPrivateDirectory(t *testing.T) string {
	t.Helper()
	profile, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(profile) || filepath.Clean(profile) != profile {
		t.Fatal("publication fixture profile")
	}
	path, err := os.MkdirTemp(profile, ".mii-publication-test-")
	if err != nil || filepath.Dir(path) != profile {
		t.Fatal("publication fixture random child")
	}
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("publication fixture encoding")
	}
	h, err := windows.CreateFile(ptr, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal("publication fixture pin")
	}
	var original windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &original); err != nil || original.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || original.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(h)
		t.Fatal("publication fixture identity")
	}
	// Pin the original until cleanup. Cleanup never recursively deletes a
	// directory or removes unknown entries in order to make the test pass.
	t.Cleanup(func() {
		var actual windows.ByHandleFileInformation
		identityErr := windows.GetFileInformationByHandle(h, &actual)
		closeErr := windows.CloseHandle(h)
		if identityErr != nil || closeErr != nil || actual.VolumeSerialNumber != original.VolumeSerialNumber || actual.FileIndexHigh != original.FileIndexHigh || actual.FileIndexLow != original.FileIndexLow || actual.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			t.Error("publication fixture cleanup identity")
			return
		}
		for _, name := range backupPublicationFiles(t, path) {
			if err := os.Remove(filepath.Join(path, name)); err != nil {
				t.Error("publication fixture owned archive cleanup")
			}
		}
		if err := os.Remove(path); err != nil {
			t.Error("publication fixture empty directory cleanup")
		}
	})
	var name [4096]uint16
	n, err := windows.GetFinalPathNameByHandle(h, &name[0], uint32(len(name)), 0)
	if err != nil || n == 0 || n >= uint32(len(name)) {
		t.Fatal("publication fixture canonical name")
	}
	canonical := strings.TrimPrefix(windows.UTF16ToString(name[:n]), `\\?\`)
	if strings.HasPrefix(canonical, `\\`) || !strings.EqualFold(canonical, path) {
		t.Fatal("publication fixture noncanonical profile")
	}
	path = canonical
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("publication fixture owner")
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)")
	if err != nil {
		t.Fatal("publication fixture DACL")
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal("publication fixture DACL decode")
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal("publication fixture DACL set")
	}
	return path
}
