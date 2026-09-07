//go:build windows

package reportstorage

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func currentSID() (*windows.SID, error) {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, ErrUnavailable
	}
	return u.User.Sid, nil
}
func openDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return nil, ErrUnsafe
	}
	absolute := filepath.Clean(path)
	volume := filepath.VolumeName(absolute)
	if len(volume) != 2 || volume[1] != ':' || len(absolute) < 4 || strings.Contains(absolute[2:], ":") {
		return nil, ErrUnsafe
	}
	for _, part := range strings.Split(strings.ReplaceAll(path, "/", `\`)[3:], `\`) {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return nil, ErrUnsafe
		}
	}
	rootName, e := windows.UTF16PtrFromString(volume + `\`)
	if e != nil {
		return nil, ErrUnsafe
	}
	root, e := windows.CreateFile(rootName, windows.FILE_READ_ATTRIBUTES|windows.FILE_TRAVERSE|windows.SYNCHRONIZE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer func() { _ = windows.CloseHandle(root) }()
	name, e := windows.NewNTUnicodeString(absolute[3:])
	if e != nil {
		return nil, ErrUnsafe
	}
	sid, e := currentSID()
	if e != nil {
		return nil, e
	}
	security, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + sid.String() + ")(A;OICI;FA;;;SY)")
	if e != nil {
		return nil, ErrUnavailable
	}
	attributes := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), ObjectName: name, RootDirectory: root, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE, SecurityDescriptor: security}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	e = windows.NtCreateFile(&handle, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE, &attributes, &status, nil, windows.FILE_ATTRIBUTE_DIRECTORY, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_OPEN_IF, windows.FILE_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT, 0, 0)
	runtime.KeepAlive(attributes)
	if e != nil {
		return nil, ErrUnsafe
	}
	return os.NewFile(uintptr(handle), "report-directory"), nil
}
func validateHandle(file *os.File, directory bool) error {
	if file == nil {
		return ErrUnsafe
	}
	h := windows.Handle(file.Fd())
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil {
		return ErrUnavailable
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || !directory && info.NumberOfLinks != 1 {
		return ErrUnsafe
	}
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || !sd.IsValid() {
		return ErrUnsafe
	}
	defer runtime.KeepAlive(sd)
	current, e := currentSID()
	if e != nil {
		return e
	}
	allowed := func(s *windows.SID) bool {
		return s != nil && s.IsValid() && (s.Equals(current) || s.IsWellKnown(windows.WinLocalSystemSid) || s.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	}
	owner, _, e := sd.Owner()
	if e != nil || !allowed(owner) {
		return ErrUnsafe
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil || acl.AceCount == 0 {
		return ErrUnsafe
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace == nil {
			return ErrUnsafe
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceSize < 16 {
			return ErrUnsafe
		}
		const access = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_EXECUTE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE | windows.GENERIC_ALL | windows.GENERIC_READ | windows.GENERIC_WRITE | windows.GENERIC_EXECUTE
		if ace.Mask&access == 0 {
			continue
		}
		// #nosec G103 -- GetSecurityInfo returns a validated Windows security descriptor; only basic allow ACEs are interpreted, with SID length bounded to AceSize.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || sid.Len()+8 > int(ace.Header.AceSize) || !allowed(sid) {
			return ErrUnsafe
		}
	}
	return nil
}

// NTFS file Sync is required before publishing the hard link. Windows does not
// offer portable directory fsync; a power loss can still require file repair.
func syncDirectory(*os.File) error { return nil }

func openArtifact(directory *os.File, name string) (*os.File, error) {
	unicodeName, e := windows.NewNTUnicodeString(name)
	if e != nil {
		return nil, ErrUnsafe
	}
	attributes := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), ObjectName: unicodeName, RootDirectory: windows.Handle(directory.Fd()), Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	e = windows.NtCreateFile(&handle, windows.FILE_GENERIC_READ, &attributes, &status, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT, 0, 0)
	runtime.KeepAlive(attributes)
	if e != nil {
		return nil, ErrUnsafe
	}
	return os.NewFile(uintptr(handle), "report-artifact"), nil
}
