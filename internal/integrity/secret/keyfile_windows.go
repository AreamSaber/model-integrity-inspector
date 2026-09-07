//go:build windows

package secret

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func currentKeyFileSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, ErrUnavailable
	}
	return user.User.Sid, nil
}

func openRestrictedKeyFile(path string, create bool) (*os.File, error) {
	if path == "" || strings.ContainsRune(path, 0) {
		return nil, ErrKeyFileUnsafe
	}
	for _, component := range strings.Split(strings.ReplaceAll(path, "/", `\`), `\`) {
		if component != "." && component != ".." && (strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ")) {
			return nil, ErrKeyFileUnsafe
		}
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, ErrKeyFileUnsafe
	}
	volume := filepath.VolumeName(absolute)
	// Do not interpret UNC shares, device namespaces, alternate streams, or
	// Win32 trailing-dot aliases as local master-key file names.
	if len(volume) != 2 || volume[1] != ':' || strings.Contains(absolute[2:], ":") {
		return nil, ErrKeyFileUnsafe
	}
	for _, component := range strings.Split(absolute[3:], `\`) {
		if component == "" || strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") {
			return nil, ErrKeyFileUnsafe
		}
	}
	// Resolve only the trusted DOS drive root with Win32, then apply native
	// no-reparse resolution to the entire filesystem-relative path. Applying
	// OBJ_DONT_REPARSE to \??\C: itself also rejects Windows' drive mapping.
	rootName, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil {
		return nil, ErrKeyFileUnsafe
	}
	root, err := windows.CreateFile(rootName, windows.FILE_READ_ATTRIBUTES|windows.FILE_TRAVERSE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer func() { _ = windows.CloseHandle(root) }()
	var rootInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(root, &rootInfo); err != nil || rootInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, ErrKeyFileUnsafe
	}
	name, err := windows.NewNTUnicodeString(absolute[3:])
	if err != nil {
		return nil, ErrKeyFileUnsafe
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), ObjectName: name, RootDirectory: root,
		Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	disposition := uint32(windows.FILE_OPEN)
	access := uint32(windows.FILE_GENERIC_READ)
	share := uint32(windows.FILE_SHARE_READ)
	if create {
		sid, err := currentKeyFileSID()
		if err != nil {
			return nil, err
		}
		security, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + sid.String() + ")(A;;FA;;;SY)")
		if err != nil {
			return nil, ErrUnavailable
		}
		attributes.SecurityDescriptor = security
		disposition = windows.FILE_CREATE
		access |= windows.FILE_GENERIC_WRITE
		share = 0
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access, &attributes, &status, nil, windows.FILE_ATTRIBUTE_NORMAL, share, disposition,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT, 0, 0)
	runtime.KeepAlive(attributes)
	if err != nil {
		var ntStatus windows.NTStatus
		if errors.As(err, &ntStatus) {
			switch ntStatus {
			case windows.STATUS_OBJECT_NAME_COLLISION:
				return nil, ErrKeyFileExists
			case windows.STATUS_REPARSE_POINT_ENCOUNTERED, windows.STATUS_FILE_IS_A_DIRECTORY:
				return nil, ErrKeyFileUnsafe
			case windows.STATUS_ACCESS_DENIED:
				return nil, ErrKeyFilePermissions
			}
		}
		return nil, ErrUnavailable
	}
	file := os.NewFile(uintptr(handle), "master-key")
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, ErrUnavailable
	}
	return file, nil
}

func validateKeyHandle(file *os.File) error {
	if err := regularKeyFile(file); err != nil {
		return err
	}
	handle := windows.Handle(file.Fd())
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return ErrUnavailable
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		return ErrKeyFileUnsafe
	}
	security, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || !security.IsValid() {
		return ErrKeyFilePermissions
	}
	defer runtime.KeepAlive(security)
	current, err := currentKeyFileSID()
	if err != nil {
		return err
	}
	allowed := func(sid *windows.SID) bool {
		if sid == nil || !sid.IsValid() {
			return false
		}
		return sid.Equals(current) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
	}
	owner, _, err := security.Owner()
	if err != nil || !allowed(owner) {
		return ErrKeyFilePermissions
	}
	acl, _, err := security.DACL()
	// A NULL DACL grants everyone full access; an empty DACL cannot supply a
	// loadable service key. Unknown/conditional ACE forms fail closed.
	if err != nil || acl == nil || acl.AceCount == 0 {
		return ErrKeyFilePermissions
	}
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, &ace); err != nil || ace == nil {
			return ErrKeyFilePermissions
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceSize < 16 {
			return ErrKeyFilePermissions
		}
		const sensitiveAccess = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_EXECUTE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE | windows.GENERIC_ALL | windows.GENERIC_READ | windows.GENERIC_WRITE | windows.GENERIC_EXECUTE
		if uint32(ace.Mask)&sensitiveAccess == 0 {
			continue
		}
		// #nosec G103 -- GetSecurityInfo/GetAce return an OS-validated ACE; only
		// basic allow ACEs are interpreted, and SID size is checked within AceSize.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || sid.Len()+8 > int(ace.Header.AceSize) || !allowed(sid) {
			return ErrKeyFilePermissions
		}
	}
	return nil
}
