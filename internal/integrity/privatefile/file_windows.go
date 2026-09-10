//go:build windows

package privatefile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func validatePath(path string) error {
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' || len(path) < 4 || path[2] != '\\' || strings.ContainsAny(path[2:], ":/") {
		return ErrUnsafe
	}
	for _, part := range strings.Split(path[3:], `\`) {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return ErrUnsafe
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		port := strings.TrimPrefix(base, "COM")
		if port == base {
			port = strings.TrimPrefix(base, "LPT")
		}
		devicePort := port != base && (len(port) == 1 && port[0] >= '0' && port[0] <= '9' || port == "¹" || port == "²" || port == "³")
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || base == "CONIN$" || base == "CONOUT$" ||
			devicePort {
			return ErrUnsafe
		}
	}
	root, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil || windows.GetDriveType(root) != windows.DRIVE_FIXED {
		return ErrUnsafe
	}
	return nil
}

func nativeError(err error) error {
	var status windows.NTStatus
	if errors.As(err, &status) {
		switch status {
		case windows.STATUS_OBJECT_NAME_COLLISION:
			return ErrExists
		case windows.STATUS_REPARSE_POINT_ENCOUNTERED, windows.STATUS_FILE_IS_A_DIRECTORY:
			return ErrUnsafe
		case windows.STATUS_ACCESS_DENIED:
			return ErrPermissions
		}
	}
	return ErrUnavailable
}

func currentSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, ErrUnavailable
	}
	return user.User.Sid, nil
}

func openNative(root windows.Handle, name string, directory, create bool) (*os.File, error) {
	nativeName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, ErrUnsafe
	}
	attrs := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: root, ObjectName: nativeName, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	access := uint32(windows.FILE_GENERIC_READ)
	share := uint32(windows.FILE_SHARE_READ)
	options := uint32(windows.FILE_NON_DIRECTORY_FILE | windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT)
	disposition := uint32(windows.FILE_OPEN)
	if directory {
		options = windows.FILE_DIRECTORY_FILE | windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT
		share |= windows.FILE_SHARE_WRITE // Never share directory deletion/rename.
	}
	if create {
		sid, err := currentSID()
		if err != nil {
			return nil, err
		}
		security, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + sid.String() + ")(A;;FA;;;SY)")
		if err != nil {
			return nil, ErrUnavailable
		}
		attrs.SecurityDescriptor = security
		access |= windows.FILE_GENERIC_WRITE | windows.DELETE
		share, disposition = 0, windows.FILE_CREATE
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access, &attrs, &status, nil, windows.FILE_ATTRIBUTE_NORMAL, share, disposition, options, 0, 0)
	runtime.KeepAlive(attrs)
	if err != nil {
		return nil, nativeError(err)
	}
	f := os.NewFile(uintptr(handle), "private-file")
	if f == nil {
		_ = windows.CloseHandle(handle)
		return nil, ErrUnavailable
	}
	return f, nil
}

func openDirectory(path string) (*os.File, error) {
	volume := filepath.VolumeName(path)
	rootName, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil {
		return nil, ErrUnsafe
	}
	root, err := windows.CreateFile(rootName, windows.FILE_READ_ATTRIBUTES|windows.FILE_TRAVERSE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer func() { _ = windows.CloseHandle(root) }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(root, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, ErrUnsafe
	}
	name := "."
	if len(path) > 3 {
		name = path[3:]
	}
	dir, err := openNative(root, name, true, false)
	if err != nil {
		return nil, err
	}
	if err := windows.GetFileInformationByHandle(windows.Handle(dir.Fd()), &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		_ = dir.Close()
		return nil, ErrUnsafe
	}
	if err := validateDirectory(dir); err != nil {
		_ = dir.Close()
		return nil, err
	}
	actual, err := canonicalName(dir)
	if err != nil || !strings.EqualFold(actual, path) {
		_ = dir.Close()
		return nil, ErrUnsafe
	}
	return dir, nil
}

func openInput(dir *os.File, name string) (*os.File, error) {
	f, err := openNative(windows.Handle(dir.Fd()), name, false, false)
	if err != nil {
		return nil, err
	}
	actual, err := canonicalName(f)
	if err != nil || !strings.EqualFold(filepath.Base(actual), name) {
		_ = f.Close()
		return nil, ErrUnsafe
	}
	return f, nil
}
func createTemp(dir *os.File, name string) (*os.File, error) {
	return openNative(windows.Handle(dir.Fd()), name, false, true)
}

func validateFile(f *os.File) error {
	if err := validateVolume(f); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ErrUnsafe
	}
	h := windows.Handle(f.Fd())
	kind, err := windows.GetFileType(h)
	if err != nil || kind != windows.FILE_TYPE_DISK {
		return ErrUnsafe
	}
	var native windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &native); err != nil {
		return ErrUnavailable
	}
	if native.NumberOfLinks != 1 || native.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return ErrUnsafe
	}
	return validateACL(f)
}

func validateACL(f *os.File) error {
	security, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || !security.IsValid() {
		return ErrPermissions
	}
	defer runtime.KeepAlive(security)
	current, err := currentSID()
	if err != nil {
		return err
	}
	allowed := func(sid *windows.SID) bool {
		return sid != nil && sid.IsValid() && (sid.Equals(current) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	}
	owner, _, err := security.Owner()
	if err != nil || !allowed(owner) {
		return ErrPermissions
	}
	acl, _, err := security.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return ErrPermissions
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil || ace == nil {
			return ErrPermissions
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceSize < 16 {
			return ErrPermissions
		}
		// FILE_DELETE_CHILD is 0x40 in the Windows native file access mask;
		// the pinned x/sys/windows version does not export its symbolic name.
		const deleteChild = 0x00000040
		const sensitive = windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_EXECUTE | deleteChild | windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE | windows.GENERIC_ALL | windows.GENERIC_READ | windows.GENERIC_WRITE | windows.GENERIC_EXECUTE
		if uint32(ace.Mask)&sensitive == 0 {
			continue
		}
		// #nosec G103 -- OS-validated basic ACE; SID length is checked against AceSize.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || sid.Len()+8 > int(ace.Header.AceSize) || !allowed(sid) {
			return ErrPermissions
		}
	}
	return nil
}

// The layout matches Go 1.26's internal/syscall/windows.FILE_RENAME_INFORMATION
// and Windows ntifs.h. False ReplaceIfExists makes the namespace commit no-replace.
type renameInformation struct {
	ReplaceIfExists bool
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [260]uint16
}

func publish(dir, f *os.File, _, name string) error {
	encoded, err := windows.UTF16FromString(name)
	if err != nil || len(encoded) > 260 {
		return ErrUnsafe
	}
	// #nosec G115 -- len(encoded) was bounded to 260 UTF-16 units above.
	info := renameInformation{RootDirectory: windows.Handle(dir.Fd()), FileNameLength: uint32((len(encoded) - 1) * 2)}
	copy(info.FileName[:], encoded)
	var status windows.IO_STATUS_BLOCK
	// #nosec G103 -- fixed native structure with bounded inline UTF-16 filename.
	err = windows.NtSetInformationFile(windows.Handle(f.Fd()), &status, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), 10)
	runtime.KeepAlive(info)
	if err != nil {
		return nativeError(err)
	}
	return nil
}

func removeTemp(_ *os.File, f *os.File, _ string) error {
	// Delete only the exact still-open handle that this call created, never a path.
	var status windows.IO_STATUS_BLOCK
	deleteFile := byte(1)
	if err := windows.NtSetInformationFile(windows.Handle(f.Fd()), &status, &deleteFile, 1, 13); err != nil {
		return ErrUnavailable
	}
	return nil
}

// File data was flushed before native rename. Windows does not expose a portable
// directory fsync; successful namespace publication is not a power-loss warranty.
func syncDirectory(_ *os.File) error { return nil }

// canonicalName rejects DOS short names and substituted drive aliases. Windows
// casing is not a separate namespace: spelling is compared case-insensitively.
func canonicalName(f *os.File) (string, error) {
	var buffer [4096]uint16
	n, err := windows.GetFinalPathNameByHandle(windows.Handle(f.Fd()), &buffer[0], uint32(len(buffer)), 0)
	if err != nil || n == 0 || n >= uint32(len(buffer)) {
		return "", ErrUnsafe
	}
	name := windows.UTF16ToString(buffer[:n])
	if !strings.HasPrefix(name, `\\?\`) {
		return "", ErrUnsafe
	}
	return strings.TrimPrefix(name, `\\?\`), nil
}

func validateVolume(f *os.File) error {
	var filesystem [32]uint16
	var flags uint32
	if windows.GetVolumeInformationByHandle(windows.Handle(f.Fd()), nil, 0, nil, nil, &flags, &filesystem[0], uint32(len(filesystem))) != nil {
		return ErrFilesystem
	}
	// Require the actual handle's NTFS volume and persistent ACL support. FAT,
	// unvalidated ReFS/virtual filesystems and remote paths do not silently pass.
	if windows.UTF16ToString(filesystem[:]) != "NTFS" || flags&0x00000008 == 0 {
		return ErrFilesystem
	}
	return nil
}

func validateDirectory(f *os.File) error {
	if err := validateVolume(f); err != nil {
		return err
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info) != nil {
		return ErrUnavailable
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return ErrUnsafe
	}
	return validateACL(f)
}
