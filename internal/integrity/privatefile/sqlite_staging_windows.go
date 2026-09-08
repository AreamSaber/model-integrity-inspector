//go:build windows

package privatefile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const sqliteWindowsMain = "snapshot.db"

// This is the fixed Windows TrustedInstaller service SID, not a display-name
// allowlist. It is resolved locally and allowed ONLY as the OS volume root owner.
const sqliteWindowsInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

type sqliteWindowsIdentity struct {
	volume, high, low uint32
}

type sqliteWindowsDirectory struct {
	file *os.File
	path string
	id   sqliteWindowsIdentity
}

type sqliteWindowsStaging struct {
	chain      []sqliteWindowsDirectory
	work       *os.File
	workName   string
	workID     sqliteWindowsIdentity
	main       *os.File
	mainID     sqliteWindowsIdentity
	mainExists bool
	sealed     bool
	sidecars   map[string]sqliteWindowsIdentity
	closed     bool
	cleanupErr error
}

type sqliteWindowsOpenOptions struct {
	directory bool
	create    bool
	write     bool
	delete    bool
	metadata  bool
	share     uint32
}

func sqliteWindowsOpen(root windows.Handle, name string, options sqliteWindowsOpenOptions) (*os.File, error) {
	nativeName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, ErrUnsafe
	}
	attrs := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: root, ObjectName: nativeName,
		Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	access := uint32(windows.FILE_GENERIC_READ)
	if options.metadata {
		access = windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL | windows.SYNCHRONIZE
	}
	if options.write {
		access |= windows.FILE_GENERIC_WRITE
	}
	if options.delete {
		access |= windows.DELETE
	}
	flags := uint32(windows.FILE_NON_DIRECTORY_FILE | windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT)
	if options.directory {
		flags = windows.FILE_DIRECTORY_FILE | windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT
	}
	disposition := uint32(windows.FILE_OPEN)
	if options.create {
		sid, err := currentSID()
		if err != nil {
			return nil, err
		}
		inherit := ""
		if options.directory {
			inherit = "OICI" // SQLite-created sidecars must be private from birth.
		}
		security, err := windows.SecurityDescriptorFromString("D:P(A;" + inherit + ";FA;;;" + sid.String() + ")(A;" + inherit + ";FA;;;SY)")
		if err != nil {
			return nil, ErrUnavailable
		}
		attrs.SecurityDescriptor = security
		disposition = windows.FILE_CREATE
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access, &attrs, &status, nil, windows.FILE_ATTRIBUTE_NORMAL,
		options.share, disposition, flags, 0, 0)
	runtime.KeepAlive(attrs)
	if err != nil {
		return nil, nativeError(err)
	}
	f := os.NewFile(uintptr(handle), "private-sqlite-file")
	if f == nil {
		_ = windows.CloseHandle(handle)
		return nil, ErrUnavailable
	}
	return f, nil
}

func sqliteWindowsFileID(f *os.File) (sqliteWindowsIdentity, error) {
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info) != nil {
		return sqliteWindowsIdentity{}, ErrUnavailable
	}
	return sqliteWindowsIdentity{info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow}, nil
}

func sqliteWindowsMatches(f *os.File, expected sqliteWindowsIdentity) error {
	actual, err := sqliteWindowsFileID(f)
	if err != nil {
		return err
	}
	if actual != expected {
		return ErrUnsafe
	}
	return nil
}

func sqliteWindowsInstallerOwner(owner *windows.SID, path string) bool {
	if owner == nil || !owner.IsValid() || owner.String() != sqliteWindowsInstallerSID || len(path) != 3 {
		return false
	}
	windowsPath, err := windows.GetWindowsDirectory()
	if err != nil || !strings.EqualFold(path, filepath.VolumeName(windowsPath)+`\`) {
		return false
	}
	resolved, _, _, err := windows.LookupSID("", `NT SERVICE\TrustedInstaller`)
	return err == nil && resolved != nil && resolved.IsValid() &&
		resolved.String() == sqliteWindowsInstallerSID && resolved.Equals(owner)
}

// Ancestors may be publicly readable/traversable. ADD_FILE/ADD_SUBDIRECTORY
// alone cannot replace the existing components, each of which remains pinned
// without FILE_SHARE_DELETE. No other principal may mutate their metadata,
// ownership, DACL, or existing child names. The private workspace also checks
// inherit-only ACEs: those apply to sidecars created later by SQLite.
func sqliteWindowsACL(f *os.File, ancestorPath string) error {
	security, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || !security.IsValid() {
		return ErrPermissions
	}
	defer runtime.KeepAlive(security)
	current, err := currentSID()
	if err != nil {
		return err
	}
	allowed := func(sid *windows.SID) bool {
		return sid != nil && sid.IsValid() && (sid.Equals(current) ||
			sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	}
	owner, _, err := security.Owner()
	if err != nil || !allowed(owner) && !sqliteWindowsInstallerOwner(owner, ancestorPath) {
		return ErrPermissions
	}
	acl, _, err := security.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return ErrPermissions
	}
	const deleteChild = 0x40
	const mutations = windows.DELETE | deleteChild | windows.WRITE_DAC | windows.WRITE_OWNER |
		windows.FILE_WRITE_ATTRIBUTES | windows.FILE_WRITE_EA | windows.GENERIC_WRITE | windows.GENERIC_ALL
	sensitive := uint32(mutations)
	if ancestorPath == "" {
		sensitive |= windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
			windows.FILE_EXECUTE | windows.GENERIC_READ | windows.GENERIC_EXECUTE
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace == nil {
			return ErrPermissions
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE ||
			ancestorPath != "" && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceSize < 16 {
			return ErrPermissions
		}
		if uint32(ace.Mask)&sensitive == 0 {
			continue
		}
		// #nosec G103 -- OS-validated basic ACE; SID extent is checked against AceSize.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || sid.Len()+8 > int(ace.Header.AceSize) || !allowed(sid) {
			return ErrPermissions
		}
	}
	return nil
}

func sqliteWindowsCheckDirectory(f *os.File, path string, private bool) error {
	if err := validateVolume(f); err != nil {
		return err
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info) != nil {
		return ErrUnavailable
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrUnsafe
	}
	actual, err := canonicalName(f)
	if err != nil || !strings.EqualFold(actual, path) {
		return ErrUnsafe
	}
	if private {
		if err := validateDirectory(f); err != nil {
			return err
		}
		return sqliteWindowsACL(f, "")
	}
	return sqliteWindowsACL(f, path)
}

func (s *sqliteWindowsStaging) openChain(parent string) error {
	if len(parent) < 3 || len(strings.Split(parent[3:], `\`)) > 256 {
		return ErrLimit
	}
	rootPath := filepath.VolumeName(parent) + `\`
	rootName, err := windows.UTF16PtrFromString(rootPath)
	if err != nil {
		return ErrUnsafe
	}
	handle, err := windows.CreateFile(rootName, windows.FILE_GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return ErrUnavailable
	}
	root := os.NewFile(uintptr(handle), "private-sqlite-root")
	if root == nil {
		_ = windows.CloseHandle(handle)
		return ErrUnavailable
	}
	s.chain = append(s.chain, sqliteWindowsDirectory{file: root, path: rootPath})
	for i := 0; ; i++ {
		entry := &s.chain[i]
		entry.id, err = sqliteWindowsFileID(entry.file)
		if err != nil {
			return err
		}
		if err := sqliteWindowsCheckDirectory(entry.file, entry.path, strings.EqualFold(entry.path, parent)); err != nil {
			return err
		}
		if strings.EqualFold(entry.path, parent) {
			return nil
		}
		relative := strings.TrimPrefix(parent[len(entry.path):], `\`)
		name, _, _ := strings.Cut(relative, `\`)
		if name == "" {
			return ErrUnsafe
		}
		next, err := sqliteWindowsOpen(windows.Handle(entry.file.Fd()), name,
			sqliteWindowsOpenOptions{directory: true, share: windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE})
		if err != nil {
			return err
		}
		s.chain = append(s.chain, sqliteWindowsDirectory{file: next, path: filepath.Join(entry.path, name)})
	}
}

func newSQLiteStaging(parent string) (_ sqliteStagingNative, finalErr error) {
	s := &sqliteWindowsStaging{sidecars: make(map[string]sqliteWindowsIdentity)}
	defer func() {
		if finalErr != nil {
			_ = s.cleanup() // Best effort, exact owned handles only; preserve classification.
		}
	}()
	if _, _, err := splitPath(parent); err != nil {
		return nil, err
	}
	if err := s.openChain(parent); err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, ErrUnavailable
	}
	s.workName = ".mii-sqlite-" + hex.EncodeToString(nonce[:])
	var err error
	s.work, err = sqliteWindowsOpen(windows.Handle(s.parent().file.Fd()), s.workName,
		sqliteWindowsOpenOptions{directory: true, create: true, delete: true,
			share: windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE})
	if err != nil {
		return nil, err
	}
	s.workID, err = sqliteWindowsFileID(s.work)
	if err != nil {
		return nil, err
	}
	if err := sqliteWindowsCheckDirectory(s.work, s.workspacePath(), true); err != nil {
		return nil, err
	}
	// DELETE access on the MAIN guard is incompatible with SQLite's VFS, whose
	// new handles share only READ|WRITE. Keep DELETE on the directory instead.
	s.main, err = sqliteWindowsOpen(windows.Handle(s.work.Fd()), sqliteWindowsMain,
		sqliteWindowsOpenOptions{create: true, write: true, share: windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE})
	if err != nil {
		return nil, err
	}
	s.mainExists = true
	s.mainID, err = sqliteWindowsFileID(s.main)
	if err != nil {
		return nil, err
	}
	if err := s.inspect(MaxBytes, 2*MaxBytes, false); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *sqliteWindowsStaging) parent() *sqliteWindowsDirectory { return &s.chain[len(s.chain)-1] }
func (s *sqliteWindowsStaging) workspacePath() string {
	return filepath.Join(s.parent().path, s.workName)
}
func (s *sqliteWindowsStaging) databasePath() string {
	if s.closed || s.work == nil {
		return ""
	}
	return filepath.Join(s.workspacePath(), sqliteWindowsMain)
}

func (s *sqliteWindowsStaging) inspectDirectories() error {
	for i := range s.chain {
		entry := &s.chain[i]
		if err := sqliteWindowsMatches(entry.file, entry.id); err != nil {
			return err
		}
		if err := sqliteWindowsCheckDirectory(entry.file, entry.path, i == len(s.chain)-1); err != nil {
			return err
		}
	}
	if err := sqliteWindowsMatches(s.work, s.workID); err != nil {
		return err
	}
	return sqliteWindowsCheckDirectory(s.work, s.workspacePath(), true)
}

func (s *sqliteWindowsStaging) names() (_ []string, finalErr error) {
	// A fresh enumeration handle restarts the directory cursor on every check.
	// Sharing DELETE here accommodates our original workdir DELETE-access
	// handle; that original handle still denies EVERY additional DELETE open.
	dir, err := sqliteWindowsOpen(windows.Handle(s.parent().file.Fd()), s.workName,
		sqliteWindowsOpenOptions{directory: true, share: windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := dir.Close(); err != nil && finalErr == nil {
			finalErr = ErrUnavailable
		}
	}()
	if err := sqliteWindowsMatches(dir, s.workID); err != nil {
		return nil, err
	}
	names, err := dir.Readdirnames(5)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, ErrUnavailable
	}
	if len(names) > 4 {
		return nil, ErrUnsafe
	}
	for _, name := range names {
		switch name {
		case sqliteWindowsMain, sqliteWindowsMain + "-journal", sqliteWindowsMain + "-wal", sqliteWindowsMain + "-shm":
		default:
			return nil, ErrUnsafe
		}
	}
	return names, nil
}

func (s *sqliteWindowsStaging) checkFile(f *os.File, name string, expected sqliteWindowsIdentity) (int64, error) {
	if err := sqliteWindowsMatches(f, expected); err != nil {
		return 0, err
	}
	if err := validateFile(f); err != nil {
		return 0, err
	}
	if err := sqliteWindowsACL(f, ""); err != nil {
		return 0, err
	}
	actual, err := canonicalName(f)
	if err != nil || !strings.EqualFold(actual, filepath.Join(s.workspacePath(), name)) {
		return 0, ErrUnsafe
	}
	info, err := f.Stat()
	if err != nil || info.Size() < 0 {
		return 0, ErrUnavailable
	}
	return info.Size(), nil
}

func (s *sqliteWindowsStaging) observeSidecar(name string) (_ int64, finalErr error) {
	f, err := sqliteWindowsOpen(windows.Handle(s.work.Fd()), name,
		sqliteWindowsOpenOptions{metadata: true, share: windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE})
	if err != nil {
		return 0, err
	}
	defer func() {
		if err := f.Close(); err != nil && finalErr == nil {
			finalErr = ErrUnavailable
		}
	}()
	id, err := sqliteWindowsFileID(f)
	if err != nil {
		return 0, err
	}
	if observed, exists := s.sidecars[name]; exists && observed != id {
		return 0, ErrUnsafe
	}
	size, err := s.checkFile(f, name, id)
	if err != nil {
		return 0, err
	}
	s.sidecars[name] = id
	return size, nil
}

func (s *sqliteWindowsStaging) inspect(maxDatabase, maxWorkspace int64, sealed bool) error {
	if s.closed || s.work == nil || s.main == nil {
		return ErrClosed
	}
	if maxDatabase < 1 || maxDatabase > MaxBytes || maxWorkspace < maxDatabase || maxWorkspace > 2*MaxBytes {
		return ErrLimit
	}
	if err := s.inspectDirectories(); err != nil {
		return err
	}
	names, err := s.names()
	if err != nil {
		return err
	}
	mainFound := false
	for _, name := range names {
		if name == sqliteWindowsMain {
			mainFound = true
		} else if sealed {
			return ErrIncomplete
		}
	}
	if !mainFound {
		return ErrUnsafe
	}
	total, err := s.checkFile(s.main, sqliteWindowsMain, s.mainID)
	if err != nil {
		return err
	}
	if total > maxDatabase || sealed && total == 0 {
		return ErrLimit
	}
	for _, name := range names {
		if name == sqliteWindowsMain {
			continue
		}
		size, err := s.observeSidecar(name)
		if err != nil {
			return err
		}
		if size > maxWorkspace-total {
			return ErrLimit
		}
		total += size
	}
	// DELETE-mode journals can be recreated by a later transaction. Retire a
	// generation only after this entire successful check observed its absence;
	// a replacement without that observation still fails in observeSidecar.
	for name := range s.sidecars {
		present := false
		for _, observed := range names {
			if observed == name {
				present = true
				break
			}
		}
		if !present {
			delete(s.sidecars, name)
		}
	}
	return nil
}

func (s *sqliteWindowsStaging) seal() (*os.File, error) {
	if s.closed || s.sealed || s.main == nil {
		return nil, ErrClosed
	}
	if err := s.inspect(MaxBytes, 2*MaxBytes, true); err != nil {
		return nil, err
	}
	// This transition is confined by the private DACL and the entire pinned
	// ancestor chain. It is not atomic against a malicious trusted same-SID
	// owner. Identity checks do not retroactively prevent earlier path writes.
	closeErr := s.main.Close()
	s.main = nil
	if closeErr != nil {
		return nil, ErrUnavailable
	}
	f, err := sqliteWindowsOpen(windows.Handle(s.work.Fd()), sqliteWindowsMain,
		sqliteWindowsOpenOptions{write: true, delete: true}) // share0 excludes live SQLite readers AND writers.
	if err != nil {
		return nil, err
	}
	s.main = f
	if _, err := s.checkFile(f, sqliteWindowsMain, s.mainID); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, ErrUnavailable
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, ErrUnavailable
	}
	s.sealed = true
	return f, nil
}

func (s *sqliteWindowsStaging) removeEntry(name string, expected sqliteWindowsIdentity) (finalErr error) {
	f, err := sqliteWindowsOpen(windows.Handle(s.work.Fd()), name,
		sqliteWindowsOpenOptions{write: true, delete: true})
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil && finalErr == nil {
			finalErr = ErrUnavailable
		}
	}()
	if _, err := s.checkFile(f, name, expected); err != nil {
		return err
	}
	return removeTemp(s.work, f, name)
}

func (s *sqliteWindowsStaging) cleanup() error {
	if s.closed {
		return s.cleanupErr
	}
	s.closed = true
	keep := func(err error) {
		if err != nil && s.cleanupErr == nil {
			s.cleanupErr = err
		}
	}
	// Finish by closing every owned handle, even if a permissions/identity
	// check leaves private orphans. Unknown entries are never removed.
	if s.work != nil {
		keep(s.cleanupFiles())
		// The directory was created with DELETE access, so its exact original
		// handle can remove it without releasing its deny-delete pin first.
		if s.cleanupErr == nil {
			keep(removeTemp(nil, s.work, ""))
		}
		keep(sqliteWindowsClose(s.work))
		s.work = nil
	}
	if s.main != nil {
		keep(sqliteWindowsClose(s.main))
		s.main = nil
	}
	for i := len(s.chain) - 1; i >= 0; i-- {
		keep(sqliteWindowsClose(s.chain[i].file))
	}
	s.chain = nil
	return s.cleanupErr
}

func sqliteWindowsClose(f *os.File) error {
	if f.Close() != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *sqliteWindowsStaging) cleanupFiles() error {
	// A failed constructor can still own an empty workspace before acquiring
	// an ID or a main file. Delete that exact workspace handle, never its path.
	if !s.mainExists {
		return nil
	}
	if err := s.inspectDirectories(); err != nil {
		return err
	}
	names, err := s.names()
	if err != nil {
		return err
	}
	for _, name := range names {
		if name != sqliteWindowsMain {
			if _, err := s.observeSidecar(name); err != nil {
				return err
			}
		}
	}
	// Close the no-DELETE guard before asking for DELETE access. A sealed
	// handle is already exclusively owned and can be removed directly.
	mainRemoved := false
	if s.main != nil {
		if s.sealed {
			if _, err := s.checkFile(s.main, sqliteWindowsMain, s.mainID); err != nil {
				return err
			}
			if err := removeTemp(s.work, s.main, sqliteWindowsMain); err != nil {
				return err
			}
			mainRemoved = true
		}
		err := s.main.Close()
		s.main = nil
		if err != nil {
			return ErrUnavailable
		}
	}
	for _, name := range names {
		if name == sqliteWindowsMain {
			if !mainRemoved {
				if err := s.removeEntry(name, s.mainID); err != nil {
					return err
				}
			}
		} else if err := s.removeEntry(name, s.sidecars[name]); err != nil {
			return err
		}
	}
	return nil
}
