//go:build windows

package privatefile

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This failure-only diagnostic reads the handles already retained by the opener.
// It never opens another path, changes an ACL, or retries a rejected fixture.
// Paths, principal names/SIDs, complete ACLs and native errors are not logged.
func logSQLiteProfileAncestryFailure(t *testing.T, stage *sqliteWindowsStaging, profile string, profilePrivate bool, failure error) {
	t.Helper()
	t.Logf("SQLite ancestry diagnostic failure=%s retained_depths=%d", sqliteACLDiagnosticError(failure), len(stage.chain))
	current, err := currentSID()
	if err != nil {
		t.Log("SQLite ancestry diagnostic current_identity=unavailable")
		return
	}
	for depth, entry := range stage.chain {
		// openChain itself bounds ancestry; retain an independent output bound.
		if depth >= 258 {
			t.Log("SQLite ancestry diagnostic depths=truncated")
			break
		}
		private := profilePrivate && strings.EqualFold(entry.path, profile)
		if entry.file == nil {
			t.Logf("SQLite ancestry diagnostic depth=%d metadata=unavailable", depth)
			continue
		}
		check := sqliteWindowsCheckDirectory(entry.file, entry.path, private)
		t.Logf("SQLite ancestry diagnostic depth=%d private=%t check=%s", depth, private, sqliteACLDiagnosticError(check))
		security, err := windows.GetSecurityInfo(windows.Handle(entry.file.Fd()), windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil || security == nil || !security.IsValid() {
			t.Logf("SQLite ancestry diagnostic depth=%d security=unavailable", depth)
			continue
		}
		owner, _, ownerErr := security.Owner()
		installerAllowed := ownerErr == nil && !private && sqliteWindowsInstallerOwner(owner, entry.path)
		for _, row := range sqliteACLDiagnosticRows(security, current, private, installerAllowed) {
			t.Logf("SQLite ancestry diagnostic depth=%d %s", depth, row)
		}
		runtime.KeepAlive(security)
	}
}

func sqliteACLDiagnosticError(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, ErrPermissions):
		return "permissions"
	case errors.Is(err, ErrUnsafe):
		return "unsafe"
	case errors.Is(err, ErrUnavailable):
		return "unavailable"
	case errors.Is(err, ErrFilesystem):
		return "filesystem"
	case errors.Is(err, ErrLimit):
		return "limit"
	default:
		return "other"
	}
}

func sqliteACLDiagnosticPrincipal(sid, current *windows.SID) string {
	switch {
	case sid == nil || !sid.IsValid():
		return "invalid"
	case current != nil && current.IsValid() && sid.Equals(current):
		return "current"
	case sid.IsWellKnown(windows.WinLocalSystemSid):
		return "system"
	case sid.IsWellKnown(windows.WinBuiltinAdministratorsSid):
		return "administrators"
	case sid.String() == sqliteWindowsInstallerSID:
		return "trusted_installer"
	default:
		return "other"
	}
}

func sqliteACLDiagnosticAllowed(class string) bool {
	return class == "current" || class == "system" || class == "administrators"
}

func sqliteACLDiagnosticRows(security *windows.SECURITY_DESCRIPTOR, current *windows.SID, private, installerAllowed bool) []string {
	if security == nil || !security.IsValid() {
		return []string{"security=invalid"}
	}
	defer runtime.KeepAlive(security)
	owner, _, err := security.Owner()
	ownerClass := "invalid"
	if err == nil {
		ownerClass = sqliteACLDiagnosticPrincipal(owner, current)
	}
	ownerAllowed := sqliteACLDiagnosticAllowed(ownerClass) || !private && installerAllowed && ownerClass == "trusted_installer"
	rows := []string{fmt.Sprintf("owner=%s owner_allowed=%t", ownerClass, ownerAllowed)}
	acl, _, err := security.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return append(rows, "dacl=missing_or_empty")
	}
	const mutations = windows.DELETE | 0x40 | windows.WRITE_DAC | windows.WRITE_OWNER |
		windows.FILE_WRITE_ATTRIBUTES | windows.FILE_WRITE_EA | windows.GENERIC_WRITE | windows.GENERIC_ALL
	sensitive := uint32(mutations)
	if private {
		sensitive |= windows.FILE_READ_DATA | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
			windows.FILE_EXECUTE | windows.GENERIC_READ | windows.GENERIC_EXECUTE
	}
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		if index >= 64 {
			rows = append(rows, "aces=truncated")
			break
		}
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, index, &ace) != nil || ace == nil {
			rows = append(rows, fmt.Sprintf("ace=%d metadata=unavailable", index))
			continue
		}
		inheritOnly := ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0
		kind := "other"
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			kind = "allow"
		case windows.ACCESS_DENIED_ACE_TYPE:
			kind = "deny"
		}
		if kind == "other" || ace.Header.AceSize < 16 {
			rows = append(rows, fmt.Sprintf("ace=%d kind=%s metadata=unsupported inherit_only=%t", index, kind, inheritOnly))
			continue
		}
		// #nosec G103 -- OS-validated basic ACE, with SID extent checked below.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		class := "invalid"
		if sid.IsValid() && sid.Len()+8 <= int(ace.Header.AceSize) {
			class = sqliteACLDiagnosticPrincipal(sid, current)
		}
		rights := uint32(ace.Mask) & sensitive
		ignored := kind == "deny" || !private && inheritOnly
		risk := !ignored && rights != 0 && !sqliteACLDiagnosticAllowed(class)
		// Only the fixed policy-sensitive bits are emitted, never a raw ACL mask.
		rows = append(rows, fmt.Sprintf("ace=%d kind=%s principal=%s sensitive_rights=0x%08x inherit_only=%t ignored=%t risk=%t",
			index, kind, class, rights, inheritOnly, ignored, risk))
	}
	return rows
}

func TestSQLiteACLDiagnosticClosedClassesAndPrivatePolicy(t *testing.T) {
	current, err := windows.StringToSid("S-1-5-21-100-200-300-400")
	if err != nil {
		t.Fatal("synthetic current identity")
	}
	security, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;;0x40;;;WD)(A;IO;GR;;;WD)(D;;GA;;;WD)")
	if err != nil {
		t.Fatal("synthetic security descriptor")
	}
	ancestor := strings.Join(sqliteACLDiagnosticRows(security, current, false, false), "\n")
	private := strings.Join(sqliteACLDiagnosticRows(security, current, true, false), "\n")
	for _, want := range []string{
		"owner=administrators owner_allowed=true",
		"principal=other sensitive_rights=0x00000040 inherit_only=false ignored=false risk=true",
		"principal=other sensitive_rights=0x00000000 inherit_only=true ignored=true risk=false",
		"kind=deny principal=other sensitive_rights=0x10000000 inherit_only=false ignored=true risk=false",
	} {
		if !strings.Contains(ancestor, want) {
			t.Fatal("ancestor diagnostic lost closed policy fact")
		}
	}
	if !strings.Contains(private, "principal=other sensitive_rights=0x80000000 inherit_only=true ignored=false risk=true") {
		t.Fatal("private diagnostic lost inheritable read exposure")
	}
	for _, value := range []string{ancestor, private} {
		if strings.Contains(value, "S-1-") || strings.Contains(value, "O:BA") || strings.Contains(value, "\\") || strings.Contains(value, "100-200") {
			t.Fatal("diagnostic exposed a source representation")
		}
	}
	for _, test := range []struct{ sid, want string }{
		{current.String(), "current"}, {"S-1-5-18", "system"}, {"S-1-5-32-544", "administrators"},
		{sqliteWindowsInstallerSID, "trusted_installer"}, {"S-1-1-0", "other"},
	} {
		sid, err := windows.StringToSid(test.sid)
		if err != nil || sqliteACLDiagnosticPrincipal(sid, current) != test.want {
			t.Fatal("wrong closed principal category")
		}
	}
	if sqliteACLDiagnosticPrincipal(nil, current) != "invalid" || sqliteACLDiagnosticError(errors.New("synthetic path/identity must not escape")) != "other" ||
		sqliteACLDiagnosticError(fmt.Errorf("private native context: %w", ErrPermissions)) != "permissions" {
		t.Fatal("diagnostic error or principal was not closed")
	}
}

func TestSQLiteACLDiagnosticOutputBoundAndInstallerScope(t *testing.T) {
	security, err := windows.SecurityDescriptorFromString("O:" + sqliteWindowsInstallerSID + "D:P" + strings.Repeat("(A;;GR;;;WD)", 65))
	if err != nil {
		t.Fatal("synthetic bounded security descriptor")
	}
	rows := sqliteACLDiagnosticRows(security, nil, false, true)
	if len(rows) != 66 || rows[len(rows)-1] != "aces=truncated" || rows[0] != "owner=trusted_installer owner_allowed=true" {
		t.Fatal("diagnostic output bound or installer root category changed")
	}
	for _, scope := range []struct{ private, installerAllowed bool }{{true, true}, {false, false}} {
		rows := sqliteACLDiagnosticRows(security, nil, scope.private, scope.installerAllowed)
		if rows[0] != "owner=trusted_installer owner_allowed=false" {
			t.Fatal("diagnostic expanded installer owner scope")
		}
	}
}
