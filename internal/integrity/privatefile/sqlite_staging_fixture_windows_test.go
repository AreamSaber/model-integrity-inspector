//go:build windows

package privatefile

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestSQLiteFixtureProfileTraverseOnlyIsAncestor(t *testing.T) {
	base := newSQLiteTestDirectory(t)
	profile := sqliteWindowsTestChild(t, base, "synthetic-profile")
	sid, err := currentSID()
	if err != nil {
		t.Fatal("synthetic profile identity unavailable")
	}
	// This is a new test-owned directory, never the actual UserHomeDir ACL.
	if err := setTestDACL(profile, "D:P(A;OICI;FA;;;"+sid.String()+")(A;OICI;FA;;;SY)(A;;0x20;;;WD)"); err != nil {
		t.Fatal("synthetic traverse-only profile ACL setup failed")
	}
	stage := &sqliteWindowsStaging{}
	defer func() {
		if err := stage.cleanup(); err != nil {
			t.Error("synthetic profile handles did not close")
		}
	}()
	if err := openSQLiteTestProfileAncestors(stage, profile); err != nil {
		t.Fatalf("fixture rejected traverse-only profile ancestor: permissions=%t", errors.Is(err, ErrPermissions))
	}
	if len(stage.chain) < 2 || stage.parent().path != profile {
		t.Fatal("fixture did not pin the complete profile chain")
	}
	if err := sqliteWindowsCheckDirectory(stage.parent().file, profile, true); !errors.Is(err, ErrPermissions) {
		t.Fatal("production private-parent policy was weakened")
	}
	for _, entry := range stage.chain {
		if err := sqliteWindowsCheckDirectory(entry.file, entry.path, false); err != nil {
			t.Fatal("fixture ancestor policy differs from production")
		}
	}
	for _, path := range []string{base, profile} {
		if err := os.Rename(path, path+"-moved"); err == nil {
			_ = os.Rename(path+"-moved", path)
			t.Fatal("fixture ancestor was replaceable while pinned")
		}
	}
	child := newSQLiteTestDirectoryBelow(t, profile)
	private := &sqliteWindowsStaging{}
	defer func() {
		if err := private.cleanup(); err != nil {
			t.Error("strict private child handles did not close")
		}
	}()
	if err := private.openChain(child); err != nil {
		t.Fatal("new child did not satisfy unchanged production private-parent policy")
	}
	if err := revalidateSQLiteTestProfileAncestors(stage, profile); err != nil {
		t.Fatal("creating the private child invalidated the pinned profile chain")
	}
	if err := setTestDACL(child, "D:P(A;OICI;FA;;;"+sid.String()+")(A;OICI;FA;;;SY)(A;OIIO;FR;;;WD)"); err != nil {
		t.Fatal("synthetic child inheritable exposure setup failed")
	}
	check := sqliteWindowsCheckDirectory(private.parent().file, child, true)
	if err := protectTestDirectory(child); err != nil {
		t.Fatal("synthetic child DACL restoration failed")
	}
	if !errors.Is(check, ErrPermissions) {
		t.Fatal("strict child accepted inheritable outsider disclosure")
	}
}

func TestSQLiteFixtureProfileMutationAndLateACLChangesRejected(t *testing.T) {
	sid, err := currentSID()
	if err != nil {
		t.Fatal("synthetic profile identity unavailable")
	}
	for _, outsider := range []struct{ name, rights string }{
		{"delete", "0x10000"}, {"delete_child", "0x40"}, {"write_dacl", "0x40000"},
		{"write_owner", "0x80000"}, {"write_attributes", "0x100"}, {"write_ea", "0x10"}, {"generic_write", "GW"},
	} {
		t.Run(outsider.name, func(t *testing.T) {
			base := newSQLiteTestDirectory(t)
			profile := sqliteWindowsTestChild(t, base, "synthetic-profile")
			privateACL := "D:P(A;OICI;FA;;;" + sid.String() + ")(A;OICI;FA;;;SY)"
			unsafeACL := privateACL + "(A;;" + outsider.rights + ";;;WD)"
			if err := setTestDACL(profile, unsafeACL); err != nil {
				t.Fatal("synthetic profile mutation ACL setup failed")
			}
			rejected := &sqliteWindowsStaging{}
			admission := openSQLiteTestProfileAncestors(rejected, profile)
			closeErr := rejected.cleanup()
			if err := setTestDACL(profile, privateACL); err != nil {
				t.Fatal("synthetic profile DACL restoration failed")
			}
			if !errors.Is(admission, ErrPermissions) || closeErr != nil {
				t.Fatal("fixture accepted outsider mutation or leaked a rejected chain")
			}
			assertEntries(t, profile, 0)
			stage := &sqliteWindowsStaging{}
			defer func() {
				if err := stage.cleanup(); err != nil {
					t.Error("synthetic profile handles did not close")
				}
			}()
			if err := openSQLiteTestProfileAncestors(stage, profile); err != nil {
				t.Fatal("protected synthetic profile rejected")
			}
			if err := setTestDACL(profile, unsafeACL); err != nil {
				t.Fatal("synthetic late mutation ACL setup failed")
			}
			recheck := revalidateSQLiteTestProfileAncestors(stage, profile)
			if err := setTestDACL(profile, privateACL); err != nil {
				t.Fatal("synthetic late DACL restoration failed")
			}
			if !errors.Is(recheck, ErrPermissions) {
				t.Fatal("fixture omitted late ancestor ACL revalidation")
			}
			originalID := stage.parent().id
			stage.parent().id.low ^= 1
			identityCheck := revalidateSQLiteTestProfileAncestors(stage, profile)
			stage.parent().id = originalID
			if !errors.Is(identityCheck, ErrUnsafe) {
				t.Fatal("fixture omitted pinned ancestor identity revalidation")
			}
			if err := revalidateSQLiteTestProfileAncestors(stage, filepath.Join(profile, "not-opened")); !errors.Is(err, ErrUnsafe) {
				t.Fatal("fixture accepted an incomplete ancestor chain")
			}
			assertEntries(t, profile, 0)
		})
	}
}

func TestSQLiteFixturePrivateChildCleanupBelowTraverseProfile(t *testing.T) {
	base := newSQLiteTestDirectory(t)
	profile := sqliteWindowsTestChild(t, base, "synthetic-profile")
	sid, err := currentSID()
	if err != nil {
		t.Fatal("synthetic profile identity unavailable")
	}
	if err := setTestDACL(profile, "D:P(A;OICI;FA;;;"+sid.String()+")(A;OICI;FA;;;SY)(A;;0x20;;;WD)"); err != nil {
		t.Fatal("synthetic traverse-only profile ACL setup failed")
	}
	t.Run("create_and_cleanup", func(t *testing.T) {
		child := newSQLiteTestDirectoryBelow(t, profile)
		if filepath.Dir(child) != profile {
			t.Fatal("fixture private child left the selected ancestor")
		}
		assertEntries(t, profile, 1)
	})
	assertEntries(t, profile, 0)
}

func TestSQLiteFixtureTraverseProfileRealDatabaseAndCleanup(t *testing.T) {
	base := newSQLiteTestDirectory(t)
	profile := sqliteWindowsTestChild(t, base, "synthetic-profile")
	sid, err := currentSID()
	if err != nil {
		t.Fatal("synthetic profile identity unavailable")
	}
	if err := setTestDACL(profile, "D:P(A;OICI;FA;;;"+sid.String()+")(A;OICI;FA;;;SY)(A;;0x20;;;WD)"); err != nil {
		t.Fatal("synthetic traverse-only profile ACL setup failed")
	}
	t.Run("real_sqlite", func(t *testing.T) {
		child := newSQLiteTestDirectoryBelow(t, profile)
		var consumed int64
		receipt, err := WithSQLiteStaging(t.Context(), child, sqliteTestLimits(), buildSQLiteTestDatabase,
			func(_ context.Context, reader io.Reader) error {
				var err error
				consumed, err = io.Copy(io.Discard, reader)
				return err
			})
		if err != nil || consumed == 0 || receipt.Size != consumed || receipt.Published {
			t.Fatal("real SQLite staging below traverse-only profile did not complete privately")
		}
		assertSQLiteParentEmpty(t, child)
	})
	assertEntries(t, profile, 0)
}
