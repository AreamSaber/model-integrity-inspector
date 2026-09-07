package repository

import (
	"strings"
	"testing"
)

func TestMigrationCommentsAreNeverExecuted(t *testing.T) {
	script := "-- a description ending in a semicolon;\n\nCREATE TABLE example(id INTEGER);\n-- trailing note;\n"
	statements := migrationStatements(script)
	if len(statements) != 1 || strings.TrimSpace(statements[0]) != "CREATE TABLE example(id INTEGER);" {
		t.Fatalf("comment-only SQL emitted: %#v", statements)
	}
	if len(migrationStatements("-- comment-only;\n-- one more\n")) != 0 {
		t.Fatal("comment-only migration emitted a statement")
	}
	trigger := "CREATE TRIGGER test AFTER INSERT ON t BEGIN SELECT 1; SELECT 2; END;"
	if got := migrationStatements(trigger); len(got) != 1 || strings.TrimSpace(got[0]) != trigger {
		t.Fatal("one-line trigger split internally")
	}
}
