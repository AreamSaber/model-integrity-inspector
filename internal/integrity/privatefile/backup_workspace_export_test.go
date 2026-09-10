//go:build windows || linux

package privatefile

// Test-only bridges reuse the real SQLite builder and strict native fixture;
// importing secret from this package's internal tests would create a cycle.
var BackupWorkspaceTestDirectory = newSQLiteTestDirectory
var BackupWorkspaceTestBuildSQLite = buildSQLiteTestDatabase
var BackupWorkspaceTestSQLiteLimits = sqliteTestLimits
