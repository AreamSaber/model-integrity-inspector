//go:build windows || linux

package privatefile

// Test-only fixture bridges for the external integration tests. Production
// exports and the platform-native fixture protection/cleanup stay unchanged.
var (
	BackupIntegrationTestDir     = privateDir
	BackupIntegrationTestLimits  = testLimits
	BackupIntegrationTestProduce = testProduce
	BackupIntegrationTestRead    = readTestFile
	BackupIntegrationTestWrite   = writeTestFile
	BackupIntegrationTestEntries = assertEntries
)
