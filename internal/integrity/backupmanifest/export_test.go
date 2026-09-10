package backupmanifest

// TestOnlyFixture shares the existing owned synthetic manifest with external
// integration tests. This bridge exists only in the package's test binary;
// it adds no production export or alternate validation path.
var TestOnlyFixture = fixture

var TestOnlyScopedFixture = scopedFixture

var TestOnlyLegacyFixture = legacyFixture
