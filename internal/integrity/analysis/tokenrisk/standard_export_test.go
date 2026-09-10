package tokenrisk

import "testing"

// Only the external cross-module Standard60 tests use these narrow bridges.
// Keep the original fixture, digest, analyzer assertion and family predicate;
// no second algorithm or production API is introduced to break the test cycle.
func StandardSampleForTest(id, tier, output int64) Sample { return sample(id, tier, output) }
func StandardDigestForTest(value string) string           { return testDigest(value) }
func StandardLadderForTest(s Sample) bool                 { return ladder(s) }
func StandardAnalyzeForTest(t testing.TB, samples []Sample) Result {
	t.Helper()
	return analyzeTest(t, samples)
}
