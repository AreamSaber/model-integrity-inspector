package tokenrisk

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestBuiltinRuntimeGolden(t *testing.T) {
	input := Input{OrganizationID: 1, RunID: 2, Samples: fixture([]int64{128, 256, 512, 1024}, 6, func(tier int64, repetition int) int64 { return min(tier, 256) + int64(repetition%3) })}
	result, err := Analyze(input)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	if got := hex.EncodeToString(hash[:]); got != "7f08924aa981a93a6163be30cb47783a149cedebcd4b744af3336ac3279c7c45" {
		t.Fatalf("builtin output drift: %s", got)
	}
}
