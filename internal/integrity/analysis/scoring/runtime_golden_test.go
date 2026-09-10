package scoring

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestBuiltinRuntimeGolden(t *testing.T) {
	input := behaviorInput(t, formatDifferential, "strong")
	result, err := Analyze(input)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	if got := hex.EncodeToString(hash[:]); got != "0b875b1faf77b70e3a017009fe7b5d2adeb40e3692e467fde74811a17a3e8bc4" {
		t.Fatalf("builtin output drift: %s", got)
	}
}
