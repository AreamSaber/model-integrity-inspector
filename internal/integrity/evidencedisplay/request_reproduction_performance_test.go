package evidencedisplay

import (
	"context"
	"math/rand/v2"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

// Frozen pre-optimization policy oracle: keep all three independent semantics,
// including PEM's ToLower, token word boundaries and assignment Unicode fold.
// Neither this oracle nor the production regex expressions may be weakened to
// make a faster implementation pass.
func originalRequestSuspectOracle(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "-----begin") && strings.Contains(lower, "private key-----") || suspectToken.MatchString(value) {
		return true
	}
	for _, match := range suspectAssignment.FindAllStringSubmatch(value, -1) {
		v := strings.Trim(strings.TrimSpace(match[1]), "\"'")
		if v != marker && !strings.EqualFold(v, "Bearer "+marker) {
			return true
		}
	}
	return false
}

func TestRequestReproductionSuspectOptimizationEqualsOriginalPolicy(t *testing.T) {
	if suspectToken.String() != `\b(?:sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{16,}|AKIA[A-Z0-9]{16})\b` || suspectAssignment.String() != `(?i)(?:authorization|api[_-]?key|access[_-]?token|password|secret)["']?\s*[:=]\s*([^\r\n,;}]+)` {
		t.Fatal("frozen original policy expressions changed")
	}
	values := []string{
		"", "ordinary text", strings.Repeat("x", 900<<10),
		"-----BEGIN PRIVATE KEY-----", "-----begin encrypted private key-----", "-----begin\nprivate key-----", "-----BEGIN CERTIFICATE-----",
		"sk-12345678", "xsk-12345678", "é_sk-12345678", "é sk-12345678", "SK-12345678", "sk-1234567", "sk-12345678-", "sk-12345678_",
		"ghp_1234567890123456", "xghp_1234567890123456", "GHP_1234567890123456", "AKIA1234567890123456", "akia1234567890123456",
		"password", "password=", "password:\n", "secret=[REDACTED]", "secret='Bearer [REDACTED]'", "secret=[REDACTED]\npassword=unsafe",
		"unboundedprefixauthorization=unsafe", "ſecret: unsafe", "paſſword=unsafe", "API_KEY: unsafe", "acceſſ_token=unsafe",
		"api__key: unsafe", "access--token: unsafe", "secret\x00=unsafe", "secret\u00a0=unsafe", "secret\t = unsafe", "secret\r\n= unsafe",
		"密钥和普通文本", "authorization='Bearer [REDACTED]'", "authorization='Bearer [REDACTED] extra'", "PASSWORD= \"[REDACTED]\"",
	}
	for _, name := range []string{"authorization", "apikey", "api_key", "api-key", "accesstoken", "access_token", "access-token", "password", "secret"} {
		for _, spelling := range []string{name, strings.ToUpper(name)} {
			for _, before := range []string{"", "prefix", "_", "é", "\n"} {
				for _, separator := range []string{":", "=", "' = ", "\"\t:\n"} {
					for _, content := range []string{"unsafe", marker, "Bearer " + marker, "", "\n", marker + ", secret=unsafe"} {
						values = append(values, before+spelling+separator+content)
					}
				}
			}
		}
		// Enumerate every SimpleFold alternative for each ASCII letter, not
		// only lowercase/uppercase. This includes long s and Kelvin sign.
		for index, letter := range name {
			for folded := unicode.SimpleFold(letter); folded != letter; folded = unicode.SimpleFold(folded) {
				values = append(values, name[:index]+string(folded)+name[index+1:]+"=unsafe")
			}
		}
	}
	// #nosec G404 -- deterministic synthetic differential corpus, not security randomness.
	random := rand.New(rand.NewPCG(0x862761, 0x419298))
	alphabet := []rune("abxyzAPS_-=:\"'\t\r\n,;}ſK密钥é😀")
	for range 512 {
		var value strings.Builder
		for range random.IntN(256) {
			value.WriteRune(alphabet[random.IntN(len(alphabet))])
		}
		values = append(values, value.String())
	}
	for index, value := range values {
		if suspectAssignment.MatchString(value) && !suspectAssignmentPossible(value, strings.ToLower(value)) {
			t.Fatalf("assignment candidate false negative at synthetic case %d", index)
		}
		if suspect(value) != originalRequestSuspectOracle(value) {
			t.Fatalf("policy oracle mismatch at synthetic case %d", index)
		}
	}
}

func FuzzRequestReproductionSuspectOptimizationEqualsOriginalPolicy(f *testing.F) {
	for _, seed := range []string{"ordinary", "ſecret=unsafe", "api_Key=unsafe", "xsk-12345678", "é sk-12345678", "-----BEGIN PRIVATE KEY-----", "secret=[REDACTED]", "prefixauthorization:unsafe"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > MaxTextBytes || !utf8.ValidString(value) {
			return
		}
		if suspect(value) != originalRequestSuspectOracle(value) {
			t.Fatal("optimized policy differs from frozen oracle")
		}
		if suspectAssignment.MatchString(value) && !suspectAssignmentPossible(value, strings.ToLower(value)) {
			t.Fatal("assignment prefilter missed an original regexp match")
		}
	})
}

func TestRequestReproductionSuspectPrefilterAlwaysFallsBackForUnicode(t *testing.T) {
	for value := rune(utf8.RuneSelf); value <= unicode.MaxRune; value++ {
		if !utf8.ValidRune(value) {
			continue
		}
		text := string(value)
		if !suspectAssignmentPossible(text, strings.ToLower(text)) {
			t.Fatalf("non-ASCII input failed to use original regex at rune %d", value)
		}
	}
}

func BenchmarkRequestReproductionLargeBoundedPrepare(b *testing.B) {
	source := reproductionSource(b, "", func(request *domain.NormalizedRequest) {
		request.Messages[0].Content = strings.Repeat("x", 900<<10)
	})
	b.SetBytes(900 << 10)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		prepared, err := PrepareRequestReproduction(context.Background(), source, []byte(displayCanary), nil)
		if err != nil {
			b.Fatal("bounded request preparation did not finish successfully")
		}
		prepared.Close()
	}
}

func BenchmarkRequestReproductionSuspect900KiB(b *testing.B) {
	value := strings.Repeat("x", 900<<10)
	for _, item := range []struct {
		name string
		run  func(string) bool
	}{{"original", originalRequestSuspectOracle}, {"current", suspect}} {
		b.Run(item.name, func(b *testing.B) {
			b.SetBytes(int64(len(value)))
			b.ReportAllocs()
			for b.Loop() {
				if item.run(value) {
					b.Fatal("synthetic benign request was classified as suspicious")
				}
			}
		})
	}
}
