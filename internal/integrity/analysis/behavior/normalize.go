package behavior

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"unicode"
)

// These are development suppression rules, not calibrated language models.
// A repeat candidate is an observable string pattern, never an anomaly verdict.
const minimumInformativeRunes = 12

var courtesyPhrases = []string{
	"here is the requested output", "here is the result", "here is the answer",
	"the answer is", "the result is", "as requested", "you are welcome",
	"thank you", "thanks", "certainly", "of course", "sure", "okay", "ok",
	"answer", "result", "output", "json", "done", "hello", "hi",
	"以下是结果", "结果如下", "答案如下", "答案是", "结果是", "没问题",
	"不客气", "当然可以", "可以", "好的", "谢谢", "您好", "你好", "完成",
}

func digest(domain, value string) string {
	sum := sha256.Sum256([]byte("mii-behavior\x00" + Version + "\x00" + domain + "\x00" + value))
	return hex.EncodeToString(sum[:])
}

func variablesFor(sample Sample) []string {
	values := append([]string(nil), sample.Variables...)
	for _, value := range []string{sample.Contract.Expected, sample.Contract.Key} {
		if markerPattern.MatchString(value) {
			values = append(values, value)
		}
	}
	return values
}

// This intentionally does not claim Unicode NFKC, semantic equivalence, or
// brand recognition. It folds case/whitespace and masks only planned markers.
func normalized(value string, variables []string) (string, int, string) {
	value = strings.ToLower(value)
	markers := append([]string(nil), variables...)
	sort.Slice(markers, func(i, j int) bool { return len(markers[i]) > len(markers[j]) })
	for _, marker := range markers {
		value = strings.ReplaceAll(value, strings.ToLower(marker), "\x00")
	}
	value = strings.Join(strings.Fields(value), " ")
	visible := strings.ReplaceAll(value, "\x00", " ")
	letters := 0
	for _, r := range visible {
		if unicode.IsLetter(r) {
			letters++
		}
	}
	if letters == 0 {
		return value, letters, "marker_whitespace_or_punctuation_only"
	}
	plain := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			return r
		}
		return ' '
	}, visible)
	plain = " " + strings.Join(strings.Fields(plain), " ") + " "
	for {
		before := plain
		for _, phrase := range courtesyPhrases {
			if strings.IndexFunc(phrase, func(r rune) bool { return r > 127 }) >= 0 {
				plain = strings.ReplaceAll(plain, phrase, " ")
			} else {
				plain = strings.ReplaceAll(plain, " "+phrase+" ", " ")
			}
		}
		plain = " " + strings.Join(strings.Fields(plain), " ") + " "
		if plain == before {
			break
		}
	}
	if strings.TrimSpace(plain) == "" {
		return value, letters, "common_courtesy"
	}
	if letters < minimumInformativeRunes {
		return value, letters, "insufficient_distinctive_text"
	}
	return value, letters, ""
}

func evidenceFor(sample Sample, text string, start, end int, kind EvidenceKind) Evidence {
	norm, count, suppression := normalized(text[start:end], variablesFor(sample))
	return Evidence{SampleID: freshFeatures(sample.ID).SampleID, StartByte: start, EndByte: end, Kind: kind, NormalizedSHA256: digest(string(kind), norm), InformativeRunes: count, Candidate: suppression == "", Suppression: suppression}
}
