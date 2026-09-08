package evidencedisplay

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const marker = "[REDACTED]"

type boundedText struct {
	ctx   context.Context
	value strings.Builder
	limit int
}

func (b *boundedText) Write(p []byte) (int, error) { return b.WriteString(string(p)) }
func (b *boundedText) WriteString(s string) (int, error) {
	if b.ctx.Err() != nil {
		return 0, ErrCancelled
	}
	if len(s) > b.limit-b.value.Len() {
		return 0, ErrLimit
	}
	return b.value.WriteString(s)
}

func variants(value []byte) []string {
	s := string(value)
	quoted, _ := json.Marshal(s)
	jsonForm := string(quoted[1 : len(quoted)-1])
	clear(quoted)
	var unicodeForm, percentUpper, percentLower strings.Builder
	for _, r := range s {
		units := []rune{r}
		if r > 0xffff {
			hi, lo := utf16.EncodeRune(r)
			units = []rune{hi, lo}
		}
		for _, unit := range units {
			hexUnit := strconv.FormatInt(int64(unit), 16)
			unicodeForm.WriteString(`\u` + strings.Repeat("0", 4-len(hexUnit)) + hexUnit)
		}
	}
	const upper, lower = "0123456789ABCDEF", "0123456789abcdef"
	for _, b := range value {
		percentUpper.WriteByte('%')
		percentUpper.WriteByte(upper[b>>4])
		percentUpper.WriteByte(upper[b&15])
		percentLower.WriteByte('%')
		percentLower.WriteByte(lower[b>>4])
		percentLower.WriteByte(lower[b&15])
	}
	return []string{s, jsonForm, unicodeForm.String(), strings.ReplaceAll(strings.ToUpper(unicodeForm.String()), `\U`, `\u`), url.QueryEscape(s), url.PathEscape(s), percentUpper.String(), percentLower.String(), base64.StdEncoding.EncodeToString(value), base64.RawStdEncoding.EncodeToString(value), base64.URLEncoding.EncodeToString(value), base64.RawURLEncoding.EncodeToString(value), hex.EncodeToString(value), strings.ToUpper(hex.EncodeToString(value))}
}

func dictionary(ctx context.Context, key []byte, headers map[string][]byte) (*strings.Replacer, []string, error) {
	if len(key) == 0 || len(key) > 8192 || len(headers) > 32 {
		return nil, nil, ErrInvalid
	}
	values := [][]byte{key}
	total := len(key)
	names := make(map[string]bool, len(headers))
	for name, value := range headers {
		if len(name) == 0 || len(name) > 128 || names[strings.ToLower(name)] {
			return nil, nil, ErrInvalid
		}
		names[strings.ToLower(name)] = true
		for _, r := range name {
			if r <= 32 || r >= 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={} ", r) {
				return nil, nil, ErrInvalid
			}
		}
		if len(value) > 8192 {
			return nil, nil, ErrInvalid
		}
		total += len(name) + len(value)
		if total > 32<<10 {
			return nil, nil, ErrLimit
		}
		if len(value) != 0 {
			values = append(values, value)
		}
	}
	unique := map[string]bool{}
	bytesUsed := 0
	for _, value := range values {
		if ctx.Err() != nil {
			return nil, nil, ErrCancelled
		}
		if !utf8.Valid(value) || strings.ContainsAny(string(value), "\r\n\x00") {
			return nil, nil, ErrInvalid
		}
		// Never ignore short credentials: matching arbitrary ordinary text and
		// the fixed output schema cannot establish a useful display boundary.
		if len(value) < 4 {
			return nil, nil, ErrPolicy
		}
		forms := variants(value)
		if len(forms) > 16 {
			return nil, nil, ErrLimit
		}
		for _, form := range forms {
			if unique[form] {
				continue
			}
			if form == "" || strings.Contains(marker, form) {
				return nil, nil, ErrPolicy
			}
			bytesUsed += len(form)
			if bytesUsed > MaxDictionaryBytes {
				return nil, nil, ErrLimit
			}
			unique[form] = true
		}
	}
	patterns := make([]string, 0, len(unique))
	for value := range unique {
		patterns = append(patterns, value)
	}
	sort.Slice(patterns, func(i, j int) bool {
		if len(patterns[i]) == len(patterns[j]) {
			return patterns[i] < patterns[j]
		}
		return len(patterns[i]) > len(patterns[j])
	})
	pairs := make([]string, 0, len(patterns)*2)
	for _, pattern := range patterns {
		pairs = append(pairs, pattern, marker)
	}
	return strings.NewReplacer(pairs...), patterns, nil
}

var suspectToken = regexp.MustCompile(`\b(?:sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{16,}|AKIA[A-Z0-9]{16})\b`)
var suspectAssignment = regexp.MustCompile(`(?i)(?:authorization|api[_-]?key|access[_-]?token|password|secret)["']?\s*[:=]\s*([^\r\n,;}]+)`)

func suspect(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "-----begin") && strings.Contains(lower, "private key-----") {
		return true
	}
	// These exact, case-sensitive prefixes are necessary but not sufficient.
	// Keep the original regex responsible for its suffix and word boundaries.
	if (strings.Contains(value, "sk-") || strings.Contains(value, "ghp_") || strings.Contains(value, "AKIA")) && suspectToken.MatchString(value) {
		return true
	}
	if !suspectAssignmentPossible(value, lower) {
		return false
	}
	for _, match := range suspectAssignment.FindAllStringSubmatch(value, -1) {
		v := strings.Trim(strings.TrimSpace(match[1]), "\"'")
		if v != marker && !strings.EqualFold(v, "Bearer "+marker) {
			return true
		}
	}
	return false
}

func suspectAssignmentPossible(value, lower string) bool {
	// Non-ASCII input always falls back to the unchanged Unicode-folding regex,
	// including long s and Kelvin sign. Do not replace its semantics with an
	// approximate normalization. The common large ASCII case can use fast byte
	// searches instead of running an unanchored regexp machine at every rune.
	for index := range len(value) {
		if value[index] >= utf8.RuneSelf {
			return true
		}
	}
	for _, prefix := range []string{"authorization", "apikey", "api_key", "api-key", "accesstoken", "access_token", "access-token", "password", "secret"} {
		if strings.Contains(lower, prefix) {
			return true
		}
	}
	return false
}

func redactText(ctx context.Context, r *strings.Replacer, value string) (string, error) {
	if len(value) > MaxTextBytes || !utf8.ValidString(value) {
		return "", ErrLimit
	}
	w := &boundedText{ctx: ctx, limit: MaxTextBytes}
	if _, err := r.WriteString(w, value); err != nil {
		return "", err
	}
	redacted := w.value.String()
	if suspect(redacted) {
		return "", ErrPolicy
	}
	return redacted, nil
}

func prepareContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, ErrInvalid
	}
	if ctx.Err() != nil {
		return nil, nil, ErrCancelled
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	return bounded, cancel, nil
}
