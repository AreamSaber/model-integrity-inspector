package tokenizer

import (
	"errors"
	"math"
	"time"
	"unicode/utf8"

	"github.com/dlclark/regexp2/v2"
)

// Patterns are frozen from openai/tiktoken 0.14.0. Python possessive quantifiers
// in cl100k are expressed as equivalent atomic groups for the .NET-compatible
// regexp engine. The outer group avoids the dependency's generated-regexp
// registration: differential tests found its generated code drops NUL and
// splits several mixed-newline runs differently from the official tokenizer.
const clPattern = `(?:'(?i:[sdmt]|ll|ve|re)|(?>[^\r\n\p{L}\p{N}]?)(?>\p{L}+)|(?>\p{N}{1,3})| ?(?>[^\s\p{L}\p{N}]+)(?>[\r\n]*)|(?>\s+)$|\s*[\r\n]|\s+(?!\S)|\s)`
const oPattern = `(?:[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]*[\p{Ll}\p{Lm}\p{Lo}\p{M}]+(?i:'s|'t|'re|'ve|'m|'ll|'d)?|[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]+[\p{Ll}\p{Lm}\p{Lo}\p{M}]*(?i:'s|'t|'re|'ve|'m|'ll|'d)?|\p{N}{1,3}| ?[^\s\p{L}\p{N}]+[\r\n/]*|\s*[\r\n]+|\s+(?!\S)|\s+)`

type counter interface{ Count(string) (int, error) }
type boundedBPE struct {
	ranks map[string]int
	split *regexp2.Regexp
}

func newBoundedBPE(id string, ranks map[string]int) (*boundedBPE, error) {
	pattern := clPattern
	if id == "o200k_base" {
		pattern = oPattern
	} else if id != "cl100k_base" {
		return nil, ErrBundle
	}
	re, err := regexp2.Compile(pattern, regexp2.None)
	if err != nil {
		return nil, ErrBundle
	}
	re.MatchTimeout = 100 * time.Millisecond
	return &boundedBPE{ranks: ranks, split: re}, nil
}

func (b *boundedBPE) Count(text string) (int, error) {
	match, err := b.split.FindStringMatch(text)
	if err != nil {
		return 0, ErrInput
	}
	count, runes, work := 0, 0, 0
	for match != nil {
		if match.RuneIndex != runes || match.RuneLength <= 0 {
			return 0, ErrInput
		}
		piece := match.String()
		runes += match.RuneLength
		if len(piece) > maxBPESpan+4 {
			return 0, ErrLimit
		}
		work += len(piece) * len(piece)
		if work > maxBPEWork {
			return 0, ErrLimit
		}
		if _, ok := b.ranks[piece]; ok {
			count++
		} else {
			n, err := b.countPiece(piece)
			if err != nil {
				return 0, err
			}
			count += n
		}
		match, err = b.split.FindNextMatch(match)
		if err != nil {
			return 0, ErrInput
		}
	}
	// A regex gap must never silently become an undercount labeled exact.
	if runes != utf8.RuneCountInString(text) {
		return 0, ErrInput
	}
	return count, nil
}

type bpePart struct{ start, end, next, previous, rank int }

func (b *boundedBPE) countPiece(piece string) (int, error) {
	if len(piece) == 0 {
		return 0, nil
	}
	parts := make([]bpePart, len(piece))
	for i := range parts {
		parts[i] = bpePart{start: i, end: i + 1, next: i + 1, previous: i - 1, rank: math.MaxInt}
		if _, ok := b.ranks[piece[i:i+1]]; !ok {
			return 0, ErrBundle
		}
	}
	parts[len(parts)-1].next = -1
	update := func(i int) {
		parts[i].rank = math.MaxInt
		if next := parts[i].next; next >= 0 {
			if rank, ok := b.ranks[piece[parts[i].start:parts[next].end]]; ok {
				parts[i].rank = rank
			}
		}
	}
	for i := range parts {
		update(i)
	}
	count := len(parts)
	for count > 1 {
		best, rank := -1, math.MaxInt
		// Strict < preserves the leftmost tie break in byte-pair encoding.
		for i := 0; i >= 0; i = parts[i].next {
			if parts[i].rank < rank {
				best, rank = i, parts[i].rank
			}
		}
		if best < 0 {
			break
		}
		right := parts[best].next
		if right < 0 {
			return 0, errors.New("MI_TOKENIZER_FAILED")
		}
		parts[best].end = parts[right].end
		parts[best].next = parts[right].next
		if next := parts[best].next; next >= 0 {
			parts[next].previous = best
		}
		update(best)
		if previous := parts[best].previous; previous >= 0 {
			update(previous)
		}
		count--
	}
	return count, nil
}
