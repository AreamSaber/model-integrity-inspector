package structure

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

func analyzeSequence(lines []string, c Contract, f *Features) {
	lines = contentLines(lines)
	f.Parse, f.Numbering, f.LastUnit = Complete, Complete, Complete
	expected := c.FirstNumber
	if expected == 0 {
		expected = 1
	}
	for i, line := range lines {
		line = strings.TrimSpace(line)
		number, complete, partial := sequenceRecord(line, c.SequencePrefix)
		if complete {
			f.CompleteUnits++
			if number != expected {
				f.Numbering = Invalid
			}
			expected++
		} else {
			f.Parse = Invalid
			if i == len(lines)-1 {
				f.LastUnit = Invalid
				if partial {
					f.LastUnit = Incomplete
					f.HardTruncation = true
					f.Parse = Incomplete
				}
			}
		}
	}
	f.StructureComplete = f.Parse == Complete && f.Numbering == Complete
}

func sequenceRecord(line, prefix string) (int64, bool, bool) {
	if prefix != "" {
		marker := prefix + "|"
		if !strings.HasPrefix(line, marker) {
			return 0, false, line != "" && strings.HasPrefix(marker, line)
		}
		value := strings.TrimPrefix(line, marker)
		number, err := strconv.ParseInt(value, 10, 64)
		return number, err == nil && number > 0 && strconv.FormatInt(number, 10) == value, value == ""
	}
	// Generic numbered prose requires a nonempty completed unit after 1. / 1).
	end := 0
	for end < len(line) && line[end] >= '0' && line[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false, false
	}
	number, err := strconv.ParseInt(line[:end], 10, 64)
	if err != nil || number <= 0 {
		return 0, false, false
	}
	if end == len(line) {
		return number, false, true
	}
	if line[end] != '.' && line[end] != ')' {
		return number, false, false
	}
	unit := strings.TrimSpace(line[end+1:])
	return number, unit != "", unit == ""
}

func fenceState(lines []string) State {
	var open byte
	width := 0
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		indent := 0
		for indent < len(line) && line[indent] == ' ' {
			indent++
		}
		if indent > 3 {
			continue
		}
		line = line[indent:]
		if len(line) < 3 || (line[0] != '`' && line[0] != '~') {
			continue
		}
		marker := line[0]
		n := 0
		for n < len(line) && line[n] == marker {
			n++
		}
		if n < 3 {
			continue
		}
		tail := line[n:]
		if open == 0 {
			if marker == '`' && strings.ContainsRune(tail, '`') {
				continue
			}
			open, width = marker, n
		} else if marker == open && n >= width && strings.TrimSpace(tail) == "" {
			open, width = 0, 0
		}
	}
	if open != 0 {
		return Incomplete
	}
	return Complete
}

func sentenceState(text string) State {
	text = strings.TrimSpace(text)
	// Closing quotation marks/brackets do not hide a preceding sentence end.
	text = strings.TrimRight(text, "\"'”’」』）)]}")
	if text == "" {
		return Unknown
	}
	last, _ := utf8.DecodeLastRuneInString(text)
	if strings.ContainsRune(".!?。！？", last) {
		return Complete
	}
	if strings.ContainsRune(",，:：;；—-([{（", last) {
		return Incomplete
	}
	return Unknown
}
