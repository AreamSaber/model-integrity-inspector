package structure

import (
	"encoding/json"
	"strconv"
	"strings"
)

func jsonClosure(text string) (brackets, quoted State, err error) {
	stack := make([]byte, 0, MaxDepth)
	inString, escaped, mismatch := false, false, false
	for i := 0; i < len(text); i++ {
		c := text[i]
		if inString {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			if len(stack) == MaxDepth {
				return Unknown, Unknown, ErrLimit
			}
			stack = append(stack, c)
		case '}', ']':
			if len(stack) == 0 || (c == '}' && stack[len(stack)-1] != '{') || (c == ']' && stack[len(stack)-1] != '[') {
				mismatch = true
			} else {
				stack = stack[:len(stack)-1]
			}
		}
	}
	brackets, quoted = Complete, Complete
	if len(stack) > 0 {
		brackets = Incomplete
	}
	if mismatch {
		brackets = Invalid
	}
	if inString {
		quoted = Incomplete
	}
	return
}

func analyzeJSON(text string, f *Features) error {
	brackets, quoted, err := jsonClosure(text)
	if err != nil {
		return err
	}
	f.Brackets, f.Strings = brackets, quoted
	f.Parse = Invalid
	if json.Valid([]byte(text)) {
		f.Parse = Complete
		f.CompleteUnits = 1
	} else if brackets == Incomplete || quoted == Incomplete {
		f.Parse = Incomplete
	}
	f.LastUnit = f.Parse
	f.StructureComplete = f.Parse == Complete
	f.HardTruncation = brackets == Incomplete || quoted == Incomplete
	return nil
}

func contentLines(lines []string) []string {
	// One or more terminal newline/whitespace lines are presentation only.
	// Interior blank lines remain visible and violate JSONL/sequence contracts.
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func analyzeJSONL(lines []string, c Contract, f *Features) error {
	lines = contentLines(lines)
	f.Parse, f.Brackets, f.Strings, f.LastUnit = Complete, Complete, Complete, Complete
	if c.JSONNumberKey != "" {
		f.Numbering = Complete
	}
	expected := c.FirstNumber
	if expected == 0 {
		expected = 1
	}
	for i, line := range lines {
		line = strings.TrimSpace(line)
		brackets, quoted, err := jsonClosure(line)
		if err != nil {
			return err
		}
		valid := len(line) > 0 && line[0] == '{' && json.Valid([]byte(line))
		if valid {
			f.CompleteUnits++
			if c.JSONNumberKey != "" {
				number, ok := jsonRecordNumber(line, c.JSONNumberKey)
				if !ok || number != expected {
					f.Numbering = Invalid
				}
				expected++
			}
		} else {
			f.Parse = Invalid
			if i == len(lines)-1 && (brackets == Incomplete || quoted == Incomplete) {
				f.Parse = Incomplete
				f.HardTruncation = true
			}
		}
		if brackets != Complete {
			f.Brackets = brackets
		}
		if quoted != Complete {
			f.Strings = quoted
		}
		if i == len(lines)-1 && !valid {
			f.LastUnit = Invalid
			if brackets == Incomplete || quoted == Incomplete {
				f.LastUnit = Incomplete
			}
		}
	}
	f.StructureComplete = f.Parse == Complete && f.Numbering != Invalid
	return nil
}

func jsonRecordNumber(line, key string) (int64, bool) {
	decoder := json.NewDecoder(strings.NewReader(line))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return 0, false
	}
	seen := map[string]bool{}
	var number int64
	found := false
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return 0, false
		}
		seen[name] = true
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return 0, false
		}
		if name == key {
			value, err := strconv.ParseInt(string(raw), 10, 64)
			if err != nil || value < 0 {
				return 0, false
			}
			number, found = value, true
		}
	}
	return number, found
}
