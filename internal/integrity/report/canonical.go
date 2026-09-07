package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
)

// This is the versioned project profile, NOT an RFC 8785/JCS implementation.
// Object keys are sorted, arrays preserve their defined order, finite safe
// numbers use Go's shortest round-trip binary64 form, and negative zero is 0.
func canonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInput
	}
	if len(raw) > MaxOutputBytes {
		return nil, ErrLimit
	}
	var normalized any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&normalized) != nil {
		return nil, ErrInput
	}
	var output bytes.Buffer
	var encode func(any) error
	encode = func(v any) error {
		if output.Len() > MaxOutputBytes {
			return ErrLimit
		}
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			output.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					output.WriteByte(',')
				}
				key, _ := json.Marshal(k)
				output.Write(key)
				output.WriteByte(':')
				if err := encode(x[k]); err != nil {
					return err
				}
			}
			output.WriteByte('}')
		case []any:
			output.WriteByte('[')
			for i, item := range x {
				if i > 0 {
					output.WriteByte(',')
				}
				if err := encode(item); err != nil {
					return err
				}
			}
			output.WriteByte(']')
		case json.Number:
			n, err := strconv.ParseFloat(string(x), 64)
			if err != nil || !number(n, -9007199254740991, 9007199254740991) {
				return ErrInput
			}
			if n == 0 {
				output.WriteByte('0')
			} else {
				output.WriteString(strconv.FormatFloat(n, 'g', -1, 64))
			}
		default:
			raw, err := json.Marshal(x)
			if err != nil {
				return ErrInput
			}
			output.Write(raw)
		}
		if output.Len() > MaxOutputBytes {
			return ErrLimit
		}
		return nil
	}
	if err := encode(normalized); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func Generate(snapshot *Snapshot) (*Artifacts, error) {
	if snapshot == nil || snapshot.doc.SchemaVersion != SchemaVersion || snapshot.doc.CanonicalVersion != CanonicalVersion {
		return nil, ErrInput
	}
	content, err := canonical(snapshot.doc)
	if err != nil {
		return nil, err
	}
	contentHash := digest(content)
	// The content_hash field is entirely ABSENT from the hashed document.
	// It is included in the final JSON file, whose file hash is independent.
	final := struct {
		document
		ContentHash string `json:"content_hash"`
	}{snapshot.doc, contentHash}
	jsonBytes, err := canonical(final)
	if err != nil {
		return nil, err
	}
	htmlBytes, err := renderHTML(snapshot.doc, contentHash, jsonBytes)
	if err != nil {
		return nil, err
	}
	return &Artifacts{json: jsonBytes, html: htmlBytes, contentHash: contentHash, jsonHash: digest(jsonBytes), htmlHash: digest(htmlBytes)}, nil
}
