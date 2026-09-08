package backupmanifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Count before materializing typed slices: a compact array of {} must not cause
// a multi-gigabyte Report allocation before bounded rejects its element count.
// Byte size alone is not an adequate decoded-memory limit. Tokenization keeps
// at most six small stack frames/maps and one JSON string (bounded input), not
// an accumulated generic JSON tree. Final typed/canonical validation remains.
func preflight(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var files int
	if err := scanValue(d, 0, "", &files); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func scanValue(d *json.Decoder, depth int, field string, files *int) error {
	if depth > 6 {
		return ErrLimit
	}
	token, err := d.Token()
	if err != nil {
		return ErrInvalid
	}
	if depth == 0 && token != json.Delim('{') {
		return ErrInvalid
	}
	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
			return scanObject(d, depth, files)
		case '[':
			return scanArray(d, depth, field, files)
		default:
			return ErrInvalid
		}
	case string:
		if len(t) > 128 {
			return ErrLimit
		}
	case json.Number:
		if len(t) > 20 {
			return ErrLimit
		}
	case nil, bool:
		// Typed decoding and exact canonical comparison reject invalid null/bool.
	default:
		return ErrInvalid
	}
	return nil
}

func scanObject(d *json.Decoder, depth int, files *int) error {
	seen := make(map[string]bool)
	for d.More() {
		if len(seen) >= 32 {
			return ErrLimit
		}
		token, err := d.Token()
		if err != nil {
			return ErrInvalid
		}
		field, ok := token.(string)
		if !ok || len(field) > 64 || seen[field] {
			return ErrInvalid
		}
		seen[field] = true
		if err := scanValue(d, depth+1, field, files); err != nil {
			return err
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return ErrInvalid
	}
	return nil
}

func scanArray(d *json.Decoder, depth int, field string, files *int) error {
	// The wire format contains arrays only at the root's known inventory fields.
	if depth != 1 {
		return ErrInvalid
	}
	var limit int
	switch field {
	case "migrations":
		limit = MaxMigrations
	case "reports", "artifacts":
		limit = MaxEntries - 3
	case "key_versions":
		limit = 64
	case "audit_anchors", "jobs":
		limit = MaxOrganizations
	default:
		return ErrInvalid
	}
	for count := 0; d.More(); count++ {
		if count >= limit {
			return ErrLimit
		}
		if field == "reports" || field == "artifacts" {
			if *files >= MaxEntries-3 {
				return ErrLimit
			}
			*files++
		}
		if err := scanValue(d, depth+1, "", files); err != nil {
			return err
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim(']') {
		return ErrInvalid
	}
	return nil
}
