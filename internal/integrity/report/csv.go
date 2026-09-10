package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// CSVSchemaVersion identifies the full-node JSON Pointer long-table profile,
// not the JSON document's schema or its existing canonical content hash.
const CSVSchemaVersion = "mii.report.csv.v1"

// CSVArtifact owns a complete S1 export. It is not a publication, authorization,
// signature, review approval, or a promise about a spreadsheet application's
// import behavior. Byte access never exposes its owned backing array.
type CSVArtifact struct {
	data                  []byte
	contentHash, fileHash string
}

func (a *CSVArtifact) Bytes() []byte {
	if a == nil {
		return nil
	}
	return append([]byte(nil), a.data...)
}

func (a *CSVArtifact) ContentHash() string {
	if a == nil {
		return ""
	}
	return a.contentHash
}

func (a *CSVArtifact) FileHash() string {
	if a == nil {
		return ""
	}
	return a.fileHash
}

func (a *CSVArtifact) SchemaVersion() string {
	if a == nil || a.data == nil {
		return ""
	}
	return CSVSchemaVersion
}

// GenerateCSV consumes only the same immutable, constructor-validated S1
// Snapshot as Generate. It does not perform IO or render HTML. The final JSON
// construction deliberately matches canonical-json.v1 without changing that
// profile, its golden bytes, or the existing Generate API.
func GenerateCSV(snapshot *Snapshot) (*CSVArtifact, error) {
	if snapshot == nil || snapshot.doc.SchemaVersion != SchemaVersion || snapshot.doc.CanonicalVersion != CanonicalVersion {
		return nil, ErrInput
	}
	content, err := canonical(snapshot.doc)
	if err != nil {
		return nil, err
	}
	contentHash := digest(content)
	final := struct {
		document
		ContentHash string `json:"content_hash"`
	}{snapshot.doc, contentHash}
	finalJSON, err := canonical(final)
	if err != nil {
		return nil, err
	}
	data, err := renderCSV(finalJSON)
	if err != nil {
		return nil, err
	}
	return &CSVArtifact{data: data, contentHash: contentHash, fileHash: digest(data)}, nil
}

// renderCSV is private: input is the complete canonical final JSON, never a
// public request, arbitrary user field selection, or a separate evidence source.
// Streaming tokens avoids materializing all rows or another full JSON tree.
func renderCSV(finalJSON []byte) ([]byte, error) {
	if len(finalJSON) > MaxOutputBytes {
		return nil, ErrLimit
	}
	if !utf8.Valid(finalJSON) {
		return nil, ErrInput
	}
	decoder := json.NewDecoder(bytes.NewReader(finalJSON))
	decoder.UseNumber()
	var output boundedWriter
	writer := csv.NewWriter(&output)
	writer.UseCRLF = true
	if err := writer.Write([]string{"csv_schema", "path", "value_type", "json_value"}); err != nil {
		return nil, csvRenderError(err)
	}
	if err := writeCSVNode(decoder, writer, "", 0); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrInput
	}
	// CSV buffers writes; a successful final record is not proof of a successful
	// flush. No partial bytes or artifact escape either failure path.
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, csvRenderError(err)
	}
	return output.buffer.Bytes(), nil
}

func csvRenderError(err error) error {
	if errors.Is(err, ErrLimit) {
		return ErrLimit
	}
	return ErrRender
}

func writeCSVNode(decoder *json.Decoder, writer *csv.Writer, path string, depth int) error {
	if depth > 24 || len(path) > 4096 {
		return ErrLimit
	}
	// Current schema keys are fixed ASCII. Do not silently lose CR/LF in a
	// future key through encoding/csv's CRLF normalization, or emit control cells.
	if strings.ContainsAny(path, "\x00\r\n\t") {
		return ErrInput
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInput
	}
	kind, value, err := csvNodeValue(token)
	if err != nil {
		return err
	}
	if err := writer.Write([]string{CSVSchemaVersion, path, kind, value}); err != nil {
		return csvRenderError(err)
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return nil
	}
	lastKey := ""
	index := 0
	for decoder.More() {
		component := strconv.Itoa(index)
		if delimiter == '{' {
			keyToken, err := decoder.Token()
			if err != nil {
				return ErrInput
			}
			key, ok := keyToken.(string)
			if !ok || index > 0 && key <= lastKey {
				return ErrInput // Reject duplicate or noncanonical object ordering.
			}
			lastKey = key
			component = strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
		}
		if err := writeCSVNode(decoder, writer, path+"/"+component, depth+1); err != nil {
			return err
		}
		index++
	}
	end, err := decoder.Token()
	if err != nil || delimiter == '{' && end != json.Delim('}') || delimiter == '[' && end != json.Delim(']') {
		return ErrInput
	}
	return nil
}

func csvNodeValue(token any) (kind, value string, err error) {
	switch v := token.(type) {
	case json.Delim:
		switch v {
		case '{':
			return "object", "{}", nil
		case '[':
			return "array", "[]", nil
		}
	case string:
		if !utf8.ValidString(v) {
			return "", "", ErrInput
		}
		// These are literal JSON quotes inside the decoded CSV cell, not just
		// CSV transport quotes. A string beginning =,+,-,@,tab,CR,LF stays a
		// JSON string cell, with controls escaped and large IDs unrounded.
		encoded, err := json.Marshal(v)
		if err != nil {
			return "", "", ErrInput
		}
		return "string", string(encoded), nil
	case json.Number:
		n, err := strconv.ParseFloat(string(v), 64)
		if err != nil || !number(n, -9007199254740991, 9007199254740991) {
			return "", "", ErrInput
		}
		encoded := "0"
		if n != 0 {
			encoded = strconv.FormatFloat(n, 'g', -1, 64)
		}
		if string(v) != encoded {
			return "", "", ErrInput
		}
		return "number", encoded, nil
	case bool:
		return "boolean", strconv.FormatBool(v), nil
	case nil:
		return "null", "null", nil
	}
	return "", "", ErrInput
}
