package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

var errJSONContract = errors.New("invalid JSON contract")

// strictJSON rejects ambiguous encodings before Go's permissive struct decoder
// can accept duplicate keys, case aliases or null scalar values. Depth and body
// size are bounded separately; errors never contain submitted data.
func strictJSON(raw []byte, out any) error {
	if !utf8.Valid(raw) {
		return errJSONContract
	}
	shape := reflect.TypeOf(out)
	if shape == nil || shape.Kind() != reflect.Pointer {
		return errJSONContract
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := validateJSONValue(decoder, shape.Elem(), false, 0); err != nil {
		return errJSONContract
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errJSONContract
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		return errJSONContract
	}
	return nil
}

func jsonFields(shape reflect.Type) map[string]reflect.Type {
	fields := map[string]reflect.Type{}
	for index := range shape.NumField() {
		field := shape.Field(index)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if field.Anonymous && name == "" && field.Type.Kind() == reflect.Struct {
			for key, value := range jsonFields(field.Type) {
				fields[key] = value
			}
			continue
		}
		if !field.IsExported() {
			continue
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	return fields
}

func validateJSONValue(decoder *json.Decoder, shape reflect.Type, nullable bool, depth int) error {
	if depth > 32 {
		return errJSONContract
	}
	for shape != nil && shape.Kind() == reflect.Pointer {
		shape = shape.Elem()
	}
	if shape == reflect.TypeFor[json.RawMessage]() || (shape != nil && shape.Kind() == reflect.Interface) {
		shape = nil
	}
	value, err := decoder.Token()
	if err != nil || (value == nil && !nullable) {
		return errJSONContract
	}
	delim, container := value.(json.Delim)
	if !container {
		return nil // Exact scalar types are enforced by the final typed decoder.
	}
	switch delim {
	case '{':
		var fields map[string]reflect.Type
		if shape != nil {
			switch shape.Kind() {
			case reflect.Struct:
				fields = jsonFields(shape)
			case reflect.Map:
			default:
				return errJSONContract
			}
		}
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return errJSONContract
			}
			seen[name] = true
			var child reflect.Type
			if fields != nil {
				child, ok = fields[name]
				if !ok {
					return errJSONContract
				}
			} else if shape != nil {
				child = shape.Elem()
			}
			// These optional target references are explicitly nullable. Other
			// fields must be omitted to request a default/no change.
			allowNull := (name == "provider_id" || name == "model_profile_id" || name == "input_price_micros_per_million" || name == "output_price_micros_per_million" || name == "max_cost_micros") && (child == nil || child == reflect.TypeFor[json.RawMessage]() || child.Kind() == reflect.Pointer)
			if err := validateJSONValue(decoder, child, allowNull, depth+1); err != nil {
				return err
			}
		}
	case '[':
		var child reflect.Type
		if shape != nil {
			if shape.Kind() != reflect.Slice && shape.Kind() != reflect.Array {
				return errJSONContract
			}
			child = shape.Elem()
		}
		for decoder.More() {
			if err := validateJSONValue(decoder, child, false, depth+1); err != nil {
				return err
			}
		}
	default:
		return errJSONContract
	}
	closing, err := decoder.Token()
	if err != nil || (delim == '{' && closing != json.Delim('}')) || (delim == '[' && closing != json.Delim(']')) {
		return errJSONContract
	}
	return nil
}
