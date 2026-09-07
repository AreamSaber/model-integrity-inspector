package behavior

import (
	"encoding/json"
	"strings"
)

// A single-field JSON contract is semantic about JSON whitespace/escapes,
// but strict about key case, duplicate keys, string type and extra fields.
func jsonObjectEnd(text string, contract Contract) (int, bool) {
	d := json.NewDecoder(strings.NewReader(text))
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return 0, false
	}
	key, err := d.Token()
	if err != nil || key != contract.Key {
		return 0, false
	}
	var value string
	// Decoding null into a string succeeds in encoding/json, so inspect its token.
	token, err := d.Token()
	if err != nil {
		return 0, false
	}
	value, ok := token.(string)
	if !ok || value != contract.Expected {
		return 0, false
	}
	closing, err := d.Token()
	if err != nil || closing != json.Delim('}') {
		return 0, false
	}
	return int(d.InputOffset()), true
}

func applyContract(sample Sample, text string, out *Features) {
	contract := sample.Contract
	if contract.Kind == NoContract {
		return
	}
	out.Contract = Deviates
	start, end := -1, -1
	if contract.Kind == Exact {
		if text == contract.Expected {
			out.Contract, out.ContractReason, out.Anchor = Matches, "exact_bytes", "whole_response"
			return
		}
		start = strings.Index(text, contract.Expected)
		if start < 0 {
			out.ContractReason = "expected_marker_absent"
			return
		}
		if strings.Index(text[start+1:], contract.Expected) >= 0 {
			out.ContractReason, out.Anchor = "ambiguous_repeated_marker", "ambiguous"
			return
		}
		end = start + len(contract.Expected)
	} else {
		trimmed := strings.Trim(text, " \t\r\n")
		if n, ok := jsonObjectEnd(trimmed, contract); ok && n == len(trimmed) {
			out.Contract, out.ContractReason, out.Anchor = Matches, "single_field_json", "whole_response"
			return
		}
		if json.Valid([]byte(trimmed)) {
			out.ContractReason = "single_field_json_mismatch"
			return
		}
		// Never pick an arbitrary object from an object-dense response. The scan
		// is deliberately capped; general structural parsing belongs elsewhere.
		if strings.Count(text, "{") > 64 {
			out.ContractReason = "json_anchor_scan_limit"
			return
		}
		for index := 0; index < len(text); index++ {
			if text[index] != '{' {
				continue
			}
			if n, ok := jsonObjectEnd(text[index:], contract); ok {
				if start >= 0 {
					out.ContractReason, out.Anchor = "ambiguous_repeated_object", "ambiguous"
					return
				}
				start, end = index, index+n
				index += n - 1
			} else {
				// A valid outer object with the wrong contract is not a prefix
				// around one of its nested values. Skip that entire object.
				d := json.NewDecoder(strings.NewReader(text[index:]))
				var raw json.RawMessage
				if d.Decode(&raw) == nil {
					index += int(d.InputOffset()) - 1
				}
			}
		}
		if start < 0 {
			out.ContractReason = "single_field_json_mismatch"
			return
		}
	}
	out.Anchor, out.ContractReason = "unique_embedded_contract", "extra_affix"
	out.PrefixBytes, out.SuffixBytes = start, len(text)-end
	if start > 0 {
		out.Evidence = append(out.Evidence, evidenceFor(sample, text, 0, start, Prefix))
	}
	if end < len(text) {
		out.Evidence = append(out.Evidence, evidenceFor(sample, text, end, len(text), Suffix))
	}
}
