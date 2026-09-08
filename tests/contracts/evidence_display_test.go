package contracts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/format"
	"go/token"
	"math"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/evidencedisplay"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

const displayContractPath = "/runs/{id}/samples/{sampleId}/attempts/{attemptId}/evidence"

func displayContract(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile("../../docs/api/openapi-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if json.Unmarshal(raw, &spec) != nil {
		t.Fatal("invalid OpenAPI document")
	}
	methods := contractObject(t, contractObject(t, spec["paths"])[displayContractPath])
	if len(methods) != 1 || methods["get"] == nil {
		t.Fatal("only the implemented response display GET may be exposed")
	}
	return contractObject(t, methods["get"]), contractObject(t, contractObject(t, spec["components"])["schemas"])
}

func TestEvidenceDisplayOperationContract(t *testing.T) {
	op, schemas := displayContract(t)
	if op["operationId"] != "getRunAttemptEvidenceDisplay" || op["requestBody"] != nil || op["x-permission-mode"] != "all" || !reflect.DeepEqual(op["x-permission"], []any{"run.read", "evidence.read", "evidence.body"}) || !reflect.DeepEqual(op["security"], []any{map[string]any{"SessionCookie": []any{}}}) {
		t.Fatal("display authority or GET operation drift")
	}
	for key, want := range map[string]any{
		"x-development-status": "implemented-database-backed", "x-source": "authenticated-display-only", "x-private-disclosure-codec": true, "x-request-only-reproduction": false,
		"x-query-unknown": "reject", "x-query-duplicates": "reject", "x-max-response-bytes": float64(8 << 20), "x-max-canonical-content-bytes": float64(evidencedisplay.MaxPayloadBytes),
		"x-request-deadline-ms": float64(10000), "x-decryption-deadline-ms": float64(2000), "x-write-deadline-ms": float64(2000), "x-max-write-bytes": float64(64 << 10), "x-max-inflight": float64(4),
	} {
		if op[key] != want {
			t.Fatal("display boundary drift", key)
		}
	}
	blocked := []any{"Range", "If-Range", "If-Match", "If-None-Match", "If-Modified-Since", "If-Unmodified-Since"}
	if !reflect.DeepEqual(op["x-disallowed-headers"], blocked) || !reflect.DeepEqual(op["x-disallowed-methods"], []any{"HEAD"}) {
		t.Fatal("display alternative disclosure path contract drift")
	}
	params, ok := op["parameters"].([]any)
	if !ok || len(params) != 5 {
		t.Fatal("display parameter whitelist drift")
	}
	for i, name := range []string{"X-Organization-ID", "id", "sampleId", "attemptId", "analysis_revision"} {
		p := contractObject(t, params[i])
		location := "path"
		switch i {
		case 0:
			location = "header"
		case 4:
			location = "query"
		}
		if p["name"] != name || p["in"] != location || p["required"] != true {
			t.Fatal("display parameter scope drift", name)
		}
		schema := contractObject(t, p["schema"])
		if i < 4 && schema["$ref"] != "#/components/schemas/ID" || i == 4 && (schema["type"] != "string" || schema["const"] != "1") {
			t.Fatal("display identifier/revision encoding drift", name)
		}
	}
	responses := contractObject(t, op["responses"])
	wantStatuses := []string{"200", "400", "401", "403", "404", "405", "409", "429", "500", "503"}
	if len(responses) != len(wantStatuses) {
		t.Fatal("display response set changed; no 206/304 success is supported")
	}
	for _, status := range wantStatuses {
		r := contractObject(t, responses[status])
		headers := contractObject(t, r["headers"])
		for name, want := range map[string]string{"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"} {
			if contractObject(t, contractObject(t, headers[name])["schema"])["const"] != want {
				t.Fatal("display security header drift", status, name)
			}
		}
		body := contractObject(t, contractObject(t, contractObject(t, r["content"])["application/json"])["schema"])
		if status == "200" {
			fields := closedContractFields(t, body, "request_id", "data")
			if contractObject(t, fields["request_id"])["pattern"] != "^[a-f0-9]{32}$" || contractObject(t, fields["data"])["$ref"] != "#/components/schemas/EvidenceDisplayData" {
				t.Fatal("display standard private response envelope drift")
			}
		} else if body["$ref"] != "#/components/schemas/ErrorEnvelope" {
			t.Fatal("display error envelope drift", status)
		}
	}
	busy := contractObject(t, responses["429"])
	if !reflect.DeepEqual(busy["x-error-codes"], []any{"MI_EVIDENCE_LIMIT"}) || contractObject(t, contractObject(t, contractObject(t, busy["headers"])["Retry-After"])["schema"])["const"] != "2" {
		t.Fatal("display bounded admission response drift")
	}
	errorCodes := contractObject(t, contractObject(t, contractObject(t, contractObject(t, schemas["ErrorEnvelope"])["properties"])["error"])["properties"])
	codes := contractObject(t, errorCodes["code"])["enum"].([]any)
	for _, code := range []string{runservice.ErrEvidenceLimit.Error(), runservice.ErrEvidenceUnavailable.Error()} {
		if !slices.Contains(codes, any(code)) {
			t.Fatal("display error is absent from shared envelope", code)
		}
	}
}

func TestEvidenceDisplayPrivateSchemaAndStatusContract(t *testing.T) {
	_, schemas := displayContract(t)
	for _, item := range []struct{ schema, file, structure string }{
		{"EvidenceDisplayContent", "../../internal/integrity/evidencedisplay/types.go", "document"},
		{"EvidenceDisplayResponse", "../../internal/integrity/evidencedisplay/types.go", "responseView"},
	} {
		fields := displayStructFields(t, item.file, item.structure)
		closedContractFields(t, contractObject(t, schemas[item.schema]), fields...)
	}
	eventNames := []string{}
	eventType := reflect.TypeFor[domain.StreamEventSummary]()
	for i := range eventType.NumField() {
		eventNames = append(eventNames, eventType.Field(i).Tag.Get("json"))
	}
	closedContractFields(t, contractObject(t, schemas["EvidenceDisplayStreamEvent"]), eventNames...)
	content := contractObject(t, contractObject(t, schemas["EvidenceDisplayContent"])["properties"])
	for name, want := range map[string]any{"version": float64(1), "policy": evidencedisplay.PolicyVersion, "metadata_omitted": true} {
		if contractObject(t, content[name])["const"] != want {
			t.Fatal("authenticated display version/policy drift", name)
		}
	}
	request := contractObject(t, content["request_json"])
	if request["type"] != "string" || request["contentMediaType"] != "application/json" || request["x-max-utf8-bytes"] != float64(evidencedisplay.MaxTextBytes) || !strings.Contains(request["description"].(string), "int64") {
		t.Fatal("request_json must remain bounded lossless JSON text, not an object")
	}
	response := contractObject(t, contractObject(t, schemas["EvidenceDisplayResponse"])["properties"])
	for _, name := range []string{"prompt_tokens", "completion_tokens", "total_tokens", "reasoning_tokens"} {
		choices := contractObject(t, response[name])["anyOf"].([]any)
		if len(choices) != 2 || contractObject(t, choices[0])["maximum"] != float64(1<<53-1) || contractObject(t, choices[1])["type"] != "null" {
			t.Fatal("display nullable token precision drift", name)
		}
	}
	events := contractObject(t, response["events"])["anyOf"].([]any)
	if len(events) != 2 || contractObject(t, events[0])["maxItems"] != float64(evidencedisplay.MaxEvents) || contractObject(t, events[1])["type"] != "null" {
		t.Fatal("display event summary null/bound drift")
	}
	data := contractObject(t, schemas["EvidenceDisplayData"])
	if !reflect.DeepEqual(data["oneOf"], []any{map[string]any{"$ref": "#/components/schemas/EvidenceDisplayAvailable"}, map[string]any{"$ref": "#/components/schemas/EvidenceDisplayUnavailable"}}) {
		t.Fatal("available/null status union drift")
	}
	available := closedContractFields(t, contractObject(t, schemas["EvidenceDisplayAvailable"]), "version", "run_id", "sample_id", "attempt_id", "analysis_revision", "is_final", "status", "payload_hash", "content")
	unavailable := contractObject(t, schemas["EvidenceDisplayUnavailable"])
	uFields := contractObject(t, unavailable["properties"])
	if unavailable["additionalProperties"] != false || len(uFields) != 9 || len(unavailable["required"].([]any)) != 8 || slices.Contains(unavailable["required"].([]any), any("payload_hash")) || contractObject(t, uFields["content"])["type"] != "null" {
		t.Fatal("unavailable content must be null with optional non-null hash")
	}
	for _, fields := range []map[string]any{available, uFields} {
		if contractObject(t, fields["version"])["const"] != repository.DisclosureFormatVersion || contractObject(t, fields["analysis_revision"])["const"] != float64(1) {
			t.Fatal("output format or published revision drift")
		}
	}
	statuses := []any{"unavailable_policy_zero", "unavailable_not_retained", "unavailable_not_captured", "unavailable_uncertain", "unavailable_expired", "unavailable_legacy_unverified", repository.DisplayUnavailablePolicy, repository.DisplayUnavailableLimit, repository.DisplayUnavailableSource, repository.DisplayUnavailableCancelled, repository.DisplayUnavailableCapture, repository.DisplayUnavailableSeal}
	if contractObject(t, available["status"])["const"] != "available" || !reflect.DeepEqual(contractObject(t, uFields["status"])["enum"], statuses) {
		t.Fatal("unavailable reason set is not closed")
	}
}

func displayStructFields(t *testing.T, file, name string) []string {
	t.Helper()
	var fields []string
	ast.Inspect(contractSource(t, file), func(node ast.Node) bool {
		spec, ok := node.(*ast.TypeSpec)
		if !ok || spec.Name.Name != name {
			return true
		}
		structure, ok := spec.Type.(*ast.StructType)
		if !ok {
			t.Fatal("private display schema is no longer a struct")
		}
		for _, field := range structure.Fields.List {
			if field.Tag == nil {
				t.Fatal("private display field has no explicit codec tag")
			}
			tag, err := strconv.Unquote(field.Tag.Value)
			if err != nil {
				t.Fatal(err)
			}
			name := reflect.StructTag(tag).Get("json")
			if name == "" || strings.Contains(name, ",") {
				t.Fatal("authenticated display fields must be explicit and required")
			}
			fields = append(fields, name)
		}
		return false
	})
	if len(fields) == 0 {
		t.Fatal("missing private display codec structure")
	}
	return fields
}

func TestEvidenceDisplayContractMatchesPrivateRuntimeBoundaries(t *testing.T) {
	op, schemas := displayContract(t)
	apiSource := contractSource(t, "../../internal/integrity/api/evidence_display.go")
	registered := 0
	ast.Inspect(apiSource, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 || contractLiteral(call.Args[0]) != "GET /api/v1"+displayContractPath {
			return true
		}
		method, ok := call.Fun.(*ast.SelectorExpr)
		handler, handlerOK := call.Args[1].(*ast.SelectorExpr)
		if !ok || method.Sel.Name != "HandleFunc" || !handlerOK || handler.Sel.Name != "readEvidenceDisplay" {
			t.Fatal("documented display operation lost its real handler")
		}
		registered++
		return true
	})
	if registered != 1 {
		t.Fatal("missing or duplicate real response display route")
	}
	// These AST-formatted function checks intentionally tie documentation to
	// actual guard/codec bodies, rather than matching comments or test fixtures.
	handler := displayFunctionText(t, apiSource, "readEvidenceDisplay")
	for _, guard := range []string{
		"r.Method != http.MethodGet", "r.ContentLength != 0", "len(r.TransferEncoding) != 0", "len(query) != 1", "len(query[\"analysis_revision\"]) != 1", "query.Get(\"analysis_revision\") != \"1\"",
		"c.authorizeOrganization(w, r, \"evidence.body\")", "disclosure.WriteTo(ctx, sink)", "!sink.started",
	} {
		if !strings.Contains(handler, guard) {
			t.Fatal("documented display handler guard changed", guard)
		}
	}
	for _, header := range op["x-disallowed-headers"].([]any) {
		if !strings.Contains(handler, strconv.Quote(header.(string))) {
			t.Fatal("documented forbidden header missing from handler")
		}
	}
	source := contractSource(t, "../../internal/integrity/run/evidence_display.go")
	prepare := displayFunctionText(t, source, "PrepareDisplay")
	for _, boundary := range []string{
		"context.WithTimeout(ctx, 10*time.Second)", "context.WithTimeout(life, 2*time.Second)", "meta.Status == \"available\"", "s.opener.Open(prepare, binding, record)", "opened.WithCanonicalForDisplay",
		"RequestID string `json:\"request_id\"`", "EvidenceDisplayView", "Content json.RawMessage `json:\"content\"`", "`json:\"data\"`", "len(d.data) > 8<<20",
	} {
		if !strings.Contains(prepare, boundary) {
			t.Fatal("private envelope or authenticated-only preparation boundary changed", boundary)
		}
	}
	write := displayFunctionText(t, source, "WriteTo")
	for _, boundary := range []string{"CommitEvidenceDisplayRead(d.source, d.summary)", "permit.Begin(operation, d.summary)", "permit.Revalidate(operation)", "min(offset+(64<<10), len(data))"} {
		if !strings.Contains(write, boundary) {
			t.Fatal("documented bounded grant/output boundary changed", boundary)
		}
	}
	statusFunction := displayFunctionText(t, source, "knownDisplayStatus")
	constants := map[string]string{
		"repository.DisplayUnavailablePolicy": repository.DisplayUnavailablePolicy, "repository.DisplayUnavailableLimit": repository.DisplayUnavailableLimit,
		"repository.DisplayUnavailableSource": repository.DisplayUnavailableSource, "repository.DisplayUnavailableCancelled": repository.DisplayUnavailableCancelled,
		"repository.DisplayUnavailableCapture": repository.DisplayUnavailableCapture, "repository.DisplayUnavailableSeal": repository.DisplayUnavailableSeal,
	}
	for expression, value := range constants {
		statusFunction = strings.ReplaceAll(statusFunction, expression, strconv.Quote(value))
	}
	// All status values in the accepted switch must be represented, including
	// future added values; only the default false branch has no string literal.
	actual := regexp.MustCompile(`"([a-z_]+)"`).FindAllStringSubmatch(statusFunction, -1)
	status := contractObject(t, contractObject(t, contractObject(t, schemas["EvidenceDisplayUnavailable"])["properties"])["status"])
	want := append([]any{"available"}, status["enum"].([]any)...)
	if len(actual) != len(want) {
		t.Fatal("runtime display status count differs from contract")
	}
	for i, match := range actual {
		if match[1] != want[i] {
			t.Fatal("runtime display status differs from contract")
		}
	}
	permissionSource := contractSource(t, "../../internal/integrity/repository/evidence_display_read.go")
	permissions := displayFunctionText(t, permissionSource, "displayPermissions")
	if !strings.Contains(permissions, "count != 3") || strings.Count(permissions, "IN ('run.read','evidence.read','evidence.body')") != 2 {
		t.Fatal("documented simultaneous current permission requirement changed")
	}
}

func displayFunctionText(t *testing.T, file *ast.File, name string) string {
	t.Helper()
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != name {
			continue
		}
		var text bytes.Buffer
		if err := format.Node(&text, token.NewFileSet(), function.Body); err != nil {
			t.Fatal(err)
		}
		return text.String()
	}
	t.Fatal("missing documented runtime function", name)
	return ""
}

type displayContractNoNetwork struct{}

func (displayContractNoNetwork) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("contract-network-forbidden")
}

// This fixture uses real wire construction, redaction and display-purpose AEAD,
// but no database, HTTP request or invented disclosure grant. It tests the inner
// authenticated format, not the independent authorization/release workflow.
func TestEvidenceDisplayAuthenticatedContentContract(t *testing.T) {
	_, schemas := displayContract(t)
	for _, populated := range []bool{false, true} {
		t.Run(strconv.FormatBool(populated), func(t *testing.T) {
			ctx := context.Background()
			seed := int64(9007199254740993)
			const canary = "synthetic-contract-only-key-7e25f98a"
			request := domain.NormalizedRequest{Model: "contract-model", Messages: []domain.NormalizedMessage{{Role: "user", Content: "Synthetic " + canary}}, MaxOutputTokens: 64, Seed: &seed}
			adapter, err := openaichat.New(openaichat.Config{Endpoint: "https://contract.invalid/v1", Doer: displayContractNoNetwork{}})
			if err != nil {
				t.Fatal(err)
			}
			wire, snapshot, err := adapter.BuildRequest(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			if err := wire.Body.Close(); err != nil {
				t.Fatal(err)
			}
			response := domain.NormalizedResponse{Content: "Synthetic " + canary, HTTPStatus: 200, ParseStatus: "valid", FinishReason: "stop", DurationMs: 20}
			if populated {
				count, first := int64(1<<53-1), int64(10)
				response.PromptTokens, response.CompletionTokens, response.TotalTokens, response.ReasoningTokens = &count, &count, &count, &count
				response.FirstTokenMs = &first
				response.Events = []domain.StreamEventSummary{{Sequence: 1, Type: "content_delta", Bytes: 12, ArrivalMs: 10, IntervalMs: 10}, {Sequence: 3, Type: "done", Bytes: 0, ArrivalMs: 20, IntervalMs: 10}}
				response.StreamTerminated = true
			}
			prepared, err := evidencedisplay.Prepare(ctx, evidencedisplay.Source{Request: request, Snapshot: snapshot, Response: response}, []byte(canary), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Close()
			ring, err := secret.NewKeyRing("contract", map[string][]byte{"contract": bytes.Repeat([]byte{0x31}, 32)})
			if err != nil {
				t.Fatal(err)
			}
			now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
			sealer, opener, err := ring.NewDisplayCapabilities(func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			sourceHash, requestHash := prepared.Hashes()
			binding := secret.DisplayBinding{Scope: secret.EvidenceScope{OrganizationID: 1, RunID: 2, LogicalSampleID: 3, AttemptID: 4, RequestHash: requestHash}, SourceHash: sourceHash, CapturedAtMicros: now.UnixMicro(), ExpiresAtMicros: now.Add(time.Hour).UnixMicro()}
			record, err := sealer.Seal(ctx, binding, prepared)
			if err != nil {
				t.Fatal(err)
			}
			opened, err := opener.Open(ctx, binding, record)
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Close()
			for _, protected := range []any{prepared, opened, runservice.Disclosure{}} {
				if _, err := json.Marshal(protected); !errors.Is(err, evidencedisplay.ErrSensitive) {
					t.Fatal("sensitive display wrapper gained ordinary serialization")
				}
			}
			if err := opened.WithCanonicalForDisplay(ctx, func(raw []byte) error {
				var doc map[string]any
				if json.Unmarshal(raw, &doc) != nil || !displayMatchesSchema(schemas, contractObject(t, schemas["EvidenceDisplayContent"]), doc) || bytes.Contains(raw, []byte(canary)) {
					t.Fatal("real authenticated display does not match the closed content schema")
				}
				text, ok := doc["request_json"].(string)
				if !ok {
					t.Fatal("request_json lost its string representation")
				}
				var requestFields map[string]json.RawMessage
				if json.Unmarshal([]byte(text), &requestFields) != nil || string(requestFields["seed"]) != "9007199254740993" {
					t.Fatal("request_json lost exact int64 wire value")
				}
				view := contractObject(t, doc["response"])
				if view["event_summary_partial"] != populated || populated && view["events"] == nil || !populated && (view["events"] != nil || view["prompt_tokens"] != nil) {
					t.Fatal("actual nullable/event summary representation drift")
				}
				data := map[string]any{"version": repository.DisclosureFormatVersion, "run_id": "2", "sample_id": "3", "attempt_id": "4", "analysis_revision": float64(1), "is_final": true, "status": "available", "payload_hash": record.PayloadHash, "content": doc}
				union := contractObject(t, schemas["EvidenceDisplayData"])
				if !displayMatchesSchema(schemas, union, data) {
					t.Fatal("available display branch rejected")
				}
				data["content"] = nil
				if displayMatchesSchema(schemas, union, data) {
					t.Fatal("available status must not accept null content")
				}
				statusSchema := contractObject(t, contractObject(t, contractObject(t, schemas["EvidenceDisplayUnavailable"])["properties"])["status"])
				for _, status := range statusSchema["enum"].([]any) {
					data["status"] = status
					for _, withHash := range []bool{true, false} {
						if withHash {
							data["payload_hash"] = record.PayloadHash
						} else {
							delete(data, "payload_hash")
						}
						if !displayMatchesSchema(schemas, union, data) {
							t.Fatal("known unavailable/null branch rejected")
						}
					}
					data["content"] = doc
					if displayMatchesSchema(schemas, union, data) {
						t.Fatal("unavailable status accepted plaintext content")
					}
					data["content"] = nil
				}
				data["status"] = "unavailable_unknown"
				if displayMatchesSchema(schemas, union, data) {
					t.Fatal("unknown unavailable status accepted")
				}
				doc["request_json"] = map[string]any{"seed": float64(seed)}
				if displayMatchesSchema(schemas, contractObject(t, schemas["EvidenceDisplayContent"]), doc) {
					t.Fatal("request object alias accepted")
				}
				doc["request_json"] = text
				doc["raw_headers"] = "forbidden"
				if displayMatchesSchema(schemas, contractObject(t, schemas["EvidenceDisplayContent"]), doc) {
					t.Fatal("unknown sensitive field accepted")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Small test-only evaluator for the explicitly used schema assertions. This is
// not a production validator or a general JSON Schema implementation; it checks
// actual codec fixtures and negative unions without adding runtime dependencies.
func displayMatchesSchema(schemas, schema map[string]any, value any) bool {
	if ref, ok := schema["$ref"].(string); ok {
		return displayMatchesSchema(schemas, schemas[strings.TrimPrefix(ref, "#/components/schemas/")].(map[string]any), value)
	}
	for _, name := range []string{"oneOf", "anyOf"} {
		if choices, ok := schema[name].([]any); ok {
			matched := 0
			for _, choice := range choices {
				if displayMatchesSchema(schemas, choice.(map[string]any), value) {
					matched++
				}
			}
			if matched == 0 || name == "oneOf" && matched != 1 {
				return false
			}
		}
	}
	if constant, ok := schema["const"]; ok && !reflect.DeepEqual(constant, value) {
		return false
	}
	if enum, ok := schema["enum"].([]any); ok && !slices.ContainsFunc(enum, func(item any) bool { return reflect.DeepEqual(item, value) }) {
		return false
	}
	switch schema["type"] {
	case "null":
		return value == nil
	case "object":
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		properties, _ := schema["properties"].(map[string]any)
		for _, name := range schema["required"].([]any) {
			if _, ok := object[name.(string)]; !ok {
				return false
			}
		}
		for name, child := range object {
			p, ok := properties[name].(map[string]any)
			if !ok && schema["additionalProperties"] == false || ok && !displayMatchesSchema(schemas, p, child) {
				return false
			}
		}
	case "string":
		text, ok := value.(string)
		if !ok {
			return false
		}
		if pattern, ok := schema["pattern"].(string); ok && !regexp.MustCompile(pattern).MatchString(text) {
			return false
		}
		if max, ok := schema["maxLength"].(float64); ok && utf8.RuneCountInString(text) > int(max) {
			return false
		}
		if min, ok := schema["minLength"].(float64); ok && utf8.RuneCountInString(text) < int(min) {
			return false
		}
		if max, ok := schema["x-max-utf8-bytes"].(float64); ok && len(text) > int(max) {
			return false
		}
	case "integer":
		number, ok := value.(float64)
		if !ok || math.Trunc(number) != number {
			return false
		}
		if min, ok := schema["minimum"].(float64); ok && number < min {
			return false
		}
		if max, ok := schema["maximum"].(float64); ok && number > max {
			return false
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return false
		}
	case "array":
		items, ok := value.([]any)
		if !ok {
			return false
		}
		if max, ok := schema["maxItems"].(float64); ok && len(items) > int(max) {
			return false
		}
		for _, item := range items {
			if !displayMatchesSchema(schemas, schema["items"].(map[string]any), item) {
				return false
			}
		}
	}
	return true
}
