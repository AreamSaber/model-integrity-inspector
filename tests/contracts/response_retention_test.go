package contracts

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/format"
	"go/token"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

const retentionContractPath = "/runs/{id}/response-retention"

func retentionContract(t *testing.T) (map[string]any, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile("../../docs/api/openapi-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if json.Unmarshal(raw, &spec) != nil {
		t.Fatal("invalid OpenAPI document")
	}
	methods := contractObject(t, contractObject(t, spec["paths"])[retentionContractPath])
	if len(methods) != 1 || methods["get"] == nil {
		t.Fatal("only the implemented retention observation GET may be exposed")
	}
	return contractObject(t, methods["get"]), contractObject(t, contractObject(t, spec["components"])["schemas"])
}

func TestResponseRetentionOperationContract(t *testing.T) {
	op, schemas := retentionContract(t)
	if op["operationId"] != "getRunResponseRetention" || op["requestBody"] != nil || op["x-permission-mode"] != "all" || !reflect.DeepEqual(op["x-permission"], []any{"run.read", "evidence.read"}) || !reflect.DeepEqual(op["security"], []any{map[string]any{"SessionCookie": []any{}}}) {
		t.Fatal("retention observation authority or operation drift")
	}
	for key, want := range map[string]any{
		"x-development-status": "implemented-database-backed", "x-source": "live-response-storage-observation", "x-immutable-report-mutation": false,
		"x-authenticated-plaintext-availability": false, "x-request-only-reproduction": false, "x-complete-retention-program": false,
		"x-query-unknown": "reject", "x-query-duplicates": "reject", "x-request-deadline-ms": float64(2000), "x-max-inflight": float64(4),
	} {
		if op[key] != want {
			t.Fatal("retention boundary drift", key)
		}
	}
	if !reflect.DeepEqual(op["x-not-required-permissions"], []any{"report.export", "evidence.body"}) || !reflect.DeepEqual(op["x-disallowed-methods"], []any{"HEAD"}) || op["x-disallowed-headers"] != nil {
		t.Fatal("retention GET must not inherit plaintext permissions or undocumented header restrictions")
	}
	params, ok := op["parameters"].([]any)
	if !ok || len(params) != 3 {
		t.Fatal("retention parameter whitelist drift")
	}
	for i, expected := range []struct{ name, in string }{{"X-Organization-ID", "header"}, {"id", "path"}, {"analysis_revision", "query"}} {
		p := contractObject(t, params[i])
		schema := contractObject(t, p["schema"])
		if p["name"] != expected.name || p["in"] != expected.in || p["required"] != true || i < 2 && schema["$ref"] != "#/components/schemas/ID" || i == 2 && (schema["type"] != "string" || schema["const"] != "1") {
			t.Fatal("retention scope/revision encoding drift", expected.name)
		}
	}
	responses := contractObject(t, op["responses"])
	statuses := []string{"200", "400", "401", "403", "404", "405", "409", "429", "500", "503"}
	if len(responses) != len(statuses) {
		t.Fatal("retention response status set drift")
	}
	for _, status := range statuses {
		response := contractObject(t, responses[status])
		headers := contractObject(t, response["headers"])
		for key, want := range map[string]string{"Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"} {
			if contractObject(t, contractObject(t, headers[key])["schema"])["const"] != want {
				t.Fatal("retention security header drift", status, key)
			}
		}
		body := contractObject(t, contractObject(t, contractObject(t, response["content"])["application/json"])["schema"])
		if status == "200" {
			fields := closedContractFields(t, body, "request_id", "data")
			if contractObject(t, fields["request_id"])["pattern"] != "^[a-f0-9]{32}$" || contractObject(t, fields["data"])["$ref"] != "#/components/schemas/ResponseRetentionView" {
				t.Fatal("retention standard response envelope drift")
			}
		} else if body["$ref"] != "#/components/schemas/ErrorEnvelope" {
			t.Fatal("retention error envelope drift", status)
		}
	}
	busy := contractObject(t, responses["429"])
	if !reflect.DeepEqual(busy["x-error-codes"], []any{"MI_RETENTION_LIMIT"}) || contractObject(t, contractObject(t, contractObject(t, busy["headers"])["Retry-After"])["schema"])["const"] != "2" {
		t.Fatal("retention admission response drift")
	}
	if !reflect.DeepEqual(contractObject(t, responses["503"])["x-error-codes"], []any{repository.ErrRetentionSource.Error(), "MI_SERVICE_UNAVAILABLE", "MI_ANALYSIS_RESULT_INVALID"}) {
		t.Fatal("retention source errors must use actual closed HTTP mappings")
	}
	if !reflect.DeepEqual(contractObject(t, responses["409"])["x-error-codes"], []any{"MI_SETUP_REQUIRED", "MI_VERSION_CONFLICT"}) {
		t.Fatal("retention fallback conflict code differs from the real targetError mapping")
	}
	errorEnvelope := contractObject(t, schemas["ErrorEnvelope"])
	if !slices.Contains(errorEnvelope["required"].([]any), any("request_id")) {
		t.Fatal("standard errors cannot omit request_id")
	}
	errorCode := contractObject(t, contractObject(t, contractObject(t, contractObject(t, errorEnvelope["properties"])["error"])["properties"])["code"])
	for _, code := range []string{"MI_RETENTION_LIMIT", repository.ErrRetentionSource.Error()} {
		if !slices.Contains(errorCode["enum"].([]any), any(code)) {
			t.Fatal("retention code missing from shared error envelope", code)
		}
	}
}

func TestResponseRetentionClosedDTOAndEnvelopeContract(t *testing.T) {
	op, schemas := retentionContract(t)
	schema := contractObject(t, schemas["ResponseRetentionView"])
	typ := reflect.TypeFor[runservice.ResponseRetentionView]()
	fields := make([]string, 0, typ.NumField())
	typedSchemas := make(map[string]map[string]any, len(schemas))
	for name, value := range schemas {
		typedSchemas[name] = contractObject(t, value)
	}
	for i := range typ.NumField() {
		field := typ.Field(i)
		name := field.Tag.Get("json")
		if name == "" || strings.Contains(name, ",") {
			t.Fatal("retention DTO fields must remain explicit and required")
		}
		fields = append(fields, name)
	}
	if len(fields) != 12 {
		t.Fatal("retention DTO no longer has its 12-field boundary")
	}
	properties := closedContractFields(t, schema, fields...)
	for i, name := range fields {
		checkPublicFieldType(t, typedSchemas, contractObject(t, properties[name]), typ.Field(i).Type, true, name)
	}
	for name, want := range map[string]any{"version": "mii.response-retention-summary.v1", "analysis_revision": float64(1)} {
		if contractObject(t, properties[name])["const"] != want {
			t.Fatal("retention version drift", name)
		}
	}
	for name, bounds := range map[string][2]float64{"policy_days": {0, 180}, "attempt_count": {0, 1536}, "raw_deleted_count": {0, 1536}, "display_deleted_count": {0, 1536}, "display_expired_count": {0, 1536}, "display_retained_count": {0, 1536}} {
		property := contractObject(t, properties[name])
		if property["minimum"] != bounds[0] || property["maximum"] != bounds[1] || property["enum"] != nil {
			t.Fatal("retention numeric bound drift", name)
		}
	}
	if version := contractObject(t, properties["policy_version"]); version["minimum"] != float64(1) || version["maximum"] != nil {
		t.Fatal("policy version must be positive without an invented upper bound")
	}
	if !reflect.DeepEqual(schema["x-runtime-invariants"], []any{
		"each count <= attempt_count", "display_deleted_count + display_expired_count + display_retained_count <= attempt_count",
		"last_deleted_at is null iff raw_deleted_count + display_deleted_count == 0", "non-null last_deleted_at <= observed_at",
	}) {
		t.Fatal("cross-field runtime invariants lost; JSON Schema bounds alone cannot express them")
	}
	response := contractObject(t, contractObject(t, op["responses"])["200"])
	envelopeSchema := contractObject(t, contractObject(t, contractObject(t, response["content"])["application/json"])["schema"])
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	view := runservice.ResponseRetentionView{Version: "mii.response-retention-summary.v1", RunID: "9007199254740993", AnalysisRevision: 1, ObservedAt: now, PolicyDays: 30, PolicyVersion: 1, AttemptCount: 18, DisplayRetainedCount: 18}
	for _, deleted := range []bool{false, true} {
		if deleted {
			view.RawDeletedCount, view.DisplayDeletedCount, view.DisplayRetainedCount = 1, 1, 17
			view.LastDeletedAt = &now
		}
		raw, err := json.Marshal(view)
		if err != nil {
			t.Fatal(err)
		}
		var data map[string]any
		if json.Unmarshal(raw, &data) != nil || data["run_id"] != "9007199254740993" {
			t.Fatal("actual DTO serialization lost decimal int64 identity")
		}
		envelope := map[string]any{"request_id": strings.Repeat("a", 32), "data": data}
		if !displayMatchesSchema(schemas, envelopeSchema, envelope) {
			t.Fatal("actual DTO does not match retention envelope")
		}
		for name, mutate := range map[string]func(map[string]any){
			"missing_request_id":   func(v map[string]any) { delete(v, "request_id") },
			"malformed_request_id": func(v map[string]any) { v["request_id"] = "not-a-request-id" },
			"bare_data":            func(v map[string]any) { delete(v, "data") },
			"extra_body":           func(v map[string]any) { v["content"] = "forbidden" },
		} {
			negative := maps.Clone(envelope)
			mutate(negative)
			if displayMatchesSchema(schemas, envelopeSchema, negative) {
				t.Fatal("invalid retention envelope accepted", name)
			}
		}
		for name, mutate := range map[string]func(map[string]any){
			"missing_nullable":  func(v map[string]any) { delete(v, "last_deleted_at") },
			"numeric_run_id":    func(v map[string]any) { v["run_id"] = float64(1) },
			"unknown_version":   func(v map[string]any) { v["version"] = "unknown" },
			"wrong_revision":    func(v map[string]any) { v["analysis_revision"] = float64(2) },
			"too_many_attempts": func(v map[string]any) { v["attempt_count"] = float64(1537) },
			"negative_count":    func(v map[string]any) { v["raw_deleted_count"] = float64(-1) },
			"body_alias":        func(v map[string]any) { v["content"] = nil },
		} {
			negative := maps.Clone(data)
			mutate(negative)
			if displayMatchesSchema(schemas, schema, negative) {
				t.Fatal("invalid retention DTO accepted", name)
			}
		}
	}
	for _, code := range []string{"MI_RETENTION_LIMIT", repository.ErrRetentionSource.Error()} {
		errorValue := map[string]any{"request_id": strings.Repeat("b", 32), "error": map[string]any{"code": code, "message": code}}
		if !displayMatchesSchema(schemas, contractObject(t, schemas["ErrorEnvelope"]), errorValue) {
			t.Fatal("actual dedicated error code rejected", code)
		}
		delete(errorValue, "request_id")
		if displayMatchesSchema(schemas, contractObject(t, schemas["ErrorEnvelope"]), errorValue) {
			t.Fatal("error envelope silently lost mandatory request_id")
		}
	}
}

func retentionRequireFunction(t *testing.T, path, name string, boundaries ...string) string {
	t.Helper()
	body := displayFunctionText(t, contractSource(t, "../../"+path), name)
	normalized := strings.Join(strings.Fields(body), " ")
	for _, boundary := range boundaries {
		if !strings.Contains(normalized, strings.Join(strings.Fields(boundary), " ")) {
			t.Fatal("documented retention runtime boundary changed", name, boundary)
		}
	}
	return body
}

func retentionMiddlewareGuards(t *testing.T) {
	t.Helper()
	source := contractSource(t, "../../internal/integrity/api/control.go")
	deadlines, admissions := 0, 0
	for _, declaration := range source.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "middleware" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			statement, ok := node.(*ast.IfStmt)
			if !ok {
				return true
			}
			retentionCondition := false
			ast.Inspect(statement.Cond, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if ok {
					name, direct := call.Fun.(*ast.Ident)
					retentionCondition = retentionCondition || direct && name.Name == "isResponseRetentionRequest"
				}
				return true
			})
			if !retentionCondition {
				return true
			}
			var text bytes.Buffer
			if err := format.Node(&text, token.NewFileSet(), statement.Body); err != nil {
				t.Fatal(err)
			}
			body := strings.Join(strings.Fields(text.String()), " ")
			if strings.Contains(body, "context.WithTimeout(r.Context(), 2*time.Second)") && strings.Contains(body, "r = r.WithContext(ctx)") {
				deadlines++
			}
			if strings.Contains(body, "case c.retentionSlots <- struct{}{}:") && strings.Contains(body, "default:") && strings.Contains(body, "defer func() { <-c.retentionSlots }()") && strings.Contains(body, "c.failure(w, r, 429, \"MI_RETENTION_LIMIT\")") && strings.Contains(body, "SetWriteDeadline(deadline)") {
				admissions++
			}
			return true
		})
	}
	if deadlines != 1 || admissions != 1 {
		t.Fatal("retention path must directly select its HTTP deadline and bounded admission; another endpoint's gates do not count")
	}
}

// AST checks bind the contract to real production functions, not comments or
// fabricated HTTP fixtures. They are not a substitute for DB/concurrency tests.
func TestResponseRetentionContractMatchesRuntimeBoundaries(t *testing.T) {
	retentionContract(t)
	retentionMiddlewareGuards(t)
	routes := contractSource(t, "../../internal/integrity/api/run_results.go")
	registered := 0
	ast.Inspect(routes, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 || contractLiteral(call.Args[0]) != "GET /api/v1"+retentionContractPath {
			return true
		}
		method, methodOK := call.Fun.(*ast.SelectorExpr)
		handler, handlerOK := call.Args[1].(*ast.SelectorExpr)
		if !methodOK || method.Sel.Name != "HandleFunc" || !handlerOK || handler.Sel.Name != "getResponseRetention" {
			t.Fatal("retention route lost its real handler")
		}
		registered++
		return true
	})
	if registered != 1 {
		t.Fatal("missing or duplicate real retention GET")
	}
	retentionRequireFunction(t, "internal/integrity/api/response_retention.go", "validResponseRetentionRequest", "r.Method != http.MethodGet", "r.ContentLength != 0", "len(r.TransferEncoding) != 0", "url.ParseQuery(r.URL.RawQuery)", "err == nil", "len(query) == 1", "len(query[\"analysis_revision\"]) == 1", "query.Get(\"analysis_revision\") == \"1\"")
	retentionRequireFunction(t, "internal/integrity/api/response_retention.go", "getResponseRetention", "r.Method != http.MethodGet", "c.failure(w, r, 405, \"MI_INVALID_REQUEST\")", "!validResponseRetentionRequest(r)", "c.failure(w, r, 400, \"MI_INVALID_REQUEST\")", "c.authorizeOrganization(w, r, \"run.read\")", "c.managementPathID(w, r, \"id\")", "c.cfg.Runs.ResponseRetention(ctx, org, id)", "errors.Is(err, repository.ErrRetentionSource)", "c.failure(w, r, 503, \"MI_RETENTION_SOURCE_INVALID\")", "c.resultError(w, r, err)", "c.success(w, r, 200, view)")
	retentionRequireFunction(t, "internal/integrity/api/control.go", "NewControlHandler", "c.retentionSlots = make(chan struct{}, 4)", "if cfg.Runs != nil", "c.registerRunResultRoutes(mux)")
	retentionRequireFunction(t, "internal/integrity/api/control.go", "middleware", "isResponseRetentionRequest(r)", "context.WithTimeout(r.Context(), 2*time.Second)", "SetWriteDeadline(deadline)", "w.Header().Set(\"Cache-Control\", \"no-store\")", "case c.retentionSlots <- struct{}{}:", "defer func() { <-c.retentionSlots }()", "w.Header().Set(\"Retry-After\", \"2\")", "c.failure(w, r, 429, \"MI_RETENTION_LIMIT\")", "c.failure(w, r, 503, \"MI_RETENTION_SOURCE_INVALID\")")
	retentionRequireFunction(t, "internal/integrity/api/control.go", "success", "map[string]any{\"data\": data, \"request_id\": id}")
	retentionRequireFunction(t, "internal/integrity/api/run_results.go", "resultError", "errors.Is(err, repository.ErrResultDocument)", "c.failure(w, r, 503, \"MI_ANALYSIS_RESULT_INVALID\")", "c.runError(w, r, err)")
	retentionRequireFunction(t, "internal/integrity/api/targets.go", "targetError", "errors.Is(err, repository.ErrConflict)", "c.failure(w, r, 409, \"MI_VERSION_CONFLICT\")", "c.error(w, r, err)")
	retentionRequireFunction(t, "internal/integrity/run/response_retention.go", "ResponseRetention", "context.WithTimeout(ctx, 2*time.Second)", "s.cfg.Store.WithOrganization(bounded, orgID)", "tenant.ReadResponseRetentionSummary(runID)", "responseRetentionView(runID, row)")
	retentionRequireFunction(t, "internal/integrity/run/response_retention.go", "responseRetentionView", "row.PolicyDays > 180", "row.PolicyVersion <= 0", "row.AttemptCount > 1536", "count < 0 || count > row.AttemptCount", "row.DisplayDeletedCount+row.DisplayExpiredCount+row.DisplayRetainedCount > row.AttemptCount", "(row.RawDeletedCount+row.DisplayDeletedCount == 0) != (row.LastDeletedAt == nil)", "row.LastDeletedAt.After(row.ObservedAt)", "AnalysisRevision: 1")
	summary := retentionRequireFunction(t, "internal/integrity/repository/response_retention_cleanup_read.go", "ReadResponseRetentionSummary", "t.resultReadTransaction(true", "publishedReviewScope(db, t.orgID, runID, 1)", "verifyResponseRetentionBatch(t.store, db, t.orgID, item.BatchID)", "errors.Is(businessErr, ErrRetentionSource)", "out.DisplayExpiredCount = int(expired)", "out.DisplayRetainedCount = int(retained - expired)")
	permission := retentionRequireFunction(t, "internal/integrity/repository/run_history.go", "resultReadTransaction", "RequireControlAuthority(t.ctx, t.orgID)", "!slices.Contains(grants, \"run.read\") || evidence && !slices.Contains(grants, \"evidence.read\")")
	for _, forbidden := range []string{"report.export", "evidence.body", "Decrypt", "OpenEvidence", "OpenDisplay", "WithCanonical", ".Create(", ".Updates(", ".Delete("} {
		if strings.Contains(summary, forbidden) || strings.Contains(permission, forbidden) {
			t.Fatal("observation must not acquire plaintext/export authority or mutate artifacts", forbidden)
		}
	}
	retentionRequireFunction(t, "internal/integrity/worker/response_retention.go", "NewResponseRetentionHandler", "repository.JobType(execution.Lease.Job.Type) != repository.JobRetentionDelete", "ctx.Err()", "tx.DeleteResponseEvidenceBatch()")
	retentionRequireFunction(t, "internal/app/app.go", "prepareWithNetworkAndLogger", "handlers[repository.JobRetentionDelete] = worker.NewResponseRetentionHandler()", "queue.ScheduleResponseRetention(ctx)")
}

func TestResponseRetentionDeletedDisplayRequiresVerifiedFactContract(t *testing.T) {
	_, schemas := displayContract(t)
	u := contractObject(t, schemas["EvidenceDisplayUnavailable"])
	fields := contractObject(t, u["properties"])
	if !slices.Contains(contractObject(t, fields["status"])["enum"].([]any), any(repository.DisplayReadDeleted)) || contractObject(t, fields["content"])["type"] != "null" {
		t.Fatal("deleted display must be a closed unavailable/null branch")
	}
	retentionRequireFunction(t, "internal/integrity/repository/response_retention_cleanup_read.go", "verifyResponseRetentionBatch", "responseRetentionReceiptHash(batch, items)", "hash != batch.ReceiptHash", "len(events) != 1", "audit.Verify(events[0], store.auditSigner) != nil", "status='completed'", "retentionAuditAction", "retentionAuditObject")
	retentionRequireFunction(t, "internal/integrity/repository/response_retention_cleanup_read.go", "loadVerifiedEvidenceDeletion", "verifyResponseRetentionBatch(store, db, orgID, rows[0].BatchID)", "item.AttemptID == attemptID && item.SourceKind == source", "item != rows[0]")
	retentionRequireFunction(t, "internal/integrity/repository/evidence_display_read_source.go", "loadDisplayReadSnapshot", "loadVerifiedEvidenceDeletion(store, db, orgID, attempt.ID, retentionDisplaySource)", "deletion.RequestHash != facts.RequestHash", "deletion.RunID != selection.RunID", "deletion.LogicalSampleID != selection.SampleID", "attempt.ResponseBodyReceipt == BodyRecorded && deletion == nil", "return out, ErrDisplaySource")
	retentionRequireFunction(t, "internal/integrity/repository/evidence_display_read_source.go", "displayReadStatus", "facts.Deletion != nil", "if present", "return DisplayReadDeleted, nil")
	// The existing authenticated-content contract exercises every unavailable
	// status with null content and rejects plaintext under each status, including
	// this added value. This AST check separately guards the provenance chain.
}
