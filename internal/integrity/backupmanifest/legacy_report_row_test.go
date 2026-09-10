package backupmanifest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"runtime"
	"strings"
	"testing"
	"time"
)

func legacyRowText(s string) LegacyReportRowText {
	return LegacyReportRowText{Present: true, Bytes: int64(len(s)), Reader: strings.NewReader(s)}
}

func legacyRowTimestamp(s string) LegacyReportRowTime { return LegacyReportRowTime(legacyRowText(s)) }

func legacyRowFixture() LegacyReportRow {
	return LegacyReportRow{
		DatabaseDriver: "sqlite",
		ID:             1, OrganizationID: 2, RunID: 3, AnalysisRevision: 1,
		ReportFormat: legacyRowText("legacy"), SchemaVersion: legacyRowText("old"), Revision: 2,
		StoragePath: legacyRowText(""), Status: legacyRowText("ready"), ErrorCode: legacyRowText("err\n"),
		CreatedAt: legacyRowTimestamp("2024-02-29 23:58:57.123456789+08:00"),
		CreatedBy: LegacyReportRowInteger{true, 7}, SourceJSON: legacyRowText("{\"x\": 1}\n"), SourceHash: legacyRowText("source"),
		FileSize: LegacyReportRowInteger{true, -1}, FrozenAt: legacyRowTimestamp("0001-01-01 00:00:00.000000001"),
	}
}

// Literal protocol bytes assembled independently from the documented twenty
// fields, not production columns/encoding helpers. PowerShell/.NET SHA256 over
// this literal independently produced the pinned 312-byte vector below.
const legacyRowGoldenHex = "6d69692f6c65676163792d7265706f72742d726f772f7631000114" +
	"0101010000000000000001" + "0201010000000000000002" + "0301010000000000000003" + "0401010000000000000001" +
	"05020100000000000000066c6567616379" + "06020100000000000000036f6c64" + "0701010000000000000002" +
	"080200" + "0902010000000000000000" + "0a020100000000000000057265616479" + "0b020100000000000000046572720a" +
	"0c03010000000000000023323032342d30322d32392032333a35383a35372e3132333435363738392b30383a3030" + "0d0300" + "0e01010000000000000007" + "0f0100" +
	"10020100000000000000097b2278223a20317d0a" + "1102010000000000000006736f75726365" + "120200" +
	"130101ffffffffffffffff" + "140301000000000000001d303030312d30312d30312030303a30303a30302e303030303030303031"
const legacyRowGoldenSHA = "089f52b9dac1a1c3870d6fc2076b86efbc075950277128e23a953d35f74f8220"

func TestLegacyReportRowIndependentGoldenAndExactBudget(t *testing.T) {
	wire, err := hex.DecodeString(legacyRowGoldenHex)
	if err != nil || len(wire) != 312 {
		t.Fatal("invalid independent literal")
	}
	want := sha256.Sum256(wire)
	if hex.EncodeToString(want[:]) != legacyRowGoldenSHA {
		t.Fatal("independent hash drift")
	}
	got, err := DigestLegacyReportRow(t.Context(), legacyRowFixture(), LegacyReportRowLimits{312, time.Second})
	if err != nil || got != legacyRowGoldenSHA {
		t.Fatal("fixed row protocol differs from literal", err, got)
	}
	got, err = DigestLegacyReportRow(t.Context(), legacyRowFixture(), LegacyReportRowLimits{311, time.Second})
	if err != ErrLimit || got != "" { //nolint:errorlint // The public contract requires exact closed errors, not wrappers containing private input.
		t.Fatal("canonical framing omitted from byte budget", err)
	}
	if LegacyReportRowVersion != "mii.legacy-report-row.v1" {
		t.Fatal("protocol identity drift")
	}
}

func TestLegacyReportRowPostgresBinaryGoldenAndDialectBinding(t *testing.T) {
	const createdSQLite = "0c03010000000000000023323032342d30322d32392032333a35383a35372e3132333435363738392b30383a3030"
	const frozenSQLite = "140301000000000000001d303030312d30312d30312030303a30303a30302e303030303030303031"
	// Independent protocol literals: epoch 2000-01-01, and one microsecond
	// before it. No timestamp parser or production frame helper participates.
	const createdBinary = "0c030100000000000000080000000000000000"
	const frozenBinary = "1403010000000000000008ffffffffffffffff"
	independentHex := strings.Replace(legacyRowGoldenHex, "7631000114", "7631000214", 1)
	independentHex = strings.Replace(independentHex, createdSQLite, createdBinary, 1)
	independentHex = strings.Replace(independentHex, frozenSQLite, frozenBinary, 1)
	wire, err := hex.DecodeString(independentHex)
	if err != nil || len(wire) != 264 {
		t.Fatal("invalid independent PostgreSQL vector")
	}
	const pinned = "c3ec6ca1bae3506164dcbabbbda3aa9974c9c57289b7aaf2c3de45ffcebdc1fd"
	sum := sha256.Sum256(wire)
	if hex.EncodeToString(sum[:]) != pinned {
		t.Fatal("independent PostgreSQL vector drift")
	}
	var sums [2]string
	for i, driver := range []string{"postgres", "sqlite"} {
		r := legacyRowFixture()
		r.DatabaseDriver = driver
		r.CreatedAt = legacyRowTimestamp(strings.Repeat("\x00", 8))
		r.FrozenAt = legacyRowTimestamp(strings.Repeat("\xff", 8))
		sums[i], err = DigestLegacyReportRow(t.Context(), r, LegacyReportRowLimits{264, time.Second})
		if err != nil {
			t.Fatal(err)
		}
	}
	if sums[0] != pinned || sums[0] == sums[1] {
		t.Fatal("original dialect not bound")
	}
	for _, raw := range []string{"", "1234567", "123456789"} {
		r := legacyRowFixture()
		r.DatabaseDriver = "postgres"
		r.CreatedAt, r.FrozenAt = legacyRowTimestamp(raw), LegacyReportRowTime{}
		if got, err := DigestLegacyReportRow(t.Context(), r, LegacyReportRowLimits{MaxFileBytes, time.Second}); got != "" || err != ErrInvalid { //nolint:errorlint // Exact closed sentinel is the tested confidentiality contract.
			t.Fatal("non-binary PostgreSQL timestamp accepted", err)
		}
	}
}

func TestLegacyReportRowEveryColumnAndNullableDifferenceBound(t *testing.T) {
	for name, mutate := range map[string]func(*LegacyReportRow){
		"01_id":                func(r *LegacyReportRow) { r.ID++ },
		"02_organization_id":   func(r *LegacyReportRow) { r.OrganizationID++ },
		"03_run_id":            func(r *LegacyReportRow) { r.RunID++ },
		"04_analysis_revision": func(r *LegacyReportRow) { r.AnalysisRevision++ },
		"05_format":            func(r *LegacyReportRow) { r.ReportFormat = legacyRowText("LEGACY") },
		"06_schema_version":    func(r *LegacyReportRow) { r.SchemaVersion = legacyRowText("older") },
		"07_revision":          func(r *LegacyReportRow) { r.Revision++ },
		"08_content_hash":      func(r *LegacyReportRow) { r.ContentHash = legacyRowText("") },
		"09_storage_path":      func(r *LegacyReportRow) { r.StoragePath = LegacyReportRowText{} },
		"10_status":            func(r *LegacyReportRow) { r.Status = legacyRowText("ready ") },
		"11_error_code":        func(r *LegacyReportRow) { r.ErrorCode = legacyRowText("err\r\n") },
		"12_created_at":        func(r *LegacyReportRow) { r.CreatedAt = legacyRowTimestamp("2024-02-29 23:58:57.123456788+08:00") },
		"13_completed_at":      func(r *LegacyReportRow) { r.CompletedAt = legacyRowTimestamp("") },
		"14_created_by":        func(r *LegacyReportRow) { r.CreatedBy.Value++ },
		"15_job_id":            func(r *LegacyReportRow) { r.JobID = LegacyReportRowInteger{true, 0} },
		"16_source_json":       func(r *LegacyReportRow) { r.SourceJSON = legacyRowText("{\"x\":1}") },
		"17_source_hash":       func(r *LegacyReportRow) { r.SourceHash = legacyRowText("SOURCE") },
		"18_file_hash":         func(r *LegacyReportRow) { r.FileHash = legacyRowText("") },
		"19_file_size":         func(r *LegacyReportRow) { r.FileSize.Value = math.MinInt64 },
		"20_frozen_at":         func(r *LegacyReportRow) { r.FrozenAt = LegacyReportRowTime{} },
	} {
		t.Run(name, func(t *testing.T) {
			r := legacyRowFixture()
			mutate(&r)
			got, err := DigestLegacyReportRow(t.Context(), r, LegacyReportRowLimits{MaxFileBytes, time.Second})
			if err != nil || got == "" || got == legacyRowGoldenSHA {
				t.Fatal("original column did not affect commitment", err)
			}
		})
	}
	// Every nullable column's NULL has a different representation from a
	// present zero/empty value, including integer 0 and a valid minimal timestamp.
	for _, field := range []string{"content_hash", "storage_path", "error_code", "completed_at", "created_by", "job_id", "source_json", "source_hash", "file_hash", "file_size", "frozen_at"} {
		t.Run("nullable_"+field, func(t *testing.T) {
			var sums [2]string
			for i := range 2 {
				r := legacyRowFixture()
				text := LegacyReportRowText{}
				integer := LegacyReportRowInteger{}
				stamp := LegacyReportRowTime{}
				if i == 1 {
					text = legacyRowText("")
					integer.Present = true
					stamp = legacyRowTimestamp("")
				}
				switch field {
				case "content_hash":
					r.ContentHash = text
				case "storage_path":
					r.StoragePath = text
				case "error_code":
					r.ErrorCode = text
				case "completed_at":
					r.CompletedAt = stamp
				case "created_by":
					r.CreatedBy = integer
				case "job_id":
					r.JobID = integer
				case "source_json":
					r.SourceJSON = text
				case "source_hash":
					r.SourceHash = text
				case "file_hash":
					r.FileHash = text
				case "file_size":
					r.FileSize = integer
				case "frozen_at":
					r.FrozenAt = stamp
				}
				var err error
				sums[i], err = DigestLegacyReportRow(t.Context(), r, LegacyReportRowLimits{MaxFileBytes, time.Second})
				if err != nil {
					t.Fatal(err)
				}
			}
			if sums[0] == sums[1] {
				t.Fatal("NULL and present empty/zero conflated")
			}
		})
	}
}

func TestLegacyReportRowRejectsInvalidShapeBeforeBorrowingAnyReader(t *testing.T) {
	for name, mutate := range map[string]func(*LegacyReportRow){
		"id":                   func(r *LegacyReportRow) { r.ID = 0 },
		"org":                  func(r *LegacyReportRow) { r.OrganizationID = -1 },
		"run":                  func(r *LegacyReportRow) { r.RunID = 0 },
		"analysis":             func(r *LegacyReportRow) { r.AnalysisRevision = math.MaxInt64 },
		"revision":             func(r *LegacyReportRow) { r.Revision = 0 },
		"required_format":      func(r *LegacyReportRow) { r.ReportFormat = LegacyReportRowText{} },
		"required_schema":      func(r *LegacyReportRow) { r.SchemaVersion = LegacyReportRowText{} },
		"required_status":      func(r *LegacyReportRow) { r.Status = LegacyReportRowText{} },
		"required_time":        func(r *LegacyReportRow) { r.CreatedAt = LegacyReportRowTime{} },
		"null_text_bytes":      func(r *LegacyReportRow) { r.FileHash.Bytes = 1 },
		"null_text_reader":     func(r *LegacyReportRow) { r.FileHash.Reader = strings.NewReader("") },
		"present_text_nil":     func(r *LegacyReportRow) { r.FileHash.Present = true },
		"negative_length":      func(r *LegacyReportRow) { r.SourceJSON.Bytes = -1 },
		"overflow_length":      func(r *LegacyReportRow) { r.SourceJSON.Bytes = math.MaxInt64 },
		"null_integer_value":   func(r *LegacyReportRow) { r.JobID.Value = 1 },
		"null_time_value":      func(r *LegacyReportRow) { r.CompletedAt.Bytes = 1 },
		"null_time_reader":     func(r *LegacyReportRow) { r.CompletedAt.Reader = strings.NewReader("") },
		"present_time_nil":     func(r *LegacyReportRow) { r.CompletedAt.Present = true },
		"negative_time_length": func(r *LegacyReportRow) { r.CreatedAt.Bytes = -1 },
		"driver":               func(r *LegacyReportRow) { r.DatabaseDriver = "unknown" },
		"pg_time_length":       func(r *LegacyReportRow) { r.DatabaseDriver = "postgres" },
	} {
		t.Run(name, func(t *testing.T) {
			r := legacyRowFixture()
			r.ReportFormat.Reader = inventoryReaderFunc(func([]byte) (int, error) { t.Fatal("invalid row borrowed reader"); return 0, io.EOF })
			mutate(&r)
			sum, err := DigestLegacyReportRow(t.Context(), r, LegacyReportRowLimits{MaxFileBytes, time.Second})
			if sum != "" || err != ErrInvalid { //nolint:errorlint // Invalid input must not escape in a wrapped error.
				t.Fatal("invalid shape accepted or leaked error", err)
			}
		})
	}
}

func TestLegacyReportRowReaderFaultsAndLateFailureNeverReturnHash(t *testing.T) {
	canaryErr := errors.New("private-row-reader-canary")
	for _, mode := range []string{"short", "extra", "late_error", "joined_eof", "panic", "negative_n", "oversized_n", "no_progress", "cancel_at_eof", "cancel_after_data", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			r := legacyRowFixture()
			var calls int
			reader := inventoryReaderFunc(func(p []byte) (int, error) {
				calls++
				switch mode {
				case "short":
					return 0, io.EOF
				case "extra":
					p[0], p[1] = 'x', 'y'
					return 2, io.EOF
				case "late_error":
					if calls == 2 {
						return 0, canaryErr
					}
					p[0] = 'x'
					return 1, nil
				case "joined_eof":
					p[0] = 'x'
					return 1, errors.Join(io.EOF, canaryErr)
				case "panic":
					panic("private-row-panic-canary")
				case "negative_n":
					return -1, nil
				case "oversized_n":
					return len(p) + 1, nil
				case "no_progress":
					return 0, nil
				case "cancel_at_eof":
					cancel()
					p[0] = 'x'
					return 1, io.EOF
				case "cancel_after_data":
					if calls == 2 {
						cancel()
						return 0, io.EOF
					}
					p[0] = 'x'
					return 1, nil
				case "deadline":
					time.Sleep(5 * time.Millisecond)
					p[0] = 'x'
					return 1, io.EOF
				}
				return 0, canaryErr
			})
			// The final TEXT column fails after all previous original fields have
			// already been hashed; failure must not expose that partial digest.
			r.FileHash = LegacyReportRowText{true, 1, reader}
			limit := LegacyReportRowLimits{MaxFileBytes, time.Second}
			want := ErrRead
			if mode == "short" || mode == "extra" {
				want = ErrMismatch
			}
			if strings.HasPrefix(mode, "cancel_") {
				want = ErrCanceled
			}
			if mode == "deadline" {
				limit.Timeout = time.Millisecond
				want = ErrCanceled
			}
			sum, err := DigestLegacyReportRow(ctx, r, limit)
			if sum != "" || err != want { //nolint:errorlint // Reader errors/panics must be replaced, not wrapped.
				t.Fatal("row reader failure not closed/zero", err)
			}
		})
	}
}

func TestLegacyReportRowClosedLimitsAndContext(t *testing.T) {
	for _, limits := range []LegacyReportRowLimits{{0, time.Second}, {-1, time.Second}, {MaxFileBytes + 1, time.Second}, {MaxFileBytes, 0}, {MaxFileBytes, -1}, {MaxFileBytes, MaxStreamTimeout + 1}} {
		if sum, err := DigestLegacyReportRow(t.Context(), legacyRowFixture(), limits); sum != "" || err != ErrLimit { //nolint:errorlint // Require the exact closed policy error.
			t.Fatal("invalid policy accepted", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if sum, err := DigestLegacyReportRow(ctx, legacyRowFixture(), LegacyReportRowLimits{MaxFileBytes, time.Second}); sum != "" || err != ErrCanceled { //nolint:errorlint // Require the exact closed cancellation error.
			t.Fatal("invalid context accepted", err)
		}
	}
}

func TestLegacyReportRowFullArchiveByteCeilingWithoutReadingTerabytes(t *testing.T) {
	for _, extra := range []int64{0, 1} {
		r := legacyRowFixture()
		called := false
		// The independent literal is 312 bytes and its original source is nine
		// bytes: exactly 303 bytes of other values and protocol framing remain.
		r.SourceJSON = LegacyReportRowText{true, MaxFileBytes - 303 + extra, inventoryReaderFunc(func([]byte) (int, error) {
			called = true
			return 0, errors.New("synthetic large-source read failure")
		})}
		sum, err := DigestLegacyReportRow(t.Context(), r, LegacyReportRowLimits{MaxFileBytes, time.Second})
		if extra == 0 && (err != ErrRead || !called) || extra == 1 && (err != ErrLimit || called) || sum != "" { //nolint:errorlint // Synthetic private read details must never be wrapped.
			t.Fatal("fixed archive cap was reduced/overflowed or invalid policy read input", err, called)
		}
	}
	// Time is also streamed, and failure of the final column cannot expose the
	// otherwise completely computed prefix commitment.
	r := legacyRowFixture()
	r.FrozenAt = LegacyReportRowTime{true, 0, inventoryReaderFunc(func([]byte) (int, error) { return 0, errors.Join(io.EOF, errors.New("timestamp failure")) })}
	if sum, err := DigestLegacyReportRow(t.Context(), r, LegacyReportRowLimits{MaxFileBytes, time.Second}); sum != "" || err != ErrRead { //nolint:errorlint // The joined private timestamp failure must be replaced by this exact sentinel.
		t.Fatal("final timestamp error passed", err)
	}
}

func TestLegacyReportRowPreservesArbitraryTextFramingAndNanoseconds(t *testing.T) {
	for _, values := range [][2]string{{"ab", "c"}, {"a", "bc"}, {"\x00\xff\r\n", "<>&"}, {"\x00\xff\n", "<>&"}, {"é", "e\u0301"}, {"e\u0301", "é"}} {
		r := legacyRowFixture()
		r.SourceJSON, r.SourceHash = legacyRowText(values[0]), legacyRowText(values[1])
		got, err := DigestLegacyReportRow(t.Context(), r, LegacyReportRowLimits{MaxFileBytes, time.Second})
		if err != nil || got == "" {
			t.Fatal("raw legacy bytes were parsed/normalized", err)
		}
		r = legacyRowFixture()
		r.SourceJSON, r.SourceHash = legacyRowText(values[1]), legacyRowText(values[0])
		other, err := DigestLegacyReportRow(t.Context(), r, LegacyReportRowLimits{MaxFileBytes, time.Second})
		if err != nil || got == other {
			t.Fatal("column framing does not bind exact bytes", err)
		}
	}
	seen := map[string]bool{}
	for _, stamp := range []string{"2024-02-29 23:58:57.123456789+08:00", "2024-02-29 23:58:57.123456789+07:00", "2024-02-29 23:58:57.123456788+08:00", "2024-02-29T23:58:57.123456789+08:00", ""} {
		r := legacyRowFixture()
		r.CreatedAt = legacyRowTimestamp(stamp)
		sum, err := DigestLegacyReportRow(t.Context(), r, LegacyReportRowLimits{MaxFileBytes, time.Second})
		if err != nil || seen[sum] {
			t.Fatal("original offset/nanoseconds/spelling were conflated", err)
		}
		seen[sum] = true
	}
}

func TestLegacyReportRowLargeTextUsesBoundedStreaming(t *testing.T) {
	const size = 25<<20 + 17
	r := legacyRowFixture()
	var read, largest int
	r.SourceJSON = LegacyReportRowText{true, size, inventoryReaderFunc(func(p []byte) (int, error) {
		largest = max(largest, len(p))
		if read == size {
			return 0, io.EOF
		}
		n := min(len(p), size-read)
		for i := range n {
			p[i] = 'x'
		}
		read += n
		return n, nil
	})}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	sum, err := DigestLegacyReportRow(t.Context(), r, LegacyReportRowLimits{MaxFileBytes, 5 * time.Second})
	runtime.ReadMemStats(&after)
	if err != nil || !hash(sum) || read != size || largest > 64<<10 || after.TotalAlloc-before.TotalAlloc > 2<<20 {
		t.Fatal("streaming row acquired a body-sized allocation or lost bytes", err, read, largest, after.TotalAlloc-before.TotalAlloc)
	}
	// Independently stream an explicit prefix/length/payload/suffix derived
	// from the pinned literal, not a production row/column serializer.
	parts := strings.Split(legacyRowGoldenHex, "10020100000000000000097b2278223a20317d0a")
	if len(parts) != 2 {
		t.Fatal("independent source frame not found")
	}
	prefix, _ := hex.DecodeString(parts[0] + "1002010000000001900011")
	suffix, _ := hex.DecodeString(parts[1])
	independent := sha256.New()
	_, _ = independent.Write(prefix)
	chunk := bytes.Repeat([]byte{'x'}, 64<<10)
	for remaining := size; remaining > 0; {
		n := min(len(chunk), remaining)
		_, _ = independent.Write(chunk[:n])
		remaining -= n
	}
	_, _ = independent.Write(suffix)
	if sum != hex.EncodeToString(independent.Sum(nil)) {
		t.Fatal("large row hash differs from literal framing oracle")
	}
	t.Logf("streamed=%d max_read=%d allocated=%d", read, largest, after.TotalAlloc-before.TotalAlloc)
}

func TestLegacyReportRowValuesDoNotLeakThroughFormattingOrMarshaling(t *testing.T) {
	r := legacyRowFixture()
	r.StoragePath = legacyRowText("private-row-canary")
	for _, value := range []any{r, r.StoragePath, r.CreatedBy, r.CreatedAt} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(format, value), "private-row-canary") || strings.Contains(fmt.Sprintf(format, value), "legacy-report-row/v1") {
				t.Fatal("formatter leaked protected row")
			}
		}
		if data, err := json.Marshal(value); err == nil || len(data) != 0 {
			t.Fatal("row serialized implicitly")
		}
		if _, err := value.(interface{ MarshalYAML() (any, error) }).MarshalYAML(); err != ErrInvalid { //nolint:errorlint // Implicit serializers must return only the closed sentinel.
			t.Fatal("YAML leaked row")
		}
		var out bytes.Buffer
		slog.New(slog.NewJSONHandler(&out, nil)).Info("test", "row", value)
		if strings.Contains(out.String(), "private-row-canary") {
			t.Fatal("slog leaked row")
		}
	}
}

func FuzzLegacyReportRowSourceBytes(f *testing.F) {
	for _, data := range [][]byte{nil, []byte("{\"x\": 1}\n"), {0, 255, '\r', '\n'}, []byte("e\u0301"), []byte("é")} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 256<<10 {
			t.Skip("bounded fuzz input; larger streaming input has a deterministic regression")
		}
		r := legacyRowFixture()
		r.SourceJSON = LegacyReportRowText{true, int64(len(data)), bytes.NewReader(data)}
		sum, err := DigestLegacyReportRow(t.Context(), r, LegacyReportRowLimits{MaxFileBytes, time.Second})
		if err != nil {
			t.Fatal("arbitrary original bytes rejected", err)
		}
		parts := strings.Split(legacyRowGoldenHex, "10020100000000000000097b2278223a20317d0a")
		prefix, err := hex.DecodeString(parts[0] + "100201" + fmt.Sprintf("%016x", len(data)))
		if err != nil {
			t.Fatal(err)
		}
		suffix, err := hex.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		oracle := sha256.New()
		_, _ = oracle.Write(prefix)
		_, _ = oracle.Write(data)
		_, _ = oracle.Write(suffix)
		if sum != hex.EncodeToString(oracle.Sum(nil)) {
			t.Fatal("source bytes changed or were ambiguously framed")
		}
	})
}
