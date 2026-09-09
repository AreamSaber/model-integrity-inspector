package reportstorage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var csvStorageBody = []byte("csv_schema,path,value_type,json_value\r\nmii.report.csv.v1,,object,{}\r\nmii.report.csv.v1,/review,null,null\r\n")

func TestCSVStoragePreservesExistingFormatsAndRetryIdentity(t *testing.T) {
	store, path := openTestStore(t)
	legacy := map[string][]byte{"json": []byte(`{"safe":"S1"}`), "html": []byte("<!doctype html><p>S1</p>")}
	refs := map[string]Reference{}
	identities := map[string]os.FileInfo{}
	for format, body := range legacy {
		ref, err := store.Put(t.Context(), 17, format, body)
		if err != nil {
			t.Fatal(err)
		}
		refs[format] = ref
		identities[format], err = os.Stat(filepath.Join(path, ref.Name()))
		if err != nil {
			t.Fatal(err)
		}
	}
	ref, err := store.Put(t.Context(), 17, "csv", csvStorageBody)
	if err != nil || ref.Format != "csv" || ref.Hash != hashBytes(csvStorageBody) || ref.Name() != "org-17-"+hashBytes(csvStorageBody)+".csv" {
		t.Fatal("CSV not stored at its exact independent content address", err)
	}
	before, err := os.Stat(filepath.Join(path, ref.Name()))
	if err != nil {
		t.Fatal(err)
	}
	retry, err := store.Put(t.Context(), 17, "csv", csvStorageBody)
	if err != nil || retry != ref {
		t.Fatal("CSV retry changed its reference", err)
	}
	after, err := os.Stat(filepath.Join(path, ref.Name()))
	if err != nil || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("retry replaced or rewrote the CSV file")
	}
	read, err := store.Read(t.Context(), ref)
	if err != nil || !bytes.Equal(read, csvStorageBody) {
		t.Fatal("CSV bytes changed during persistence", err)
	}
	read[0] = '!'
	if again, err := store.Read(t.Context(), ref); err != nil || !bytes.Equal(again, csvStorageBody) {
		t.Fatal("read buffer mutation changed the stored artifact")
	}
	for format, body := range legacy {
		got, err := store.Read(t.Context(), refs[format])
		if err != nil || !bytes.Equal(got, body) || refs[format].Hash != hashBytes(body) {
			t.Fatal("CSV creation changed legacy bytes/hash", format)
		}
		current, err := os.Stat(filepath.Join(path, refs[format].Name()))
		if err != nil || !os.SameFile(identities[format], current) || !identities[format].ModTime().Equal(current.ModTime()) {
			t.Fatal("CSV creation rewrote legacy file identity/time", format)
		}
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 3 {
		t.Fatal("unexpected artifact or leaked staging file", err)
	}
	other, err := store.Put(t.Context(), 18, "csv", csvStorageBody)
	if err != nil || other.Name() == ref.Name() || other.Hash != ref.Hash {
		t.Fatal("organization names were conflated", err)
	}
}

func TestCSVStorageRejectsTamperingLinksAndUnsafeNames(t *testing.T) {
	store, path := openTestStore(t)
	ref, err := store.Put(t.Context(), 31, "csv", csvStorageBody)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"", "CSV", " csv", "csv ", ".csv", "../csv", "csv/../json", "csv\x00", "csv\r\n", "pdf", "zip"} {
		if value := (Reference{31, ref.Hash, format, ref.Size}); value.Name() != "" {
			t.Fatal("unsafe format yielded an object name")
		}
		if got, err := store.Put(t.Context(), 31, format, csvStorageBody); got != (Reference{}) || !errors.Is(err, ErrUnsafe) {
			t.Fatal("unsafe format accepted")
		}
	}
	for _, value := range []Reference{{0, ref.Hash, "csv", ref.Size}, {31, "../outside", "csv", ref.Size}, {31, strings.Repeat("A", 64), "csv", ref.Size}, {31, ref.Hash, "csv", 0}, {31, ref.Hash, "csv", MaxBytes + 1}} {
		if got, err := store.Read(t.Context(), value); got != nil || !errors.Is(err, ErrUnsafe) {
			t.Fatal("unsafe CSV reference accepted")
		}
	}
	alias := filepath.Join(t.TempDir(), "csv-hardlink")
	if err := os.Link(filepath.Join(path, ref.Name()), alias); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Read(t.Context(), ref); got != nil || !errors.Is(err, ErrUnsafe) {
		t.Fatal("hard-linked CSV disclosed")
	}
	if got, err := store.Put(t.Context(), 31, "csv", csvStorageBody); got != (Reference{}) || !errors.Is(err, ErrUnsafe) {
		t.Fatal("retry reused an unsafe hard-linked CSV")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Repeat([]byte("x"), len(csvStorageBody))
	if err := os.WriteFile(filepath.Join(path, ref.Name()), tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := store.Read(t.Context(), ref); got != nil || !errors.Is(err, ErrIntegrity) {
		t.Fatal("same-size CSV corruption accepted")
	}
	if got, err := store.Put(t.Context(), 31, "csv", csvStorageBody); got != (Reference{}) || !errors.Is(err, ErrIntegrity) {
		t.Fatal("CSV retry silently replaced corrupt evidence")
	}
	// #nosec G304 -- path is this test's owned temporary store and ref was minted
	// by Put above; this read checks the exact deliberately corrupted fixture.
	unchanged, err := os.ReadFile(filepath.Join(path, ref.Name()))
	if err != nil || !bytes.Equal(unchanged, tampered) {
		t.Fatal("failed retry overwrote the existing file")
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 1 {
		t.Fatal("failure leaked staging artifacts", err)
	}
}

func TestCSVStorageRealLimitAndCanceledWrites(t *testing.T) {
	store, path := openTestStore(t)
	body := bytes.Repeat([]byte("x"), MaxBytes)
	ref, err := store.Put(t.Context(), 41, "csv", body)
	if err != nil || ref.Size != MaxBytes {
		t.Fatal("exact actual 16 MiB storage limit rejected", err)
	}
	if got, err := store.Read(t.Context(), ref); err != nil || !bytes.Equal(got, body) {
		t.Fatal("exact-limit CSV did not round trip", err)
	}
	for _, invalid := range [][]byte{nil, {}, append(body, 'x')} {
		if got, err := store.Put(t.Context(), 41, "csv", invalid); got != (Reference{}) || !errors.Is(err, ErrUnsafe) {
			t.Fatal("empty or oversized CSV accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := store.Put(ctx, 41, "csv", csvStorageBody); got != (Reference{}) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("canceled CSV write continued")
	}
	if got, err := store.Read(ctx, ref); got != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("canceled CSV read continued")
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 1 {
		t.Fatal("rejected write produced an artifact", err)
	}
}
