package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteVersion(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	printed, err := writeVersion([]string{"mii", "version"}, &output)
	if err != nil {
		t.Fatalf("writeVersion() error = %v", err)
	}
	if !printed {
		t.Fatal("writeVersion() printed = false, want true")
	}
	if !strings.Contains(output.String(), `"version":"0.1.0-dev"`) {
		t.Fatalf("writeVersion() output = %q", output.String())
	}
}

func TestWriteVersionIgnoresRunCommand(t *testing.T) {
	t.Parallel()

	printed, err := writeVersion([]string{"mii"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("writeVersion() error = %v", err)
	}
	if printed {
		t.Fatal("writeVersion() printed = true, want false")
	}
}
