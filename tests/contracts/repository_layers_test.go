package contracts

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Keep the persistence layer independent of analysis runtimes. In particular,
// tokenrisk's real compiler/secret tests reach repository; a reverse production
// import creates a test-only cycle even when selected repository tests pass.
func TestRepositoryDoesNotImportAnalysisRuntime(t *testing.T) {
	for _, layer := range []string{"repository", "secret"} {
		t.Run(layer, func(t *testing.T) { assertNoAnalysisRuntimeImports(t, layer) })
	}
}

func assertNoAnalysisRuntimeImports(t *testing.T, layer string) {
	t.Helper()
	root := filepath.Join("../../internal/integrity", layer)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, item := range file.Imports {
			path, err := strconv.Unquote(item.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			const prefix = "model-integrity-inspector.local/mii/internal/integrity/"
			for _, forbidden := range []string{"analysis", "analyzer", "bundle"} {
				if path == prefix+forbidden || strings.HasPrefix(path, prefix+forbidden+"/") {
					t.Errorf("%s imported a higher-level analysis runtime: %s -> %s", layer, name, path)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("layer boundary check did not inspect production source")
	}
}
