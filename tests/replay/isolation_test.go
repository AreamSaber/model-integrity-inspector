package replay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestOfflineCoreHasNoControllerOrNetworkExecutionImport(t *testing.T) {
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range files {
		if item.IsDir() || !strings.HasSuffix(item.Name(), ".go") || strings.HasSuffix(item.Name(), "_test.go") {
			continue
		}
		tree, err := parser.ParseFile(token.NewFileSet(), filepath.Clean(item.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		aliases := map[string]string{}
		for _, value := range tree.Imports {
			path, err := strconv.Unquote(value.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if path == "net" || strings.HasPrefix(path, "net/") && path != "net/http" || strings.Contains(path, "/tests/mock-upstream") || strings.Contains(path, "/tests/datasets") || strings.Contains(path, "/capturefixture") || strings.Contains(path, "/repository") || strings.Contains(path, "/worker") || strings.Contains(path, "/safehttp") {
				t.Fatal("offline core imports an execution/controller dependency")
			}
			name := filepath.Base(path)
			if value.Name != nil {
				name = value.Name.Name
			}
			aliases[name] = path
		}
		ast.Inspect(tree, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := selector.X.(*ast.Ident)
			if !ok || aliases[id.Name] != "net/http" {
				return true
			}
			switch selector.Sel.Name {
			case "Client", "DefaultClient", "DefaultTransport", "Transport", "Get", "Post", "PostForm", "NewRequest", "NewRequestWithContext":
				t.Error("offline core contains a real HTTP execution path")
			}
			return true
		})
	}
}

func FuzzCaptureEnvelope(f *testing.F) {
	// Fuzz the finite decoder without furnishing private keys or privileged
	// controller metadata. Valid source replay is covered by the unit fixtures.
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"capture":{"labels":["normal"]}}`))
	f.Add([]byte{255, 0, 1})
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		engine := &Engine{keyID: "dev-fuzz", publicKey: public}
		// A missing public key/verifier cannot be reached unless an input also
		// provides a valid signature, which this deliberately untrusted corpus lacks.
		if value, err := engine.verify(t.Context(), bytes.NewReader(raw)); err == nil || value != nil {
			t.Fatal("unauthenticated capture accepted")
		}
	})
}
