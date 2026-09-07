// Package migrations embeds immutable, forward-only database migrations.
package migrations

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"strings"
)

//go:embed common/*.up.sql sqlite/*.up.sql postgresql/*.up.sql
var sources embed.FS

// Migration is a versioned SQL expansion. Applied versions may never be edited.
type Migration struct {
	Version  int
	Name     string
	Checksum string
	SQL      string
}

// ForDialect includes the common schema and the dialect's explicit indexes.
// The checksum covers the precise executable SQL, not a separately maintained marker.
func ForDialect(dialect string) ([]Migration, error) {
	if dialect == "postgres" {
		dialect = "postgresql"
	}
	if dialect != "sqlite" && dialect != "postgresql" {
		return nil, fmt.Errorf("unsupported migration dialect")
	}
	const name = "000001_foundation.up.sql"
	common, err := sources.ReadFile("common/" + name)
	if err != nil {
		return nil, err
	}
	specific, err := sources.ReadFile(dialect + "/" + name)
	if err != nil {
		return nil, err
	}
	// Git/platform newline normalization must not create a false checksum drift.
	script := strings.ReplaceAll(string(common)+"\n"+string(specific), "\r\n", "\n")
	hash := sha256.Sum256([]byte(script))
	return []Migration{{Version: 1, Name: "foundation", Checksum: hex.EncodeToString(hash[:]), SQL: script}}, nil
}
