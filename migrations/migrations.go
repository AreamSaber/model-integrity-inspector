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
	var result []Migration
	for i, name := range []string{"foundation", "queue_leases", "target_metadata", "identity_management", "target_prechecks", "catalog_versions", "execution_state", "response_evidence", "run_estimates"} {
		filename := fmt.Sprintf("%06d_%s.up.sql", i+1, name)
		common, err := sources.ReadFile("common/" + filename)
		if err != nil {
			return nil, err
		}
		specific, err := sources.ReadFile(dialect + "/" + filename)
		if err != nil {
			return nil, err
		}
		// Preserve version 1's exact checksum construction. Git/platform newline
		// normalization must not create a false checksum drift.
		script := strings.ReplaceAll(string(common)+"\n"+string(specific), "\r\n", "\n")
		hash := sha256.Sum256([]byte(script))
		result = append(result, Migration{Version: i + 1, Name: name, Checksum: hex.EncodeToString(hash[:]), SQL: script})
	}
	return result, nil
}
