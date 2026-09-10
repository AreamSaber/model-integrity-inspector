package repository

import (
	"strings"

	"gorm.io/gorm"
)

// Project the existing canonical byte limits before database/sql materializes
// TEXT. Even an optional empty field must use an INVALID overflow sentinel:
// truncation or an empty replacement could recreate earlier valid signed bytes.
// Only fixed repository-owned column identifiers are composed here.
func auditEventReadColumns(tx *gorm.DB) string {
	columns := "id,organization_id,sequence,actor_id,created_at"
	for _, field := range []struct {
		name  string
		limit int
	}{
		{"action", 128}, {"object_type", 128}, {"object_id", 128}, {"result", 128},
		{"ip_summary", 128}, {"user_agent_summary", 128}, {"diff_summary", 1024},
		{"previous_hash", 64}, {"event_hmac", 64}, {"canonicalization_version", 128}, {"key_version", 128},
	} {
		columns += "," + strings.Replace(readBoundedText(tx, field.name, field.name, field.limit), "ELSE ''", "ELSE '\n'", 1)
	}
	return columns
}

func auditHeadReadColumns(tx *gorm.DB) string {
	return "organization_id,event_count,updated_at," + readBoundedText(tx, "event_hash", "event_hash", 64) + "," + readBoundedText(tx, "key_version", "key_version", 128)
}
