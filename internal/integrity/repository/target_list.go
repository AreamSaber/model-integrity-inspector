package repository

import (
	"strings"
	"unicode/utf8"
)

// TargetFilters contains only public scalar columns. Values are SQL parameters,
// never column names or snippets; search metacharacters are treated literally.
type TargetFilters struct{ Query, Model, Environment, Status string }

func (f TargetFilters) Valid() bool {
	for _, value := range []string{f.Query, f.Model, f.Environment, f.Status} {
		if !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") || len(value) > 512 {
			return false
		}
	}
	return utf8.RuneCountInString(f.Query) <= 128 && utf8.RuneCountInString(f.Model) <= 128 && utf8.RuneCountInString(f.Environment) <= 64 && (f.Status == "" || f.Status == "active" || f.Status == "disabled")
}

func (t *Tenant) ListTargetsFiltered(options ListOptions, filters TargetFilters) ([]TargetState, error) {
	if !filters.Valid() {
		return nil, ErrConfiguration
	}
	options = options.normalized()
	query := t.targetQuery().Where("target.id > ?", options.AfterID)
	if filters.Query != "" {
		literal := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(strings.ToLower(filters.Query))
		pattern := "%" + literal + "%"
		query = query.Where("(LOWER(target.name) LIKE ? ESCAPE '!' OR LOWER(target.model) LIKE ? ESCAPE '!' OR LOWER(target.channel_id) LIKE ? ESCAPE '!')", pattern, pattern, pattern)
	}
	if filters.Model != "" {
		query = query.Where("target.model = ?", filters.Model)
	}
	if filters.Environment != "" {
		query = query.Where("target.environment = ?", filters.Environment)
	}
	if filters.Status != "" {
		query = query.Where("target.status = ?", filters.Status)
	}
	var records []targetJoined
	if err := query.Order("target.id").Limit(options.Limit).Scan(&records).Error; err != nil {
		return nil, persistenceError(err)
	}
	result := make([]TargetState, len(records))
	for i, record := range records {
		result[i] = record.state()
	}
	return result, nil
}
