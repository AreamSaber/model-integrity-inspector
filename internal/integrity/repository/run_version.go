package repository

// RunVersion is a narrow, tenant-scoped change token. It deliberately cannot
// carry the S2 execution snapshot, request key, credentials, or sample bodies.
type RunVersion struct {
	ID      int64
	Version int64
	Status  string
}

func (t *Tenant) GetRunVersion(id int64) (RunVersion, error) {
	var result RunVersion
	err := t.scoped().Model(&RunRecord{}).Select("id", "version", "status").Where("id = ?", id).Take(&result).Error
	return result, executionError(err)
}
