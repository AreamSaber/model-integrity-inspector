package backupmanifest

const (
	ArtifactScopeOrganization = "organization"
	ArtifactScopeInstalled    = "installed"
)

// Original row IDs are unique within their source table/category, not across
// rule and template tables. Version uniqueness instead belongs to each tenant.
// Never rewrite an original version or hash to manufacture global uniqueness.
func validArtifactIdentities(schema string, artifacts []Artifact, organizations map[int64]bool) bool {
	if schema == Version {
		for i, a := range artifacts {
			if a.Scope != "" || a.OrganizationID != 0 || a.ID != 0 || i > 0 && a.Category == artifacts[i-1].Category && a.Version == artifacts[i-1].Version {
				return false
			}
		}
		return true
	}
	if schema != VersionV2 {
		return false
	}
	type versionKey struct {
		category string
		org      int64
		version  string
	}
	type rowKey struct {
		category string
		id       int64
	}
	versions := make(map[versionKey]bool, len(artifacts))
	rows := make(map[rowKey]bool, len(artifacts))
	for _, a := range artifacts {
		switch a.Category {
		case "rule", "template":
			key := rowKey{a.Category, a.ID}
			if a.Scope != ArtifactScopeOrganization || a.ID <= 0 || !organizations[a.OrganizationID] || rows[key] {
				return false
			}
			rows[key] = true
		case "tokenizer", "scoring":
			if a.Scope != ArtifactScopeInstalled || a.OrganizationID != 0 || a.ID != 0 {
				return false
			}
		default:
			return false
		}
		key := versionKey{a.Category, a.OrganizationID, a.Version}
		if versions[key] {
			return false
		}
		versions[key] = true
	}
	return true
}
