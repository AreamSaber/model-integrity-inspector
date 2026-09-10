package identity

import "slices"

// BuiltinPermissions returns fresh slices. Organization admin never implicitly
// grants a system-wide role; explicit grants supplement these defaults.
func BuiltinPermissions() map[string][]string {
	read := []string{"read", "organization.read", "member.read", "target.read", "run.read", "evidence.read", "baseline.read", "rules.read"}
	with := func(extra ...string) []string { return append(slices.Clone(read), extra...) }
	return map[string][]string{
		"admin":     with("target.write", "target.delete", "target.precheck", "catalog.write", "secret.replace", "run.create", "run.high-cost", "run.custom", "run.cancel-any", "evidence.body", "report.export", "data.delete", "member.write", "baseline.write", "baseline.approve", "rules.manage", "review.write", "audit.read", "organization.settings"),
		"operator":  with("target.write", "target.precheck", "catalog.write", "run.create", "run.cancel-own", "report.export", "baseline.write", "review.write"),
		"auditor":   with("run.create", "run.high-cost", "run.cancel-any", "evidence.body", "report.export", "audit.read", "review.write"),
		"developer": with("target.write", "target.precheck", "catalog.write", "run.create", "run.cancel-own", "report.export", "baseline.write", "review.write"),
		"viewer":    read,
	}
}

type Principal struct {
	UserID         int64
	OrganizationID int64
	SystemAdmin    bool
	Permissions    []string
}

// Authorize always requires a positive tenant scope for organization resources.
// System admins must select and audit a scope; no silent cross-tenant wildcard.
func (p Principal) Authorize(permission string) error {
	if p.UserID <= 0 {
		return ErrAuthentication
	}
	if len(permission) > 7 && permission[:7] == "system." {
		if p.SystemAdmin {
			return nil
		}
		return ErrPermission
	}
	if p.OrganizationID <= 0 || !slices.Contains(p.Permissions, permission) {
		return ErrPermission
	}
	return nil
}

func (p Principal) AuthorizeCancellation(createdBy int64) error {
	if p.Authorize("run.cancel-any") == nil {
		return nil
	}
	if createdBy == p.UserID {
		return p.Authorize("run.cancel-own")
	}
	return ErrPermission
}
