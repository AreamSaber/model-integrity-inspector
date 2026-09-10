package api

import (
	"net/http"
	"slices"
	"strconv"
)

// effectivePermissions reports only this authenticated user's current grants
// in the explicitly selected organization. The role catalog and system-admin
// flag are never used as substitutes for effective organization authorization.
func (c *control) effectivePermissions(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	org, ok := c.managementOrganizationID(w, r, false)
	if !ok {
		return
	}
	principal, err := c.cfg.Identity.Principal(r.Context(), token(r), org)
	if err != nil {
		c.error(w, r, err)
		return
	}
	permissions := slices.Clone(principal.Permissions)
	slices.Sort(permissions)
	c.success(w, r, 200, map[string]any{"organization_id": strconv.FormatInt(org, 10), "user_id": strconv.FormatInt(principal.UserID, 10), "permissions": permissions})
}
