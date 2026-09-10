package api

import (
	"net/http"
	"time"
)

func (c *control) logoutAll(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	// There is no user/organization selector. Reject query parameters and fields
	// instead of silently accepting an attempted cross-account request.
	var input struct{}
	if !c.decode(w, r, &input) {
		return
	}
	if err := c.cfg.Identity.LogoutAll(r.Context(), token(r)); err != nil {
		c.error(w, r, err)
		return
	}
	// Clear the browser cookie only after the transaction and audit commit.
	c.setCookie(w, "", time.Time{}, -1)
	c.success(w, r, http.StatusOK, map[string]bool{"ok": true})
}
