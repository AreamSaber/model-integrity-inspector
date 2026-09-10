package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"model-integrity-inspector.local/mii/internal/identity"
)

func (c *control) registerManagementRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/users", c.managementUsers)
	mux.HandleFunc("POST /api/v1/users", c.managementCreateUser)
	mux.HandleFunc("PATCH /api/v1/users/{id}", c.managementUpdateUser)
	mux.HandleFunc("POST /api/v1/users/{id}/unlock", c.managementUnlockUser)
	mux.HandleFunc("POST /api/v1/users/{id}/reset-password", c.managementResetPassword)
	mux.HandleFunc("GET /api/v1/organizations", c.managementOrganizations)
	mux.HandleFunc("POST /api/v1/organizations", c.managementCreateOrganization)
	mux.HandleFunc("GET /api/v1/organizations/{id}", c.managementGetOrganization)
	mux.HandleFunc("PATCH /api/v1/organizations/{id}", c.managementUpdateOrganization)
	mux.HandleFunc("GET /api/v1/organizations/{id}/members", c.managementMembers)
	mux.HandleFunc("POST /api/v1/organizations/{id}/members", c.managementAddMember)
	mux.HandleFunc("PATCH /api/v1/organizations/{id}/members/{memberId}", c.managementUpdateMember)
	mux.HandleFunc("GET /api/v1/roles", c.managementRoles)
}

func (c *control) managementError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, identity.ErrManagementValidation), errors.Is(err, ErrPagination):
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
	case errors.Is(err, identity.ErrManagementConflict):
		c.failure(w, r, 409, "MI_VERSION_CONFLICT")
	case errors.Is(err, identity.ErrManagementNotFound):
		c.failure(w, r, 404, "MI_NOT_FOUND")
	case errors.Is(err, identity.ErrLastAdministrator):
		c.failure(w, r, 409, "MI_LAST_ADMINISTRATOR")
	case errors.Is(err, identity.ErrSelfLockout):
		c.failure(w, r, 409, "MI_SELF_LOCKOUT_FORBIDDEN")
	default:
		c.error(w, r, err)
	}
}

// Management contracts have no nullable inputs. Reject null instead of silently
// interpreting a nullable patch field as "unchanged"; retain the common 64 KiB
// cap, media-type and trailing-document checks and reject unknown field names.
func (c *control) decodeManagement(w http.ResponseWriter, r *http.Request, out any) bool {
	if r.URL.RawQuery != "" {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return false
	}
	var raw json.RawMessage
	if !c.decode(w, r, &raw) {
		return false
	}
	// Match the exact contract key spelling (encoding/json otherwise accepts
	// case-insensitive aliases) and reject duplicate top-level keys.
	shape := reflect.TypeOf(out)
	if shape.Kind() != reflect.Pointer || shape.Elem().Kind() != reflect.Struct {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return false
	}
	allowed := map[string]bool{}
	for index := range shape.Elem().NumField() {
		allowed[strings.Split(shape.Elem().Field(index).Tag.Get("json"), ",")[0]] = true
	}
	fields := json.NewDecoder(bytes.NewReader(raw))
	opening, err := fields.Token()
	if err != nil || opening != json.Delim('{') {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return false
	}
	seen := map[string]bool{}
	for fields.More() {
		key, err := fields.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			c.failure(w, r, 400, "MI_INVALID_REQUEST")
			return false
		}
		seen[name] = true
		var value json.RawMessage
		if fields.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			c.failure(w, r, 400, "MI_INVALID_REQUEST")
			return false
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return false
	}
	return true
}

func managementID(value string) (int64, bool) {
	id, err := strconv.ParseInt(value, 10, 64)
	return id, err == nil && id > 0 && strconv.FormatInt(id, 10) == value
}
func (c *control) managementPathID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, ok := managementID(r.PathValue(name))
	if !ok {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
	}
	return id, ok
}
func (c *control) managementOrganizationID(w http.ResponseWriter, r *http.Request, path bool) (int64, bool) {
	values := r.Header.Values("X-Organization-ID")
	if len(values) != 1 {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return 0, false
	}
	id, ok := managementID(values[0])
	if !ok || (path && r.PathValue("id") != values[0]) {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return 0, false
	}
	return id, true
}

func managedUserDTO(user identity.UserSummary) map[string]any {
	return map[string]any{"id": strconv.FormatInt(user.ID, 10), "username": user.Username, "display_name": user.DisplayName, "status": user.Status, "system_admin": user.IsSystemAdmin, "must_change_password": user.MustChangePassword, "version": user.Version, "created_at": user.CreatedAt, "updated_at": user.UpdatedAt}
}
func managedOrganizationDTO(org identity.OrganizationSummary) map[string]any {
	return map[string]any{"id": strconv.FormatInt(org.ID, 10), "name": org.Name, "timezone": org.Timezone, "status": org.Status, "full_response_retention_days": org.FullResponseRetentionDays, "version": org.Version, "created_at": org.CreatedAt, "updated_at": org.UpdatedAt}
}
func managedMemberDTO(member identity.MemberSummary) map[string]any {
	return map[string]any{"id": strconv.FormatInt(member.ID, 10), "org_id": strconv.FormatInt(member.OrganizationID, 10), "user_id": strconv.FormatInt(member.UserID, 10), "username": member.Username, "roles": member.Roles, "permissions": member.Permissions, "status": member.Status, "version": member.Version, "created_at": member.CreatedAt, "updated_at": member.UpdatedAt}
}

// The extra one-row probe avoids emitting a spurious next cursor for a final
// page exactly as large as the limit, without increasing repository page caps.
func managementPage[T any](c *control, w http.ResponseWriter, r *http.Request, resource string, fetch func(identity.ManagementList) ([]T, error), id func(T) int64, dto func(T) map[string]any) {
	principal, err := c.cfg.Identity.Principal(r.Context(), token(r), 0)
	if err != nil {
		c.managementError(w, r, err)
		return
	}
	scope := "user:" + strconv.FormatInt(principal.UserID, 10) + "/" + resource
	page, err := c.parsePage(r, scope)
	if err != nil {
		c.managementError(w, r, err)
		return
	}
	values, err := fetch(identity.ManagementList{AfterID: page.AfterID, Limit: page.Limit, Query: page.Query})
	if err != nil {
		c.managementError(w, r, err)
		return
	}
	items := make([]map[string]any, 0, len(values))
	var lastID int64
	for _, value := range values {
		items = append(items, dto(value))
		lastID = id(value)
	}
	hasMore := false
	if len(values) == page.Limit {
		next, err := fetch(identity.ManagementList{AfterID: lastID, Limit: 1, Query: page.Query})
		if err != nil {
			c.managementError(w, r, err)
			return
		}
		hasMore = len(next) > 0
	}
	result, err := c.pageResult(items, lastID, hasMore, scope, page.Query)
	if err != nil {
		c.managementError(w, r, err)
		return
	}
	c.success(w, r, 200, result)
}

func (c *control) managementUsers(w http.ResponseWriter, r *http.Request) {
	managementPage(c, w, r, "users", func(list identity.ManagementList) ([]identity.UserSummary, error) {
		return c.cfg.Identity.ListUsers(r.Context(), token(r), list)
	}, func(v identity.UserSummary) int64 { return v.ID }, managedUserDTO)
}
func (c *control) managementCreateUser(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	var input struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
	}
	if !c.decodeManagement(w, r, &input) {
		return
	}
	result, err := c.cfg.Identity.CreateUser(r.Context(), token(r), identity.UserCreate{Username: input.Username, DisplayName: input.DisplayName, Password: input.Password})
	input.Password = ""
	if err != nil {
		c.managementError(w, r, err)
		return
	}
	c.success(w, r, 201, managedUserDTO(result))
}
func (c *control) managementUpdateUser(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	var input struct {
		Version     int     `json:"version"`
		DisplayName *string `json:"display_name"`
		Status      *string `json:"status"`
	}
	if !c.decodeManagement(w, r, &input) {
		return
	}
	result, err := c.cfg.Identity.UpdateUser(r.Context(), token(r), id, identity.UserPatch{ExpectedVersion: input.Version, DisplayName: input.DisplayName, Status: input.Status})
	if err != nil {
		c.managementError(w, r, err)
		return
	}
	c.success(w, r, 200, managedUserDTO(result))
}
func (c *control) managementUnlockUser(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	var input struct {
		Version int `json:"version"`
	}
	if !c.decodeManagement(w, r, &input) {
		return
	}
	result, err := c.cfg.Identity.UnlockUser(r.Context(), token(r), id, input.Version)
	if err != nil {
		c.managementError(w, r, err)
		return
	}
	c.success(w, r, 200, managedUserDTO(result))
}
func (c *control) managementResetPassword(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	var input struct {
		Version  int    `json:"version"`
		Password string `json:"password"`
	}
	if !c.decodeManagement(w, r, &input) {
		return
	}
	result, err := c.cfg.Identity.ResetUserPassword(r.Context(), token(r), id, input.Version, input.Password)
	input.Password = ""
	if err != nil {
		c.managementError(w, r, err)
		return
	}
	c.success(w, r, 200, managedUserDTO(result))
}

func (c *control) managementOrganizations(w http.ResponseWriter, r *http.Request) {
	managementPage(c, w, r, "organizations", func(list identity.ManagementList) ([]identity.OrganizationSummary, error) {
		return c.cfg.Identity.ListOrganizations(r.Context(), token(r), list)
	}, func(v identity.OrganizationSummary) int64 { return v.ID }, managedOrganizationDTO)
}
func (c *control) managementCreateOrganization(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	var input struct {
		Name     string `json:"name"`
		Timezone string `json:"timezone"`
	}
	if !c.decodeManagement(w, r, &input) {
		return
	}
	result, err := c.cfg.Identity.CreateOrganization(r.Context(), token(r), identity.OrganizationCreate{Name: input.Name, Timezone: input.Timezone})
	if err != nil {
		c.managementError(w, r, err)
		return
	}
	c.success(w, r, 201, managedOrganizationDTO(result))
}
func (c *control) managementGetOrganization(w http.ResponseWriter, r *http.Request) {
	id, ok := c.managementOrganizationID(w, r, true)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	result, err := c.cfg.Identity.GetOrganization(r.Context(), token(r), id)
	if err != nil {
		c.managementError(w, r, err)
		return
	}
	c.success(w, r, 200, managedOrganizationDTO(result))
}
func (c *control) managementUpdateOrganization(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	id, ok := c.managementOrganizationID(w, r, true)
	if !ok {
		return
	}
	var input struct {
		Version   int     `json:"version"`
		Name      *string `json:"name"`
		Timezone  *string `json:"timezone"`
		Status    *string `json:"status"`
		Retention *int    `json:"full_response_retention_days"`
	}
	if !c.decodeManagement(w, r, &input) {
		return
	}
	result, err := c.cfg.Identity.UpdateOrganization(r.Context(), token(r), id, identity.OrganizationPatch{ExpectedVersion: input.Version, Name: input.Name, Timezone: input.Timezone, Status: input.Status, FullResponseRetentionDays: input.Retention})
	if err != nil {
		c.managementError(w, r, err)
		return
	}
	c.success(w, r, 200, managedOrganizationDTO(result))
}

func (c *control) managementMembers(w http.ResponseWriter, r *http.Request) {
	id, ok := c.managementOrganizationID(w, r, true)
	if !ok {
		return
	}
	managementPage(c, w, r, "org:"+strconv.FormatInt(id, 10)+"/members", func(list identity.ManagementList) ([]identity.MemberSummary, error) {
		return c.cfg.Identity.ListMembers(r.Context(), token(r), id, list)
	}, func(v identity.MemberSummary) int64 { return v.ID }, managedMemberDTO)
}
func (c *control) managementAddMember(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	id, ok := c.managementOrganizationID(w, r, true)
	if !ok {
		return
	}
	var input struct {
		UserID      string   `json:"user_id"`
		Roles       []string `json:"roles"`
		Permissions []string `json:"permissions"`
	}
	if !c.decodeManagement(w, r, &input) {
		return
	}
	userID, ok := managementID(input.UserID)
	if !ok {
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
		return
	}
	result, err := c.cfg.Identity.AddMember(r.Context(), token(r), id, identity.MemberCreate{UserID: userID, Roles: input.Roles, Permissions: input.Permissions})
	if err != nil {
		c.managementError(w, r, err)
		return
	}
	c.success(w, r, 201, managedMemberDTO(result))
}
func (c *control) managementUpdateMember(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	id, ok := c.managementOrganizationID(w, r, true)
	if !ok {
		return
	}
	memberID, ok := c.managementPathID(w, r, "memberId")
	if !ok {
		return
	}
	var input struct {
		Version     int      `json:"version"`
		Roles       []string `json:"roles"`
		Permissions []string `json:"permissions"`
		Status      *string  `json:"status"`
	}
	if !c.decodeManagement(w, r, &input) {
		return
	}
	result, err := c.cfg.Identity.UpdateMember(r.Context(), token(r), id, memberID, identity.MemberPatch{ExpectedVersion: input.Version, Roles: input.Roles, Permissions: input.Permissions, Status: input.Status})
	if err != nil {
		c.managementError(w, r, err)
		return
	}
	c.success(w, r, 200, managedMemberDTO(result))
}

func (c *control) managementRoles(w http.ResponseWriter, r *http.Request) {
	orgID, ok := c.managementOrganizationID(w, r, false)
	if !ok {
		return
	}
	principal, err := c.cfg.Identity.Principal(r.Context(), token(r), orgID)
	if err != nil {
		c.managementError(w, r, err)
		return
	}
	scope := "user:" + strconv.FormatInt(principal.UserID, 10) + "/org:" + strconv.FormatInt(orgID, 10) + "/roles"
	page, err := c.parsePage(r, scope)
	if err != nil {
		c.managementError(w, r, err)
		return
	}
	roles, err := c.cfg.Identity.ListRoles(r.Context(), token(r), orgID)
	if err != nil {
		c.managementError(w, r, err)
		return
	}
	items := []map[string]any{}
	var lastID int64
	hasMore := false
	// Builtin names are immutable and the repository sorts them; their positive
	// slots form a stable cursor without exposing persistence role IDs.
	for index, role := range roles {
		slot := int64(index + 1)
		if slot <= page.AfterID || !strings.Contains(strings.ToLower(role.Name), strings.ToLower(page.Query)) {
			continue
		}
		if len(items) == page.Limit {
			hasMore = true
			break
		}
		items = append(items, map[string]any{"name": role.Name, "permissions": role.Permissions})
		lastID = slot
	}
	result, err := c.pageResult(items, lastID, hasMore, scope, page.Query)
	if err != nil {
		c.managementError(w, r, err)
		return
	}
	c.success(w, r, 200, result)
}
