package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
	"model-integrity-inspector.local/mii/internal/integrity/target"
)

// Body DTOs are write-only. They never enter logs or a response projection.
type targetFields struct {
	Name           string         `json:"name"`
	ProviderID     *string        `json:"provider_id"`
	ModelProfileID *string        `json:"model_profile_id"`
	Endpoint       string         `json:"endpoint"`
	Protocol       string         `json:"protocol"`
	Model          string         `json:"model"`
	Environment    string         `json:"environment"`
	ChannelID      string         `json:"channel_id"`
	Tags           []string       `json:"tags"`
	Options        target.Options `json:"options"`
}

// #nosec G117 -- Request-only credential DTO; never logged/serialized, encrypted before persistence, public response constructed separately.
type targetAuth struct {
	Type       string            `json:"type"`
	APIKey     string            `json:"api_key"`
	HeaderName string            `json:"header_name"`
	Headers    map[string]string `json:"headers"`
}

func (c *control) registerTargetRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/targets", c.listTargets)
	mux.HandleFunc("POST /api/v1/targets", c.createTarget)
	mux.HandleFunc("GET /api/v1/targets/{id}", c.getTarget)
	mux.HandleFunc("PATCH /api/v1/targets/{id}", c.updateTarget)
	mux.HandleFunc("POST /api/v1/targets/{id}/rotate-secret", c.rotateTarget)
	mux.HandleFunc("DELETE /api/v1/targets/{id}", c.deleteTarget)
	mux.HandleFunc("POST /api/v1/targets/{id}/precheck", c.enqueuePrecheck)
	mux.HandleFunc("GET /api/v1/targets/{id}/precheck", c.latestPrecheck)
	mux.HandleFunc("GET /api/v1/targets/{id}/prechecks/{precheckId}", c.getPrecheck)
}

func (c *control) targetError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, target.ErrInvalid), errors.Is(err, secret.ErrInvalid), errors.Is(err, repository.ErrConfiguration), errors.Is(err, ErrPagination):
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
	case errors.Is(err, repository.ErrNotFound):
		c.failure(w, r, 404, "MI_NOT_FOUND")
	case errors.Is(err, repository.ErrConflict):
		c.failure(w, r, 409, "MI_VERSION_CONFLICT")
	default:
		c.error(w, r, err)
	}
}

// authorizeOrganization binds the audit actor only after trusted session/RBAC
// verification. A user-supplied organization ID alone grants no capability.
func (c *control) authorizeOrganization(w http.ResponseWriter, r *http.Request, permission string) (context.Context, int64, bool) {
	id, ok := c.managementOrganizationID(w, r, false)
	if !ok {
		return nil, 0, false
	}
	principal, err := c.cfg.Identity.Principal(r.Context(), token(r), id)
	if err != nil {
		c.error(w, r, err)
		return nil, 0, false
	}
	if err := principal.Authorize(permission); err != nil {
		c.error(w, r, err)
		return nil, 0, false
	}
	actor, err := audit.ActorFromContext(r.Context())
	if err != nil {
		c.error(w, r, err)
		return nil, 0, false
	}
	actor.ActorID = principal.UserID
	ctx, err := c.cfg.Store.BindControlAuthority(audit.WithActor(r.Context(), actor), digest(token(r)), id)
	if err != nil {
		c.error(w, r, err)
		return nil, 0, false
	}
	return ctx, id, true
}

func (fields targetFields) input() (target.Input, error) {
	parse := func(value *string) (*int64, error) {
		if value == nil {
			return nil, nil
		}
		id, ok := managementID(*value)
		if !ok {
			return nil, target.ErrInvalid
		}
		return &id, nil
	}
	provider, err := parse(fields.ProviderID)
	if err != nil {
		return target.Input{}, err
	}
	profile, err := parse(fields.ModelProfileID)
	if err != nil {
		return target.Input{}, err
	}
	return target.Input{Name: fields.Name, ProviderID: provider, ModelProfileID: profile, Endpoint: fields.Endpoint, Protocol: fields.Protocol, Model: fields.Model, Environment: fields.Environment, ChannelID: fields.ChannelID, Tags: fields.Tags, Options: fields.Options}, nil
}
func idStringPointer(id *int64) *string {
	if id == nil {
		return nil
	}
	value := strconv.FormatInt(*id, 10)
	return &value
}
func targetFieldView(value target.View) targetFields {
	return targetFields{Name: value.Name, ProviderID: idStringPointer(value.ProviderID), ModelProfileID: idStringPointer(value.ModelProfileID), Endpoint: value.Endpoint, Protocol: value.Protocol, Model: value.Model, Environment: value.Environment, ChannelID: value.ChannelID, Tags: value.Tags, Options: value.Options}
}
func targetDTO(value target.View) any {
	return struct {
		ID string `json:"id"`
		targetFields
		Secret    map[string]any `json:"secret"`
		Status    string         `json:"status"`
		Version   int64          `json:"version"`
		CreatedAt any            `json:"created_at"`
		UpdatedAt any            `json:"updated_at"`
	}{ID: strconv.FormatInt(value.ID, 10), targetFields: targetFieldView(value), Secret: map[string]any{"id": strconv.FormatInt(value.Secret.ID, 10), "version": value.Secret.Version, "mask": value.Secret.Mask, "rotated_at": value.Secret.RotatedAt}, Status: value.Status, Version: value.Version, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt}
}
func credentials(value targetAuth) secret.Input {
	return secret.Input{Type: value.Type, APIKey: []byte(value.APIKey), HeaderName: value.HeaderName, Headers: value.Headers}
}

func (c *control) createTarget(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, orgID, ok := c.authorizeOrganization(w, r, "target.write")
	if !ok {
		return
	}
	var body struct {
		targetFields
		Auth targetAuth `json:"auth"`
	}
	if !c.decode(w, r, &body) {
		return
	}
	input, err := body.input()
	if err != nil {
		c.targetError(w, r, err)
		return
	}
	auth := credentials(body.Auth)
	defer clear(auth.APIKey)
	result, err := c.cfg.Targets.Create(ctx, orgID, input, auth)
	if err != nil {
		c.targetError(w, r, err)
		return
	}
	c.success(w, r, 201, targetDTO(result))
}
func (c *control) getTarget(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		c.targetError(w, r, target.ErrInvalid)
		return
	}
	ctx, orgID, ok := c.authorizeOrganization(w, r, "target.read")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	result, err := c.cfg.Targets.Get(ctx, orgID, id)
	if err != nil {
		c.targetError(w, r, err)
		return
	}
	c.success(w, r, 200, targetDTO(result))
}
func (c *control) listTargets(w http.ResponseWriter, r *http.Request) {
	ctx, orgID, ok := c.authorizeOrganization(w, r, "target.read")
	if !ok {
		return
	}
	scope := "org:" + strconv.FormatInt(orgID, 10) + "/targets"
	filters, pageRequest, scope, err := targetListRequest(r, scope)
	if err != nil {
		c.targetError(w, r, err)
		return
	}
	page, err := c.parsePage(pageRequest, scope)
	if err != nil {
		c.targetError(w, r, ErrPagination)
		return
	}
	filters.Query = page.Query
	rows, err := c.cfg.Targets.ListFiltered(ctx, orgID, repository.ListOptions{AfterID: page.AfterID, Limit: page.Limit}, filters)
	if err != nil {
		c.targetError(w, r, err)
		return
	}
	items := make([]any, 0, len(rows))
	var last int64
	for _, row := range rows {
		items = append(items, targetDTO(row))
		last = row.ID
	}
	more := false
	if len(rows) == page.Limit {
		next, err := c.cfg.Targets.ListFiltered(ctx, orgID, repository.ListOptions{AfterID: last, Limit: 1}, filters)
		if err != nil {
			c.targetError(w, r, err)
			return
		}
		more = len(next) > 0
	}
	result, err := c.pageResult(items, last, more, scope, page.Query)
	if err != nil {
		c.targetError(w, r, err)
		return
	}
	c.success(w, r, 200, result)
}

// Bind every non-page filter into the signed cursor scope. The copied request
// allows the common pagination parser to continue rejecting unknown parameters.
func targetListRequest(r *http.Request, scope string) (repository.TargetFilters, *http.Request, string, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return repository.TargetFilters{}, nil, "", ErrPagination
	}
	filters := repository.TargetFilters{}
	values := url.Values{}
	for name, dest := range map[string]*string{"model": &filters.Model, "environment": &filters.Environment, "status": &filters.Status} {
		if len(query[name]) > 1 {
			return filters, nil, "", ErrPagination
		}
		*dest = strings.TrimSpace(query.Get(name))
		values.Set(name, *dest)
		query.Del(name)
	}
	if !filters.Valid() {
		return filters, nil, "", ErrPagination
	}
	copyRequest := r.Clone(r.Context())
	copyRequest.URL.RawQuery = query.Encode()
	return filters, copyRequest, scope + "/filters:" + values.Encode(), nil
}

func (c *control) updateTarget(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, orgID, ok := c.authorizeOrganization(w, r, "target.write")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	var patch map[string]json.RawMessage
	if !c.decode(w, r, &patch) {
		return
	}
	if patch == nil {
		c.targetError(w, r, target.ErrInvalid)
		return
	}
	var version int64
	if json.Unmarshal(patch["version"], &version) != nil || version <= 0 {
		c.targetError(w, r, target.ErrInvalid)
		return
	}
	delete(patch, "version")
	current, err := c.cfg.Targets.Get(ctx, orgID, id)
	if err != nil {
		c.targetError(w, r, err)
		return
	}
	status := current.Status
	if value, exists := patch["status"]; exists {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, &status) != nil || (status != "active" && status != "disabled") {
			c.targetError(w, r, target.ErrInvalid)
			return
		}
		delete(patch, "status")
	}
	data, err := json.Marshal(targetFieldView(current))
	if err != nil {
		c.targetError(w, r, err)
		return
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		c.targetError(w, r, secret.ErrUnavailable)
		return
	}
	for key, value := range patch {
		if _, exists := fields[key]; !exists {
			c.targetError(w, r, target.ErrInvalid)
			return
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) && key != "provider_id" && key != "model_profile_id" {
			c.targetError(w, r, target.ErrInvalid)
			return
		}
		fields[key] = value
	}
	data, err = json.Marshal(fields)
	if err != nil {
		c.targetError(w, r, err)
		return
	}
	var body targetFields
	if strictJSON(data, &body) != nil {
		c.targetError(w, r, target.ErrInvalid)
		return
	}
	input, err := body.input()
	if err != nil {
		c.targetError(w, r, err)
		return
	}
	result, err := c.cfg.Targets.Update(ctx, orgID, id, version, input, status)
	if err != nil {
		c.targetError(w, r, err)
		return
	}
	c.success(w, r, 200, targetDTO(result))
}
func (c *control) rotateTarget(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, orgID, ok := c.authorizeOrganization(w, r, "secret.replace")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	var body struct {
		Version       int64      `json:"version"`
		SecretVersion int64      `json:"secret_version"`
		Auth          targetAuth `json:"auth"`
	}
	if !c.decode(w, r, &body) {
		return
	}
	auth := credentials(body.Auth)
	defer clear(auth.APIKey)
	result, err := c.cfg.Targets.RotateSecret(ctx, orgID, id, body.Version, body.SecretVersion, auth)
	if err != nil {
		c.targetError(w, r, err)
		return
	}
	c.success(w, r, 200, targetDTO(result))
}
func (c *control) deleteTarget(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, orgID, ok := c.authorizeOrganization(w, r, "target.delete")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	var body struct {
		Version int64 `json:"version"`
	}
	if !c.decode(w, r, &body) {
		return
	}
	if err := c.cfg.Targets.Delete(ctx, orgID, id, body.Version); err != nil {
		c.targetError(w, r, err)
		return
	}
	c.success(w, r, 200, map[string]bool{"ok": true})
}
