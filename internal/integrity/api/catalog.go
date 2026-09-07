package api

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"

	"model-integrity-inspector.local/mii/internal/identity"
	"model-integrity-inspector.local/mii/internal/integrity/catalog"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func (c *control) registerCatalogRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/providers", c.listCatalogProviders)
	mux.HandleFunc("POST /api/v1/providers", c.createCatalogProvider)
	mux.HandleFunc("GET /api/v1/providers/{id}", c.getCatalogProvider)
	mux.HandleFunc("PATCH /api/v1/providers/{id}", c.updateCatalogProvider)
	mux.HandleFunc("DELETE /api/v1/providers/{id}", c.deleteCatalogProvider)
	mux.HandleFunc("GET /api/v1/model-profiles", c.listCatalogModels)
	mux.HandleFunc("POST /api/v1/model-profiles", c.createCatalogModel)
	mux.HandleFunc("GET /api/v1/model-profiles/{id}", c.getCatalogModel)
	mux.HandleFunc("PATCH /api/v1/model-profiles/{id}", c.updateCatalogModel)
	mux.HandleFunc("DELETE /api/v1/model-profiles/{id}", c.deleteCatalogModel)
}
func (c *control) catalogError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, catalog.ErrInvalid), errors.Is(err, repository.ErrConfiguration), errors.Is(err, ErrPagination):
		c.failure(w, r, 400, "MI_INVALID_REQUEST")
	case errors.Is(err, repository.ErrNotFound):
		c.failure(w, r, 404, "MI_NOT_FOUND")
	case errors.Is(err, repository.ErrConflict):
		c.failure(w, r, 409, "MI_VERSION_CONFLICT")
	default:
		c.error(w, r, err)
	}
}
func catalogProviderDTO(value catalog.ProviderView) map[string]any {
	return map[string]any{"id": strconv.FormatInt(value.ID, 10), "name": value.Name, "description": value.Description, "contact": value.Contact, "status": value.Status, "version": value.Version, "created_at": value.CreatedAt, "updated_at": value.UpdatedAt}
}
func catalogModelSummaryDTO(value catalog.ProfileSummary) map[string]any {
	return map[string]any{"id": strconv.FormatInt(value.ID, 10), "provider_id": strconv.FormatInt(value.ProviderID, 10), "name": value.Model, "display_name": value.DisplayName, "protocol": value.Protocol, "status": value.Status, "version": value.Version, "input_price_micros_per_million": value.InputPriceMicros, "output_price_micros_per_million": value.OutputPriceMicros, "created_at": value.CreatedAt, "updated_at": value.UpdatedAt}
}
func catalogModelDTO(value catalog.ProfileView) map[string]any {
	result := map[string]any{"id": strconv.FormatInt(value.ID, 10), "provider_id": strconv.FormatInt(value.ProviderID, 10), "name": value.Name, "display_name": value.DisplayName, "protocol": value.Protocol, "status": value.Status, "version": value.Version,
		"supports_stream": value.SupportsStream, "supports_seed": value.SupportsSeed, "reasoning_model": value.ReasoningModel, "tokenizer_id": value.TokenizerID, "tokenizer_quality": value.TokenizerQuality,
		"input_price_micros_per_million": value.InputPriceMicros, "output_price_micros_per_million": value.OutputPriceMicros, "created_at": value.CreatedAt, "updated_at": value.UpdatedAt}
	if value.MaxOutputTokens != nil {
		result["max_output_tokens"] = *value.MaxOutputTokens
	}
	if value.ContextWindow != nil {
		result["context_window"] = *value.ContextWindow
	}
	return result
}
func (c *control) listCatalogProviders(w http.ResponseWriter, r *http.Request) {
	ctx, orgID, ok := c.authorizeOrganization(w, r, "read")
	if !ok {
		return
	}
	r = r.WithContext(ctx)
	managementPage(c, w, r, "org:"+strconv.FormatInt(orgID, 10)+"/providers", func(list identity.ManagementList) ([]catalog.ProviderView, error) {
		return c.cfg.Catalog.ListProviders(ctx, token(r), orgID, list)
	}, func(value catalog.ProviderView) int64 { return value.ID }, catalogProviderDTO)
}
func (c *control) listCatalogModels(w http.ResponseWriter, r *http.Request) {
	ctx, orgID, ok := c.authorizeOrganization(w, r, "read")
	if !ok {
		return
	}
	r = r.WithContext(ctx)
	managementPage(c, w, r, "org:"+strconv.FormatInt(orgID, 10)+"/model-profiles", func(list identity.ManagementList) ([]catalog.ProfileSummary, error) {
		return c.cfg.Catalog.ListModels(ctx, token(r), orgID, list)
	}, func(value catalog.ProfileSummary) int64 { return value.ID }, catalogModelSummaryDTO)
}
func (c *control) createCatalogProvider(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, orgID, ok := c.authorizeOrganization(w, r, "catalog.write")
	if !ok {
		return
	}
	input := catalog.ProviderInput{Status: "active"}
	if !c.decode(w, r, &input) {
		return
	}
	if input.Status != "active" && input.Status != "disabled" {
		c.catalogError(w, r, catalog.ErrInvalid)
		return
	}
	result, err := c.cfg.Catalog.CreateProvider(ctx, token(r), orgID, input)
	if err != nil {
		c.catalogError(w, r, err)
		return
	}
	c.success(w, r, 201, catalogProviderDTO(result))
}
func (c *control) createCatalogModel(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, orgID, ok := c.authorizeOrganization(w, r, "catalog.write")
	if !ok {
		return
	}
	var input struct {
		catalog.ProfileInput
		ProviderID string `json:"provider_id"`
	}
	input.Status = "active"
	input.TokenizerQuality = "unavailable"
	if !c.decode(w, r, &input) {
		return
	}
	if (input.Status != "active" && input.Status != "disabled") || input.TokenizerQuality == "" {
		c.catalogError(w, r, catalog.ErrInvalid)
		return
	}
	providerID, ok := managementID(input.ProviderID)
	if !ok {
		c.catalogError(w, r, catalog.ErrInvalid)
		return
	}
	input.ProfileInput.ProviderID = providerID
	result, err := c.cfg.Catalog.CreateModel(ctx, token(r), orgID, input.ProfileInput)
	if err != nil {
		c.catalogError(w, r, err)
		return
	}
	c.success(w, r, 201, catalogModelDTO(result))
}

// Patch merging is limited to the known catalog DTO, never persistence fields.
// Repository CAS checks the supplied version after this detached preparation.
func (c *control) catalogPatch(w http.ResponseWriter, r *http.Request, current any, optionalLimits bool) ([]byte, int, bool) {
	var patch map[string]json.RawMessage
	if !c.decode(w, r, &patch) {
		return nil, 0, false
	}
	var version int
	if json.Unmarshal(patch["version"], &version) != nil || version <= 0 || version >= math.MaxInt32 {
		c.catalogError(w, r, catalog.ErrInvalid)
		return nil, 0, false
	}
	delete(patch, "version")
	if len(patch) == 0 {
		c.catalogError(w, r, catalog.ErrInvalid)
		return nil, 0, false
	}
	data, err := json.Marshal(current)
	if err != nil {
		c.catalogError(w, r, repository.ErrUnavailable)
		return nil, 0, false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		c.catalogError(w, r, repository.ErrUnavailable)
		return nil, 0, false
	}
	if optionalLimits {
		for _, key := range []string{"max_output_tokens", "context_window"} {
			if _, ok := fields[key]; !ok {
				fields[key] = json.RawMessage("null")
			}
		}
	}
	for key, value := range patch {
		if _, ok := fields[key]; !ok {
			c.catalogError(w, r, catalog.ErrInvalid)
			return nil, 0, false
		}
		fields[key] = value
	}
	merged, err := json.Marshal(fields)
	if err != nil {
		c.catalogError(w, r, repository.ErrUnavailable)
		return nil, 0, false
	}
	return merged, version, true
}

func (c *control) updateCatalogProvider(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, orgID, ok := c.authorizeOrganization(w, r, "catalog.write")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	current, err := c.cfg.Catalog.GetProvider(ctx, token(r), orgID, id)
	if err != nil {
		c.catalogError(w, r, err)
		return
	}
	merged, version, ok := c.catalogPatch(w, r, current.ProviderInput, false)
	if !ok {
		return
	}
	var input catalog.ProviderInput
	if json.Unmarshal(merged, &input) != nil || (input.Status != "active" && input.Status != "disabled") {
		c.catalogError(w, r, catalog.ErrInvalid)
		return
	}
	result, err := c.cfg.Catalog.UpdateProvider(ctx, token(r), orgID, id, version, input)
	if err != nil {
		c.catalogError(w, r, err)
		return
	}
	c.success(w, r, 200, catalogProviderDTO(result))
}
func (c *control) updateCatalogModel(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, orgID, ok := c.authorizeOrganization(w, r, "catalog.write")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	current, err := c.cfg.Catalog.GetModel(ctx, token(r), orgID, id)
	if err != nil {
		c.catalogError(w, r, err)
		return
	}
	type modelFields struct {
		catalog.ProfileInput
		ProviderID string `json:"provider_id"`
	}
	merged, version, ok := c.catalogPatch(w, r, modelFields{current.ProfileInput, strconv.FormatInt(current.ProviderID, 10)}, true)
	if !ok {
		return
	}
	var input modelFields
	if json.Unmarshal(merged, &input) != nil || (input.Status != "active" && input.Status != "disabled") || input.TokenizerQuality == "" {
		c.catalogError(w, r, catalog.ErrInvalid)
		return
	}
	providerID, ok := managementID(input.ProviderID)
	if !ok {
		c.catalogError(w, r, catalog.ErrInvalid)
		return
	}
	input.ProfileInput.ProviderID = providerID
	result, err := c.cfg.Catalog.UpdateModel(ctx, token(r), orgID, id, version, input.ProfileInput)
	if err != nil {
		c.catalogError(w, r, err)
		return
	}
	c.success(w, r, 200, catalogModelDTO(result))
}
func (c *control) deleteCatalogProvider(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, orgID, ok := c.authorizeOrganization(w, r, "catalog.write")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	var input struct {
		Version int `json:"version"`
	}
	if !c.decode(w, r, &input) {
		return
	}
	if err := c.cfg.Catalog.DeleteProvider(ctx, token(r), orgID, id, input.Version); err != nil {
		c.catalogError(w, r, err)
		return
	}
	c.success(w, r, 200, map[string]bool{"ok": true})
}
func (c *control) deleteCatalogModel(w http.ResponseWriter, r *http.Request) {
	if !c.authorizeWrite(w, r) {
		return
	}
	ctx, orgID, ok := c.authorizeOrganization(w, r, "catalog.write")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	var input struct {
		Version int `json:"version"`
	}
	if !c.decode(w, r, &input) {
		return
	}
	if err := c.cfg.Catalog.DeleteModel(ctx, token(r), orgID, id, input.Version); err != nil {
		c.catalogError(w, r, err)
		return
	}
	c.success(w, r, 200, map[string]bool{"ok": true})
}
func (c *control) getCatalogProvider(w http.ResponseWriter, r *http.Request) {
	ctx, orgID, ok := c.authorizeOrganization(w, r, "read")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		c.catalogError(w, r, catalog.ErrInvalid)
		return
	}
	result, err := c.cfg.Catalog.GetProvider(ctx, token(r), orgID, id)
	if err != nil {
		c.catalogError(w, r, err)
		return
	}
	c.success(w, r, 200, catalogProviderDTO(result))
}
func (c *control) getCatalogModel(w http.ResponseWriter, r *http.Request) {
	ctx, orgID, ok := c.authorizeOrganization(w, r, "read")
	if !ok {
		return
	}
	id, ok := c.managementPathID(w, r, "id")
	if !ok {
		return
	}
	if r.URL.RawQuery != "" {
		c.catalogError(w, r, catalog.ErrInvalid)
		return
	}
	result, err := c.cfg.Catalog.GetModel(ctx, token(r), orgID, id)
	if err != nil {
		c.catalogError(w, r, err)
		return
	}
	c.success(w, r, 200, catalogModelDTO(result))
}
