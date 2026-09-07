package api

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrPagination = errors.New("MI_PAGINATION_INVALID")

type CursorSigner interface {
	ActiveVersion() string
	CursorMAC(string, []byte) ([]byte, error)
}

type Page struct {
	AfterID int64
	Limit   int
	Query   string
}
type cursorPayload struct {
	Version string `json:"v"`
	AfterID int64  `json:"after"`
	Scope   string `json:"scope"`
	Query   string `json:"q"`
	Expires int64  `json:"exp"`
}

func (c *control) parsePage(r *http.Request, scope string) (Page, error) {
	out := Page{Limit: 25}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return out, ErrPagination
	}
	for name, values := range query {
		if (name != "limit" && name != "cursor" && name != "q") || len(values) != 1 {
			return out, ErrPagination
		}
	}
	if value := query.Get("limit"); value != "" {
		out.Limit, err = strconv.Atoi(value)
		if err != nil || out.Limit < 1 || out.Limit > 100 {
			return out, ErrPagination
		}
	}
	out.Query = strings.TrimSpace(query.Get("q"))
	if len(out.Query) > 128 || !utf8.ValidString(out.Query) || strings.ContainsRune(out.Query, 0) {
		return out, ErrPagination
	}
	value := query.Get("cursor")
	if value == "" {
		return out, nil
	}
	if len(value) > 1024 || c.cfg.CursorSigner == nil {
		return out, ErrPagination
	}
	encoded, signature, ok := strings.Cut(value, ".")
	if !ok {
		return out, ErrPagination
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return out, ErrPagination
	}
	provided, err := base64.RawURLEncoding.Strict().DecodeString(signature)
	if err != nil || len(provided) != 32 {
		return out, ErrPagination
	}
	var payload cursorPayload
	if json.Unmarshal(data, &payload) != nil || payload.AfterID <= 0 || payload.Scope != digest(scope) || payload.Query != out.Query || payload.Expires <= time.Now().Unix() {
		return out, ErrPagination
	}
	expected, err := c.cfg.CursorSigner.CursorMAC(payload.Version, data)
	if err != nil || !hmac.Equal(provided, expected) {
		return out, ErrPagination
	}
	out.AfterID = payload.AfterID
	return out, nil
}

func (c *control) pageResult(items any, lastID int64, hasMore bool, scope, query string) (map[string]any, error) {
	var next any
	if hasMore {
		if lastID <= 0 || c.cfg.CursorSigner == nil {
			return nil, ErrPagination
		}
		payload := cursorPayload{Version: c.cfg.CursorSigner.ActiveVersion(), AfterID: lastID, Scope: digest(scope), Query: query, Expires: time.Now().Add(24 * time.Hour).Unix()}
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, ErrPagination
		}
		signature, err := c.cfg.CursorSigner.CursorMAC(payload.Version, data)
		if err != nil {
			return nil, ErrPagination
		}
		next = base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString(signature)
	}
	return map[string]any{"items": items, "next_cursor": next}, nil
}
