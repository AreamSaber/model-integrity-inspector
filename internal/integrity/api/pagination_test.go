package api

import (
	"bytes"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

func TestSignedCursorScopeQueryAndTampering(t *testing.T) {
	key, err := secret.NewKeyRing("v1", map[string][]byte{"v1": bytes.Repeat([]byte{23}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	c := control{cfg: ControlConfig{CursorSigner: key}}
	result, err := c.pageResult([]string{"one"}, 123, true, "org:123/targets", "hello")
	if err != nil {
		t.Fatal(err)
	}
	cursor := result["next_cursor"].(string)
	request := httptest.NewRequestWithContext(t.Context(), "GET", "/?q=hello&cursor="+url.QueryEscape(cursor), nil)
	page, err := c.parsePage(request, "org:123/targets")
	if err != nil || page.AfterID != 123 || page.Limit != 25 {
		t.Fatal("valid cursor failed")
	}
	if _, err := c.parsePage(request, "org:321/targets"); err == nil {
		t.Fatal("cross-org cursor accepted")
	}
	if _, err := c.parsePage(request, "org:123/users"); err == nil {
		t.Fatal("cross-resource cursor accepted")
	}
	for _, query := range []string{"q=other&cursor=" + url.QueryEscape(cursor), "q=hello&cursor=" + url.QueryEscape(cursor[:len(cursor)-8]+"AAAAAAAA"), "limit=101", "limit=0", "limit=1&limit=2", "offset=3", "cursor=invalid"} {
		request := httptest.NewRequestWithContext(t.Context(), "GET", "/?"+query, nil)
		if _, err := c.parsePage(request, "org:123/targets"); err == nil {
			t.Fatalf("invalid pagination accepted %s", strings.Split(query, "=")[0])
		}
	}
	mac, err := key.AuditMAC("v1", []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	pageMAC, err := key.CursorMAC("v1", []byte("same"))
	if err != nil || bytes.Equal(mac, pageMAC) {
		t.Fatal("cursor and audit purposes not isolated")
	}
}
