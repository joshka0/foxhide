package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"pii-proxy-poc/internal/scrubber"
)

func TestCopyHeadersDropsSensitiveHeadersByDefault(t *testing.T) {
	src := http.Header{}
	src.Set("Authorization", "Bearer internal")
	src.Set("Cookie", "session=internal")
	src.Set("X-Api-Key", "internal")
	src.Set("Anthropic-Version", "2023-06-01")
	src.Set("Content-Type", "application/json")
	dst := http.Header{}
	copyHeaders(src, dst, false)
	for _, h := range []string{"Authorization", "Cookie", "X-Api-Key"} {
		if dst.Get(h) != "" {
			t.Fatalf("expected %s to be dropped", h)
		}
	}
	if dst.Get("Anthropic-Version") != "2023-06-01" {
		t.Fatalf("provider header should pass through")
	}
	if dst.Get("Content-Type") != "application/json" {
		t.Fatalf("content-type should pass through")
	}
}

func TestTargetURLUsesScrubbedQuery(t *testing.T) {
	base, _ := url.Parse("https://example.test/v1")
	cfg := &config{upstreamBase: base}
	reqURL, _ := url.Parse("/chat/completions?email=ann%40example.com")
	r := &http.Request{URL: reqURL}
	query := scrubber.ScrubQueryValues(r.URL.Query(), scrubber.New())
	target := cfg.targetURL(r, query)
	if target != "https://example.test/v1/chat/completions?email=%5BEMAIL_1%5D" {
		t.Fatalf("unexpected target URL: %s", target)
	}
}

func TestDeniedSummary(t *testing.T) {
	got := deniedSummary(map[string]int{"SECRET": 1, "EMAIL": 2}, parseTypeSet("SECRET,CREDIT_CARD"))
	if len(got) != 1 || got[0] != "SECRET" {
		t.Fatalf("expected SECRET denial, got %#v", got)
	}
}

func TestResolveScopeDevMode(t *testing.T) {
	cfg := &config{authMode: "dev", orgID: "foxway", requireWorkspace: true, requireConversation: true}
	req, _ := http.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Workspace-ID", "security")
	req.Header.Set("X-Conversation-ID", "case-123")
	req.Header.Set("X-User-ID", "josh@example.com")

	scope, err := cfg.resolveScope(req)
	if err != nil {
		t.Fatal(err)
	}
	if scope.OrgID != "foxway" || scope.WorkspaceID != "security" || scope.ConversationID != "case-123" || scope.UserID != "josh@example.com" {
		t.Fatalf("unexpected scope: %#v", scope)
	}
}

func TestResolveScopeALBOIDCGroupGate(t *testing.T) {
	cfg := &config{authMode: "alb_oidc", orgID: "foxway", requireWorkspace: true, requireConversation: true, allowedGroups: parseTypeSet("pii-users")}
	req, _ := http.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Workspace-ID", "security")
	req.Header.Set("X-Conversation-ID", "case-123")
	req.Header.Set("x-amzn-oidc-data", testJWT(map[string]any{
		"email":  "josh@example.com",
		"groups": []string{"pii-users"},
	}))

	scope, err := cfg.resolveScope(req)
	if err != nil {
		t.Fatal(err)
	}
	if scope.UserID != "josh@example.com" {
		t.Fatalf("unexpected user: %#v", scope)
	}
}

func testJWT(claims map[string]any) string {
	header, _ := json.Marshal(map[string]string{"alg": "none"})
	payload, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}
