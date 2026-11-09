package oauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestContinuationTokensAreRandomAndHashed(t *testing.T) {
	first, err := newContinuationToken()
	if err != nil {
		t.Fatalf("newContinuationToken: %v", err)
	}
	second, err := newContinuationToken()
	if err != nil {
		t.Fatalf("newContinuationToken: %v", err)
	}
	if first == "" || first == second {
		t.Fatalf("continuation tokens must be non-empty and unique: %q %q", first, second)
	}

	firstHash := hashContinuationToken(first)
	if len(firstHash) != 64 {
		t.Fatalf("hash length = %d, want 64 hex characters", len(firstHash))
	}
	if firstHash != hashContinuationToken(first) {
		t.Fatal("token hash must be deterministic")
	}
	if firstHash == hashContinuationToken(second) {
		t.Fatal("different tokens must not share a hash")
	}
	if strings.Contains(firstHash, first) {
		t.Fatal("hash must not expose the raw token")
	}
}

func TestRequestWithRawQueryIgnoresSubmittedBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/oauth/consent",
		strings.NewReader("client_id=attacker&redirect_uri=https%3A%2F%2Fevil.example"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	stored := "client_id=trusted&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&scope=renewly"
	rebuilt := requestWithRawQuery(req, stored)

	if rebuilt.Method != http.MethodGet {
		t.Fatalf("method = %q, want GET", rebuilt.Method)
	}
	if rebuilt.URL.RawQuery != stored {
		t.Fatalf("RawQuery = %q, want %q", rebuilt.URL.RawQuery, stored)
	}
	if rebuilt.Body != http.NoBody {
		t.Fatal("rebuilt request must not carry the submitted body")
	}

	if err := rebuilt.ParseForm(); err != nil {
		t.Fatalf("ParseForm: %v", err)
	}
	if got := rebuilt.Form.Get("client_id"); got != "trusted" {
		t.Fatalf("client_id = %q, want trusted", got)
	}
	if got := rebuilt.Form.Get("redirect_uri"); got != "https://client.example/cb" {
		t.Fatalf("redirect_uri = %q, want stored value", got)
	}
}

func TestConsentCSRFBindsUserTokenAndTimestamp(t *testing.T) {
	server := &Server{csrfKey: []byte("0123456789abcdef0123456789abcdef")}

	base := server.consentCSRF(42, "request-token", "1700000000")
	if base == "" {
		t.Fatal("expected a consent CSRF token")
	}
	if base != server.consentCSRF(42, "request-token", "1700000000") {
		t.Fatal("consent CSRF token must be deterministic for the same inputs")
	}
	if base == server.consentCSRF(43, "request-token", "1700000000") {
		t.Fatal("consent CSRF token must change with the authenticated user")
	}
	if base == server.consentCSRF(42, "other-token", "1700000000") {
		t.Fatal("consent CSRF token must change with the continuation token")
	}
	if base == server.consentCSRF(42, "request-token", "1700000001") {
		t.Fatal("consent CSRF token must change with the timestamp")
	}
}

func TestScopeViewsExposeReadAndWriteCapabilities(t *testing.T) {
	views := scopeViews([]string{"renewly", "offline_access", "unsupported_scope"})
	if len(views) != 2 {
		t.Fatalf("views length = %d, want 2", len(views))
	}

	renewly := views[0]
	if renewly.Name != "renewly" {
		t.Fatalf("first scope = %q, want renewly", renewly.Name)
	}
	if len(renewly.Read) == 0 {
		t.Fatal("renewly scope must describe read capabilities")
	}
	if len(renewly.Write) == 0 {
		t.Fatal("renewly scope must describe write capabilities; the MCP tools can modify data")
	}
	if renewly.Offline {
		t.Fatal("renewly scope must not be marked as offline access")
	}

	offline := views[1]
	if offline.Name != "offline_access" || !offline.Offline {
		t.Fatalf("second scope = %#v, want offline_access with Offline=true", offline)
	}
}

func TestLoginContinuationCookieIsHttpOnlyAndLax(t *testing.T) {
	t.Setenv("COOKIE_SECURE", "false")

	recorder := httptest.NewRecorder()
	setLoginContinuationCookie(recorder, "opaque-token")

	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != LoginContinuationCookieName {
		t.Fatalf("cookie name = %q, want %q", cookie.Name, LoginContinuationCookieName)
	}
	if cookie.Value != "opaque-token" {
		t.Fatalf("cookie value = %q", cookie.Value)
	}
	if !cookie.HttpOnly {
		t.Error("continuation cookie must be HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Errorf("Path = %q, want /", cookie.Path)
	}
	if cookie.MaxAge <= 0 {
		t.Errorf("MaxAge = %d, want a short positive lifetime", cookie.MaxAge)
	}
}
