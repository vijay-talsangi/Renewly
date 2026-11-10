package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderWithFormActionsAllowsRedirectOrigin(t *testing.T) {
	recorder := httptest.NewRecorder()
	err := RenderWithFormActions(recorder, http.StatusOK, "consent", ConsentPage{}, "http://127.0.0.1:8765/callback")
	if err != nil {
		t.Fatalf("render consent page: %v", err)
	}

	csp := recorder.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' http://127.0.0.1:8765;") {
		t.Fatalf("CSP does not allow the redirect origin: %q", csp)
	}
}

func TestRenderWithFormActionsIgnoresInvalidOrigins(t *testing.T) {
	for _, origin := range []string{
		"",
		"javascript:alert(1)",
		"mailto:user@example.com",
		"https://user:pass@claude.ai/callback",
	} {
		recorder := httptest.NewRecorder()
		if err := RenderWithFormActions(recorder, http.StatusOK, "consent", ConsentPage{}, origin); err != nil {
			t.Fatalf("render consent page for %q: %v", origin, err)
		}
		csp := recorder.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "form-action 'self';") {
			t.Errorf("CSP for %q is not restricted to self: %q", origin, csp)
		}
	}
}

func TestRenderKeepsDefaultFormAction(t *testing.T) {
	recorder := httptest.NewRecorder()
	if err := Render(recorder, http.StatusOK, "login", LoginPage{}); err != nil {
		t.Fatalf("render login page: %v", err)
	}

	csp := recorder.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self';") {
		t.Fatalf("login CSP changed unexpectedly: %q", csp)
	}
}
