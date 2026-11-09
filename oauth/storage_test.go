package oauth

import (
	"testing"
	"time"

	"github.com/ory/fosite"
)

func TestRequesterRoundTripPreservesAuthenticationFields(t *testing.T) {
	requestedAt := time.Now().UTC().Truncate(time.Second)
	accessExpiry := requestedAt.Add(15 * time.Minute)
	const resource = "https://renewly.example/mcp"

	original := &fosite.Request{
		ID:                "request-id",
		RequestedAt:       requestedAt,
		Client:            &fosite.DefaultClient{ID: "client-id", Audience: []string{resource}},
		RequestedScope:    fosite.Arguments{"renewly", "offline_access"},
		GrantedScope:      fosite.Arguments{"renewly", "offline_access"},
		RequestedAudience: fosite.Arguments{resource},
		GrantedAudience:   fosite.Arguments{resource},
		Session: &fosite.DefaultSession{
			Subject: "42",
			ExpiresAt: map[fosite.TokenType]time.Time{
				fosite.AccessToken: accessExpiry,
			},
		},
	}

	payload, err := encodeRequester(original)
	if err != nil {
		t.Fatalf("encodeRequester: %v", err)
	}
	decoded, err := decodeRequester(payload)
	if err != nil {
		t.Fatalf("decodeRequester: %v", err)
	}

	if got := decoded.GetSession().GetSubject(); got != "42" {
		t.Errorf("subject = %q, want %q", got, "42")
	}
	if got := decoded.GetSession().GetExpiresAt(fosite.AccessToken); !got.Equal(accessExpiry) {
		t.Errorf("access token expiry = %v, want %v", got, accessExpiry)
	}
	if !containsString(decoded.GetClient().GetAudience(), resource) {
		t.Errorf("client audience = %v, want %q", decoded.GetClient().GetAudience(), resource)
	}
	if !containsString(decoded.GetGrantedAudience(), resource) {
		t.Errorf("granted audience = %v, want %q", decoded.GetGrantedAudience(), resource)
	}
	if !containsString(decoded.GetGrantedScopes(), defaultScope) {
		t.Errorf("granted scopes = %v, want %q", decoded.GetGrantedScopes(), defaultScope)
	}
}
