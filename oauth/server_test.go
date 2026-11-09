package oauth

import (
	"bytes"
	"context"
	"testing"
)

func TestProviderRegistersTokenIntrospectionHandler(t *testing.T) {
	config := newConfig(bytes.Repeat([]byte("s"), 32), "https://renewly.example")
	// Compose only stores the factories' outputs in the config; it does not
	// touch the database at construction time, so a nil pool is fine here.
	_ = newProvider(config, NewPostgresStorage(nil))

	handlers := config.GetTokenIntrospectionHandlers(context.Background())
	if len(handlers) != 1 {
		t.Fatalf("expected exactly one token introspection handler, got %d", len(handlers))
	}
}

func TestValidRedirectURI(t *testing.T) {
	cases := []struct {
		uri  string
		want bool
	}{
		{"https://client.example/callback", true},
		{"http://127.0.0.1:43123/callback", true},
		{"http://localhost:3000/callback", true},
		{"http://client.example/callback", false},
		{"https://client.example/callback#fragment", false},
		{"javascript:alert(1)", false},
		{"https://user:pass@client.example/callback", false},
	}
	for _, tc := range cases {
		t.Run(tc.uri, func(t *testing.T) {
			if got := validRedirectURI(tc.uri); got != tc.want {
				t.Fatalf("validRedirectURI(%q)=%v, want %v", tc.uri, got, tc.want)
			}
		})
	}
}

func TestSameSet(t *testing.T) {
	if !sameSet([]string{"refresh_token", "authorization_code"}, []string{"authorization_code", "refresh_token"}) {
		t.Fatal("sameSet rejected reordered set")
	}
	if sameSet([]string{"authorization_code", "authorization_code"}, []string{"authorization_code", "refresh_token"}) {
		t.Fatal("sameSet accepted duplicates")
	}
}
