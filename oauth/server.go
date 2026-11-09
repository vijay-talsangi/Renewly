package oauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/vijay-talsangi/Renewly/middleware"
)

const defaultScope = "renewly"

// Server owns the Fosite provider and its HTTP endpoints.
type Server struct {
	pool     *pgxpool.Pool
	storage  *PostgresStorage
	provider fosite.OAuth2Provider
	issuer   string
	resource string
	csrfKey  []byte
}

// NewServer constructs a narrowly scoped OAuth 2.1 authorization-code server.
// OAUTH_GLOBAL_SECRET must be a random secret of at least 32 bytes and must
// remain stable across restarts and deployments.
func NewServer(pool *pgxpool.Pool) (*Server, error) {
	secret := []byte(os.Getenv("OAUTH_GLOBAL_SECRET"))
	if len(secret) < 32 {
		return nil, errors.New("OAUTH_GLOBAL_SECRET must contain at least 32 bytes")
	}
	issuer := strings.TrimRight(os.Getenv("OAUTH_ISSUER"), "/")
	if issuer == "" {
		return nil, errors.New("OAUTH_ISSUER must be configured")
	}
	resource := issuer + "/mcp"
	storage := NewPostgresStorage(pool)
	config := newConfig(secret, issuer)
	provider := newProvider(config, storage)
	return &Server{
		pool: pool, storage: storage, provider: provider,
		issuer: issuer, resource: resource, csrfKey: secret,
	}, nil
}

func newConfig(secret []byte, issuer string) *fosite.Config {
	return &fosite.Config{
		AccessTokenLifespan:            15 * time.Minute,
		RefreshTokenLifespan:           30 * 24 * time.Hour,
		AuthorizeCodeLifespan:          5 * time.Minute,
		GlobalSecret:                   secret,
		EnforcePKCE:                    true,
		EnforcePKCEForPublicClients:    true,
		EnablePKCEPlainChallengeMethod: false,
		RefreshTokenScopes:             []string{},
		AccessTokenIssuer:              issuer,
		TokenEntropy:                   32,
	}
}

func newProvider(config *fosite.Config, storage *PostgresStorage) fosite.OAuth2Provider {
	strategy := compose.NewOAuth2HMACStrategy(config)
	return compose.Compose(
		config,
		storage,
		strategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		// Introspection is not implied by the token-issuing handlers. Without
		// this factory Fosite has no TokenIntrospector registered, so
		// IntrospectToken always fails with ErrRequestUnauthorized.
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2PKCEFactory,
	)
}

// MCPAuthMiddleware authenticates MCP requests with OAuth bearer access tokens.
// It intentionally does not accept the Renewly browser cookie as an MCP credential.
func (s *Server) MCPAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		metadataURL := s.issuer + "/.well-known/oauth-protected-resource/mcp"
		challenge := `Bearer resource_metadata="` + metadataURL + `"`
		header := strings.TrimSpace(c.GetHeader("Authorization"))
		parts := strings.Fields(header)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.Header("WWW-Authenticate", challenge)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "unauthorized",
				"error_description": "A valid OAuth bearer token is required.",
			})
			return
		}

		token := parts[1]
		if strings.ContainsAny(token, "\r\n") {
			c.Header("WWW-Authenticate", challenge+`, error="invalid_token"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}

		tokenUse, requester, err := s.provider.IntrospectToken(
			c.Request.Context(), token, fosite.AccessToken,
			&fosite.DefaultSession{}, defaultScope,
		)
		if err != nil {
			log.Printf("MCP DEBUG: introspection failed: %T: %v", err, err)
		}

		if err == nil && tokenUse != fosite.AccessToken {
			log.Printf("MCP DEBUG: unexpected token use: %v", tokenUse)
		}

		if err == nil && requester == nil {
			log.Printf("MCP DEBUG: requester is nil")
		}

		if err == nil && requester != nil && requester.GetSession() == nil {
			log.Printf("MCP DEBUG: session is nil")
		}

		if err != nil || tokenUse != fosite.AccessToken ||
			requester == nil || requester.GetSession() == nil {
			c.Header("WWW-Authenticate", challenge+`, error="invalid_token"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_token",
				"error_description": "The access token is invalid, expired, or revoked.",
			})
			return
		}

		log.Printf("MCP DEBUG: client audience: %v", requester.GetClient().GetAudience())
		log.Printf("MCP DEBUG: granted audience: %v", requester.GetGrantedAudience())
		log.Printf("MCP DEBUG: granted scopes: %v", requester.GetGrantedScopes())
		// Require both the registered client and the granted token audience
		// to identify this MCP resource.
		if !containsString(requester.GetClient().GetAudience(), s.resource) ||
			!containsString(requester.GetGrantedAudience(), s.resource) {
			c.Header("WWW-Authenticate", challenge+`, error="invalid_token"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}

		userID, err := strconv.ParseInt(requester.GetSession().GetSubject(), 10, 64)
		if err != nil || userID <= 0 {
			c.Header("WWW-Authenticate", challenge+`, error="invalid_token"`)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}

		c.Request = c.Request.WithContext(
			middleware.ContextWithUserID(c.Request.Context(), userID),
		)
		c.Next()
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// RegisterRoutes mounts the OAuth endpoints on the existing Gin router via
// net/http handlers. The caller must protect authorize and consent with the
// existing cookie authentication middleware.
func (s *Server) RegisterHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /oauth/register", s.registerClient)
	mux.HandleFunc("GET /oauth/authorize", s.authorize)
	mux.HandleFunc("POST /oauth/consent", s.consent)
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("POST /oauth/revoke", s.revoke)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.authorizationServerMetadata)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", s.protectedResourceMetadata)
	return mux
}

func (s *Server) registerClient(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	var input struct {
		ClientName              string   `json:"client_name"`
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	if err := dec.Decode(&input); err != nil {
		http.Error(w, "invalid registration request", http.StatusBadRequest)
		return
	}
	if len(input.RedirectURIs) == 0 || len(input.RedirectURIs) > 20 {
		http.Error(w, "between 1 and 20 redirect_uris are required", http.StatusBadRequest)
		return
	}
	if input.TokenEndpointAuthMethod != "" && input.TokenEndpointAuthMethod != "none" {
		http.Error(w, "only public clients using token_endpoint_auth_method=none are supported", http.StatusBadRequest)
		return
	}
	for _, redirect := range input.RedirectURIs {
		if !validRedirectURI(redirect) {
			http.Error(w, "redirect URI must use HTTPS, or loopback HTTP for native clients", http.StatusBadRequest)
			return
		}
	}
	grants := input.GrantTypes
	if len(grants) == 0 {
		grants = []string{"authorization_code", "refresh_token"}
	}
	supportedGrants := map[string]bool{
		"authorization_code": true,
		"refresh_token":      true,
	}

	hasAuthorizationCode := false

	for _, grant := range grants {
		if !supportedGrants[grant] {
			http.Error(w, "unsupported grant type", http.StatusBadRequest)
			return
		}

		if grant == "authorization_code" {
			hasAuthorizationCode = true
		}
	}

	if !hasAuthorizationCode {
		http.Error(w, "authorization_code grant is required", http.StatusBadRequest)
		return
	}
	responses := input.ResponseTypes
	if len(responses) == 0 {
		responses = []string{"code"}
	}
	if len(responses) != 1 || responses[0] != "code" {
		http.Error(w, "only response_type=code is supported", http.StatusBadRequest)
		return
	}
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		http.Error(w, "could not create client", http.StatusInternalServerError)
		return
	}
	clientID := base64.RawURLEncoding.EncodeToString(idBytes)
	_, err := s.pool.Exec(r.Context(), `
		INSERT INTO oauth_clients
		(client_id, redirect_uris, grant_types, response_types, scopes, audience, is_public)
		VALUES ($1,$2,$3,$4,$5,$6,TRUE)`,
		clientID, input.RedirectURIs, grants, responses,
		[]string{defaultScope, "offline_access"}, []string{s.resource})
	if err != nil {
		http.Error(w, "client registration failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"client_id":                  clientID,
		"client_name":                input.ClientName,
		"redirect_uris":              input.RedirectURIs,
		"grant_types":                grants,
		"response_types":             responses,
		"token_endpoint_auth_method": "none",
		"scope":                      defaultScope + " offline_access",
	})
}

func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Fragment != "" || u.User != nil {
		return false
	}
	if u.Scheme == "https" && u.Hostname() != "" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func sameSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := make(map[string]bool, len(got))
	for _, value := range got {
		if seen[value] {
			return false
		}
		seen[value] = true
	}
	for _, value := range want {
		if !seen[value] {
			return false
		}
	}
	return true
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "Sign in to Renewly, then retry authorization.", http.StatusUnauthorized)
		return
	}
	requester, err := s.provider.NewAuthorizeRequest(r.Context(), r)
	if err != nil {
		s.provider.WriteAuthorizeError(r.Context(), w, requester, err)
		return
	}
	issued := strconv.FormatInt(time.Now().Unix(), 10)
	csrf := s.csrfToken(userID, requester.GetClient().GetID(), requester.GetRequestForm().Get("redirect_uri"), requester.GetRequestForm().Get("state"), issued)
	data := struct {
		ClientID   string
		ClientName string
		Scopes     []string
		Fields     []formField
		Issued     string
		CSRF       string
	}{
		ClientID:   requester.GetClient().GetID(),
		ClientName: requester.GetClient().GetID(),
		Scopes:     requester.GetRequestedScopes(),
		Issued:     issued,
		CSRF:       csrf,
	}
	for key, values := range requester.GetRequestForm() {
		for _, value := range values {
			data.Fields = append(data.Fields, formField{Key: key, Value: value})
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := consentPage.Execute(w, data); err != nil {
		http.Error(w, "could not render consent page", http.StatusInternalServerError)
	}
}

type formField struct{ Key, Value string }

var consentPage = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize Renewly access</title></head>
<body style="font-family:system-ui;max-width:560px;margin:4rem auto;padding:0 1rem">
<h1>Connect {{.ClientName}}</h1><p>This application is requesting access to your Renewly account.</p>
<p><strong>Permissions:</strong> {{range .Scopes}}{{.}} {{end}}</p>
<form method="post" action="/oauth/consent">
{{range .Fields}}<input type="hidden" name="{{.Key}}" value="{{.Value}}">{{end}}
<input type="hidden" name="csrf_ts" value="{{.Issued}}"><input type="hidden" name="csrf_token" value="{{.CSRF}}">
<button type="submit" name="decision" value="allow">Allow access</button>
<button type="submit" name="decision" value="deny">Deny</button>
</form></body></html>`))

func (s *Server) consent(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid consent request", http.StatusBadRequest)
		return
	}
	issued, err := strconv.ParseInt(r.Form.Get("csrf_ts"), 10, 64)
	if err != nil || time.Since(time.Unix(issued, 0)) > 10*time.Minute || time.Unix(issued, 0).After(time.Now().Add(time.Minute)) {
		http.Error(w, "consent request expired; restart authorization", http.StatusBadRequest)
		return
	}
	want := s.csrfToken(userID, r.Form.Get("client_id"), r.Form.Get("redirect_uri"), r.Form.Get("state"), r.Form.Get("csrf_ts"))
	got, _ := hex.DecodeString(r.Form.Get("csrf_token"))
	wantBytes, _ := hex.DecodeString(want)
	if !hmac.Equal(got, wantBytes) {
		http.Error(w, "invalid consent request", http.StatusForbidden)
		return
	}
	requester, err := s.provider.NewAuthorizeRequest(r.Context(), r)
	if err != nil {
		s.provider.WriteAuthorizeError(r.Context(), w, requester, err)
		return
	}
	if r.Form.Get("decision") != "allow" {
		s.provider.WriteAuthorizeError(r.Context(), w, requester, fosite.ErrAccessDenied)
		return
	}
	// Explicitly grant only the scopes Renewly supports. Fosite does not
	// infer consent merely because scopes were requested.
	for _, scope := range requester.GetRequestedScopes() {
		switch scope {
		case "renewly", "offline_access":
			requester.GrantScope(scope)
		}
	}
	// Grant access to the Renewly MCP resource.
	if !containsString(requester.GetClient().GetAudience(), s.resource) {
		s.provider.WriteAuthorizeError(
			r.Context(), w, requester, fosite.ErrInvalidRequest,
		)
		return
	}

	requester.GrantAudience(s.resource)
	session := &fosite.DefaultSession{Subject: strconv.FormatInt(userID, 10)}
	response, err := s.provider.NewAuthorizeResponse(r.Context(), requester, session)
	if err != nil {
		s.provider.WriteAuthorizeError(r.Context(), w, requester, err)
		return
	}
	s.provider.WriteAuthorizeResponse(r.Context(), w, requester, response)
}

func (s *Server) csrfToken(userID int64, clientID, redirectURI, state, issued string) string {
	mac := hmac.New(sha256.New, s.csrfKey)
	_, _ = fmt.Fprintf(mac, "%d\n%s\n%s\n%s\n%s", userID, clientID, redirectURI, state, issued)
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	requester, err := s.provider.NewAccessRequest(r.Context(), r, &fosite.DefaultSession{})
	if err != nil {
		s.provider.WriteAccessError(r.Context(), w, requester, err)
		return
	}
	response, err := s.provider.NewAccessResponse(r.Context(), requester)
	if err != nil {
		s.provider.WriteAccessError(r.Context(), w, requester, err)
		return
	}
	s.provider.WriteAccessResponse(r.Context(), w, requester, response)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	err := s.provider.NewRevocationRequest(r.Context(), r)
	s.provider.WriteRevocationResponse(r.Context(), w, err)
}

// authorizationServerMetadata publishes RFC 8414 metadata for OAuth clients.
func (s *Server) authorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	writeMetadata(w, map[string]any{
		"issuer":                                s.issuer,
		"authorization_endpoint":                s.issuer + "/oauth/authorize",
		"token_endpoint":                        s.issuer + "/oauth/token",
		"registration_endpoint":                 s.issuer + "/oauth/register",
		"revocation_endpoint":                   s.issuer + "/oauth/revoke",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{defaultScope, "offline_access"},
	})
}

// protectedResourceMetadata publishes RFC 9728 metadata for the MCP resource.
func (s *Server) protectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	writeMetadata(w, map[string]any{
		"resource":                 s.resource,
		"authorization_servers":    []string{s.issuer},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{defaultScope},
	})
}

func writeMetadata(w http.ResponseWriter, value map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		// Encoding a map containing only JSON primitives should not fail.
		http.Error(w, "could not encode OAuth metadata", http.StatusInternalServerError)
	}
}
