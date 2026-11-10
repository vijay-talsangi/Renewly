package integration

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	db "github.com/vijay-talsangi/Renewly/db/sqlc"
	"github.com/vijay-talsangi/Renewly/internal/server"
)

const (
	testOAuthIssuer      = "https://renewly.test"
	testOAuthResource    = testOAuthIssuer + "/mcp"
	testOAuthRedirectURI = "http://127.0.0.1:8765/callback"
	testOAuthSecret      = "ssssssssssssssssssssssssssssssss"
)

func setupOAuthTestApp(t *testing.T) (*gin.Engine, *pgxpool.Pool) {
	t.Helper()
	pool := setupTestPool(t)
	ctx := context.Background()

	_, err := pool.Exec(ctx, `
		TRUNCATE TABLE
			oauth_authorization_continuations,
			oauth_pkce_sessions,
			oauth_sessions,
			oauth_client_assertions,
			oauth_clients,
			subscriptions,
			users
		RESTART IDENTITY CASCADE`)
	if err != nil {
		t.Fatalf("failed to clean OAuth test tables: %v", err)
	}

	t.Setenv("JWT_SECRET", "renewly-integration-test-secret")
	t.Setenv("COOKIE_SECURE", "false")
	t.Setenv("OAUTH_GLOBAL_SECRET", testOAuthSecret)
	t.Setenv("OAUTH_ISSUER", testOAuthIssuer)

	gin.SetMode(gin.TestMode)
	queries := db.New(pool)
	router, err := server.SetupRouterWithPool(queries, pool)
	if err != nil {
		t.Fatalf("SetupRouterWithPool: %v", err)
	}
	return router, pool
}

func doGet(router *gin.Engine, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func doForm(router *gin.Engine, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func doMCP(router *gin.Engine, bearerToken string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"renewly-integration-test","version":"1.0.0"}}}`

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(initialize))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

func cookieNamed(recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func hiddenInput(t *testing.T, body, name string) string {
	t.Helper()
	pattern := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]*)"`)
	match := pattern.FindStringSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("page is missing hidden input %q: %s", name, body)
	}
	return match[1]
}

func pkcePair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("generate PKCE verifier: %v", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func authorizePath(clientID, redirectURI, state, challenge string) string {
	values := url.Values{}
	values.Set("client_id", clientID)
	values.Set("response_type", "code")
	values.Set("redirect_uri", redirectURI)
	values.Set("scope", "renewly offline_access")
	values.Set("state", state)
	values.Set("code_challenge", challenge)
	values.Set("code_challenge_method", "S256")
	values.Set("resource", testOAuthResource)
	return "/oauth/authorize?" + values.Encode()
}

func registerOAuthClient(t *testing.T, router *gin.Engine) string {
	t.Helper()
	recorder := sendRequest(router, http.MethodPost, "/oauth/register", map[string]any{
		"client_name":                "Claude",
		"redirect_uris":              []string{testOAuthRedirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}, nil)
	assertStatus(t, recorder, http.StatusCreated)

	var response struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode client registration: %v", err)
	}
	if response.ClientID == "" {
		t.Fatal("client registration returned an empty client_id")
	}
	return response.ClientID
}

func registerAPIUser(t *testing.T, router *gin.Engine, name, email, password string) {
	t.Helper()
	recorder := sendRequest(router, http.MethodPost, "/api/register", map[string]any{
		"name":     name,
		"email":    email,
		"password": password,
	}, nil)
	assertStatus(t, recorder, http.StatusCreated)
}

func loginAPIUser(t *testing.T, router *gin.Engine, email, password string) *http.Cookie {
	t.Helper()
	recorder := sendRequest(router, http.MethodPost, "/api/login", map[string]any{
		"email":    email,
		"password": password,
	}, nil)
	assertStatus(t, recorder, http.StatusOK)
	cookie := cookieNamed(recorder, "auth_token")
	if cookie == nil || cookie.Value == "" {
		t.Fatal("login did not return an auth_token cookie")
	}
	return cookie
}

func consentCSRFForTest(userID int64, requestToken, issued string) string {
	mac := hmac.New(sha256.New, []byte(testOAuthSecret))
	_, _ = fmt.Fprintf(mac, "consent\n%d\n%s\n%s", userID, requestToken, issued)
	return hex.EncodeToString(mac.Sum(nil))
}

func callbackCode(t *testing.T, location string) string {
	t.Helper()
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse callback URL %q: %v", location, err)
	}
	return parsed.Query().Get("code")
}

func TestOAuthWebRegistrationConsentAndTokenFlow(t *testing.T) {
	router, pool := setupOAuthTestApp(t)
	ctx := context.Background()

	clientID := registerOAuthClient(t, router)
	verifier, challenge := pkcePair(t)
	state := "state-registration-flow"
	authPath := authorizePath(clientID, testOAuthRedirectURI, state, challenge)

	// 1. Unauthenticated /oauth/authorize must redirect to login, not JSON 401.
	recorder := doGet(router, authPath)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("authorize status = %d, want %d. body: %s", recorder.Code, http.StatusSeeOther, recorder.Body.String())
	}
	if location := recorder.Header().Get("Location"); location != "/auth/login" {
		t.Fatalf("authorize Location = %q, want /auth/login", location)
	}
	if contentType := recorder.Header().Get("Content-Type"); strings.Contains(contentType, "application/json") {
		t.Fatalf("unauthenticated authorize returned JSON (%s), want a login redirect", contentType)
	}
	continuation := cookieNamed(recorder, "renewly_oauth_continuation")
	if continuation == nil || continuation.Value == "" {
		t.Fatal("authorize did not set a login continuation cookie")
	}
	if !continuation.HttpOnly {
		t.Error("login continuation cookie must be HttpOnly")
	}
	if continuation.SameSite != http.SameSiteLaxMode {
		t.Errorf("login continuation SameSite = %v, want Lax", continuation.SameSite)
	}

	// 2. The login page is rendered for the unauthenticated user.
	recorder = doGet(router, "/auth/login", continuation)
	assertStatus(t, recorder, http.StatusOK)
	if !strings.Contains(recorder.Body.String(), "Sign in to Renewly") {
		t.Fatalf("login page missing branding: %s", recorder.Body.String())
	}
	csrfCookie := cookieNamed(recorder, "renewly_csrf")
	if csrfCookie == nil {
		t.Fatal("login page did not set a CSRF cookie")
	}
	loginCSRF := hiddenInput(t, recorder.Body.String(), "csrf_token")

	// 3. Invalid credentials are rejected without issuing a session.
	recorder = doForm(router, "/auth/login", url.Values{
		"csrf_token": {loginCSRF},
		"email":      {"new-user@example.com"},
		"password":   {"wrong-password"},
	}, csrfCookie, continuation)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("invalid login status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	if cookieNamed(recorder, "auth_token") != nil {
		t.Fatal("invalid login issued an auth_token cookie")
	}

	// 4. The registration page is available from the same continuation.
	recorder = doGet(router, "/auth/register", csrfCookie, continuation)
	assertStatus(t, recorder, http.StatusOK)
	if !strings.Contains(recorder.Body.String(), "Create your account") {
		t.Fatalf("registration page missing expected content: %s", recorder.Body.String())
	}
	registerCSRF := hiddenInput(t, recorder.Body.String(), "csrf_token")

	// 5. A new account is created and authenticated with the existing service.
	const email = "new-user@example.com"
	const password = "password123"
	recorder = doForm(router, "/auth/register", url.Values{
		"csrf_token":       {registerCSRF},
		"name":             {"New User"},
		"email":            {email},
		"password":         {password},
		"confirm_password": {password},
	}, csrfCookie, continuation)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("registration status = %d, want %d. body: %s", recorder.Code, http.StatusSeeOther, recorder.Body.String())
	}
	if location := recorder.Header().Get("Location"); location != "/oauth/authorize" {
		t.Fatalf("registration Location = %q, want /oauth/authorize", location)
	}
	authCookie := cookieNamed(recorder, "auth_token")
	if authCookie == nil || authCookie.Value == "" {
		t.Fatal("registration did not authenticate the new user")
	}
	if !authCookie.HttpOnly {
		t.Error("auth cookie must be HttpOnly")
	}

	// 6. The original OAuth request is resumed and the consent page is shown.
	recorder = doGet(router, "/oauth/authorize", authCookie, continuation)
	assertStatus(t, recorder, http.StatusOK)
	consentBody := recorder.Body.String()
	for _, want := range []string{
		"Claude",
		email,
		"Requested permissions",
		"Read",
		"Write",
		"View your subscriptions",
		"Cancel subscriptions",
	} {
		if !strings.Contains(consentBody, want) {
			t.Errorf("consent page missing %q", want)
		}
	}
	requestToken := hiddenInput(t, consentBody, "request_token")
	csrfTS := hiddenInput(t, consentBody, "csrf_ts")
	consentCSRF := hiddenInput(t, consentBody, "csrf_token")

	// Browsers apply form-action to redirects after a form POST. The consent
	// form posts locally and then redirects to the client callback, so the
	// callback origin must be explicitly allowed or Chrome blocks the redirect
	// and leaves the user on a page whose one-time token was already consumed.
	csp := recorder.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' http://127.0.0.1:8765;") {
		t.Errorf("consent CSP does not allow the client callback origin: %q", csp)
	}

	// 7. A tampered CSRF token is rejected and does not consume the request.
	recorder = doForm(router, "/oauth/consent", url.Values{
		"request_token": {requestToken},
		"csrf_ts":       {csrfTS},
		"csrf_token":    {"tampered"},
		"decision":      {"allow"},
	}, authCookie)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("tampered consent CSRF status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if recorder.Header().Get("Location") != "" {
		t.Fatal("CSRF failure must not redirect to the OAuth client")
	}

	// 8. Explicit approval returns an authorization code with the original state.
	recorder = doForm(router, "/oauth/consent", url.Values{
		"request_token": {requestToken},
		"csrf_ts":       {csrfTS},
		"csrf_token":    {consentCSRF},
		"decision":      {"allow"},
		// The browser must not be able to choose a different identity.
		"user_id": {"999999"},
	}, authCookie)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("consent status = %d, want %d. body: %s", recorder.Code, http.StatusSeeOther, recorder.Body.String())
	}
	location := recorder.Header().Get("Location")
	parsedLocation, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse consent redirect: %v", err)
	}
	if parsedLocation.Scheme != "http" || parsedLocation.Host != "127.0.0.1:8765" || parsedLocation.Path != "/callback" {
		t.Fatalf("consent redirected to unexpected URL %q", location)
	}
	query := parsedLocation.Query()
	if query.Get("state") != state {
		t.Errorf("state = %q, want %q", query.Get("state"), state)
	}
	if query.Get("error") != "" {
		t.Fatalf("consent returned an OAuth error: %s", query.Get("error"))
	}
	grantedScope := query.Get("scope")
	if !strings.Contains(grantedScope, "renewly") || !strings.Contains(grantedScope, "offline_access") {
		t.Errorf("granted scope = %q, want renewly and offline_access", grantedScope)
	}
	code := query.Get("code")
	if code == "" {
		t.Fatal("consent did not return an authorization code")
	}

	// 9. The consent continuation is single-use.
	recorder = doForm(router, "/oauth/consent", url.Values{
		"request_token": {requestToken},
		"csrf_ts":       {csrfTS},
		"csrf_token":    {consentCSRF},
		"decision":      {"allow"},
	}, authCookie)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("replayed consent status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	if recorder.Header().Get("Location") != "" {
		t.Fatal("replayed consent must not return another authorization code")
	}

	// 10. The authorization code exchanges successfully with PKCE.
	recorder = doForm(router, "/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {testOAuthRedirectURI},
		"code_verifier": {verifier},
	})
	assertStatus(t, recorder, http.StatusOK)
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &tokenResponse); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokenResponse.AccessToken == "" {
		t.Fatal("token endpoint did not return an access token")
	}
	if !strings.EqualFold(tokenResponse.TokenType, "bearer") {
		t.Errorf("token_type = %q, want Bearer", tokenResponse.TokenType)
	}

	// 11. The issued token belongs to the session user, not the submitted user_id.
	var userID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&userID); err != nil {
		t.Fatalf("look up registered user: %v", err)
	}
	var payload []byte
	if err := pool.QueryRow(ctx, `
		SELECT payload FROM oauth_sessions
		WHERE token_type = 'access_token' AND client_id = $1
		ORDER BY created_at DESC LIMIT 1`, clientID).Scan(&payload); err != nil {
		t.Fatalf("load access token session: %v", err)
	}
	var stored struct {
		Session struct {
			Subject string `json:"subject"`
		} `json:"session"`
	}
	if err := json.Unmarshal(payload, &stored); err != nil {
		t.Fatalf("decode access token session: %v", err)
	}
	if stored.Session.Subject != strconv.FormatInt(userID, 10) {
		t.Fatalf("token subject = %q, want authenticated user %d", stored.Session.Subject, userID)
	}

	// 12. MCP bearer-token authentication continues to work.
	recorder = doMCP(router, tokenResponse.AccessToken)
	assertStatus(t, recorder, http.StatusOK)
	if !strings.Contains(recorder.Body.String(), "serverInfo") {
		t.Fatalf("MCP initialize response missing serverInfo: %s", recorder.Body.String())
	}

	// 13. The browser cookie alone is not an MCP credential.
	recorder = doMCP(router, "", authCookie)
	assertStatus(t, recorder, http.StatusUnauthorized)

	// 14. A returning user with a valid cookie goes straight to consent, and
	// PKCE is still enforced at the token endpoint.
	_, challenge2 := pkcePair(t)
	state2 := "state-pkce-flow"
	recorder = doGet(router, authorizePath(clientID, testOAuthRedirectURI, state2, challenge2), authCookie)
	assertStatus(t, recorder, http.StatusOK)
	consentBody = recorder.Body.String()
	requestToken2 := hiddenInput(t, consentBody, "request_token")
	csrfTS2 := hiddenInput(t, consentBody, "csrf_ts")
	consentCSRF2 := hiddenInput(t, consentBody, "csrf_token")

	recorder = doForm(router, "/oauth/consent", url.Values{
		"request_token": {requestToken2},
		"csrf_ts":       {csrfTS2},
		"csrf_token":    {consentCSRF2},
		"decision":      {"allow"},
	}, authCookie)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("second consent status = %d, want %d", recorder.Code, http.StatusSeeOther)
	}
	code2 := callbackCode(t, recorder.Header().Get("Location"))
	if code2 == "" {
		t.Fatal("second consent did not return an authorization code")
	}

	recorder = doForm(router, "/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code2},
		"redirect_uri":  {testOAuthRedirectURI},
		"code_verifier": {"wrong-verifier"},
	})
	if recorder.Code == http.StatusOK {
		t.Fatal("token endpoint accepted a wrong PKCE verifier")
	}
}

func TestOAuthWebExistingUserLoginAndDeny(t *testing.T) {
	router, _ := setupOAuthTestApp(t)

	const email = "existing@example.com"
	const password = "password123"
	registerAPIUser(t, router, "Existing User", email, password)

	clientID := registerOAuthClient(t, router)
	_, challenge := pkcePair(t)
	state := "state-deny-flow"
	authPath := authorizePath(clientID, testOAuthRedirectURI, state, challenge)

	recorder := doGet(router, authPath)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("authorize status = %d, want %d", recorder.Code, http.StatusSeeOther)
	}
	continuation := cookieNamed(recorder, "renewly_oauth_continuation")
	if continuation == nil {
		t.Fatal("authorize did not set a continuation cookie")
	}

	recorder = doGet(router, "/auth/login", continuation)
	assertStatus(t, recorder, http.StatusOK)
	csrfCookie := cookieNamed(recorder, "renewly_csrf")
	if csrfCookie == nil {
		t.Fatal("login page did not set a CSRF cookie")
	}
	csrf := hiddenInput(t, recorder.Body.String(), "csrf_token")

	// An existing account with the wrong password is rejected.
	recorder = doForm(router, "/auth/login", url.Values{
		"csrf_token": {csrf},
		"email":      {email},
		"password":   {"wrong-password"},
	}, csrfCookie, continuation)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("invalid existing-user login status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	if cookieNamed(recorder, "auth_token") != nil {
		t.Fatal("invalid existing-user login issued an auth cookie")
	}

	recorder = doForm(router, "/auth/login", url.Values{
		"csrf_token": {csrf},
		"email":      {email},
		"password":   {password},
	}, csrfCookie, continuation)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d, want %d. body: %s", recorder.Code, http.StatusSeeOther, recorder.Body.String())
	}
	if location := recorder.Header().Get("Location"); location != "/oauth/authorize" {
		t.Fatalf("login Location = %q, want /oauth/authorize", location)
	}
	authCookie := cookieNamed(recorder, "auth_token")
	if authCookie == nil {
		t.Fatal("existing user login did not issue an auth cookie")
	}

	recorder = doGet(router, "/oauth/authorize", authCookie, continuation)
	assertStatus(t, recorder, http.StatusOK)
	consentBody := recorder.Body.String()
	requestToken := hiddenInput(t, consentBody, "request_token")
	csrfTS := hiddenInput(t, consentBody, "csrf_ts")
	consentCSRF := hiddenInput(t, consentBody, "csrf_token")

	recorder = doForm(router, "/oauth/consent", url.Values{
		"request_token": {requestToken},
		"csrf_ts":       {csrfTS},
		"csrf_token":    {consentCSRF},
		"decision":      {"deny"},
	}, authCookie)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("deny status = %d, want %d. body: %s", recorder.Code, http.StatusSeeOther, recorder.Body.String())
	}
	parsed, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse deny redirect: %v", err)
	}
	query := parsed.Query()
	if query.Get("error") != "access_denied" {
		t.Errorf("error = %q, want access_denied", query.Get("error"))
	}
	if query.Get("state") != state {
		t.Errorf("state = %q, want %q", query.Get("state"), state)
	}
	if query.Get("code") != "" {
		t.Fatal("denying consent issued an authorization code")
	}
}

func TestOAuthWebDuplicateRegistrationRejected(t *testing.T) {
	router, _ := setupOAuthTestApp(t)

	const email = "duplicate@example.com"
	const password = "password123"
	registerAPIUser(t, router, "Existing User", email, password)

	recorder := doGet(router, "/auth/register")
	assertStatus(t, recorder, http.StatusOK)
	csrfCookie := cookieNamed(recorder, "renewly_csrf")
	if csrfCookie == nil {
		t.Fatal("registration page did not set a CSRF cookie")
	}
	csrf := hiddenInput(t, recorder.Body.String(), "csrf_token")

	recorder = doForm(router, "/auth/register", url.Values{
		"csrf_token":       {csrf},
		"name":             {"Duplicate User"},
		"email":            {email},
		"password":         {password},
		"confirm_password": {password},
	}, csrfCookie)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("duplicate registration status = %d, want %d. body: %s", recorder.Code, http.StatusConflict, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "already exists") {
		t.Fatalf("duplicate registration page missing clear error: %s", recorder.Body.String())
	}
	if cookieNamed(recorder, "auth_token") != nil {
		t.Fatal("duplicate registration must not issue an auth cookie")
	}
}

func TestOAuthContinuationExpiredOrInvalidIsRejected(t *testing.T) {
	router, pool := setupOAuthTestApp(t)
	ctx := context.Background()

	clientID := registerOAuthClient(t, router)
	_, challenge := pkcePair(t)
	authPath := authorizePath(clientID, testOAuthRedirectURI, "state-expired", challenge)
	rawQuery := strings.TrimPrefix(authPath, "/oauth/authorize?")

	expiredToken := "expired-continuation-token"
	sum := sha256.Sum256([]byte(expiredToken))
	_, err := pool.Exec(ctx, `
		INSERT INTO oauth_authorization_continuations
		(token_hash, purpose, request_query, user_id, expires_at)
		VALUES ($1, 'login', $2, NULL, NOW() - INTERVAL '1 minute')`,
		hex.EncodeToString(sum[:]), rawQuery)
	if err != nil {
		t.Fatalf("insert expired continuation: %v", err)
	}

	for _, token := range []string{expiredToken, "not-a-real-continuation"} {
		recorder := doGet(router, "/oauth/authorize", &http.Cookie{
			Name:  "renewly_oauth_continuation",
			Value: token,
		})
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("continuation %q status = %d, want %d. body: %s", token, recorder.Code, http.StatusBadRequest, recorder.Body.String())
		}
		if strings.Contains(recorder.Body.String(), "Requested permissions") {
			t.Fatalf("continuation %q unexpectedly reached the consent screen", token)
		}
	}
}

func TestOAuthConsentTokenIsBoundToAuthenticatedUser(t *testing.T) {
	router, pool := setupOAuthTestApp(t)
	ctx := context.Background()

	const password = "password123"
	registerAPIUser(t, router, "User A", "user-a@example.com", password)
	registerAPIUser(t, router, "User B", "user-b@example.com", password)

	clientID := registerOAuthClient(t, router)
	_, challenge := pkcePair(t)
	authPath := authorizePath(clientID, testOAuthRedirectURI, "state-user-binding", challenge)

	cookieA := loginAPIUser(t, router, "user-a@example.com", password)
	recorder := doGet(router, authPath, cookieA)
	assertStatus(t, recorder, http.StatusOK)
	consentBody := recorder.Body.String()
	requestToken := hiddenInput(t, consentBody, "request_token")
	csrfTS := hiddenInput(t, consentBody, "csrf_ts")
	csrfA := hiddenInput(t, consentBody, "csrf_token")

	var userBID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = 'user-b@example.com'`).Scan(&userBID); err != nil {
		t.Fatalf("look up user B: %v", err)
	}

	// A valid CSRF token for user B still cannot consume user A's consent
	// continuation because the server binds the row to user A's ID.
	cookieB := loginAPIUser(t, router, "user-b@example.com", password)
	recorder = doForm(router, "/oauth/consent", url.Values{
		"request_token": {requestToken},
		"csrf_ts":       {csrfTS},
		"csrf_token":    {consentCSRFForTest(userBID, requestToken, csrfTS)},
		"decision":      {"allow"},
	}, cookieB)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("cross-user consent status = %d, want %d. body: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	if recorder.Header().Get("Location") != "" {
		t.Fatal("cross-user consent must not return an authorization code")
	}

	// User A can still use the original consent request.
	recorder = doForm(router, "/oauth/consent", url.Values{
		"request_token": {requestToken},
		"csrf_ts":       {csrfTS},
		"csrf_token":    {csrfA},
		"decision":      {"allow"},
	}, cookieA)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("owner consent status = %d, want %d. body: %s", recorder.Code, http.StatusSeeOther, recorder.Body.String())
	}
	if callbackCode(t, recorder.Header().Get("Location")) == "" {
		t.Fatal("owner consent did not return an authorization code")
	}
}
