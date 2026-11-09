package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	db "github.com/vijay-talsangi/Renewly/db/sqlc"
	"github.com/vijay-talsangi/Renewly/services"
)

type fakeAuthUserService struct {
	registerErr error
	loginToken  string
	loginErr    error
	user        db.User
	getUserErr  error

	lastRegister services.RegisterInput
	lastLogin    services.LoginInput
}

func (f *fakeAuthUserService) Register(_ context.Context, input services.RegisterInput) error {
	f.lastRegister = input
	return f.registerErr
}

func (f *fakeAuthUserService) Login(_ context.Context, input services.LoginInput) (string, error) {
	f.lastLogin = input
	return f.loginToken, f.loginErr
}

func (f *fakeAuthUserService) GetByID(_ context.Context, _ int64) (db.User, error) {
	return f.user, f.getUserErr
}

func setupAuthTestRouter(t *testing.T, users authUserService) *gin.Engine {
	t.Helper()
	t.Setenv("JWT_SECRET", "renewly-auth-page-test-secret")
	t.Setenv("COOKIE_SECURE", "false")

	gin.SetMode(gin.TestMode)
	pages := newAuthPages(users)
	router := gin.New()
	router.GET("/auth/login", pages.loginPage)
	router.POST("/auth/login", pages.loginSubmit)
	router.GET("/auth/register", pages.registerPage)
	router.POST("/auth/register", pages.registerSubmit)
	router.GET("/auth/status", pages.statusPage)
	router.POST("/auth/logout", pages.logout)
	return router
}

func authRequest(router *gin.Engine, method, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}

	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}

var csrfTokenPattern = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func csrfFromResponse(t *testing.T, recorder *httptest.ResponseRecorder) (string, *http.Cookie) {
	t.Helper()

	var cookie *http.Cookie
	for _, candidate := range recorder.Result().Cookies() {
		if candidate.Name == csrfCookieName {
			cookie = candidate
			break
		}
	}
	if cookie == nil {
		t.Fatalf("expected %s cookie, headers: %v", csrfCookieName, recorder.Result().Header)
	}

	match := csrfTokenPattern.FindStringSubmatch(recorder.Body.String())
	if len(match) != 2 || match[1] == "" {
		t.Fatalf("expected csrf_token in page, body: %s", recorder.Body.String())
	}
	return match[1], cookie
}

func findCookie(recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func testSessionJWT(t *testing.T, userID int64) string {
	t.Helper()
	claims := jwt.RegisteredClaims{
		Subject:   strconv.FormatInt(userID, 10),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		t.Fatalf("sign test JWT: %v", err)
	}
	return signed
}

func TestLoginPageRendersBrandingAndCSRF(t *testing.T) {
	router := setupAuthTestRouter(t, &fakeAuthUserService{})

	recorder := authRequest(router, http.MethodGet, "/auth/login", nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}

	body := recorder.Body.String()
	for _, want := range []string{
		"Sign in to Renewly",
		`name="email"`,
		`name="password"`,
		`data-password-toggle="password"`,
		"Create an account",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("login page missing %q", want)
		}
	}

	_, cookie := csrfFromResponse(t, recorder)
	if !cookie.HttpOnly {
		t.Error("CSRF cookie must be HttpOnly")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("CSRF cookie SameSite = %v, want Lax", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Errorf("CSRF cookie Path = %q, want /", cookie.Path)
	}
}

func TestLoginRejectsInvalidCredentials(t *testing.T) {
	users := &fakeAuthUserService{loginErr: services.ErrInvalidCredentials}
	router := setupAuthTestRouter(t, users)

	page := authRequest(router, http.MethodGet, "/auth/login", nil)
	csrf, cookie := csrfFromResponse(t, page)

	recorder := authRequest(router, http.MethodPost, "/auth/login", url.Values{
		"csrf_token": {csrf},
		"email":      {"user@example.com"},
		"password":   {"wrong-password"},
	}, cookie)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d. body: %s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "Invalid email or password") {
		t.Errorf("expected generic credential error, body: %s", recorder.Body.String())
	}
	if findCookie(recorder, "auth_token") != nil {
		t.Error("invalid login must not issue an auth_token cookie")
	}
}

func TestLoginSuccessUsesExistingAuthCookie(t *testing.T) {
	users := &fakeAuthUserService{loginToken: "signed.jwt.token"}
	router := setupAuthTestRouter(t, users)

	page := authRequest(router, http.MethodGet, "/auth/login", nil)
	csrf, cookie := csrfFromResponse(t, page)

	recorder := authRequest(router, http.MethodPost, "/auth/login", url.Values{
		"csrf_token": {csrf},
		"email":      {"user@example.com"},
		"password":   {"correct-password"},
	}, cookie)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d. body: %s", recorder.Code, http.StatusSeeOther, recorder.Body.String())
	}
	if got := recorder.Header().Get("Location"); got != "/auth/status" {
		t.Errorf("Location = %q, want /auth/status", got)
	}

	authCookie := findCookie(recorder, "auth_token")
	if authCookie == nil || authCookie.Value != "signed.jwt.token" {
		t.Fatalf("expected auth_token cookie with issued JWT, got %#v", authCookie)
	}
	if !authCookie.HttpOnly {
		t.Error("auth cookie must be HttpOnly")
	}
	if users.lastLogin.Email != "user@example.com" || users.lastLogin.Password != "correct-password" {
		t.Errorf("existing authentication service was not called with submitted credentials: %#v", users.lastLogin)
	}
}

func TestLoginSuccessResumesOAuthContinuation(t *testing.T) {
	users := &fakeAuthUserService{loginToken: "signed.jwt.token"}
	router := setupAuthTestRouter(t, users)

	continuation := &http.Cookie{Name: "renewly_oauth_continuation", Value: "opaque-token"}
	page := authRequest(router, http.MethodGet, "/auth/login", nil, continuation)
	csrf, cookie := csrfFromResponse(t, page)

	recorder := authRequest(router, http.MethodPost, "/auth/login", url.Values{
		"csrf_token": {csrf},
		"email":      {"user@example.com"},
		"password":   {"correct-password"},
	}, cookie, continuation)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusSeeOther)
	}
	if got := recorder.Header().Get("Location"); got != "/oauth/authorize" {
		t.Errorf("Location = %q, want /oauth/authorize", got)
	}
}

func TestLoginRequiresCSRF(t *testing.T) {
	router := setupAuthTestRouter(t, &fakeAuthUserService{loginToken: "signed.jwt.token"})

	recorder := authRequest(router, http.MethodPost, "/auth/login", url.Values{
		"email":    {"user@example.com"},
		"password": {"correct-password"},
	})

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if findCookie(recorder, "auth_token") != nil {
		t.Error("CSRF failure must not issue an auth cookie")
	}
}

func TestLoginRejectsTamperedCSRFToken(t *testing.T) {
	router := setupAuthTestRouter(t, &fakeAuthUserService{loginToken: "signed.jwt.token"})

	page := authRequest(router, http.MethodGet, "/auth/login", nil)
	_, cookie := csrfFromResponse(t, page)

	recorder := authRequest(router, http.MethodPost, "/auth/login", url.Values{
		"csrf_token": {"tampered.value"},
		"email":      {"user@example.com"},
		"password":   {"correct-password"},
	}, cookie)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestLoginRejectsInvalidEmail(t *testing.T) {
	router := setupAuthTestRouter(t, &fakeAuthUserService{loginToken: "signed.jwt.token"})

	page := authRequest(router, http.MethodGet, "/auth/login", nil)
	csrf, cookie := csrfFromResponse(t, page)

	recorder := authRequest(router, http.MethodPost, "/auth/login", url.Values{
		"csrf_token": {csrf},
		"email":      {"not-an-email"},
		"password":   {"correct-password"},
	}, cookie)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	if !strings.Contains(recorder.Body.String(), "valid email") {
		t.Errorf("expected email validation error, body: %s", recorder.Body.String())
	}
}

func TestRegisterRejectsDuplicateEmail(t *testing.T) {
	users := &fakeAuthUserService{registerErr: services.ErrEmailExists}
	router := setupAuthTestRouter(t, users)

	page := authRequest(router, http.MethodGet, "/auth/register", nil)
	csrf, cookie := csrfFromResponse(t, page)

	recorder := authRequest(router, http.MethodPost, "/auth/register", url.Values{
		"csrf_token":       {csrf},
		"name":             {"Vijay"},
		"email":            {"vijay@example.com"},
		"password":         {"password123"},
		"confirm_password": {"password123"},
	}, cookie)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusConflict)
	}
	if !strings.Contains(recorder.Body.String(), "already exists") {
		t.Errorf("expected duplicate email error, body: %s", recorder.Body.String())
	}
}

func TestRegisterRejectsInvalidData(t *testing.T) {
	router := setupAuthTestRouter(t, &fakeAuthUserService{loginToken: "signed.jwt.token"})

	page := authRequest(router, http.MethodGet, "/auth/register", nil)
	csrf, cookie := csrfFromResponse(t, page)

	cases := []struct {
		name string
		form url.Values
		want string
	}{
		{
			name: "missing name",
			form: url.Values{"csrf_token": {csrf}, "name": {""}, "email": {"vijay@example.com"}, "password": {"password123"}, "confirm_password": {"password123"}},
			want: "Enter your name",
		},
		{
			name: "invalid email",
			form: url.Values{"csrf_token": {csrf}, "name": {"Vijay"}, "email": {"bad"}, "password": {"password123"}, "confirm_password": {"password123"}},
			want: "valid email",
		},
		{
			name: "short password",
			form: url.Values{"csrf_token": {csrf}, "name": {"Vijay"}, "email": {"vijay@example.com"}, "password": {"12345"}, "confirm_password": {"12345"}},
			want: "at least 6 characters",
		},
		{
			name: "password mismatch",
			form: url.Values{"csrf_token": {csrf}, "name": {"Vijay"}, "email": {"vijay@example.com"}, "password": {"password123"}, "confirm_password": {"password124"}},
			want: "Passwords do not match",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := authRequest(router, http.MethodPost, "/auth/register", tc.form, cookie)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d. body: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), tc.want) {
				t.Errorf("body missing %q: %s", tc.want, recorder.Body.String())
			}
			if findCookie(recorder, "auth_token") != nil {
				t.Error("invalid registration must not issue an auth cookie")
			}
		})
	}
}

func TestRegisterSuccessAuthenticatesNewUser(t *testing.T) {
	users := &fakeAuthUserService{loginToken: "new.user.jwt"}
	router := setupAuthTestRouter(t, users)

	page := authRequest(router, http.MethodGet, "/auth/register", nil)
	csrf, cookie := csrfFromResponse(t, page)

	recorder := authRequest(router, http.MethodPost, "/auth/register", url.Values{
		"csrf_token":       {csrf},
		"name":             {"Vijay"},
		"email":            {"vijay@example.com"},
		"password":         {"password123"},
		"confirm_password": {"password123"},
	}, cookie)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d. body: %s", recorder.Code, http.StatusSeeOther, recorder.Body.String())
	}
	if got := recorder.Header().Get("Location"); got != "/auth/status" {
		t.Errorf("Location = %q, want /auth/status", got)
	}
	if users.lastRegister.Name != "Vijay" || users.lastRegister.Email != "vijay@example.com" {
		t.Errorf("existing registration service was not called correctly: %#v", users.lastRegister)
	}
	if users.lastLogin.Email != "vijay@example.com" || users.lastLogin.Password != "password123" {
		t.Errorf("new user was not authenticated with the existing login service: %#v", users.lastLogin)
	}
	authCookie := findCookie(recorder, "auth_token")
	if authCookie == nil || authCookie.Value != "new.user.jwt" {
		t.Fatalf("expected auth_token cookie, got %#v", authCookie)
	}
}

func TestStatusRequiresAuthentication(t *testing.T) {
	router := setupAuthTestRouter(t, &fakeAuthUserService{})

	recorder := authRequest(router, http.MethodGet, "/auth/status", nil)
	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusSeeOther)
	}
	if got := recorder.Header().Get("Location"); got != "/auth/login" {
		t.Errorf("Location = %q, want /auth/login", got)
	}
}

func TestStatusShowsAuthenticatedEmail(t *testing.T) {
	users := &fakeAuthUserService{user: db.User{ID: 42, Email: "user@example.com"}}
	router := setupAuthTestRouter(t, users)

	authCookie := &http.Cookie{
		Name:  "auth_token",
		Value: testSessionJWT(t, 42),
	}
	recorder := authRequest(router, http.MethodGet, "/auth/status", nil, authCookie)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d. body: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "user@example.com") {
		t.Errorf("status page missing authenticated email: %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "Sign out") {
		t.Errorf("status page missing sign-out action: %s", recorder.Body.String())
	}
}

func TestLogoutClearsOnlyBrowserSessionCookie(t *testing.T) {
	router := setupAuthTestRouter(t, &fakeAuthUserService{})

	page := authRequest(router, http.MethodGet, "/auth/login", nil)
	csrf, cookie := csrfFromResponse(t, page)

	recorder := authRequest(router, http.MethodPost, "/auth/logout", url.Values{
		"csrf_token": {csrf},
	}, cookie)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusSeeOther)
	}
	if got := recorder.Header().Get("Location"); got != "/auth/login" {
		t.Errorf("Location = %q, want /auth/login", got)
	}

	authCookie := findCookie(recorder, "auth_token")
	if authCookie == nil {
		t.Fatal("expected auth_token deletion cookie")
	}
	if authCookie.MaxAge >= 0 {
		t.Errorf("auth cookie MaxAge = %d, want a deletion cookie", authCookie.MaxAge)
	}
	if !authCookie.HttpOnly {
		t.Error("auth cookie must remain HttpOnly when cleared")
	}
}
