package middleware

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

const ContextUserIDKey = "userID"

// AuthCookieName is the browser session cookie used by the Renewly web UI and
// the existing REST API. It intentionally contains a signed JWT, never a raw
// password or OAuth token.
const AuthCookieName = "auth_token"

const authCookieMaxAgeSeconds = 60 * 60 * 24

type contextKey string

const userIDContextKey contextKey = "authenticatedUserID"

func UserIDFromContext(ctx context.Context) (int64, bool) {
	userID, ok := ctx.Value(userIDContextKey).(int64)
	return userID, ok && userID > 0
}

// ContextWithUserID attaches an authenticated Renewly user ID to a request context.
// OAuth bearer authentication uses the same context key as cookie authentication.
func ContextWithUserID(ctx context.Context, userID int64) context.Context {
	return context.WithValue(ctx, userIDContextKey, userID)
}

// SecureCookie reports whether browser cookies must carry the Secure flag.
// Production Cloud Run deployments set COOKIE_SECURE=true.
func SecureCookie() bool {
	return strings.EqualFold(
		strings.TrimSpace(os.Getenv("COOKIE_SECURE")),
		"true",
	)
}

// SetAuthCookie issues the existing Renewly JWT browser session cookie.
func SetAuthCookie(c *gin.Context, token string) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		AuthCookieName,
		token,
		authCookieMaxAgeSeconds,
		"/",
		"",
		SecureCookie(),
		true, // HttpOnly
	)
}

// ClearAuthCookie removes the browser session cookie. It deliberately does not
// revoke OAuth access or refresh tokens belonging to external MCP clients.
func ClearAuthCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(
		AuthCookieName,
		"",
		-1,
		"/",
		"",
		SecureCookie(),
		true, // HttpOnly
	)
}

// ClearAuthCookieWriter is the net/http equivalent of ClearAuthCookie, used by
// the OAuth handler when it discovers an invalid browser session.
func ClearAuthCookieWriter(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     AuthCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   SecureCookie(),
		SameSite: http.SameSiteLaxMode,
	})
}

// UserIDFromCookieRequest validates the existing JWT cookie without writing a
// response. It is used by pages that can render in both authenticated and
// unauthenticated states.
func UserIDFromCookieRequest(r *http.Request) (int64, bool) {
	cookie, err := r.Cookie(AuthCookieName)
	if err != nil || cookie.Value == "" {
		return 0, false
	}

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return 0, false
	}

	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil || !token.Valid || claims.Subject == "" {
		return 0, false
	}

	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil || userID <= 0 {
		return 0, false
	}

	return userID, true
}

func AuthFromCookie() gin.HandlerFunc {
	return func(c *gin.Context) {
		if os.Getenv("JWT_SECRET") == "" {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "server auth misconfiguration"})
			return
		}

		userID, ok := UserIDFromCookieRequest(c.Request)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		c.Set(ContextUserIDKey, userID)
		c.Request = c.Request.WithContext(
			ContextWithUserID(c.Request.Context(), userID),
		)
		c.Next()
	}
}
