package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/vijay-talsangi/Renewly/middleware"
)

const (
	// LoginContinuationCookieName references a server-side copy of the original
	// authorization request while the user signs in.
	LoginContinuationCookieName = "renewly_oauth_continuation"

	continuationLifetime = 10 * time.Minute

	continuationPurposeLogin   = "login"
	continuationPurposeConsent = "consent"
)

var errContinuationNotFound = errors.New("authorization continuation is missing, expired, or already used")

func newContinuationToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func hashContinuationToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Server) createContinuation(ctx context.Context, purpose, rawQuery string, userID *int64) (string, error) {
	token, err := newContinuationToken()
	if err != nil {
		return "", err
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO oauth_authorization_continuations
		(token_hash, purpose, request_query, user_id, expires_at)
		VALUES ($1, $2, $3, $4, $5)`,
		hashContinuationToken(token), purpose, rawQuery, userID,
		time.Now().Add(continuationLifetime),
	)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *Server) consumeLoginContinuation(ctx context.Context, token string) (string, error) {
	var rawQuery string
	err := s.pool.QueryRow(ctx, `
		UPDATE oauth_authorization_continuations
		SET consumed_at = NOW()
		WHERE token_hash = $1
		  AND purpose = 'login'
		  AND consumed_at IS NULL
		  AND expires_at > NOW()
		RETURNING request_query`,
		hashContinuationToken(token),
	).Scan(&rawQuery)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errContinuationNotFound
	}
	if err != nil {
		return "", err
	}
	return rawQuery, nil
}

func (s *Server) consumeConsentContinuation(ctx context.Context, token string, userID int64) (string, error) {
	var rawQuery string
	err := s.pool.QueryRow(ctx, `
		UPDATE oauth_authorization_continuations
		SET consumed_at = NOW()
		WHERE token_hash = $1
		  AND purpose = 'consent'
		  AND user_id = $2
		  AND consumed_at IS NULL
		  AND expires_at > NOW()
		RETURNING request_query`,
		hashContinuationToken(token), userID,
	).Scan(&rawQuery)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errContinuationNotFound
	}
	if err != nil {
		return "", err
	}
	return rawQuery, nil
}

func (s *Server) peekConsentContinuation(ctx context.Context, token string) (string, error) {
	var rawQuery string
	err := s.pool.QueryRow(ctx, `
		SELECT request_query
		FROM oauth_authorization_continuations
		WHERE token_hash = $1
		  AND purpose = 'consent'
		  AND consumed_at IS NULL
		  AND expires_at > NOW()`,
		hashContinuationToken(token),
	).Scan(&rawQuery)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errContinuationNotFound
	}
	if err != nil {
		return "", err
	}
	return rawQuery, nil
}

func (s *Server) consumeConsentContinuationAnyUser(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE oauth_authorization_continuations
		SET consumed_at = NOW()
		WHERE token_hash = $1
		  AND purpose = 'consent'
		  AND consumed_at IS NULL
		  AND expires_at > NOW()`,
		hashContinuationToken(token),
	)
	return err
}

func setLoginContinuationCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     LoginContinuationCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(continuationLifetime.Seconds()),
		HttpOnly: true,
		Secure:   middleware.SecureCookie(),
		SameSite: http.SameSiteLaxMode,
	})
}

func clearLoginContinuationCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     LoginContinuationCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   middleware.SecureCookie(),
		SameSite: http.SameSiteLaxMode,
	})
}

// requestWithRawQuery builds a GET request whose only parameters are the
// server-stored authorization query. This prevents a consent POST body from
// overriding client_id, redirect_uri, scope, state, or the PKCE challenge.
func requestWithRawQuery(r *http.Request, rawQuery string) *http.Request {
	clone := r.Clone(r.Context())
	clone.Method = http.MethodGet
	clone.Body = http.NoBody
	clone.GetBody = nil
	clone.Form = nil
	clone.PostForm = nil
	clone.MultipartForm = nil
	clone.Header.Del("Content-Type")
	clone.Header.Del("Content-Length")
	clone.URL.RawQuery = rawQuery
	clone.RequestURI = clone.URL.RequestURI()
	return clone
}
