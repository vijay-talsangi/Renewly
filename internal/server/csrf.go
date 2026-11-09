package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/vijay-talsangi/Renewly/middleware"
)

const (
	csrfCookieName = "renewly_csrf"
	csrfFormField  = "csrf_token"
	csrfMaxAge     = 60 * 60
	csrfNonceBytes = 32
)

var (
	errCSRFMissing = errors.New("csrf cookie or token is missing")
	errCSRFInvalid = errors.New("csrf token is invalid")
)

// csrfManager implements a signed synchronizer token. The browser receives a
// random nonce in an HttpOnly cookie and the corresponding HMAC in a hidden
// form field. The HMAC secret is the existing JWT_SECRET.
type csrfManager struct {
	secret []byte
	secure bool
}

func newCSRFManager() (*csrfManager, error) {
	secret := []byte(os.Getenv("JWT_SECRET"))
	if len(secret) < 16 {
		return nil, errors.New("JWT_SECRET is not configured")
	}
	return &csrfManager{
		secret: secret,
		secure: middleware.SecureCookie(),
	}, nil
}

// Token returns a CSRF token for the form and sets the nonce cookie when one
// is not already present. Reusing the nonce keeps multiple tabs working.
func (m *csrfManager) Token(w http.ResponseWriter, r *http.Request) (string, error) {
	nonce := ""
	if cookie, err := r.Cookie(csrfCookieName); err == nil {
		if decoded, err := base64.RawURLEncoding.DecodeString(cookie.Value); err == nil &&
			len(decoded) == csrfNonceBytes {
			nonce = cookie.Value
		}
	}

	if nonce == "" {
		buf := make([]byte, csrfNonceBytes)
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		nonce = base64.RawURLEncoding.EncodeToString(buf)
		http.SetCookie(w, &http.Cookie{
			Name:     csrfCookieName,
			Value:    nonce,
			Path:     "/",
			MaxAge:   csrfMaxAge,
			HttpOnly: true,
			Secure:   m.secure,
			SameSite: http.SameSiteLaxMode,
		})
	}

	return nonce + "." + m.sign(nonce), nil
}

func (m *csrfManager) sign(nonce string) string {
	mac := hmac.New(sha256.New, m.secret)
	_, _ = mac.Write([]byte("renewly-csrf:" + nonce))
	return hex.EncodeToString(mac.Sum(nil))
}

// Validate checks the hidden form token against the HttpOnly nonce cookie.
// It is constant-time with respect to the HMAC comparison.
func (m *csrfManager) Validate(r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return err
	}

	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return errCSRFMissing
	}

	token := r.PostForm.Get(csrfFormField)
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[0] != cookie.Value {
		return errCSRFInvalid
	}

	got, err := hex.DecodeString(parts[1])
	if err != nil {
		return errCSRFInvalid
	}
	want, err := hex.DecodeString(m.sign(cookie.Value))
	if err != nil || !hmac.Equal(got, want) {
		return errCSRFInvalid
	}

	return nil
}

// Clear removes the nonce cookie after a successful state-changing request.
func (m *csrfManager) Clear(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
	})
}
