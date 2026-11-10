// Package webui embeds the server-rendered Renewly authentication and OAuth
// consent pages. Templates are compiled into the Go binary so the Docker
// runtime image only needs the binary.
package webui

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

//go:embed templates/*.html
var templateFS embed.FS

var pageNames = []string{"login", "register", "consent", "status", "error"}

var pages = make(map[string]*template.Template, len(pageNames))

func init() {
	for _, name := range pageNames {
		pages[name] = template.Must(template.ParseFS(
			templateFS,
			"templates/layout.html",
			"templates/"+name+".html",
		))
	}
}

// Base carries fields shared by every page.
type Base struct {
	Title string
	Error string
	Wide  bool
}

type LoginPage struct {
	Base
	Email string
	CSRF  string
}

type RegisterPage struct {
	Base
	Name  string
	Email string
	CSRF  string
}

// ScopeView is a user-facing description of one OAuth scope. Read and Write
// lists are populated from the capabilities actually granted by that scope.
type ScopeView struct {
	Name        string
	Label       string
	Description string
	Read        []string
	Write       []string
	Offline     bool
}

type ConsentPage struct {
	Base
	ClientName   string
	ClientID     string
	UserEmail    string
	Scopes       []ScopeView
	RequestToken string
	Issued       string
	CSRF         string
}

type StatusPage struct {
	Base
	Email string
	CSRF  string
}

type ErrorPage struct {
	Base
	Heading string
	Message string
}

// Render writes a fully buffered HTML response so a template error never
// produces a partially rendered page. It also applies conservative browser
// security headers to every authentication page.
func Render(w http.ResponseWriter, status int, page string, data any) error {
	return render(w, status, page, data, nil)
}

// RenderWithFormActions renders a page whose form-action CSP directive also
// allows submissions to redirect to the given origins. Browsers check
// form-action against every redirect target after a form POST, so a page that
// only allows 'self' silently blocks redirects to another origin (for example
// an OAuth client's loopback callback).
func RenderWithFormActions(w http.ResponseWriter, status int, page string, data any, formActions ...string) error {
	return render(w, status, page, data, formActions)
}

func render(w http.ResponseWriter, status int, page string, data any, formActions []string) error {
	tmpl, ok := pages[page]
	if !ok {
		return fmt.Errorf("unknown web page %q", page)
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		return err
	}

	setSecurityHeaders(w, formActions...)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, err := w.Write(buf.Bytes())
	return err
}

// RenderError renders the shared error page.
func RenderError(w http.ResponseWriter, status int, heading, message string) error {
	return Render(w, status, "error", ErrorPage{
		Base:    Base{Title: heading},
		Heading: heading,
		Message: message,
	})
}

// SetSecurityHeaders applies the same browser hardening used by Render to
// responses that redirect or are written by the OAuth handler.
func SetSecurityHeaders(w http.ResponseWriter) {
	setSecurityHeaders(w)
}

func setSecurityHeaders(w http.ResponseWriter, formActions ...string) {
	sources := []string{"'self'"}
	for _, raw := range formActions {
		if origin, ok := formActionOrigin(raw); ok {
			sources = append(sources, origin)
		}
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; "+
			"style-src 'unsafe-inline'; "+
			"script-src 'unsafe-inline'; "+
			"img-src data:; "+
			"form-action "+strings.Join(sources, " ")+"; "+
			"base-uri 'none'; "+
			"frame-ancestors 'none'")
}

// formActionOrigin reduces a redirect URI to a CSP host-source. Only plain
// HTTP(S) origins are accepted so an unexpected value can never break or widen
// the policy.
func formActionOrigin(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	return u.Scheme + "://" + u.Host, true
}
