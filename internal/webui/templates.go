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
	tmpl, ok := pages[page]
	if !ok {
		return fmt.Errorf("unknown web page %q", page)
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		return err
	}

	setSecurityHeaders(w)
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

func setSecurityHeaders(w http.ResponseWriter) {
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
			"form-action 'self'; "+
			"base-uri 'none'; "+
			"frame-ancestors 'none'")
}
