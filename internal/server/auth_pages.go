package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/mail"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"
	db "github.com/vijay-talsangi/Renewly/db/sqlc"
	"github.com/vijay-talsangi/Renewly/internal/webui"
	"github.com/vijay-talsangi/Renewly/middleware"
	renewlyoauth "github.com/vijay-talsangi/Renewly/oauth"
	"github.com/vijay-talsangi/Renewly/services"
)

const maxAuthFormBytes = 1 << 20

type authUserService interface {
	Register(ctx context.Context, input services.RegisterInput) error
	Login(ctx context.Context, input services.LoginInput) (string, error)
	GetByID(ctx context.Context, id int64) (db.User, error)
}

type authPages struct {
	users authUserService
}

func newAuthPages(users authUserService) *authPages {
	return &authPages{users: users}
}

func (p *authPages) loginPage(c *gin.Context) {
	if _, ok := middleware.UserIDFromCookieRequest(c.Request); ok {
		p.redirectAuthenticated(c)
		return
	}

	p.renderLogin(c.Writer, c.Request, http.StatusOK, "", "")
}

func (p *authPages) loginSubmit(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxAuthFormBytes)

	csrf, err := newCSRFManager()
	if err != nil {
		log.Printf("auth login CSRF initialization failed: %v", err)
		renderAuthError(c.Writer, http.StatusInternalServerError, "Sign in unavailable", "The sign-in service is not configured correctly. Please try again later.")
		return
	}
	if err := csrf.Validate(c.Request); err != nil {
		renderAuthError(c.Writer, http.StatusForbidden, "Request could not be verified", "Refresh the sign-in page and try again.")
		return
	}

	email := strings.TrimSpace(c.Request.PostForm.Get("email"))
	password := c.Request.PostForm.Get("password")

	if email == "" || password == "" {
		p.renderLogin(c.Writer, c.Request, http.StatusBadRequest, email, "Enter your email and password.")
		return
	}
	if !validEmail(email) {
		p.renderLogin(c.Writer, c.Request, http.StatusBadRequest, email, "Enter a valid email address.")
		return
	}

	token, err := p.users.Login(c.Request.Context(), services.LoginInput{
		Email:    email,
		Password: password,
	})
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			p.renderLogin(c.Writer, c.Request, http.StatusUnauthorized, email, "Invalid email or password.")
			return
		}
		log.Printf("auth login failed: %v", err)
		p.renderLogin(c.Writer, c.Request, http.StatusInternalServerError, email, "We couldn't sign you in right now. Please try again.")
		return
	}

	middleware.SetAuthCookie(c, token)
	csrf.Clear(c.Writer)
	p.redirectAfterAuth(c)
}

func (p *authPages) registerPage(c *gin.Context) {
	if _, ok := middleware.UserIDFromCookieRequest(c.Request); ok {
		p.redirectAuthenticated(c)
		return
	}

	p.renderRegister(c.Writer, c.Request, http.StatusOK, "", "", "")
}

func (p *authPages) registerSubmit(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxAuthFormBytes)

	csrf, err := newCSRFManager()
	if err != nil {
		log.Printf("auth registration CSRF initialization failed: %v", err)
		renderAuthError(c.Writer, http.StatusInternalServerError, "Registration unavailable", "The registration service is not configured correctly. Please try again later.")
		return
	}
	if err := csrf.Validate(c.Request); err != nil {
		renderAuthError(c.Writer, http.StatusForbidden, "Request could not be verified", "Refresh the registration page and try again.")
		return
	}

	name := strings.TrimSpace(c.Request.PostForm.Get("name"))
	email := strings.TrimSpace(c.Request.PostForm.Get("email"))
	password := c.Request.PostForm.Get("password")
	confirm := c.Request.PostForm.Get("confirm_password")

	switch {
	case name == "":
		p.renderRegister(c.Writer, c.Request, http.StatusBadRequest, name, email, "Enter your name.")
		return
	case !validName(name):
		p.renderRegister(c.Writer, c.Request, http.StatusBadRequest, name, email, "Enter a valid name of 200 characters or fewer.")
		return
	case email == "":
		p.renderRegister(c.Writer, c.Request, http.StatusBadRequest, name, email, "Enter your email address.")
		return
	case !validEmail(email):
		p.renderRegister(c.Writer, c.Request, http.StatusBadRequest, name, email, "Enter a valid email address.")
		return
	case len(password) < 6:
		p.renderRegister(c.Writer, c.Request, http.StatusBadRequest, name, email, "Password must be at least 6 characters.")
		return
	case len(password) > 72:
		p.renderRegister(c.Writer, c.Request, http.StatusBadRequest, name, email, "Password must be 72 characters or fewer.")
		return
	case password != confirm:
		p.renderRegister(c.Writer, c.Request, http.StatusBadRequest, name, email, "Passwords do not match.")
		return
	}

	if err := p.users.Register(c.Request.Context(), services.RegisterInput{
		Name:     name,
		Email:    email,
		Password: password,
	}); err != nil {
		if errors.Is(err, services.ErrEmailExists) {
			p.renderRegister(c.Writer, c.Request, http.StatusConflict, name, email, "An account with this email already exists. Sign in instead.")
			return
		}
		log.Printf("auth registration failed: %v", err)
		p.renderRegister(c.Writer, c.Request, http.StatusInternalServerError, name, email, "We couldn't create your account right now. Please try again.")
		return
	}

	// Reuse the existing authentication service so the new account receives
	// exactly the same JWT cookie as an existing user.
	token, err := p.users.Login(c.Request.Context(), services.LoginInput{
		Email:    email,
		Password: password,
	})
	if err != nil {
		log.Printf("auth post-registration login failed: %v", err)
		p.renderLogin(c.Writer, c.Request, http.StatusInternalServerError, email, "Your account was created, but we couldn't sign you in. Please sign in.")
		return
	}

	middleware.SetAuthCookie(c, token)
	csrf.Clear(c.Writer)
	p.redirectAfterAuth(c)
}

func (p *authPages) statusPage(c *gin.Context) {
	userID, ok := middleware.UserIDFromCookieRequest(c.Request)
	if !ok {
		c.Redirect(http.StatusSeeOther, "/auth/login")
		return
	}

	user, err := p.users.GetByID(c.Request.Context(), userID)
	if err != nil {
		log.Printf("auth status lookup failed: %v", err)
		middleware.ClearAuthCookie(c)
		c.Redirect(http.StatusSeeOther, "/auth/login")
		return
	}

	csrf, err := newCSRFManager()
	if err != nil {
		log.Printf("auth status CSRF initialization failed: %v", err)
		renderAuthError(c.Writer, http.StatusInternalServerError, "Account unavailable", "The account service is not configured correctly. Please try again later.")
		return
	}
	token, err := csrf.Token(c.Writer, c.Request)
	if err != nil {
		log.Printf("auth status CSRF token failed: %v", err)
		renderAuthError(c.Writer, http.StatusInternalServerError, "Account unavailable", "We couldn't prepare the account page. Please try again.")
		return
	}

	page := webui.StatusPage{
		Base:  webui.Base{Title: "Account"},
		Email: user.Email,
		CSRF:  token,
	}
	if err := webui.Render(c.Writer, http.StatusOK, "status", page); err != nil {
		log.Printf("auth status render failed: %v", err)
		http.Error(c.Writer, "internal server error", http.StatusInternalServerError)
	}
}

func (p *authPages) logout(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxAuthFormBytes)

	csrf, err := newCSRFManager()
	if err != nil {
		log.Printf("auth logout CSRF initialization failed: %v", err)
		renderAuthError(c.Writer, http.StatusInternalServerError, "Sign out unavailable", "The sign-out service is not configured correctly. Please try again later.")
		return
	}
	if err := csrf.Validate(c.Request); err != nil {
		renderAuthError(c.Writer, http.StatusForbidden, "Request could not be verified", "Refresh the account page and try again.")
		return
	}

	// Only the browser session cookie is removed. OAuth access and refresh
	// tokens issued to MCP clients remain valid until revoked separately.
	middleware.ClearAuthCookie(c)
	csrf.Clear(c.Writer)
	c.Redirect(http.StatusSeeOther, "/auth/login")
}

func (p *authPages) redirectAuthenticated(c *gin.Context) {
	if hasLoginContinuation(c.Request) {
		c.Redirect(http.StatusSeeOther, "/oauth/authorize")
		return
	}
	c.Redirect(http.StatusSeeOther, "/auth/status")
}

func (p *authPages) redirectAfterAuth(c *gin.Context) {
	if hasLoginContinuation(c.Request) {
		c.Redirect(http.StatusSeeOther, "/oauth/authorize")
		return
	}
	c.Redirect(http.StatusSeeOther, "/auth/status")
}

func (p *authPages) renderLogin(w http.ResponseWriter, r *http.Request, status int, email, message string) {
	csrf, err := newCSRFManager()
	if err != nil {
		log.Printf("auth login page CSRF initialization failed: %v", err)
		renderAuthError(w, http.StatusInternalServerError, "Sign in unavailable", "The sign-in service is not configured correctly. Please try again later.")
		return
	}
	token, err := csrf.Token(w, r)
	if err != nil {
		log.Printf("auth login page CSRF token failed: %v", err)
		renderAuthError(w, http.StatusInternalServerError, "Sign in unavailable", "We couldn't prepare the sign-in page. Please try again.")
		return
	}

	page := webui.LoginPage{
		Base:  webui.Base{Title: "Sign in", Error: message},
		Email: email,
		CSRF:  token,
	}
	if err := webui.Render(w, status, "login", page); err != nil {
		log.Printf("auth login page render failed: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func (p *authPages) renderRegister(w http.ResponseWriter, r *http.Request, status int, name, email, message string) {
	csrf, err := newCSRFManager()
	if err != nil {
		log.Printf("auth registration page CSRF initialization failed: %v", err)
		renderAuthError(w, http.StatusInternalServerError, "Registration unavailable", "The registration service is not configured correctly. Please try again later.")
		return
	}
	token, err := csrf.Token(w, r)
	if err != nil {
		log.Printf("auth registration page CSRF token failed: %v", err)
		renderAuthError(w, http.StatusInternalServerError, "Registration unavailable", "We couldn't prepare the registration page. Please try again.")
		return
	}

	page := webui.RegisterPage{
		Base:  webui.Base{Title: "Create account", Error: message},
		Name:  name,
		Email: email,
		CSRF:  token,
	}
	if err := webui.Render(w, status, "register", page); err != nil {
		log.Printf("auth registration page render failed: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func renderAuthError(w http.ResponseWriter, status int, heading, message string) {
	if err := webui.RenderError(w, status, heading, message); err != nil {
		log.Printf("auth error page render failed: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

func hasLoginContinuation(r *http.Request) bool {
	cookie, err := r.Cookie(renewlyoauth.LoginContinuationCookieName)
	return err == nil && cookie.Value != ""
}

func validEmail(value string) bool {
	if value == "" || len(value) > 320 || strings.ContainsAny(value, "\r\n") {
		return false
	}
	addr, err := mail.ParseAddress(value)
	return err == nil && addr.Address == value
}

func validName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 200 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
