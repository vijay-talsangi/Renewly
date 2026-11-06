package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
)

func sendRequest(
	router *gin.Engine,
	method string,
	path string,
	body any,
	cookie *http.Cookie,
) *httptest.ResponseRecorder {
	var requestBody *bytes.Reader

	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			panic(err)
		}
		requestBody = bytes.NewReader(data)
	} else {
		requestBody = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, path, requestBody)

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if cookie != nil {
		req.AddCookie(cookie)
	}

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	return recorder
}

func assertStatus(
	t *testing.T,
	recorder *httptest.ResponseRecorder,
	expected int,
) {
	t.Helper()

	if recorder.Code != expected {
		t.Fatalf(
			"expected status %d, got %d. Response: %s",
			expected,
			recorder.Code,
			recorder.Body.String(),
		)
	}
}

func TestAPIFlow(t *testing.T) {
	router := setupTestApp(t)

	// ---------------------------------
	// 1. Registration
	// ---------------------------------

	t.Run("Register user", func(t *testing.T) {
		body := map[string]any{
			"name":     "Vijay",
			"email":    "vijay@example.com",
			"password": "password123",
		}

		recorder := sendRequest(
			router,
			http.MethodPost,
			"/api/register",
			body,
			nil,
		)

		assertStatus(t, recorder, http.StatusCreated)
	})

	// ---------------------------------
	// 2. Duplicate registration
	// ---------------------------------

	t.Run("Reject duplicate registration", func(t *testing.T) {
		body := map[string]any{
			"name":     "Vijay",
			"email":    "vijay@example.com",
			"password": "password123",
		}

		recorder := sendRequest(
			router,
			http.MethodPost,
			"/api/register",
			body,
			nil,
		)

		// Current controller maps service errors to 500.
		assertStatus(t, recorder, http.StatusInternalServerError)
	})

	// ---------------------------------
	// 3. Invalid login
	// ---------------------------------

	t.Run("Reject invalid login", func(t *testing.T) {
		body := map[string]any{
			"email":    "vijay@example.com",
			"password": "wrongpassword",
		}

		recorder := sendRequest(
			router,
			http.MethodPost,
			"/api/login",
			body,
			nil,
		)

		assertStatus(t, recorder, http.StatusUnauthorized)
	})

	// ---------------------------------
	// 4. Successful login
	// ---------------------------------

	var authCookie *http.Cookie

	t.Run("Login user", func(t *testing.T) {
		body := map[string]any{
			"email":    "vijay@example.com",
			"password": "password123",
		}

		recorder := sendRequest(
			router,
			http.MethodPost,
			"/api/login",
			body,
			nil,
		)

		assertStatus(t, recorder, http.StatusOK)

		for _, cookie := range recorder.Result().Cookies() {
			if cookie.Name == "auth_token" {
				authCookie = cookie
				break
			}
		}

		if authCookie == nil {
			t.Fatal("expected auth_token cookie after login")
		}

		if authCookie.Value == "" {
			t.Fatal("expected a non-empty auth token")
		}

		if !authCookie.HttpOnly {
			t.Error("expected auth cookie to be HttpOnly")
		}
	})

	// ---------------------------------
	// 5. Reject unauthenticated request
	// ---------------------------------

	t.Run("Reject subscriptions without authentication", func(t *testing.T) {
		recorder := sendRequest(
			router,
			http.MethodGet,
			"/api/subscriptions",
			nil,
			nil,
		)

		assertStatus(t, recorder, http.StatusUnauthorized)
	})

	// ---------------------------------
	// 6. Create subscription
	// ---------------------------------

	subscriptionBody := map[string]any{
		"name":              "Netflix",
		"category":          "Entertainment",
		"amount":            649.00,
		"currency":          "INR",
		"billing_cycle":     "monthly",
		"auto_renew":        true,
		"start_date":        "2026-11-01",
		"next_billing_date": "2026-12-01",
	}

	t.Run("Create subscription", func(t *testing.T) {
		recorder := sendRequest(
			router,
			http.MethodPost,
			"/api/subscriptions",
			subscriptionBody,
			authCookie,
		)

		assertStatus(t, recorder, http.StatusCreated)
	})

	// ---------------------------------
	// 7. Retrieve subscriptions
	// ---------------------------------

	var subscriptionID int64

	t.Run("Get subscriptions", func(t *testing.T) {
		recorder := sendRequest(
			router,
			http.MethodGet,
			"/api/subscriptions",
			nil,
			authCookie,
		)

		assertStatus(t, recorder, http.StatusOK)

		var subscriptions []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		}

		if err := json.Unmarshal(recorder.Body.Bytes(), &subscriptions); err != nil {
			t.Fatalf("failed to decode subscriptions: %v", err)
		}

		if len(subscriptions) != 1 {
			t.Fatalf(
				"expected 1 subscription, got %d",
				len(subscriptions),
			)
		}

		if subscriptions[0].Name != "Netflix" {
			t.Errorf(
				"expected Netflix, got %s",
				subscriptions[0].Name,
			)
		}

		subscriptionID = subscriptions[0].ID

		if subscriptionID <= 0 {
			t.Fatal("expected a valid subscription ID")
		}
	})

	// ---------------------------------
	// 8. Update subscription
	// ---------------------------------

	t.Run("Update subscription", func(t *testing.T) {
		body := map[string]any{
			"name":              "Netflix Premium",
			"category":          "Entertainment",
			"amount":            799.00,
			"currency":          "INR",
			"billing_cycle":     "monthly",
			"auto_renew":        true,
			"start_date":        "2026-11-01",
			"next_billing_date": "2026-12-01",
		}

		path := "/api/subscriptions/" + strconv.FormatInt(subscriptionID, 10)

		recorder := sendRequest(
			router,
			http.MethodPut,
			path,
			body,
			authCookie,
		)

		assertStatus(t, recorder, http.StatusOK)
	})

	// ---------------------------------
	// 9. Verify updated subscription
	// ---------------------------------

	t.Run("Verify subscription update", func(t *testing.T) {
		recorder := sendRequest(
			router,
			http.MethodGet,
			"/api/subscriptions",
			nil,
			authCookie,
		)

		assertStatus(t, recorder, http.StatusOK)

		var subscriptions []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		}

		if err := json.Unmarshal(recorder.Body.Bytes(), &subscriptions); err != nil {
			t.Fatalf("failed to decode subscriptions: %v", err)
		}

		if len(subscriptions) != 1 {
			t.Fatalf("expected 1 subscription, got %d", len(subscriptions))
		}

		if subscriptions[0].Name != "Netflix Premium" {
			t.Errorf(
				"expected updated name Netflix Premium, got %s",
				subscriptions[0].Name,
			)
		}
	})

	// ---------------------------------
	// 10. Logout
	// ---------------------------------

	var logoutCookie *http.Cookie

	t.Run("Logout user", func(t *testing.T) {
		recorder := sendRequest(
			router,
			http.MethodPost,
			"/api/logout",
			nil,
			authCookie,
		)

		assertStatus(t, recorder, http.StatusOK)

		for _, cookie := range recorder.Result().Cookies() {
			if cookie.Name == "auth_token" {
				logoutCookie = cookie
				break
			}
		}

		if logoutCookie == nil {
			t.Fatal("expected auth_token deletion cookie")
		}
	})

	// ---------------------------------
	// 11. Verify logout
	// ---------------------------------

	t.Run("Reject request after logout", func(t *testing.T) {
		recorder := sendRequest(
			router,
			http.MethodGet,
			"/api/subscriptions",
			nil,
			logoutCookie,
		)

		assertStatus(t, recorder, http.StatusUnauthorized)
	})
}
