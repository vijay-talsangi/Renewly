package controllers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/vijay-talsangi/Renewly/services"
)

type MockUserService struct {
	RegisterErr error
}

func (m *MockUserService) Register(
	ctx context.Context,
	input services.RegisterInput,
) error {
	return m.RegisterErr
}

func (m *MockUserService) Login(
	ctx context.Context,
	input services.LoginInput,
) (string, error) {
	return "", nil
}

func setupUserController(service UserServiceInterface) (*UserController, *gin.Engine) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	controller := NewUserController(service)
	router.POST("/register", controller.Register)
	return controller, router
}

func TestRegister(t *testing.T) {
	mockService := &MockUserService{
		RegisterErr: nil,
	}
	_, router := setupUserController(mockService)

	body := `{
    "name": "Vijay",
    "email": "vijay@example.com",
    "password": "password123"
  }`

	req := httptest.NewRequest(
		http.MethodPost,
		"/register",
		strings.NewReader(body),
	)

	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusCreated {
		t.Errorf(
			"expected status %d, got %d",
			http.StatusCreated,
			recorder.Code,
		)
	}
}
