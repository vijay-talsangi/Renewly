// Package controllers handles http requests
package controllers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vijay-talsangi/Renewly/middleware"
	"github.com/vijay-talsangi/Renewly/services"
)

type UserServiceInterface interface {
	Register(
		ctx context.Context,
		input services.RegisterInput,
	) error

	Login(
		ctx context.Context,
		input services.LoginInput,
	) (string, error)
}

type UserController struct {
	userService UserServiceInterface
}

func NewUserController(userService UserServiceInterface) *UserController {
	return &UserController{
		userService: userService,
	}
}

func (uc *UserController) Register(c *gin.Context) {
	var input services.RegisterInput

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := uc.userService.Register(c.Request.Context(), input); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration failed. Email exists."})
		return
	}

	c.IndentedJSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
}

func (uc *UserController) Login(c *gin.Context) {
	var input services.LoginInput

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	token, err := uc.userService.Login(c.Request.Context(), input)
	if err != nil {
		if err == services.ErrInvalidCredentials {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Login failed"})
		}
		return
	}

	middleware.SetAuthCookie(c, token)

	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

func (uc *UserController) Logout(c *gin.Context) {
	middleware.ClearAuthCookie(c)

	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}
