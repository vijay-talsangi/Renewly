package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vijay-talsangi/Renewly/services"
)

type UserController struct {
	userService *services.UserService
}

func NewUserController(userService *services.UserService) *UserController {
	return &UserController{
		userService: userService,
	}
}

func (uc *UserController) RegisterRoutes(r *gin.Engine) {
	user := r.Group("/user")
	user.GET("/", uc.getUser)
}

func (uc *UserController) getUser(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, gin.H{
		"message": uc.userService.GetUser(),
	})
}
