// Package server is implementation of routing and handling
package server

import (
	"github.com/gin-gonic/gin"
	"github.com/vijay-talsangi/Renewly/controllers"
	db "github.com/vijay-talsangi/Renewly/db/sqlc"
	"github.com/vijay-talsangi/Renewly/middleware"
	"github.com/vijay-talsangi/Renewly/services"
)

func SetupRouter(queries *db.Queries) *gin.Engine {
	userService := services.NewUserService(queries)
	subscriptionService := services.NewSubscriptionService(queries)

	userController := controllers.NewUserController(userService)
	subscriptionController := controllers.NewSubscriptionController(subscriptionService)

	r := gin.Default()

	api := r.Group("/api")
	{
		api.POST("/register", userController.Register)
		api.POST("/login", userController.Login)
		api.POST("/logout", userController.Logout)
	}

	authorized := r.Group("/api")
	authorized.Use(middleware.AuthFromCookie())
	{
		authorized.POST("/subscriptions", subscriptionController.CreateSubscription)
		authorized.GET("/subscriptions", subscriptionController.GetAllSubscriptions)
		authorized.PUT("/subscriptions/:id", subscriptionController.UpdateSubscription)
	}

	return r
}
