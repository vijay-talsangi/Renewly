// Package server is implementation of routing and handling
package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vijay-talsangi/Renewly/controllers"
	db "github.com/vijay-talsangi/Renewly/db/sqlc"
	renewlymcp "github.com/vijay-talsangi/Renewly/mcp"
	"github.com/vijay-talsangi/Renewly/middleware"
	renewlyoauth "github.com/vijay-talsangi/Renewly/oauth"
	"github.com/vijay-talsangi/Renewly/services"
)

func SetupRouter(queries *db.Queries) *gin.Engine {
	r, err := setupRouter(queries, nil)
	if err != nil {
		panic(err)
	}
	return r
}

func SetupRouterWithPool(queries *db.Queries, pool *pgxpool.Pool) (*gin.Engine, error) {
	return setupRouter(queries, pool)
}

func setupRouter(queries *db.Queries, pool *pgxpool.Pool) (*gin.Engine, error) {
	userService := services.NewUserService(queries)
	subscriptionService := services.NewSubscriptionService(queries)

	userController := controllers.NewUserController(userService)
	subscriptionController := controllers.NewSubscriptionController(subscriptionService)

	var oauthHandler http.Handler
	var oauthServer *renewlyoauth.Server
	var err error
	if pool != nil {
		oauthServer, err = renewlyoauth.NewServer(pool)
		if err != nil {
			return nil, err
		}
		oauthHandler = oauthServer.RegisterHandler()
	}
	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	})

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
	mcpHandler := renewlymcp.NewHTTPHandler(queries)

	if oauthHandler != nil {
		r.POST("/oauth/register", gin.WrapH(oauthHandler))
		r.GET("/oauth/authorize", middleware.AuthFromCookie(), gin.WrapH(oauthHandler))
		r.POST("/oauth/consent", middleware.AuthFromCookie(), gin.WrapH(oauthHandler))
		r.POST("/oauth/token", gin.WrapH(oauthHandler))
		r.POST("/oauth/revoke", gin.WrapH(oauthHandler))
		r.GET("/.well-known/oauth-authorization-server", gin.WrapH(oauthHandler))
		r.GET("/.well-known/oauth-protected-resource/mcp", gin.WrapH(oauthHandler))
	}
	if oauthServer != nil {
		r.Any("/mcp", oauthServer.MCPAuthMiddleware(), gin.WrapH(mcpHandler))
	} else {
		// SetupRouter without a pool remains available to legacy tests.
		r.Any("/mcp", middleware.AuthFromCookie(), gin.WrapH(mcpHandler))
	}

	return r, nil
}
