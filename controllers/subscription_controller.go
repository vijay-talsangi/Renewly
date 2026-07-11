package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vijay-talsangi/Renewly/middleware"
	"github.com/vijay-talsangi/Renewly/services"
)

type SubscriptionController struct {
	ss *services.SubscriptionService
}

func NewSubscriptionController(ss *services.SubscriptionService) *SubscriptionController {
	return &SubscriptionController{ss: ss}
}

func (sc *SubscriptionController) CreateSubscription(c *gin.Context) {
	userIDValue, exists := c.Get(middleware.ContextUserIDKey)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userID, ok := userIDValue.(int64)
	if !ok || userID <= 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var input services.CreateSubscriptionInput
	input.UserID = userID

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	input.UserID = userID

	if err := sc.ss.CreateSubscription(c.Request.Context(), input); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create subscription"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Subscription created successfully"})
}

func (sc *SubscriptionController) GetAllSubscriptions(c *gin.Context) {
	userIDValue, exists := c.Get(middleware.ContextUserIDKey)

	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	userID, ok := userIDValue.(int64)
	if !ok || userID <= 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	subscriptions, err := sc.ss.GetAllSubscriptions(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve subscriptions"})
		return
	}

	c.JSON(http.StatusOK, subscriptions)
}
