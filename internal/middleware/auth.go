package middleware

import (
	"armur-codescanner/internal/logger"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// APIKeyAuth returns a Gin middleware that enforces Bearer token authentication.
// The expected key is read from the ARMUR_API_KEY environment variable.
// If the env var is empty, authentication is skipped (useful for local dev).
func APIKeyAuth() gin.HandlerFunc {
	apiKey := os.Getenv("ARMUR_API_KEY")
	if apiKey == "" {
		logger.Warn().Msg("ARMUR_API_KEY is not set — API authentication is disabled")
		return func(c *gin.Context) { c.Next() }
	}

	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header must be 'Bearer <token>'"})
			return
		}

		if parts[1] != apiKey {
			logger.Warn().Str("ip", c.ClientIP()).Msg("rejected request with invalid API key")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid API key"})
			return
		}

		c.Next()
	}
}
