package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const RequestIDHeader = "X-Request-ID"

// CorrelationID adds a unique request ID to every request/response.
// If the caller provides X-Request-ID, it is reused; otherwise a new UUID is generated.
func CorrelationID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader(RequestIDHeader)
		if requestID == "" {
			requestID = uuid.New().String()
		}

		c.Set("request_id", requestID)
		c.Writer.Header().Set(RequestIDHeader, requestID)
		c.Next()
	}
}
