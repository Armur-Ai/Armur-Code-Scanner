package api

import (
	"armur-codescanner/internal/middleware"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine) {
	// Apply global middleware
	r.Use(middleware.CorrelationID())
	r.Use(middleware.RequestSizeLimit(middleware.MaxUploadSize))

	// Health endpoints (no auth required)
	r.GET("/health", HealthCheck)
	r.GET("/ready", ReadinessCheck)

	api := r.Group("/api/v1")
	api.Use(middleware.RateLimiter(60, 10)) // 60 req/min, burst of 10
	api.Use(middleware.APIKeyAuth())
	{
		// Scan routes
		api.POST("/scan/repo", ScanHandler)
		api.POST("/advanced-scan/repo", AdvancedScanResult)
		api.POST("/scan/file", ScanFile)
		api.POST("/scan/local", ScanLocalHandler)

		// Status
		api.GET("/status/:task_id", TaskStatus)

		// Progress (SSE stream)
		api.GET("/progress/:task_id", TaskProgress)

		// Cancel an in-progress scan
		api.DELETE("/scan/:task_id", CancelScan)

		// Batch scanning
		api.POST("/scan/batch", BatchScan)

		// Reports
		api.GET("/reports/owasp/:task_id", TaskOwasp)
		api.GET("/reports/sans/:task_id", TaskSans)
	}
}
