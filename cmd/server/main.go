package main

import (
	"armur-codescanner/internal/api"
	"armur-codescanner/internal/redis"
	"armur-codescanner/internal/worker"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/hibiken/asynq"

	_ "armur-codescanner/docs"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title vibescan API
// @version 1.0
// @description This is a code scanner service API.
// @termsOfService http://swagger.io/terms/
// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io
// @license.name MIT
// @license.url https://opensource.org/licenses/MIT
// @BasePath /
func main() {
	router := gin.Default()
	go func() {
		if err := startAsynqWorker(); err != nil {
			log.Fatalf("Failed to start Asynq worker: %v", err)
		}
	}()
	api.RegisterRoutes(router)

	// Swagger route
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "4500"
	}
	if err := router.Run(":" + port); err != nil {
		log.Fatal("Server failed to start: ", err)
	}
}

func startAsynqWorker() error {
	server := asynq.NewServer(
		redis.RedisClientOptions(),
		asynq.Config{
			Concurrency: 10,
		},
	)

	mux := asynq.NewServeMux()
	mux.Handle("scan:repo", &worker.ScanTaskHandler{})

	// Start the Asynq server and process tasks
	return server.Start(mux)
}
