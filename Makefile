# Run all tests
test:
	@echo "Running tests..."
	go test ./... -v

# Run tests with coverage report
cover:
	@echo "Running tests with coverage..."
	go test ./... -coverprofile=coverage.out -covermode=atomic
	go tool cover -func=coverage.out
	@echo "Coverage report written to coverage.out"

# Open HTML coverage report in browser
cover-html: cover
	go tool cover -html=coverage.out -o coverage.html
	@echo "HTML coverage report written to coverage.html"

# Run docker compose up dev
docker-up:
	@echo "Starting Docker containers in dev mode..."
	docker-compose up --build -d

# Stop docker containers
docker-down:
	@echo "Stopping Docker containers..."
	docker-compose down

.PHONY: build run test cover cover-html docker-build docker-up docker-down swagger clean dev prod
