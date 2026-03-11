# Minimum test coverage threshold (percentage)
COVERAGE_THRESHOLD ?= 40

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

# Enforce minimum coverage threshold
check-coverage: cover
	@echo "Checking coverage >= $(COVERAGE_THRESHOLD)%..."
	@total=$$(go tool cover -func=coverage.out | grep "^total:" | awk '{print $$3}' | tr -d '%'); \
	echo "Total coverage: $${total}%"; \
	if [ $$(echo "$${total} < $(COVERAGE_THRESHOLD)" | bc -l) -eq 1 ]; then \
		echo "FAIL: coverage $${total}% is below threshold $(COVERAGE_THRESHOLD)%"; \
		exit 1; \
	fi; \
	echo "PASS: coverage $${total}% meets threshold $(COVERAGE_THRESHOLD)%"

# Run integration tests (requires tools installed in PATH)
test-integration:
	@echo "Running integration tests..."
	INTEGRATION_TESTS=1 go test ./... -v -run Integration

# Run linter
lint:
	@echo "Running golangci-lint..."
	golangci-lint run ./...

# Run docker compose up dev
docker-up:
	@echo "Starting Docker containers in dev mode..."
	docker-compose up --build -d

# Stop docker containers
docker-down:
	@echo "Stopping Docker containers..."
	docker-compose down

.PHONY: build run test cover cover-html check-coverage test-integration lint docker-build docker-up docker-down swagger clean dev prod
