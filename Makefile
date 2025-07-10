# Makefile for scep2acme

.PHONY: build test test-integration test-unit lint vet clean coverage help

# Build the application
build:
	go build -o scep2acme ./cmd/scep2acme

# Run unit tests
test:
	go test -v ./...

# Run unit tests only
test-unit:
	go test -v ./...

# Run integration tests
test-integration:
	SCEP2ACME_INTEGRATION_TESTS=1 go test -v -tags=integration ./...

# Run all tests (unit + integration)
test-all: test test-integration

# Run linter (using go vet and static analysis)
lint:
	go fmt ./...
	go vet ./...

# Run go vet
vet:
	go vet ./...

# Generate test coverage
coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Generate test coverage including integration tests
coverage-all:
	go test -v -coverprofile=coverage.out ./...
	SCEP2ACME_INTEGRATION_TESTS=1 go test -v -tags=integration -coverprofile=coverage-integration.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean built files
clean:
	rm -f scep2acme
	rm -f coverage.out coverage.html coverage-integration.out

# Docker compose for integration tests
docker-up:
	cd cmd/scep2acme/testdata && docker-compose up -d

# Stop docker compose
docker-down:
	cd cmd/scep2acme/testdata && docker-compose down

# Show help
help:
	@echo "Available targets:"
	@echo "  build           - Build the application"
	@echo "  test            - Run unit tests"
	@echo "  test-unit       - Run unit tests only"
	@echo "  test-integration - Run integration tests"
	@echo "  test-all        - Run all tests (unit + integration)"
	@echo "  lint            - Run linter (go fmt and go vet)"
	@echo "  vet             - Run go vet"
	@echo "  coverage        - Generate test coverage report"
	@echo "  coverage-all    - Generate test coverage with integration tests"
	@echo "  docker-up       - Start Docker containers for integration tests"
	@echo "  docker-down     - Stop Docker containers for integration tests"
	@echo "  clean           - Clean built files"
	@echo "  help            - Show this help message"