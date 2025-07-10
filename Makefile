# Makefile for scep2acme

.PHONY: build test lint vet clean coverage help

# Build the application
build:
	go build -o scep2acme ./cmd/scep2acme

# Run tests
test:
	go test -v ./...

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

# Clean built files
clean:
	rm -f scep2acme
	rm -f coverage.out coverage.html

# Show help
help:
	@echo "Available targets:"
	@echo "  build     - Build the application"
	@echo "  test      - Run tests"
	@echo "  lint      - Run linter (go fmt and go vet)"
	@echo "  vet       - Run go vet"
	@echo "  coverage  - Generate test coverage report"
	@echo "  clean     - Clean built files"
	@echo "  help      - Show this help message"