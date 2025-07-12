# Makefile for scep2acme

.PHONY: build test lint vet clean coverage help fmt mod-tidy mod-download mod-verify generate bench binary

# Build the application (depends on preparation steps)
build: fmt generate mod-tidy vet
	go build ./...

# Build binary (depends on preparation steps)
binary: fmt generate mod-tidy vet
	go build -o scep2acme ./cmd/scep2acme

# Run tests with race detection and coverage (depends on build)
test: build
	go test -v -count=1 -race -shuffle=on -coverprofile=coverage.txt ./...

# Format code
fmt:
	gofmt -s -w .

# Run linter (format check, vet, and module operations)
lint: fmt mod-tidy mod-verify vet

# Run go vet (depends on mod operations)
vet: mod-download
	go vet ./...

# Tidy go modules (depends on download)
mod-tidy: mod-download
	go mod tidy

# Download go modules
mod-download:
	go mod download

# Verify go modules (depends on tidy)
mod-verify: mod-tidy
	go mod verify

# Run go generate
generate:
	go generate ./...

# Run benchmarks (depends on build)
bench: build
	go test -v -shuffle=on -run=- -bench=. ./...

# Generate test coverage (depends on build)
coverage: build
	go test -v -count=1 -race -shuffle=on -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean built files
clean:
	rm -f scep2acme
	rm -f coverage.out coverage.html coverage.txt

# Show help
help:
	@echo "Available targets:"
	@echo "  build       - Build all packages"
	@echo "  binary      - Build the scep2acme binary"
	@echo "  test        - Run tests with race detection and coverage"
	@echo "  fmt         - Format code with gofmt"
	@echo "  lint        - Run comprehensive linting (fmt, vet, mod operations)"
	@echo "  vet         - Run go vet"
	@echo "  mod-tidy    - Tidy go modules"
	@echo "  mod-download - Download go modules"
	@echo "  mod-verify  - Verify go modules"
	@echo "  generate    - Run go generate"
	@echo "  bench       - Run benchmarks"
	@echo "  coverage    - Generate test coverage report"
	@echo "  clean       - Clean built files"
	@echo "  help        - Show this help message"