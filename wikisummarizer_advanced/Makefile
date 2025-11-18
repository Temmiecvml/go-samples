.PHONY: all build test test-unit test-integration test-coverage clean run deps lint help

all: test build

build:
	go build -o bin/wikisummarizer ./cmd/server

run:
	go run ./cmd/server/main.go

test: test-unit

test-unit:
	go test -v -race -timeout 30s ./...

test-integration:
	go test -v -race -tags=integration -timeout 60s ./tests/integration/...

test-coverage:
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-fuzz:
	go test -fuzz=FuzzHashPassword -fuzztime=30s ./internal/auth
	go test -fuzz=FuzzArticleName -fuzztime=30s ./internal/db

test-bench:
	go test -bench=. -benchmem ./...

clean:
	rm -rf bin/ coverage.out coverage.html logs/ data/ tmp/

lint:
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run

deps:
	go mod download
	go mod tidy
	go mod verify

fmt:
	go fmt ./...
	gofmt -s -w .

vet:
	go vet ./...

install-tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

check: fmt vet lint test

help:
	@echo "Available targets:"
	@echo "  build            - Build the application"
	@echo "  run              - Run the application"
	@echo "  test             - Run all unit tests"
	@echo "  test-unit        - Run unit tests only"
	@echo "  test-integration - Run integration tests"
	@echo "  test-coverage    - Run tests with coverage report"
	@echo "  test-fuzz        - Run fuzz tests"
	@echo "  test-bench       - Run benchmark tests"
	@echo "  clean            - Clean build artifacts"
	@echo "  lint             - Run linter"
	@echo "  deps             - Download and verify dependencies"
	@echo "  fmt              - Format code"
	@echo "  vet              - Run go vet"
	@echo "  check            - Run fmt, vet, lint, and test"
	@echo "  install-tools    - Install development tools"
