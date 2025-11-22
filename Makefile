.PHONY: help test test-verbose test-coverage test-race lint fmt vet tidy clean deps check build \
        client-install client client-build client-lint client-clean \
        examples dev all ci

# Default target
.DEFAULT_GOAL := help

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Coverage parameters
COVERAGE_DIR=coverage
COVERAGE_PROFILE=$(COVERAGE_DIR)/coverage.out
COVERAGE_HTML=$(COVERAGE_DIR)/coverage.html

# Example directories
BUILT_CLIENT=client/dist/nopasswords.js
EXAMPLES=webauthn-demo srp-demo

## help: Display this help message
help:
	@echo 'Usage:'
	@echo '  make <target>'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## test: Run all tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

## test-race: Run tests with race detector
test-race:
	@echo "Running tests with race detector..."
	$(GOTEST) -v -race ./...

## test-short: Run tests without long-running tests
test-short:
	@echo "Running short tests..."
	$(GOTEST) -short -v ./...

## test-coverage: Run tests with coverage report
test-coverage:
	@echo "Running tests with coverage..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -coverprofile=$(COVERAGE_PROFILE) -covermode=atomic ./...
	$(GOCMD) tool cover -html=$(COVERAGE_PROFILE) -o $(COVERAGE_HTML)
	@echo "Coverage report generated: $(COVERAGE_HTML)"
	@$(GOCMD) tool cover -func=$(COVERAGE_PROFILE) | tail -n 1

## lint: Run golangci-lint
lint:
	@echo "Running golangci-lint..."
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed. Install with: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin" && exit 1)
	golangci-lint run ./... || true

## fmt: Format all Go files
fmt:
	@echo "Formatting Go files..."
	$(GOFMT) ./...

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GOVET) ./...

## tidy: Tidy go.mod
tidy:
	@echo "Tidying go.mod..."
	$(GOMOD) tidy

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download

## check: Run fmt, vet, lint, and test
check: fmt vet lint test
	@echo "All checks passed!"

## build: Build all packages
build:
	@echo "Building all packages..."
	$(GOBUILD) ./...

## clean: Clean build artifacts and coverage reports
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(COVERAGE_DIR)
	@echo "Clean complete!"

## client-install: Install client dependencies
client-install:
	@echo "Installing client dependencies..."
	cd client && npm install && cd ..

## client-build: Build client library
client-build:
	@echo "Building client library..."
	cd client && npm run build && cd ..

## client: Build client library and populate example directories
client: client-clean client-install client-build
	@for ex in $(EXAMPLES); do \
		cp ${BUILT_CLIENT}.map cmd/examples/$$ex/static/nopasswords.min.js.map; \
		cp ${BUILT_CLIENT} cmd/examples/$$ex/static/nopasswords.min.js; \
	done

## client-lint: Lint client code
client-lint:
	@echo "Linting client code..."
	if [ -f "client/package.json" ] && grep -q "\"lint\"" "client/package.json"; then \
		echo "Linting client..."; \
		cd client && npm run lint && cd ..; \
	else \
		echo "No lint script in client, skipping..."; \
	fi; \

## client-clean: Clean client build artifacts
client-clean:
	@echo "Cleaning client artifacts..."
	rm -rf client/dist client/node_modules client/package-lock.json; \

## examples: Build all examples
examples: client
	@echo "Building examples..."
	@for ex in $(EXAMPLES); do \
		echo "Building $$ex..."; \
		cd cmd/examples/$$ex && $(GOBUILD) -o $$(basename cmd/examples/$$ex) . && cd ../../..; \
	done

## dev: Start development environment (install deps, build clients)
dev: deps client-install client-build
	@echo "Development environment ready!"
	@echo "Run 'make examples' to build example applications"
	@echo "Run 'make test' to run tests"
	@echo "Run 'make lint' to check code quality"

## all: Run complete build pipeline (format, lint, test, build)
all: fmt vet lint test build client-build examples
	@echo "Complete build pipeline successful!"

## ci: Run CI checks (optimized for GitHub Actions)
ci: deps lint test-race test-coverage build client-build examples
	@echo "CI checks complete!"
