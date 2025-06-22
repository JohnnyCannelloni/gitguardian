# GitGuardian Makefile
.PHONY: build install test clean lint fmt vet run help hooks-install hooks-uninstall release

# Variables
BINARY_NAME=gitguardian
VERSION?=1.0.0
BUILD_DIR=build
PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64
LDFLAGS=-ldflags "-X main.version=$(VERSION) -s -w"

# Default target
all: build

# Build the binary
build:
	@echo "🔨 Building GitGuardian..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./

# Install the binary to GOPATH/bin
install: build
	@echo "📦 Installing GitGuardian..."
	go install $(LDFLAGS) ./

# Install to system PATH (requires sudo on Unix)
install-system: build
	@echo "🌐 Installing GitGuardian to system PATH..."
ifeq ($(OS),Windows_NT)
	@echo "Please copy $(BUILD_DIR)/$(BINARY_NAME).exe to a directory in your PATH"
else
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	@echo "✅ GitGuardian installed to /usr/local/bin/"
endif

# Run tests
test:
	@echo "🧪 Running tests..."
	go test -v ./...

# Run tests with coverage
test-coverage:
	@echo "📊 Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Format code
fmt:
	@echo "🎨 Formatting code..."
	go fmt ./...

# Run go vet
vet:
	@echo "🔍 Running go vet..."
	go vet ./...

# Run linter (requires golangci-lint)
lint:
	@echo "🔍 Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found. Install it with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Run the application
run:
	@echo "🚀 Running GitGuardian..."
	go run . -path .

# Install Git hooks in current repository
hooks-install: build
	@echo "🪝 Installing Git hooks..."
	./$(BUILD_DIR)/$(BINARY_NAME) -install-hooks

# Uninstall Git hooks from current repository
hooks-uninstall:
	@echo "🗑️  Uninstalling Git hooks..."
	@if [ -f $(BUILD_DIR)/$(BINARY_NAME) ]; then \
		./$(BUILD_DIR)/$(BINARY_NAME) -uninstall-hooks; \
	else \
		echo "Binary not found. Run 'make build' first."; \
	fi

# Build for multiple platforms
release:
	@echo "🚀 Building release binaries..."
	@mkdir -p $(BUILD_DIR)/release
	@for platform in $(PLATFORMS); do \
		OS=$$(echo $$platform | cut -d'/' -f1); \
		ARCH=$$(echo $$platform | cut -d'/' -f2); \
		echo "Building for $$OS/$$ARCH..."; \
		GOOS=$$OS GOARCH=$$ARCH go build $(LDFLAGS) -o $(BUILD_DIR)/release/$(BINARY_NAME)-$$OS-$$ARCH ./; \
		if [ "$$OS" = "windows" ]; then \
			mv $(BUILD_DIR)/release/$(BINARY_NAME)-$$OS-$$ARCH $(BUILD_DIR)/release/$(BINARY_NAME)-$$OS-$$ARCH.exe; \
		fi; \
	done
	@echo "✅ Release binaries built in $(BUILD_DIR)/release/"

# Create distribution packages
dist: release
	@echo "📦 Creating distribution packages..."
	@cd $(BUILD_DIR)/release && \
	for file in *; do \
		if [[ $$file == *"windows"* ]]; then \
			zip "$$file.zip" "$$file"; \
		else \
			tar -czf "$$file.tar.gz" "$$file"; \
		fi; \
	done
	@echo "✅ Distribution packages created in $(BUILD_DIR)/release/"

# Generate default configuration file
config:
	@echo "⚙️  Generating default configuration..."
	@if [ -f $(BUILD_DIR)/$(BINARY_NAME) ]; then \
		./$(BUILD_DIR)/$(BINARY_NAME) -generate-config > .gitguardian.json; \
		echo "✅ Default configuration saved to .gitguardian.json"; \
	else \
		echo "Binary not found. Run 'make build' first."; \
	fi

# Check dependencies for vulnerabilities (requires 'govulncheck')
security-check:
	@echo "🛡️  Checking for security vulnerabilities..."
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not found. Install it with: go install golang.org/x/vuln/cmd/govulncheck@latest"; \
	fi

# Benchmark performance
benchmark:
	@echo "⚡ Running benchmarks..."
	go test -bench=. -benchmem ./...

# Update dependencies
deps-update:
	@echo "📦 Updating dependencies..."
	go get -u ./...
	go mod tidy

# Verify dependencies
deps-verify:
	@echo "🔐 Verifying dependencies..."
	go mod verify

# Development setup
dev-setup:
	@echo "🛠️  Setting up development environment..."
	@echo "Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	@echo "✅ Development environment setup complete"

# Docker build
docker-build:
	@echo "🐳 Building Docker image..."
	docker build -t gitguardian:$(VERSION) .
	docker tag gitguardian:$(VERSION) gitguardian:latest

# Docker run
docker-run:
	@echo "🐳 Running GitGuardian in Docker..."
	docker run --rm -v $(PWD):/app gitguardian:latest

# Display help
help:
	@echo "GitGuardian - Security Scanner for Git Repositories"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build            Build the binary"
	@echo "  install          Install to GOPATH/bin"
	@echo "  install-system   Install to system PATH (/usr/local/bin)"
	@echo "  test             Run tests"
	@echo "  test-coverage    Run tests with coverage report"
	@echo "  fmt              Format code"
	@echo "  vet              Run go vet"
	@echo "  lint             Run linter"
	@echo "  clean            Clean build artifacts"
	@echo "  run              Run the application"
	@echo "  hooks-install    Install Git hooks in current repo"
	@echo "  hooks-uninstall  Uninstall Git hooks"
	@echo "  release          Build for multiple platforms"
	@echo "  dist             Create distribution packages"
	@echo "  config           Generate default configuration"
	@echo "  security-check   Check for security vulnerabilities"
	@echo "  benchmark        Run performance benchmarks"
	@echo "  deps-update      Update dependencies"
	@echo "  deps-verify      Verify dependencies"
	@echo "  dev-setup        Setup development environment"
	@echo "  docker-build     Build Docker image"
	@echo "  docker-run       Run in Docker"
	@echo "  help             Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION          Version to build (default: 1.0.0)"
	@echo ""
	@echo "Examples:"
	@echo "  make build                    # Build the binary"
	@echo "  make install                  # Install to GOPATH"
	@echo "  make hooks-install            # Install Git hooks"
	@echo "  make release VERSION=1.1.0   # Build v1.1.0 for all platforms"