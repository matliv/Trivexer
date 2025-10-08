# Trivexer Makefile

# Variables
BINARY_NAME=trivexer
DOCKER_IMAGE=trivexer
DOCKER_TAG=latest
GO_VERSION=1.21

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build:
	@echo "🔨 Building Trivexer..."
	go build -o $(BINARY_NAME) .
	@echo "✅ Build complete: $(BINARY_NAME)"

# Build for multiple platforms
.PHONY: build-all
build-all:
	@echo "🔨 Building for multiple platforms..."
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME)-linux-amd64 .
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY_NAME)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build -o $(BINARY_NAME)-windows-amd64.exe .
	@echo "✅ Multi-platform build complete"

# Run tests
.PHONY: test
test:
	@echo "🧪 Running tests..."
	go test -v ./...

# Run with coverage
.PHONY: test-coverage
test-coverage:
	@echo "🧪 Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "📊 Coverage report generated: coverage.html"

# Clean build artifacts
.PHONY: clean
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-*
	rm -f coverage.out coverage.html
	@echo "✅ Clean complete"

# Format code
.PHONY: fmt
fmt:
	@echo "🎨 Formatting code..."
	go fmt ./...
	@echo "✅ Format complete"

# Lint code
.PHONY: lint
lint:
	@echo "🔍 Linting code..."
	golangci-lint run
	@echo "✅ Lint complete"

# Install dependencies
.PHONY: deps
deps:
	@echo "📦 Installing dependencies..."
	go mod download
	go mod tidy
	@echo "✅ Dependencies installed"

# Build Docker image
.PHONY: docker-build
docker-build:
	@echo "🐳 Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	@echo "✅ Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)"

# Run Docker container
.PHONY: docker-run
docker-run:
	@echo "🐳 Running Docker container..."
	docker run --rm -it $(DOCKER_IMAGE):$(DOCKER_TAG) --help

# Test Docker image with a sample scan
.PHONY: docker-test
docker-test:
	@echo "🐳 Testing Docker image with nginx:alpine..."
	docker run --rm $(DOCKER_IMAGE):$(DOCKER_TAG) nginx:alpine

# Run debug script
.PHONY: debug
debug:
	@echo "🔍 Running debug script..."
	./debug.sh

# Run test script
.PHONY: test-local
test-local:
	@echo "🧪 Running local test..."
	./test.sh

# Push Docker image
.PHONY: docker-push
docker-push:
	@echo "🐳 Pushing Docker image..."
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	@echo "✅ Docker image pushed"

# Install trivy locally (for development)
.PHONY: install-trivy
install-trivy:
	@echo "📦 Installing Trivy..."
	@if command -v brew >/dev/null 2>&1; then \
		brew install trivy; \
	elif command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get update && sudo apt-get install -y wget apt-transport-https gnupg lsb-release; \
		wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -; \
		echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list; \
		sudo apt-get update && sudo apt-get install -y trivy; \
	else \
		echo "❌ Please install Trivy manually: https://github.com/aquasecurity/trivy#installation"; \
	fi

# Install vexctl locally (for development)
.PHONY: install-vexctl
install-vexctl:
	@echo "📦 Installing Vexctl..."
	@if command -v brew >/dev/null 2>&1; then \
		brew install vexctl; \
	else \
		echo "❌ Please install Vexctl manually: https://github.com/openvex/vexctl#installation"; \
	fi

# Install all development dependencies
.PHONY: install-deps
install-deps: install-trivy install-vexctl
	@echo "✅ Development dependencies installed"

# Development setup
.PHONY: dev-setup
dev-setup: deps install-deps
	@echo "🚀 Development environment ready!"

# Show help
.PHONY: help
help:
	@echo "Trivexer - Available targets:"
	@echo ""
	@echo "  build          - Build the binary"
	@echo "  build-all      - Build for multiple platforms"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage"
	@echo "  test-local     - Run local test script"
	@echo "  debug          - Run debug script"
	@echo "  clean          - Clean build artifacts"
	@echo "  fmt            - Format code"
	@echo "  lint           - Lint code"
	@echo "  deps           - Install Go dependencies"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-run     - Run Docker container"
	@echo "  docker-test    - Test Docker image"
	@echo "  docker-push     - Push Docker image"
	@echo "  install-deps   - Install development dependencies"
	@echo "  dev-setup     - Setup development environment"
	@echo "  help           - Show this help"
