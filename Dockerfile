# Build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o trivexer .

# Runtime stage
FROM alpine:3.22

# Install runtime dependencies
RUN apk --no-cache add \
    ca-certificates \
    curl \
    bash \
    git

# Install trivy v0.67.0 (latest 2025 version - released September 2025)
# Pinned to specific version for reproducibility
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.67.0

# Install vexctl v0.2.0 (pinned version for reproducibility)
# Pinned to specific version to ensure consistent VEX generation
RUN curl -L https://github.com/openvex/vexctl/releases/download/v0.2.0/vexctl_linux_amd64 -o /usr/local/bin/vexctl && \
    chmod +x /usr/local/bin/vexctl

# Copy the binary from builder stage
COPY --from=builder /app/trivexer /usr/local/bin/trivexer

# Set executable permissions
RUN chmod +x /usr/local/bin/trivexer

# Create non-root user
RUN addgroup -g 1001 -S trivexer && \
    adduser -u 1001 -S trivexer -G trivexer

# Switch to non-root user
USER trivexer

# Set working directory
WORKDIR /workspace

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD trivexer --help > /dev/null || exit 1

# Default command
ENTRYPOINT ["trivexer"]
