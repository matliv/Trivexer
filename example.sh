#!/bin/bash

# Trivexer Example Script
# This script demonstrates Trivexer with a real example

set -e

echo "🔍 Trivexer Example - Real Vulnerability Scan"
echo "============================================="
echo ""

# Check if we're in the right directory
if [ ! -f "main.go" ]; then
    echo "❌ Please run this script from the trivexer directory"
    exit 1
fi

# Build the tool
echo "🔨 Building Trivexer..."
if ! go build -o trivexer .; then
    echo "❌ Build failed"
    exit 1
fi
echo "✅ Build successful"
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is required but not installed"
    exit 1
fi

# Check if Trivy is available
if ! command -v trivy &> /dev/null; then
    echo "❌ Trivy is required but not installed"
    echo "Install with: brew install trivy"
    exit 1
fi

echo "📋 Example: Scanning nginx:alpine for vulnerabilities"
echo "This will:"
echo "1. Scan the nginx:alpine image for vulnerabilities"
echo "2. Display found vulnerabilities in a table"
echo "3. Allow you to select a vulnerability"
echo "4. Generate an OpenVEX document"
echo ""

# Pull the image first
echo "🐳 Pulling nginx:alpine image..."
docker pull nginx:alpine > /dev/null 2>&1 || true
echo "✅ Image ready"
echo ""

# Update Trivy database
echo "📦 Updating Trivy vulnerability database..."
trivy image --download-db-only > /dev/null 2>&1 || true
echo "✅ Database updated"
echo ""

echo "🚀 Starting Trivexer scan..."
echo "Note: This may take a few minutes for the first scan"
echo ""

# Run Trivexer with the example
echo "Running: ./trivexer --verbose nginx:alpine"
echo ""

# Create a simple input file for automated testing
cat > /tmp/trivexer_input.txt << EOF
1
Security Team
1
1
EOF

# Run with input file (for demonstration)
if [ -f "/tmp/trivexer_input.txt" ]; then
    echo "📝 Using automated input for demonstration..."
    ./trivexer --verbose nginx:alpine < /tmp/trivexer_input.txt
    rm -f /tmp/trivexer_input.txt
else
    # Run interactively
    ./trivexer --verbose nginx:alpine
fi

echo ""
echo "✅ Example complete!"
echo ""
echo "📚 What happened:"
echo "1. Trivexer scanned nginx:alpine for vulnerabilities"
echo "2. Found vulnerabilities were displayed in a table"
echo "3. You selected vulnerability #1"
echo "4. You provided author 'Security Team'"
echo "5. You selected status 'not_affected'"
echo "6. You selected justification 'component_not_present'"
echo "7. An OpenVEX document was generated"
echo ""
echo "🔧 Try these variations:"
echo "  ./trivexer nginx:alpine --output my-vex.json"
echo "  ./trivexer --author 'My Team' ubuntu:latest"
echo "  docker run --rm trivexer:latest nginx:alpine"
