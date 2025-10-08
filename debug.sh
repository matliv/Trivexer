#!/bin/bash

# Trivexer Debug Script
# This script helps debug issues with Trivexer

set -e

echo "🔍 Trivexer Debug Tool"
echo "====================="
echo ""

# Check if we're in the right directory
if [ ! -f "main.go" ]; then
    echo "❌ Please run this script from the trivexer directory"
    exit 1
fi

echo "📋 System Information:"
echo "OS: $(uname -s)"
echo "Architecture: $(uname -m)"
echo "Go version: $(go version 2>/dev/null || echo 'Go not installed')"
echo "Docker version: $(docker --version 2>/dev/null || echo 'Docker not installed')"
echo ""

# Check if trivy is available
echo "🔍 Checking Trivy:"
if command -v trivy &> /dev/null; then
    echo "✅ Trivy is installed: $(trivy --version)"
else
    echo "❌ Trivy is not installed"
    echo "   Install with: brew install trivy"
fi
echo ""

# Check if vexctl is available
echo "🔍 Checking Vexctl:"
if command -v vexctl &> /dev/null; then
    echo "✅ Vexctl is installed: $(vexctl --version)"
else
    echo "❌ Vexctl is not installed"
    echo "   Install with: brew install vexctl"
fi
echo ""

# Test Go build
echo "🔨 Testing Go build:"
if go build -o trivexer-test .; then
    echo "✅ Go build successful"
    rm -f trivexer-test
else
    echo "❌ Go build failed"
    exit 1
fi
echo ""

# Test Docker build
echo "🐳 Testing Docker build:"
if docker build -t trivexer-debug . > /dev/null 2>&1; then
    echo "✅ Docker build successful"
    docker rmi trivexer-debug > /dev/null 2>&1
else
    echo "❌ Docker build failed"
fi
echo ""

# Test with a simple image
echo "🧪 Testing with hello-world image:"
echo "This will test if Trivy can scan a simple image..."
echo ""

if command -v trivy &> /dev/null; then
    echo "Running: trivy image --format json hello-world"
    if timeout 30 trivy image --format json hello-world > /tmp/trivy-test.json 2>&1; then
        echo "✅ Trivy scan successful"
        echo "Output preview:"
        head -20 /tmp/trivy-test.json
        echo ""
        echo "Full output saved to: /tmp/trivy-test.json"
    else
        echo "❌ Trivy scan failed or timed out"
        echo "This might be due to network issues or missing image"
    fi
else
    echo "⚠️  Skipping Trivy test (not installed)"
fi

echo ""
echo "🔧 Debug Information:"
echo "If you're still having issues, try:"
echo "1. Run with verbose flag: ./trivexer --verbose <image>"
echo "2. Check Docker logs: docker logs <container>"
echo "3. Test Trivy directly: trivy image <image>"
echo "4. Check network connectivity"
echo ""
echo "✅ Debug complete!"
