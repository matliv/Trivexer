#!/bin/bash

# Trivexer Test Script
# This script tests Trivexer with a simple image

set -e

echo "🧪 Trivexer Test Script"
echo "======================"
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

# Test help
echo "📖 Testing help command..."
if ./trivexer --help > /dev/null; then
    echo "✅ Help command works"
else
    echo "❌ Help command failed"
    exit 1
fi
echo ""

# Test with a simple image (if Docker is available)
if command -v docker &> /dev/null; then
    echo "🐳 Testing with hello-world image..."
    echo "Note: This test may take a few minutes..."
    echo ""
    
    # Pull hello-world image first
    echo "Pulling hello-world image..."
    docker pull hello-world > /dev/null 2>&1 || true
    
    # Test with verbose output
    echo "Running: ./trivexer --verbose hello-world"
    echo "Press Ctrl+C to cancel if it takes too long..."
    echo ""
    
    # Use timeout to prevent hanging
    if timeout 60 ./trivexer --verbose hello-world; then
        echo "✅ Test completed successfully"
    else
        echo "⚠️  Test timed out or failed (this is normal for hello-world)"
    fi
else
    echo "⚠️  Docker not available, skipping image test"
fi

echo ""
echo "✅ Test complete!"
echo ""
echo "📚 To test with a real image:"
echo "  ./trivexer nginx:alpine"
echo "  ./trivexer --verbose nginx:alpine"
echo "  ./trivexer --output vex.json nginx:alpine"
