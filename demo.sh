#!/bin/bash

# Trivexer Demo Script
# This script demonstrates how to use Trivexer

set -e

echo "🔍 Trivexer Demo - Container Vulnerability Scanner"
echo "=================================================="
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is required but not installed"
    exit 1
fi

# Build the image if it doesn't exist
if ! docker image inspect trivexer:latest &> /dev/null; then
    echo "🔨 Building Trivexer Docker image..."
    make docker-build
    echo ""
fi

echo "📋 Available commands:"
echo "1. Show help"
echo "2. Scan nginx:alpine (demo)"
echo "3. Scan with custom author"
echo "4. Scan and save to file"
echo ""

read -p "Select option (1-4): " choice

case $choice in
    1)
        echo "📖 Showing help..."
        docker run --rm trivexer:latest --help
        ;;
    2)
        echo "🔍 Scanning nginx:alpine (this may take a few minutes)..."
        echo "Note: This is a demo - the scan will run but may not find vulnerabilities"
        docker run --rm trivexer:latest nginx:alpine
        ;;
    3)
        echo "🔍 Scanning with custom author..."
        docker run --rm trivexer:latest --author "Security Team" nginx:alpine
        ;;
    4)
        echo "🔍 Scanning and saving to file..."
        docker run --rm -v $(pwd):/workspace trivexer:latest --output /workspace/demo-vex.json --author "Demo User" nginx:alpine
        echo "📁 VEX document saved to: demo-vex.json"
        ;;
    *)
        echo "❌ Invalid option"
        exit 1
        ;;
esac

echo ""
echo "✅ Demo complete!"
echo ""
echo "📚 For more information, see the README.md file"
