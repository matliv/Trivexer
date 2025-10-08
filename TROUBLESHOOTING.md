# Trivexer Troubleshooting Guide

This guide helps you resolve common issues with Trivexer.

## Common Issues and Solutions

### 1. "Invalid selection" errors when selecting vulnerabilities

**Symptoms:**
- Tool shows vulnerabilities but keeps saying "Invalid selection"
- User input is not being accepted properly

**Solutions:**
1. **Check input format**: Make sure you're entering a number (1, 2, 3, etc.) not text
2. **Use verbose mode**: Run with `--verbose` to see detailed scan information
3. **Check for empty vulnerabilities**: The tool might not be parsing Trivy output correctly

**Debug steps:**
```bash
# Run with verbose output to see what's happening
./trivexer --verbose nginx:alpine

# Test Trivy directly to see if it's working
trivy image --format json nginx:alpine

# Check if the image exists locally
docker images | grep nginx
```

### 2. Trivy scan fails or times out

**Symptoms:**
- "trivy scan failed" error
- Long delays with no output
- Network-related errors

**Solutions:**
1. **Check network connectivity**: Trivy needs internet access to download vulnerability databases
2. **Update Trivy database**: Run `trivy image --download-db-only`
3. **Use a different image**: Try with a well-known image like `nginx:alpine`
4. **Check Docker**: Ensure Docker is running and the image exists

**Debug steps:**
```bash
# Update Trivy database
trivy image --download-db-only

# Test with a simple image
trivy image alpine:latest

# Check Trivy version
trivy --version
```

### 3. No vulnerabilities found

**Symptoms:**
- Tool says "No vulnerabilities found" for images that should have vulnerabilities
- Empty vulnerability list

**Solutions:**
1. **Check image**: Some minimal images (like hello-world) have no vulnerabilities
2. **Try different image**: Use `nginx:alpine`, `ubuntu:latest`, or `node:alpine`
3. **Check Trivy severity**: Ensure you're scanning with appropriate severity levels
4. **Update vulnerability database**: Run `trivy image --download-db-only`

### 4. Docker-related issues

**Symptoms:**
- "Docker not found" errors
- Permission denied errors
- Container fails to start

**Solutions:**
1. **Install Docker**: Ensure Docker is installed and running
2. **Check permissions**: Make sure your user can run Docker
3. **Pull image first**: Run `docker pull <image>` before scanning
4. **Use local binary**: Build and run locally instead of using Docker

### 5. VEX document generation fails

**Symptoms:**
- "Failed to generate VEX document" error
- Missing fields in generated VEX
- Invalid JSON output

**Solutions:**
1. **Check Vexctl**: Ensure vexctl is installed and working
2. **Verify input**: Make sure you're providing valid author and justification
3. **Check output format**: Verify the generated JSON is valid
4. **Use verbose mode**: Run with `--verbose` to see detailed error messages

## Debug Commands

### Run debug script
```bash
make debug
# or
./debug.sh
```

### Test with verbose output
```bash
./trivexer --verbose nginx:alpine
```

### Test Trivy directly
```bash
# Test basic scan
trivy image nginx:alpine

# Test JSON output
trivy image --format json nginx:alpine

# Test with specific severity
trivy image --severity CRITICAL,HIGH nginx:alpine
```

### Test Vexctl
```bash
# Check vexctl version
vexctl version

# Test vexctl generate
vexctl generate --help
```

## Performance Issues

### Slow scans
- **Cause**: Large images or slow network
- **Solution**: Use smaller images or wait for completion

### Memory issues
- **Cause**: Large vulnerability databases
- **Solution**: Ensure sufficient RAM (4GB+ recommended)

### Timeout issues
- **Cause**: Network timeouts or large images
- **Solution**: Use `timeout` command or increase timeout values

## Network Issues

### Corporate networks
- **Issue**: Firewall blocking Trivy database downloads
- **Solution**: Configure proxy or use offline mode

### Slow downloads
- **Issue**: Vulnerability database downloads are slow
- **Solution**: Pre-download databases with `trivy image --download-db-only`

## Getting Help

1. **Run debug script**: `./debug.sh`
2. **Check logs**: Look for error messages in verbose output
3. **Test components**: Verify Trivy and Vexctl work independently
4. **Check system**: Ensure all dependencies are installed

## Example Working Commands

```bash
# Basic scan
./trivexer nginx:alpine

# With verbose output
./trivexer --verbose nginx:alpine

# Save to file
./trivexer --output vex.json --author "Security Team" nginx:alpine

# Using Docker
docker run --rm trivexer:latest nginx:alpine

# Test with different images
./trivexer ubuntu:latest
./trivexer node:alpine
./trivexer python:3.9
```

## System Requirements

- **Go**: 1.21 or later
- **Docker**: Latest version
- **Trivy**: 0.50 or later
- **Vexctl**: Latest version
- **RAM**: 4GB+ recommended
- **Disk**: 2GB+ for vulnerability databases
- **Network**: Internet access for database updates
