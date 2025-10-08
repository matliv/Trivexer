# Trivexer 🔍

**Trivexer** is a Go-based container vulnerability scanner that generates OpenVEX documents. It scans container images using Trivy, allows interactive vulnerability selection, and creates compliant OpenVEX documents following the [OpenVEX specification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md).

## Features

- 🔍 **Container Image Scanning**: Uses Trivy to scan container images for vulnerabilities
- 📋 **Interactive Vulnerability Selection**: Lists vulnerabilities with severity indicators and allows user selection
- 📄 **OpenVEX Document Generation**: Creates compliant OpenVEX documents with proper product/subcomponent structure
- 🐳 **Containerized**: Available as a Docker image for easy deployment
- ⚡ **Fast**: Built in Go for optimal performance

## Quick Start

### Using Docker (Recommended)

```bash
# Scan an image and generate VEX document
docker run --rm -it trivexer:latest nginx:alpine

# Save VEX document to file
docker run --rm -it -v $(pwd):/workspace trivexer:latest nginx:alpine --output /workspace/vex.json

# With custom author
docker run --rm -it trivexer:latest nginx:alpine --author "Security Team"
```

### Building from Source

```bash
# Clone and build
git clone <repository>
cd trivexer
make dev-setup
make build

# Run
./trivexer nginx:alpine
```

## Installation

### Prerequisites

- **Trivy v0.67.0**: For vulnerability scanning (latest 2025 version)
- **Vexctl v0.2.0**: For VEX document generation (pinned for reproducibility)
- **Go 1.25**: For building from source (latest 2025 version)

### Docker Installation

```bash
# Build the image
make docker-build

# Or pull from registry (when available)
docker pull trivexer:latest
```

### Local Installation

```bash
# Install dependencies
make install-deps

# Build
make build

# Install globally
sudo cp trivexer /usr/local/bin/
```

## Usage

### Basic Usage

```bash
# Scan a container image
trivexer nginx:alpine

# With verbose output
trivexer --verbose nginx:alpine

# Save VEX document to file
trivexer --output vex.json nginx:alpine

# Specify author
trivexer --author "Security Team" nginx:alpine
```

### Command Line Options

- `image`: Container image to scan (required)
- `--verbose, -v`: Enable verbose output
- `--output, -o`: Output file for VEX document
- `--author`: Author for VEX document

## Workflow

1. **Image Scanning**: Trivexer scans the specified container image using Trivy
2. **Vulnerability Listing**: All found vulnerabilities are displayed in a formatted table
3. **Vulnerability Selection**: User selects a specific vulnerability from the list
4. **Status Selection**: User chooses the VEX status (not_affected, affected, fixed, under_investigation)
5. **Justification/Action Statement**: Based on status, user provides appropriate justification
6. **VEX Generation**: OpenVEX document is generated with proper product/subcomponent structure

## OpenVEX Document Structure

Trivexer generates OpenVEX documents that follow the [OpenVEX specification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md):

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/public/vex-...",
  "author": "Your Organization",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2023-1234"
      },
      "timestamp": "2024-01-15T10:30:00Z",
      "products": [
        {
          "@id": "pkg:oci/nginx:alpine",
          "subcomponents": [
            {
              "@id": "pkg:generic/libssl@1.1.1f"
            }
          ]
        }
      ],
      "status": "not_affected",
      "justification": "component_not_present"
    }
  ]
}
```

### Status and Justifications

#### For `not_affected` status, choose from:
- `component_not_present`
- `vulnerable_code_not_present`
- `vulnerable_code_not_in_execute_path`
- `vulnerable_code_cannot_be_controlled_by_adversary`
- `inline_mitigations_already_exist`

#### For `affected` status:
- Provide an `action_statement` describing the impact and recommended actions

## Development

### Setup Development Environment

```bash
# Install dependencies
make dev-setup

# Run tests
make test

# Run with coverage
make test-coverage

# Format code
make fmt

# Lint code
make lint
```

### Building

```bash
# Build binary
make build

# Build for all platforms
make build-all

# Build Docker image
make docker-build
```

### Testing

```bash
# Test locally
make test

# Test Docker image
make docker-test
```

## Docker Usage

### Build and Run

```bash
# Build the image
make docker-build

# Run with help
make docker-run

# Test with nginx
make docker-test
```

### Advanced Docker Usage

```bash
# Scan with volume mount for output
docker run --rm -it -v $(pwd):/workspace trivexer:latest nginx:alpine --output /workspace/vex.json

# Interactive mode with custom author
docker run --rm -it trivexer:latest nginx:alpine --author "Security Team" --verbose
```

## Examples

### Example 1: Basic Scan

```bash
$ trivexer nginx:alpine

🔍 Trivexer - Container Vulnerability Scanner
==================================================

✅ Trivy is available

📦 Scanning image: nginx:alpine
[INFO] Scan completed successfully

🔍 Found 15 vulnerabilities:
========================================================================================================================
#   ID                   Package             Severity Title                                                
========================================================================================================================
1   CVE-2023-1234        libssl1.1           🔴 CRITICAL OpenSSL vulnerability in SSL/TLS implementation
2   CVE-2023-5678        libc6               🟠 HIGH     Buffer overflow in glibc
...

Select a vulnerability (1-15, or 'q' to quit): 1

✅ Selected vulnerability: CVE-2023-1234
   Package: libssl1.1 1.1.1f-1ubuntu2.18
   Severity: CRITICAL
   Title: OpenSSL vulnerability in SSL/TLS implementation

📋 Vulnerability Details:
============================================================
ID: CVE-2023-1234
Package: libssl1.1 1.1.1f-1ubuntu2.18
Severity: CRITICAL
Title: OpenSSL vulnerability in SSL/TLS implementation
Description: A critical vulnerability in OpenSSL that could allow...
References:
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234
  - https://nvd.nist.gov/vuln/detail/CVE-2023-1234
============================================================

Enter author for VEX document: Security Team

📋 Select VEX status:
1. not_affected
2. affected
3. fixed
4. under_investigation
Enter status (1-4): 1

📋 Select justification for 'not_affected' status:
1. component_not_present
2. vulnerable_code_not_present
3. vulnerable_code_not_in_execute_path
4. vulnerable_code_cannot_be_controlled_by_adversary
5. inline_mitigations_already_exist
Enter justification (1-5): 1

📄 Generated VEX Document:
----------------------------------------
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/public/vex-1705312200",
  "author": "Security Team",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2023-1234"
      },
      "timestamp": "2024-01-15T10:30:00Z",
      "products": [
        {
          "@id": "pkg:oci/nginx:alpine",
          "subcomponents": [
            {
              "@id": "pkg:generic/libssl1.1@1.1.1f-1ubuntu2.18"
            }
          ]
        }
      ],
      "status": "not_affected",
      "justification": "component_not_present"
    }
  ]
}
```

## Troubleshooting

### Quick Debug

Run the debug script to check your system:
```bash
make debug
# or
./debug.sh
```

### Common Issues

1. **"Invalid selection" errors**: 
   - Make sure you're entering numbers (1, 2, 3) not text
   - Use `--verbose` flag to see detailed scan information
   - Check if vulnerabilities were actually found

2. **Trivy scan fails**:
   - Ensure internet connectivity for database downloads
   - Update Trivy database: `trivy image --download-db-only`
   - Try with a different image like `nginx:alpine`

3. **No vulnerabilities found**:
   - Some minimal images (like hello-world) have no vulnerabilities
   - Try `nginx:alpine`, `ubuntu:latest`, or `node:alpine`
   - Check Trivy directly: `trivy image nginx:alpine`

4. **Docker issues**:
   - Ensure Docker is running
   - Pull image first: `docker pull nginx:alpine`
   - Check permissions for Docker access

### Debug Commands

```bash
# Run with verbose output
./trivexer --verbose nginx:alpine

# Test Trivy directly
trivy image --format json nginx:alpine

# Test with different images
./trivexer ubuntu:latest
./trivexer node:alpine

# Run example script
./example.sh
```

For detailed troubleshooting, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Security Considerations

- This tool downloads and analyzes container images
- Ensure you trust the source of container images before scanning
- VEX documents should be reviewed before being used in production
- Consider the security implications of the justifications provided in VEX documents

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Trivy](https://github.com/aquasecurity/trivy) for vulnerability scanning
- [OpenVEX](https://github.com/openvex/spec) for the VEX specification
- [Vexctl](https://github.com/openvex/vexctl) for VEX document generation
