# scep2acme

[![CI](https://github.com/drawks/scep2acme/workflows/CI/badge.svg)](https://github.com/drawks/scep2acme/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/drawks/scep2acme/branch/main/graph/badge.svg)](https://codecov.io/gh/drawks/scep2acme)
[![Go Report Card](https://goreportcard.com/badge/go.bog.dev/scep2acme)](https://goreportcard.com/report/go.bog.dev/scep2acme)
[![Go Reference](https://pkg.go.dev/badge/go.bog.dev/scep2acme.svg)](https://pkg.go.dev/go.bog.dev/scep2acme)

A SCEP (Simple Certificate Enrollment Protocol) server that uses ACME (Automatic Certificate Management Environment) to obtain certificates from Let's Encrypt or other ACME providers.

## Features

- SCEP server implementation that proxies requests to ACME providers
- Support for DNS-01 challenges for domain validation
- Configurable hostname whitelist for security
- Support for both Let's Encrypt staging and production environments
- Comprehensive logging with configurable levels

## Installation

### From Source

```bash
git clone https://github.com/drawks/scep2acme.git
cd scep2acme
make build
```

### Prerequisites

- Go 1.21 or later
- Access to DNS provider for DNS-01 challenges
- ACME account key
- Certificate and key files for SCEP server

## Usage

```bash
./scep2acme -help
```

### Required Parameters

- `-cert`: Path to certificate file (should include 2 certificates: RA & CA)
- `-certkey`: Path to certificate key file
- `-acmekey`: Path to ACME account key
- `-acmeemail`: ACME account email address
- `-dnsprovider`: DNS provider for DNS-01 challenges
- `-whitelist`: Path to hostname whitelist configuration

### Optional Parameters

- `-listen`: Listen address and port (default: "127.0.0.1:8383")
- `-acmeurl`: ACME directory URL (default: Let's Encrypt staging)
- `-debug`: Enable debug logging

### Example

```bash
./scep2acme \
  -cert /path/to/cert.pem \
  -certkey /path/to/key.pem \
  -acmekey /path/to/acme.key \
  -acmeemail your@email.com \
  -dnsprovider cloudflare \
  -whitelist /path/to/whitelist.yaml
```

## Configuration

### Whitelist Configuration

The whitelist file is a YAML file that maps passwords to allowed hostnames:

```yaml
password1: example.com
password2: 
  - subdomain1.example.com
  - subdomain2.example.com
```

### DNS Provider Configuration

Configure your DNS provider using environment variables. See the [lego DNS provider documentation](https://go-acme.github.io/lego/dns/) for specific configuration options.

## Development

### Requirements

- Go 1.21 or later
- Make

### Building

```bash
make build
```

### Testing

```bash
make test
```

### Linting

```bash
make lint
```

### Coverage

```bash
make coverage
```

### Available Make Targets

- `build` - Build the application
- `test` - Run tests
- `lint` - Run linter (go fmt and go vet)
- `vet` - Run go vet
- `coverage` - Generate test coverage report
- `clean` - Clean built files
- `help` - Show help message

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting: `make test lint`
5. Submit a pull request

## License

This project is open source. Please check the repository for license information.