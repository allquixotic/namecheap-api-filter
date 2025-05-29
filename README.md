# Namecheap API Filter 🔒

A secure API proxy for Namecheap that provides controlled access to DNS management operations through token-based authentication.

## Features

- **🛡️ Security First**: Never expose your real Namecheap API credentials
- **🔑 Token Authentication**: Use static tokens instead of API keys
- **✅ Operation Allowlist**: Only pre-approved DNS operations are permitted
- **🌐 Domain Filtering**: Optional domain-level access control
- **🚀 Tailscale Ready**: Designed for secure internal networks
- **📝 Full API Compatibility**: Drop-in replacement for Namecheap API

## Quick Start

```bash
# Clone the repository
git clone https://github.com/allquixotic/namecheap-api-filter
cd namecheap-api-filter

# Set up environment variables
cp .env.example .env
# Edit .env with your credentials

# Build and run
go build
./namecheap-api-filter
```

## Installation

### Prerequisites
- Go 1.24 or later
- Namecheap API credentials
- A whitelisted IP address for Namecheap API access

### Build from Source

```bash
go mod download
go build -o namecheap-api-filter
```

## Configuration

Configure the service using environment variables:

| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| `AUTH_TOKEN` | ✅ | Static token for client authentication | - |
| `NAMECHEAP_API_USER` | ✅ | Your Namecheap API username | - |
| `NAMECHEAP_API_KEY` | ✅ | Your Namecheap API key | - |
| `NAMECHEAP_CLIENT_IP` | ✅ | Whitelisted IP for Namecheap API | - |
| `ALLOWED_DOMAINS` | ❌ | Comma-separated list of allowed domains | All domains |
| `ALLOW_DELETE` | ❌ | Enable DNS record deletion | `false` |
| `LISTEN_ADDR` | ❌ | Server listen address | `:8080` |
| `NAMECHEAP_SANDBOX` | ❌ | Use Namecheap sandbox environment | `false` |

### Example Configuration

```bash
# Production configuration
export AUTH_TOKEN="your-secret-token-here"
export NAMECHEAP_API_USER="your-username"
export NAMECHEAP_API_KEY="your-api-key"
export NAMECHEAP_CLIENT_IP="203.0.113.1"
export ALLOWED_DOMAINS="example.com,mydomain.org"
export LISTEN_ADDR="100.64.0.1:8080"  # Tailscale IP
```

## Usage

### Starting the Server

```bash
./namecheap-api-filter
```

The server will start on the configured `LISTEN_ADDR` (default `:8080`).

### Making API Requests

Replace the Namecheap API endpoint with your filter server:

```bash
# Instead of: https://api.namecheap.com/xml.response
# Use: http://your-server:8080/xml.response

curl -X POST http://localhost:8080/xml.response \
  -d "ApiUser=${AUTH_TOKEN}" \
  -d "ApiKey=${AUTH_TOKEN}" \
  -d "Command=namecheap.domains.dns.getHosts" \
  -d "ClientIp=127.0.0.1" \
  -d "SLD=example" \
  -d "TLD=com"
```

## Allowed Operations

### Read Operations (Always Allowed)
- `namecheap.domains.dns.getList` - Get DNS servers
- `namecheap.domains.dns.getHosts` - Get DNS records
- `namecheap.domains.dns.getEmailForwarding` - Get email forwarding
- `namecheap.domains.ns.getInfo` - Get nameserver info

### Write Operations
- `namecheap.domains.dns.setHosts` - Update DNS records
  - Subject to domain filtering
  - Deletion controlled by `ALLOW_DELETE`

## Domain Filtering

When `ALLOWED_DOMAINS` is configured, the filter supports:
- Exact domain matches: `example.com`
- Subdomain wildcards: `*.example.com` matches `api.example.com`

Example:
```bash
ALLOWED_DOMAINS="example.com,test.org"
# Allows: example.com, www.example.com, test.org, api.test.org
# Blocks: other.com, unauthorized.net
```

## Important DNS Behavior ⚠️

When using `setHosts`:
- **ALL existing records not included in the request will be DELETED**
- Always fetch current records first with `getHosts`
- Include all records you want to keep in `setHosts` requests
- Use POST method for domains with >10 records

## Security Considerations

1. **Network Security**: Deploy behind a firewall or on a private network
2. **Token Management**: Use strong, unique tokens and rotate regularly
3. **Domain Filtering**: Enable domain restrictions in production
4. **Deletion Control**: Keep `ALLOW_DELETE=false` unless necessary
5. **Logging**: Monitor access logs for unauthorized attempts

## Deployment

### Docker

```dockerfile
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o namecheap-api-filter

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/namecheap-api-filter /
CMD ["/namecheap-api-filter"]
```

### Systemd Service

```ini
[Unit]
Description=Namecheap API Filter
After=network.target

[Service]
Type=simple
User=namecheap
EnvironmentFile=/etc/namecheap-api-filter.env
ExecStart=/usr/local/bin/namecheap-api-filter
Restart=always

[Install]
WantedBy=multi-user.target
```

## Development

### Running Tests
```bash
go test ./...
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License - see LICENSE file for details

## Support

- Issues: [GitHub Issues](https://github.com/allquixotic/namecheap-api-filter/issues)
- Documentation: [Wiki](https://github.com/allquixotic/namecheap-api-filter/wiki)

---

*This tool was generated using [Claude Code](https://claude.ai/code) with Claude Opus 4*