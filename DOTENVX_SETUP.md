# Dotenvx Setup for namecheap-api-filter

This guide explains how to securely manage credentials for namecheap-api-filter using dotenvx encryption.

## Prerequisites

Install dotenvx:
```bash
# Using curl
curl -sfS https://dotenvx.sh | sh

# Or using npm
npm install -g @dotenvx/dotenvx

# Or using Homebrew
brew install dotenvx/brew/dotenvx
```

## Quick Start

1. **Copy the example environment file**:
   ```bash
   cp .env.example .env
   ```

2. **Edit `.env` with your credentials**:
   ```bash
   nano .env  # or use your preferred editor
   ```

   Required variables:
   - `AUTH_TOKEN` - Your chosen authentication token for clients
   - `NAMECHEAP_API_USER` - Your Namecheap username
   - `NAMECHEAP_API_KEY` - Your Namecheap API key
   - `NAMECHEAP_CLIENT_IP` - Your whitelisted IP address

3. **Encrypt the `.env` file**:
   ```bash
   dotenvx encrypt
   ```
   
   This creates:
   - An encrypted `.env` file (safe to commit)
   - A `.env.keys` file containing your private key (NEVER commit this!)

4. **Add to `.gitignore`**:
   ```bash
   echo ".env.keys" >> .gitignore
   echo "*.env.keys" >> .gitignore
   ```

5. **Run the filter**:
   ```bash
   # During development
   dotenvx run -- go run main.go
   
   # Or with the built binary
   dotenvx run -- ./namecheap-api-filter
   ```

## Environment Variables

### Required Variables

- **`AUTH_TOKEN`**: Static authentication token that clients will use to authenticate with your filter
- **`NAMECHEAP_API_USER`**: Your Namecheap account username
- **`NAMECHEAP_API_KEY`**: Your Namecheap API key (get from Namecheap dashboard)
- **`NAMECHEAP_CLIENT_IP`**: IP address whitelisted in your Namecheap account

### Optional Variables

- **`ALLOWED_DOMAINS`**: Comma-separated list of allowed domains (e.g., `example.com,test.org`). Leave empty to allow all domains.
- **`ALLOW_DELETE`**: Set to `true` to allow delete operations via setHosts. Default: `false`
- **`LISTEN_ADDR`**: Server listen address. Default: `:8080`
- **`NAMECHEAP_SANDBOX`**: Set to `true` to use Namecheap's sandbox API. Default: `false`

## Production Deployment

1. **Extract your private key**:
   ```bash
   cat .env.keys
   # Copy the DOTENV_PRIVATE_KEY value
   ```

2. **On your production server**, set the private key:
   ```bash
   export DOTENV_PRIVATE_KEY="your-private-key-here"
   ```

3. **Copy the encrypted `.env` file** to your production server

4. **Run the application**:
   ```bash
   dotenvx run -- ./namecheap-api-filter
   ```

## Multiple Environments

For different configurations per environment:

```bash
# Create environment-specific files
cp .env .env.production
cp .env .env.development

# Edit each file with appropriate values
nano .env.production

# Encrypt each file
dotenvx encrypt -f .env.production
dotenvx encrypt -f .env.development

# Run with specific environment
dotenvx run -f .env.development -- ./namecheap-api-filter

# In production, use environment-specific private key
DOTENV_PRIVATE_KEY_PRODUCTION="prod-key" dotenvx run -- ./namecheap-api-filter
```

## Security Notes

- The `AUTH_TOKEN` should be a strong, random string
- Never expose your Namecheap API credentials
- Rotate your `AUTH_TOKEN` periodically
- Keep `.env.keys` files secure and never commit them
- Use different tokens for different environments

## Example `.env` Configuration

```env
# Authentication token for clients
AUTH_TOKEN=my-secure-random-token-123

# Namecheap API credentials
NAMECHEAP_API_USER=myusername
NAMECHEAP_API_KEY=1234567890abcdef1234567890abcdef
NAMECHEAP_CLIENT_IP=192.168.1.100

# Optional: Restrict to specific domains
ALLOWED_DOMAINS=mydomain.com,myotherdomain.com

# Optional: Security settings
ALLOW_DELETE=false

# Optional: Server configuration
LISTEN_ADDR=:8080
NAMECHEAP_SANDBOX=false
```