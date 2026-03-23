(English | [Русский](README.ru.md))

# Multi-Protocol Proxy Server

A high-performance proxy server supporting SOCKS5, HTTP and TLS protocols with flexible rule-based routing and upstream proxy chaining.

## Features

- **Multiple Protocols**: SOCKS5, HTTP CONNECT, and TLS-wrapped versions of both
- **Rule-Based Routing**: Define rules to allow, deny, or proxy traffic based on:
  - IP addresses (single IP, CIDR ranges)
  - Domain names (exact match or wildcard patterns like `*.example.com`)
  - Port ranges (single ports, ranges like `80-88`, or comma-separated lists)
- **Upstream Proxy Chaining**: Route traffic through upstream HTTP or SOCKS5 proxies with optional TLS and authentication
- **Authentication**: Username/password authentication for client connections
- **TLS Support**: Both client-to-proxy and proxy-to-upstream TLS encryption
- **Private Network Filtering**: Automatic blocking of private IPv4/IPv6 addresses and internal domains
- **Zero-Copy Forwarding**: Efficient data transfer using `socket.pipe()`

## Installation

```bash
git clone https://github.com/zuenkoma/proxy-server
cd proxy-server
npm install
```

## Usage

### Command Line

```bash
# Start with config file
npm start -- --config config.json

# Override settings via CLI
npm start -- --host 0.0.0.0 --port 8080 --http --socks5

# Add users via CLI
npm start -- --port 8080 --http --user user1:pass1 --user user2:pass2
```

### Configuration File

```json
{
  "host": "0.0.0.0",
  "port": 1984,

  "tls-key": "privkey.pem",
  "tls-cert": "fullchain.pem",

  "http": true,
  "http-tls": true,
  "socks5": true,
  "socks5-tls": true,

  "users": [
    { "username": "user1", "password": "pass1" },
    { "username": "user2", "password": "pass2" }
  ],

  "rules": [
    {
      "type": "allow",
      "address": "8.8.8.8",
      "port": 53
    },
    {
      "type": "proxy",
      "address": "12.34.56.78/24",
      "port": "1-65535",
      "proxy": {
        "proto": "socks5",
        "host": "127.0.0.1",
        "port": 1080,
        "tls": true,
        "auth": {
          "username": "proxyuser",
          "password": "proxypass"
        }
      }
    }
  ]
}
```

### Configuration Options

| Option | Type | Description |
|--------|------|-------------|
| `host` | string | IPv4 address to bind to (default: `0.0.0.0`) |
| `port` | number | Port to listen on (required) |
| `tls-key` | string | Path to TLS private key file |
| `tls-cert` | string | Path to TLS certificate file |
| `http` | boolean | Enable plain HTTP proxy |
| `http-tls` | boolean | Enable HTTPS (TLS) proxy |
| `socks5` | boolean | Enable plain SOCKS5 proxy |
| `socks5-tls` | boolean | Enable SOCKS5 over TLS |
| `users` | array | List of allowed users (empty = no authentication) |
| `rules` | array | Traffic routing rules (evaluated in order, last matching rule wins) |

### Rule Types

#### Allow Rule
Directly connect to the destination without proxying.

```json
{
  "type": "allow",
  "address": "example.com",
  "port": 443
}
```

#### Deny Rule
Block the connection.

```json
{
  "type": "deny",
  "address": "192.168.0.0/24",
  "port": "1-1024"
}
```

#### Proxy Rule
Route through an upstream proxy.

```json
{
  "type": "proxy",
  "address": "*.example.com",
  "port": "80,443,8080",
  "proxy": {
    "proto": "http",
    "host": "upstream.proxy.com",
    "port": 3128,
    "tls": false,
    "auth": {
      "username": "user",
      "password": "pass"
    }
  }
}
```

### Address Patterns

- **Single IP**: `192.168.1.1`
- **CIDR Range**: `10.0.0.0/8`, `172.16.0.0/12`
- **Exact Domain**: `example.com`
- **Wildcard Domain**: `*.example.com` (matches `example.com` and any subdomain)

### Port Patterns

- **Single Port**: `443`
- **Range**: `80-88`
- **List**: `80,443,8080,8443`
- **All Ports**: `1-65535`

### Default Behavior

If no rule matches a connection, it is **allowed** by default. If multiple rules match, the **last matching rule** in the configuration file determines the action.

## Architecture

```
Client → Proxy Server → [Rule Match] → Direct Connection / Upstream Proxy → Destination
```

The proxy automatically:
1. Detects protocol (SOCKS5, HTTP, or TLS) from the first byte
2. Performs authentication if configured
3. Matches rules against the destination address/port
4. Either connects directly or forwards through an upstream proxy
5. Pipes data bidirectionally with zero buffering