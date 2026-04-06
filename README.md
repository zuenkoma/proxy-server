(English | [Русский](README.ru.md))

# Multi-Protocol Proxy Server

A high-performance proxy server supporting SOCKS5, HTTP and TLS protocols with flexible rule-based routing and upstream proxy chaining.

## Features

- **Multiple Protocols**: SOCKS5, HTTP CONNECT, and TLS-wrapped versions of both
- **Rule-Based Routing**: Define rules to allow, deny, or proxy traffic based on:
  - IP addresses (single IP, CIDR ranges)
  - Domain names (exact match or wildcard patterns like `*.example.com`)
  - Port ranges (single ports, ranges like `80-88`, or lists)
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
    { "username": "user1", "password": "pass1", "max-ips": 2 },
    { "username": "user2", "password": "pass2" }
  ],

  "rules": [
    {
      "type": "allow",
      "hosts": ["8.8.8.8"],
      "ports": [53]
    },
    {
      "type": "proxy",
      "hosts": ["12.34.56.78/24"],
      "ports": ["1-65535"],
      "proxy": {
        "protocol": "socks5",
        "host": "127.0.0.1",
        "port": 1080,
        "tls": true,
        "auth": {
          "username": "proxyuser",
          "password": "proxypass"
        }
      }
    }
  ],

  "debug": false
}
```

### Configuration Options

| Option       | Type    | Description                                                                                                           |
|--------------|---------|-----------------------------------------------------------------------------------------------------------------------|
| `host`       | string  | IPv4 address to bind to (default: `0.0.0.0`)                                                                          |
| `port`       | number  | Port to listen on (required)                                                                                          |
| `tls-key`    | string  | Path to TLS private key file                                                                                          |
| `tls-cert`   | string  | Path to TLS certificate file                                                                                          |
| `http`       | boolean | Enable plain HTTP proxy                                                                                               |
| `http-tls`   | boolean | Enable HTTPS (TLS) proxy                                                                                              |
| `socks5`     | boolean | Enable plain SOCKS5 proxy                                                                                             |
| `socks5-tls` | boolean | Enable SOCKS5 over TLS                                                                                                |
| `users`      | array   | List of allowed users (empty = no authentication). Each user can have `username`, `password`, and optional `max-ips`. |
| `rules`      | array   | Traffic routing rules (evaluated in order, last matching rule wins)                                                   |
| `debug`      | boolean | Enable debug logging (default: `false`)                                                                               |

If `max-ips` is set, the server limits the number of distinct client IP addresses that can be connected using this user account simultaneously. This helps prevent credential sharing across many devices.

### Rule Structure

Each rule can have:
- `type` - `"allow"`, `"deny"`, or `"proxy"`
- `hosts` (optional) - array of address patterns (see below)
- `ports` (optional) - array of port patterns (see below)
- `proxy` (required for type `"proxy"`) - upstream proxy configuration

### Address Patterns

- **Single IP**: `"192.168.1.1"`
- **CIDR Range**: `"10.0.0.0/8"`, `"172.16.0.0/12"`
- **Exact Domain**: `"example.com"`
- **Wildcard Domain**: `"*.example.com"` (matches `example.com` and any subdomain)

### Port Patterns

- **Single Port**: `443`
- **Range**: `"80-88"`
- **List**: `80,443,8080` (as numbers or strings) – actually use array elements, e.g. `[80, "443-445", 8080]`
- **All Ports**: `"1-65535"`

### Rule Examples

#### Allow Rule
Directly connect to the destination without proxying.

```json
{
  "type": "allow",
  "hosts": ["example.com"],
  "ports": [443]
}
```

#### Deny Rule
Block the connection.

```json
{
  "type": "deny",
  "hosts": ["192.168.0.0/24"],
  "ports": ["1-1024"]
}
```

#### Proxy Rule
Route through an upstream proxy.

```json
{
  "type": "proxy",
  "hosts": ["*.example.com"],
  "ports": ["80", "443", "8080"],
  "proxy": {
    "protocol": "http",
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

### Upstream Proxy Configuration

| Field      | Type    | Description                                     |
|------------|---------|-------------------------------------------------|
| `protocol` | string  | `"socks5"` or `"http"`                          |
| `host`     | string  | Upstream proxy hostname or IP                   |
| `port`     | number  | Upstream proxy port                             |
| `tls`      | boolean | Enable TLS to upstream proxy (default: `false`) |
| `auth`     | object  | Optional username/password authentication       |

### Default Behavior

If no rule matches a connection, it is **allowed** by default. If multiple rules match, the **last matching rule** in the configuration file determines the action.

The server also automatically blocks connections to private IPv4/IPv6 addresses and internal domains.

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