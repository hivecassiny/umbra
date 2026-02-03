# ECC Socket - Secure Communication Library with DPI Bypass

[![Go Version](https://img.shields.io/badge/Go-1.17+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A secure network communication library for Go that provides end-to-end encrypted communication using Elliptic Curve Cryptography (ECC) with **advanced traffic obfuscation capabilities designed to bypass Deep Packet Inspection (DPI)**.

## Features

- 🔒 **End-to-End Encryption**: ECDH key exchange with ChaCha20-Poly1305 encryption
- 🎭 **DPI-Resistant Obfuscation**: TLS + WebSocket encapsulation to bypass traffic analysis
- 🚀 **High Performance**: Modern cryptographic algorithms with low latency
- 🔑 **Flexible Key Management**: Support for both static and ephemeral keys (forward secrecy)
- 📜 **Standards Compliant**: PEM format for key storage, RFC 6455 WebSocket frames
- 🛡️ **Security Hardened**: Replay protection, integrity verification, TLS 1.3 support
- 🔧 **Easy to Use**: net-like API design for easy integration

## Installation

```bash
go get github.com/hivecassiny/umbra
```

## Quick Start

### Basic Example (No Obfuscation)

```go
package main

import (
    "fmt"
    "github.com/hivecassiny/umbra"
    "log"
)

func main() {
    // Server
    go func() {
        listener, _ := umbra.Listen("tcp", ":8080", nil)
        defer listener.Close()
        
        conn, _ := listener.Accept()
        defer conn.Close()
        
        buf := make([]byte, 1024)
        n, _ := conn.Read(buf)
        fmt.Println("Received:", string(buf[:n]))
    }()

    // Client
    conn, _ := umbra.Dial("tcp", "localhost:8080", nil)
    defer conn.Close()
    
    conn.Write([]byte("Hello, secure world!"))
}
```

## Advanced: DPI-Resistant Obfuscation

For environments with Deep Packet Inspection (such as ISPs in China), use advanced obfuscation mode. This makes your traffic appear as legitimate HTTPS WebSocket communication.

### Obfuscation Levels

| Level | Description | Requirements |
|-------|-------------|--------------|
| `ObfuscationLevelBasic` | Padding and header obfuscation | None |
| `ObfuscationLevelAdvanced` | TLS + WebSocket encapsulation | Domain + TLS cert |

### Obfuscation Modes

| Mode | Description |
|------|-------------|
| `ObfuscationNone` | No obfuscation |
| `ObfuscationHTTP` | HTTP traffic obfuscation |
| `ObfuscationRandom` | Random padding |
| `ObfuscationWebSocket` | WebSocket frames (recommended for DPI bypass) |

### Example: Advanced Mode (DPI Bypass)

```go
package main

import (
    "crypto/elliptic"
    "fmt"
    "github.com/hivecassiny/umbra"
    "log"
    "time"
)

func main() {
    // Generate self-signed certificate for your domain
    certPEM, keyPEM, err := umbra.GenerateSelfSignedCert([]string{"pool.yoursite.com"})
    if err != nil {
        log.Fatal(err)
    }

    // Server configuration
    serverConfig := &umbra.Config{
        Curve: elliptic.P256(),
        TLS: &umbra.TLSConfig{
            CertPEM: certPEM,
            KeyPEM:  keyPEM,
        },
        Obfuscation: &umbra.ObfuscationConfig{
            Enabled:   true,
            Level:     umbra.ObfuscationLevelAdvanced,
            Mode:      umbra.ObfuscationWebSocket,
            Domain:    "pool.yoursite.com",  // Your domain
            CoverPath: "/ws",                 // WebSocket endpoint
        },
    }

    // Client configuration
    clientConfig := &umbra.Config{
        Curve: elliptic.P256(),
        TLS: &umbra.TLSConfig{
            ServerName: "pool.yoursite.com",
            SkipVerify: true,  // For self-signed certs
        },
        Obfuscation: &umbra.ObfuscationConfig{
            Enabled:   true,
            Level:     umbra.ObfuscationLevelAdvanced,
            Mode:      umbra.ObfuscationWebSocket,
            Domain:    "pool.yoursite.com",
        },
    }

    // Start server
    go func() {
        listener, err := umbra.Listen("tcp", ":443", serverConfig)
        if err != nil {
            log.Fatal(err)
        }
        defer listener.Close()
        
        fmt.Println("DPI-resistant server listening on :443")
        
        for {
            conn, err := listener.Accept()
            if err != nil {
                continue
            }
            go handleConnection(conn)
        }
    }()

    time.Sleep(time.Second)

    // Connect with client
    conn, err := umbra.Dial("tcp", "localhost:443", clientConfig)
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    
    fmt.Println("Connected with DPI-resistant obfuscation")
}
```

## Configuration Validation

The library validates your configuration and provides helpful error messages:

```go
// Validate config before use
if err := umbra.ValidateConfig(config, isServer); err != nil {
    log.Fatal(err)
}

// Or with verbose output
umbra.ValidateAndExplain(config, isServer, true)
```

## Important Security Notes

### ⚠️ Domain Requirements

When using `ObfuscationLevelAdvanced`:

1. **Use a domain you control** (e.g., `pool.yoursite.com`)
2. **Do NOT use** `google.com`, `cloudflare.com`, or similar major domains
3. DPI systems perform **active probing** - they will verify if your server is the real domain
4. **Domain must resolve to your server IP** via DNS A record

### 🔐 TLS Certificate Configuration

You have two options for certificates. **Let's Encrypt is strongly recommended**.

#### Option 1: Let's Encrypt Certificate (Recommended ⭐)

| Advantage | Description |
|-----------|-------------|
| **Trusted CA** | Browser and DPI systems recognize it as legitimate |
| **Free** | No cost, auto-renews every 90 days |
| **No SkipVerify** | Client doesn't need to skip verification |
| **Best Stealth** | Indistinguishable from normal HTTPS |

```bash
# Install certbot
sudo apt install certbot  # Ubuntu/Debian
sudo yum install certbot  # CentOS/RHEL

# Get certificate (domain must resolve to this server)
sudo certbot certonly --standalone -d pool.yoursite.com

# Certificate files location:
# /etc/letsencrypt/live/pool.yoursite.com/fullchain.pem  (certificate)
# /etc/letsencrypt/live/pool.yoursite.com/privkey.pem   (private key)
```

```go
// Server: Load Let's Encrypt certificate
certPEM, _ := os.ReadFile("/etc/letsencrypt/live/pool.yoursite.com/fullchain.pem")
keyPEM, _ := os.ReadFile("/etc/letsencrypt/live/pool.yoursite.com/privkey.pem")

serverConfig := &umbra.Config{
    TLS: &umbra.TLSConfig{
        CertPEM: string(certPEM),
        KeyPEM:  string(keyPEM),
    },
    Obfuscation: &umbra.ObfuscationConfig{
        Enabled: true,
        Level:   umbra.ObfuscationLevelAdvanced,
        Mode:    umbra.ObfuscationWebSocket,
        Domain:  "pool.yoursite.com",
    },
}

// Client: No need to skip verification!
clientConfig := &umbra.Config{
    TLS: &umbra.TLSConfig{
        ServerName: "pool.yoursite.com",
        SkipVerify: false,  // Real cert, no need to skip
    },
    // ...
}
```

#### Option 2: Self-Signed Certificate

| Consideration | Description |
|---------------|-------------|
| **Quick Setup** | No domain verification needed |
| **Requires SkipVerify** | Client must set `SkipVerify: true` |
| **Less Stealthy** | DPI may flag non-CA certificates |

```go
// Generate self-signed certificate
certPEM, keyPEM, err := umbra.GenerateSelfSignedCert([]string{"pool.yoursite.com"})

// Client MUST skip verification
clientConfig.TLS.SkipVerify = true
```

### 📋 Complete Setup Checklist

1. ✅ Buy a domain (~$5-10/year from Namecheap, Cloudflare, etc.)
2. ✅ Add DNS A record: `pool.yoursite.com` → `your.server.ip`
3. ✅ Get Let's Encrypt certificate with `certbot`
4. ✅ Configure Nginx as reverse proxy (optional but recommended)
5. ✅ Set up a cover website at `/` for active probing defense

### 🛡️ Nginx Reverse Proxy (Optional)

For best stealth, put a normal website in front:

```nginx
server {
    listen 443 ssl http2;
    server_name pool.yoursite.com;
    
    ssl_certificate /etc/letsencrypt/live/pool.yoursite.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/pool.yoursite.com/privkey.pem;
    
    # Normal website (for cover - defeats active probing)
    location / {
        root /var/www/html;
        index index.html;
    }
    
    # WebSocket endpoint (your actual service)
    location /ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

## API Reference

### Key Management

```go
// Generate key pair
privKey, err := umbra.GenerateKey(elliptic.P256())

// Encode/decode keys
privPEM, _ := umbra.EncodePrivateKey(privKey)
pubPEM, _ := umbra.EncodePublicKey(&privKey.PublicKey)

privKey, _ := umbra.DecodePrivateKey(privPEM)
pubKey, _ := umbra.DecodePublicKey(pubPEM)
```

### Connection Management

```go
// Client connection
conn, err := umbra.Dial("tcp", "host:port", config)
conn, err := umbra.DialTimeout(5*time.Second, "tcp", "host:port", config)

// Server listener
listener, err := umbra.Listen("tcp", ":port", config)
conn, err := listener.Accept()
```

### TLS Certificate Generation

```go
// RSA certificate
certPEM, keyPEM, err := umbra.GenerateSelfSignedCert([]string{"domain.com", "192.168.1.1"})

// ECDSA certificate (better performance)
certPEM, keyPEM, err := umbra.GenerateSelfSignedCertECDSA([]string{"domain.com"})
```

## Performance

| Metric | Value |
|--------|-------|
| Encryption throughput | ~800 Mbps |
| Handshake time | ~2.5 ms |
| Memory per connection | ~4 KB |
| Obfuscation overhead | 5-15% |

## Protocol Details

### Encryption Stack

1. **Key Exchange**: ECDH (P-256/P-384/P-521)
2. **Symmetric Encryption**: ChaCha20-Poly1305
3. **Key Derivation**: HKDF-SHA256
4. **TLS Layer**: TLS 1.2/1.3 (advanced mode)

### Message Format

```
+------+-----------+----------------+
| Type | Length    | Encrypted Data |
+------+-----------+----------------+
| 1B   | 4B        | Variable       |
+------+-----------+----------------+
```

## Future Roadmap

### v2.0 - HTTP/3 (QUIC) Support

When current TLS + WebSocket obfuscation is no longer sufficient, upgrade to HTTP/3:

| Feature | Description | Priority |
|---------|-------------|----------|
| **QUIC Protocol** | UDP-based transport, better for high-latency networks | High |
| **HTTP/3 Disguise** | Traffic appears as standard HTTP/3 | High |
| **0-RTT Connection** | Faster connection establishment | Medium |
| **Brutal Congestion Control** | Better performance on lossy networks | Medium |

**Implementation Notes:**
- Requires `quic-go` library (~50MB dependency)
- Need to handle UDP blocking in some networks
- Consider Hysteria2 protocol as reference

**When to Upgrade:**
- If current WebSocket mode gets blocked
- If users report UDP works better in their network
- If 0-RTT fast reconnection is needed

---

## Related Projects

- [obfs4](https://github.com/Yawning/obfs4) - Pluggable transport for Tor
- [V2Ray](https://github.com/v2fly/v2ray-core) - Platform for building proxies
- [WireGuard](https://www.wireguard.com/) - Modern VPN protocol
- [Hysteria2](https://hysteria.network/) - QUIC-based proxy protocol (reference for HTTP/3)

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request
