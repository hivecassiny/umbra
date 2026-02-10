package umbra

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// TLSConfig holds TLS-specific configuration for advanced obfuscation.
// For advanced obfuscation mode (ObfuscationAdvanced), TLS is REQUIRED.
type TLSConfig struct {
	// ===== Server Configuration =====

	// CertPEM is the PEM-encoded certificate for TLS.
	// Required for server-side advanced obfuscation.
	// You can generate a self-signed cert using GenerateSelfSignedCert().
	CertPEM string

	// KeyPEM is the PEM-encoded private key for TLS.
	// Required for server-side advanced obfuscation.
	KeyPEM string

	// ===== Client Configuration =====

	// ServerName is the SNI (Server Name Indication) to send during TLS handshake.
	// This MUST match the domain in your certificate.
	// IMPORTANT: DPI systems inspect SNI to identify destination.
	// Use your own domain, NOT google.com or cloudflare.com.
	// Those will be detected by active probing.
	ServerName string

	// SkipVerify skips certificate verification.
	// Use this with self-signed certificates.
	// WARNING: Only enable this if you trust the server.
	SkipVerify bool

	// CACertPEM is an optional custom CA certificate for verification.
	// If provided, this CA will be used instead of system roots.
	CACertPEM string

	// ===== Advanced Settings =====

	// ALPN protocols to advertise. Defaults to ["h2", "http/1.1"].
	// Setting this to match real browsers improves stealth.
	ALPNProtos []string
}

// WrapWithTLS wraps a connection with TLS encryption.
// For clients, this performs a TLS handshake as a client.
// For servers, this performs a TLS handshake as a server.
func WrapWithTLS(conn net.Conn, config *TLSConfig, isClient bool) (net.Conn, error) {
	if config == nil {
		return nil, fmt.Errorf("TLS configuration is required")
	}

	if isClient {
		return wrapClientTLS(conn, config)
	}
	return wrapServerTLS(conn, config)
}

// wrapClientTLS wraps a connection as TLS client
func wrapClientTLS(conn net.Conn, config *TLSConfig) (net.Conn, error) {
	tlsConfig := &tls.Config{
		ServerName:         config.ServerName,
		InsecureSkipVerify: config.SkipVerify,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}

	// Set ALPN protocols for better stealth
	if len(config.ALPNProtos) > 0 {
		tlsConfig.NextProtos = config.ALPNProtos
	} else {
		// Default to common browser protocols
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	}

	// Load custom CA if provided
	if config.CACertPEM != "" {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM([]byte(config.CACertPEM)) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = certPool
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	return tlsConn, nil
}

// wrapServerTLS wraps a connection as TLS server
func wrapServerTLS(conn net.Conn, config *TLSConfig) (net.Conn, error) {
	if config.CertPEM == "" || config.KeyPEM == "" {
		return nil, fmt.Errorf("server TLS requires CertPEM and KeyPEM")
	}

	cert, err := tls.X509KeyPair([]byte(config.CertPEM), []byte(config.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}

	// Set ALPN protocols
	if len(config.ALPNProtos) > 0 {
		tlsConfig.NextProtos = config.ALPNProtos
	} else {
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	}

	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	return tlsConn, nil
}

// GenerateSelfSignedCert generates a self-signed TLS certificate.
// The certificate is valid for the specified hosts (domains or IPs).
// Returns PEM-encoded certificate and private key.
//
// Example:
//
//	certPEM, keyPEM, err := umbra.GenerateSelfSignedCert([]string{"pool.example.com", "192.168.1.100"})
func GenerateSelfSignedCert(hosts []string) (certPEM, keyPEM string, err error) {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Umbra"},
			CommonName:   hosts[0],
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year validity
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add hosts to certificate (DNS names and IP addresses)
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	// Create certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEMBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Encode private key to PEM
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return string(certPEMBytes), string(keyPEMBytes), nil
}

// GenerateSelfSignedCertECDSA generates a self-signed TLS certificate using ECDSA.
// Uses P-256 curve for better performance than RSA.
func GenerateSelfSignedCertECDSA(hosts []string) (certPEM, keyPEM string, err error) {
	// Generate ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Umbra"},
			CommonName:   hosts[0],
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add hosts
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	// Create certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, privateKey.Public(), privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEMBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Encode private key to PEM
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	return string(certPEMBytes), string(keyPEMBytes), nil
}
