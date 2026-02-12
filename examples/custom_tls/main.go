// Custom TLS example demonstrates using CustomTLSConfig for dynamic certificate management.
// This is useful for integrating with CertMagic or other auto-renewal certificate managers.
//
// In this example, we build a *tls.Config manually with GetCertificate callback,
// simulating what CertMagic provides for automatic certificate renewal.
//
// Usage:
//
//	go run ./examples/custom_tls/
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/hivecassiny/umbra"
)

func main() {
	fmt.Println("━━━ Umbra: Custom TLS Config Demo ━━━")
	fmt.Println("This demo shows how to use CustomTLSConfig for dynamic certificate management.")
	fmt.Println("In production, you would use CertMagic's TLSConfig() instead of building manually.")
	fmt.Println()

	// Generate a certificate (simulating what CertMagic would provide)
	cert, certPEM, err := generateCert("custom.example.com")
	if err != nil {
		log.Fatal("Failed to generate certificate:", err)
	}
	fmt.Printf("🔑 Generated certificate for custom.example.com\n\n")

	// Build a custom *tls.Config with GetCertificate callback
	// This is the key feature - the callback is called for each new connection,
	// allowing the certificate to be updated dynamically (e.g., after auto-renewal).
	customTLSConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			fmt.Printf("   🔄 GetCertificate called for SNI: %s\n", hello.ServerName)
			// In production with CertMagic, this returns the latest renewed cert
			return &cert, nil
		},
	}

	// Server config: Use CustomTLSConfig instead of CertPEM/KeyPEM
	serverConfig := &umbra.Config{
		Curve: elliptic.P256(),
		TLS: &umbra.TLSConfig{
			// No CertPEM/KeyPEM needed! CustomTLSConfig takes priority.
			CustomTLSConfig: customTLSConfig,
		},
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled:   true,
			Level:     umbra.ObfuscationLevelAdvanced,
			Mode:      umbra.ObfuscationWebSocket,
			Domain:    "custom.example.com",
			CoverPath: "/ws",
		},
	}

	// Client config
	clientConfig := &umbra.Config{
		Curve: elliptic.P256(),
		TLS: &umbra.TLSConfig{
			ServerName: "custom.example.com",
			SkipVerify: true, // Self-signed cert
		},
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled:   true,
			Level:     umbra.ObfuscationLevelAdvanced,
			Mode:      umbra.ObfuscationWebSocket,
			Domain:    "custom.example.com",
			CoverPath: "/ws",
		},
	}

	listener, err := umbra.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		log.Fatal("Listen error:", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	fmt.Printf("🔒 Server listening on %s (using CustomTLSConfig)\n\n", addr)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			log.Println("Read error:", err)
			return
		}
		fmt.Printf("📥 Server received: %s\n", string(buf[:n]))

		response := "Response via CustomTLSConfig - dynamic cert ready! 🔐"
		conn.Write([]byte(response))
	}()

	time.Sleep(50 * time.Millisecond)

	conn, err := umbra.Dial("tcp", addr, clientConfig)
	if err != nil {
		log.Fatal("Dial error:", err)
	}
	defer conn.Close()

	fmt.Println("📤 Client connected via CustomTLSConfig")

	msg := "Hello from client using dynamic TLS! 🕵️"
	conn.Write([]byte(msg))
	fmt.Printf("   Sent: %s\n", msg)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal("Read error:", err)
	}
	fmt.Printf("   Reply: %s\n\n", string(buf[:n]))

	wg.Wait()

	// Show CertMagic integration pattern
	fmt.Println("━━━ CertMagic Integration Pattern ━━━")
	fmt.Println()
	fmt.Println("  // import \"github.com/caddyserver/certmagic\"")
	fmt.Println("  //")
	fmt.Println("  // certmagic.DefaultACME.Agreed = true")
	fmt.Println("  // cfg := certmagic.NewDefault()")
	fmt.Println("  // cfg.ManageAsync(ctx, []string{\"yourdomain.com\"})")
	fmt.Println("  //")
	fmt.Println("  // serverConfig := &umbra.Config{")
	fmt.Println("  //     TLS: &umbra.TLSConfig{")
	fmt.Println("  //         CustomTLSConfig: cfg.TLSConfig(),  // <-- dynamic renewal!")
	fmt.Println("  //     },")
	fmt.Println("  // }")
	fmt.Println()

	_ = certPEM // certPEM available if needed for other purposes
	fmt.Println("✅ CustomTLSConfig demo complete!")
}

// generateCert creates a self-signed certificate and returns both
// the tls.Certificate and the PEM-encoded cert (for reference).
func generateCert(domain string) (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyBytes, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	return cert, string(certPEM), nil
}
