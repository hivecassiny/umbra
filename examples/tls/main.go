// TLS example demonstrates advanced obfuscation with TLS encryption.
//
// Usage:
//
//	go run ./examples/tls/
package main

import (
	"crypto/elliptic"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/hivecassiny/umbra"
)

func main() {
	fmt.Println("━━━ Umbra: Advanced TLS + Obfuscation Demo ━━━\n")

	// Generate self-signed certificate
	certPEM, keyPEM, err := umbra.GenerateSelfSignedCert([]string{"demo.example.com"})
	if err != nil {
		log.Fatal("GenerateSelfSignedCert error:", err)
	}
	fmt.Printf("🔑 Generated self-signed cert (RSA)\n")
	fmt.Printf("   Cert PEM: %d bytes\n", len(certPEM))
	fmt.Printf("   Key PEM:  %d bytes\n\n", len(keyPEM))

	// Server config: TLS + Advanced WebSocket obfuscation
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
			Domain:    "demo.example.com",
			CoverPath: "/ws",
		},
	}

	// Client config: TLS + Advanced WebSocket obfuscation
	clientConfig := &umbra.Config{
		Curve: elliptic.P256(),
		TLS: &umbra.TLSConfig{
			ServerName: "demo.example.com",
			SkipVerify: true, // Self-signed cert
		},
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled:   true,
			Level:     umbra.ObfuscationLevelAdvanced,
			Mode:      umbra.ObfuscationWebSocket,
			Domain:    "demo.example.com",
			CoverPath: "/ws",
		},
	}

	listener, err := umbra.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		log.Fatal("Listen error:", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	fmt.Printf("🔒 TLS Server listening on %s\n", addr)
	fmt.Printf("   Obfuscation: Advanced + WebSocket\n")
	fmt.Printf("   Domain:      demo.example.com\n\n")

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

		response := "Secure response over TLS + WebSocket obfuscation 🔐"
		conn.Write([]byte(response))
	}()

	time.Sleep(50 * time.Millisecond)

	conn, err := umbra.Dial("tcp", addr, clientConfig)
	if err != nil {
		log.Fatal("Dial error:", err)
	}
	defer conn.Close()

	fmt.Println("📤 Client connected via TLS")

	msg := "Secret message through TLS + WebSocket obfuscation 🕵️"
	conn.Write([]byte(msg))
	fmt.Printf("   Sent: %s\n", msg)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal("Read error:", err)
	}
	fmt.Printf("   Reply: %s\n\n", string(buf[:n]))

	wg.Wait()

	// Also demonstrate ECDSA cert
	fmt.Println("━━━ ECDSA Certificate Demo ━━━\n")

	ecdsaCert, ecdsaKey, err := umbra.GenerateSelfSignedCertECDSA([]string{"ecdsa.example.com"})
	if err != nil {
		log.Fatal("GenerateSelfSignedCertECDSA error:", err)
	}
	fmt.Printf("🔑 Generated self-signed cert (ECDSA)\n")
	fmt.Printf("   Cert PEM: %d bytes\n", len(ecdsaCert))
	fmt.Printf("   Key PEM:  %d bytes\n\n", len(ecdsaKey))

	fmt.Println("✅ TLS demo complete!")
}
