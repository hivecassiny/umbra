package umbra_test

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hivecassiny/umbra"
)

// testEcho runs a simple echo test: client sends data, server echoes it back
func testEcho(t *testing.T, serverConfig, clientConfig *umbra.Config, testName string) {
	t.Helper()

	listener, err := umbra.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("[%s] Listen failed: %v", testName, err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	testData := []byte("Hello, Umbra obfuscation test! 你好世界 🌍")

	var wg sync.WaitGroup
	var serverErr error

	// Server goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			serverErr = fmt.Errorf("Accept failed: %v", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			serverErr = fmt.Errorf("Server Read failed: %v", err)
			return
		}

		// Echo back
		_, err = conn.Write(buf[:n])
		if err != nil {
			serverErr = fmt.Errorf("Server Write failed: %v", err)
			return
		}
	}()

	// Client
	time.Sleep(50 * time.Millisecond)
	conn, err := umbra.Dial("tcp", addr, clientConfig)
	if err != nil {
		t.Fatalf("[%s] Dial failed: %v", testName, err)
	}
	defer conn.Close()

	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("[%s] Client Write failed: %v", testName, err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("[%s] Client Read failed: %v", testName, err)
	}

	if !bytes.Equal(buf[:n], testData) {
		t.Fatalf("[%s] Data mismatch: got %q, want %q", testName, string(buf[:n]), string(testData))
	}

	wg.Wait()
	if serverErr != nil {
		t.Fatalf("[%s] Server error: %v", testName, serverErr)
	}

	t.Logf("[%s] PASSED ✓", testName)
}

// Test 1: No obfuscation (baseline)
func TestNoObfuscation(t *testing.T) {
	config := &umbra.Config{
		Curve: elliptic.P256(),
	}
	testEcho(t, config, config, "NoObfuscation")
}

// Test 2: Basic level + HTTP mode
func TestBasicHTTPObfuscation(t *testing.T) {
	serverConfig := &umbra.Config{
		Curve: elliptic.P256(),
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled: true,
			Level:   umbra.ObfuscationLevelBasic,
			Mode:    umbra.ObfuscationHTTP,
		},
	}
	clientConfig := &umbra.Config{
		Curve: elliptic.P256(),
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled: true,
			Level:   umbra.ObfuscationLevelBasic,
			Mode:    umbra.ObfuscationHTTP,
		},
	}
	testEcho(t, serverConfig, clientConfig, "BasicHTTP")
}

// Test 3: Basic level + Random mode
func TestBasicRandomObfuscation(t *testing.T) {
	serverConfig := &umbra.Config{
		Curve: elliptic.P256(),
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled: true,
			Level:   umbra.ObfuscationLevelBasic,
			Mode:    umbra.ObfuscationRandom,
		},
	}
	clientConfig := &umbra.Config{
		Curve: elliptic.P256(),
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled: true,
			Level:   umbra.ObfuscationLevelBasic,
			Mode:    umbra.ObfuscationRandom,
		},
	}
	testEcho(t, serverConfig, clientConfig, "BasicRandom")
}

// Test 4: Basic level + WebSocket mode
func TestBasicWebSocketObfuscation(t *testing.T) {
	serverConfig := &umbra.Config{
		Curve: elliptic.P256(),
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled:   true,
			Level:     umbra.ObfuscationLevelBasic,
			Mode:      umbra.ObfuscationWebSocket,
			Domain:    "test.example.com",
			CoverPath: "/ws",
		},
	}
	clientConfig := &umbra.Config{
		Curve: elliptic.P256(),
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled:   true,
			Level:     umbra.ObfuscationLevelBasic,
			Mode:      umbra.ObfuscationWebSocket,
			Domain:    "test.example.com",
			CoverPath: "/ws",
		},
	}
	testEcho(t, serverConfig, clientConfig, "BasicWebSocket")
}

// Test 5: Advanced level with TLS + WebSocket
func TestAdvancedTLSWebSocketObfuscation(t *testing.T) {
	certPEM, keyPEM, err := umbra.GenerateSelfSignedCert([]string{"test.example.com"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

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
			Domain:    "test.example.com",
			CoverPath: "/ws",
		},
	}
	clientConfig := &umbra.Config{
		Curve: elliptic.P256(),
		TLS: &umbra.TLSConfig{
			ServerName: "test.example.com",
			SkipVerify: true,
		},
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled:   true,
			Level:     umbra.ObfuscationLevelAdvanced,
			Mode:      umbra.ObfuscationWebSocket,
			Domain:    "test.example.com",
			CoverPath: "/ws",
		},
	}
	testEcho(t, serverConfig, clientConfig, "AdvancedTLSWebSocket")
}

// Test 6: Advanced TLS + HTTP mode
func TestAdvancedTLSHTTPObfuscation(t *testing.T) {
	certPEM, keyPEM, err := umbra.GenerateSelfSignedCert([]string{"test.example.com"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	serverConfig := &umbra.Config{
		Curve: elliptic.P256(),
		TLS: &umbra.TLSConfig{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		},
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled: true,
			Level:   umbra.ObfuscationLevelAdvanced,
			Mode:    umbra.ObfuscationHTTP,
			Domain:  "test.example.com",
		},
	}
	clientConfig := &umbra.Config{
		Curve: elliptic.P256(),
		TLS: &umbra.TLSConfig{
			ServerName: "test.example.com",
			SkipVerify: true,
		},
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled: true,
			Level:   umbra.ObfuscationLevelAdvanced,
			Mode:    umbra.ObfuscationHTTP,
			Domain:  "test.example.com",
		},
	}
	testEcho(t, serverConfig, clientConfig, "AdvancedTLSHTTP")
}

// Test 7: Advanced TLS + Random mode
func TestAdvancedTLSRandomObfuscation(t *testing.T) {
	certPEM, keyPEM, err := umbra.GenerateSelfSignedCert([]string{"test.example.com"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	serverConfig := &umbra.Config{
		Curve: elliptic.P256(),
		TLS: &umbra.TLSConfig{
			CertPEM: certPEM,
			KeyPEM:  keyPEM,
		},
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled: true,
			Level:   umbra.ObfuscationLevelAdvanced,
			Mode:    umbra.ObfuscationRandom,
			Domain:  "test.example.com",
		},
	}
	clientConfig := &umbra.Config{
		Curve: elliptic.P256(),
		TLS: &umbra.TLSConfig{
			ServerName: "test.example.com",
			SkipVerify: true,
		},
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled: true,
			Level:   umbra.ObfuscationLevelAdvanced,
			Mode:    umbra.ObfuscationRandom,
			Domain:  "test.example.com",
		},
	}
	testEcho(t, serverConfig, clientConfig, "AdvancedTLSRandom")
}

// Test 8: Obfuscation + Compression together
func TestObfuscationWithCompression(t *testing.T) {
	serverConfig := &umbra.Config{
		Curve: elliptic.P256(),
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled: true,
			Level:   umbra.ObfuscationLevelBasic,
			Mode:    umbra.ObfuscationRandom,
		},
		Compression: &umbra.CompressionConfig{
			Enabled: true,
			Type:    umbra.CompressionSnappy,
		},
	}
	clientConfig := &umbra.Config{
		Curve: elliptic.P256(),
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled: true,
			Level:   umbra.ObfuscationLevelBasic,
			Mode:    umbra.ObfuscationRandom,
		},
		Compression: &umbra.CompressionConfig{
			Enabled: true,
			Type:    umbra.CompressionSnappy,
		},
	}
	testEcho(t, serverConfig, clientConfig, "ObfuscationWithCompression")
}

// Test 9: Advanced TLS + WebSocket + Compression (full stack)
func TestAdvancedFullStack(t *testing.T) {
	certPEM, keyPEM, err := umbra.GenerateSelfSignedCert([]string{"test.example.com"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

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
			Domain:    "test.example.com",
			CoverPath: "/ws",
		},
		Compression: &umbra.CompressionConfig{
			Enabled: true,
			Type:    umbra.CompressionLZ4,
		},
	}
	clientConfig := &umbra.Config{
		Curve: elliptic.P256(),
		TLS: &umbra.TLSConfig{
			ServerName: "test.example.com",
			SkipVerify: true,
		},
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled:   true,
			Level:     umbra.ObfuscationLevelAdvanced,
			Mode:      umbra.ObfuscationWebSocket,
			Domain:    "test.example.com",
			CoverPath: "/ws",
		},
		Compression: &umbra.CompressionConfig{
			Enabled: true,
			Type:    umbra.CompressionLZ4,
		},
	}
	testEcho(t, serverConfig, clientConfig, "AdvancedFullStack")
}

// Test 10: Multiple messages in sequence
func TestMultipleMessages(t *testing.T) {
	serverConfig := &umbra.Config{
		Curve: elliptic.P256(),
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled: true,
			Level:   umbra.ObfuscationLevelBasic,
			Mode:    umbra.ObfuscationRandom,
		},
	}
	clientConfig := &umbra.Config{
		Curve: elliptic.P256(),
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled: true,
			Level:   umbra.ObfuscationLevelBasic,
			Mode:    umbra.ObfuscationRandom,
		},
	}

	listener, err := umbra.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	messageCount := 20

	var wg sync.WaitGroup
	var serverErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			serverErr = fmt.Errorf("Accept: %v", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		for i := 0; i < messageCount; i++ {
			n, err := conn.Read(buf)
			if err != nil {
				serverErr = fmt.Errorf("Read msg %d: %v", i, err)
				return
			}
			_, err = conn.Write(buf[:n])
			if err != nil {
				serverErr = fmt.Errorf("Write msg %d: %v", i, err)
				return
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)
	conn, err := umbra.Dial("tcp", addr, clientConfig)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	for i := 0; i < messageCount; i++ {
		msg := []byte(fmt.Sprintf("Message #%d with obfuscation 混淆消息", i))
		_, err = conn.Write(msg)
		if err != nil {
			t.Fatalf("Write msg %d failed: %v", i, err)
		}

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("Read msg %d failed: %v", i, err)
		}

		if !bytes.Equal(buf[:n], msg) {
			t.Fatalf("Msg %d mismatch: got %q, want %q", i, string(buf[:n]), string(msg))
		}
	}

	wg.Wait()
	if serverErr != nil {
		t.Fatalf("Server error: %v", serverErr)
	}
	t.Logf("[MultipleMessages] PASSED ✓ (%d messages)", messageCount)
}

// Test 11: Large data transfer with obfuscation
func TestLargeDataObfuscation(t *testing.T) {
	serverConfig := &umbra.Config{
		Curve: elliptic.P256(),
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled: true,
			Level:   umbra.ObfuscationLevelBasic,
			Mode:    umbra.ObfuscationHTTP,
		},
	}
	clientConfig := &umbra.Config{
		Curve: elliptic.P256(),
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled: true,
			Level:   umbra.ObfuscationLevelBasic,
			Mode:    umbra.ObfuscationHTTP,
		},
	}

	listener, err := umbra.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	// Create a large payload (32KB)
	largeData := make([]byte, 32*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	var wg sync.WaitGroup
	var serverErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := listener.Accept()
		if err != nil {
			serverErr = fmt.Errorf("Accept: %v", err)
			return
		}
		defer conn.Close()

		// Read all data
		received := make([]byte, 0, len(largeData))
		buf := make([]byte, 4096)
		for len(received) < len(largeData) {
			n, err := conn.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				serverErr = fmt.Errorf("Read: %v", err)
				return
			}
			received = append(received, buf[:n]...)
		}

		// Echo back
		_, err = conn.Write(received)
		if err != nil {
			serverErr = fmt.Errorf("Write: %v", err)
		}
	}()

	time.Sleep(50 * time.Millisecond)
	conn, err := umbra.Dial("tcp", addr, clientConfig)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(largeData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Read all echoed data
	received := make([]byte, 0, len(largeData))
	buf := make([]byte, 4096)
	for len(received) < len(largeData) {
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("Read failed (got %d/%d bytes): %v", len(received), len(largeData), err)
		}
		received = append(received, buf[:n]...)
	}

	if !bytes.Equal(received, largeData) {
		t.Fatalf("Large data mismatch: got %d bytes, want %d bytes", len(received), len(largeData))
	}

	wg.Wait()
	if serverErr != nil {
		t.Fatalf("Server error: %v", serverErr)
	}
	t.Logf("[LargeData] PASSED ✓ (%d bytes)", len(largeData))
}

// Test 12: Concurrent connections with obfuscation
func TestConcurrentObfuscation(t *testing.T) {
	serverConfig := &umbra.Config{
		Curve: elliptic.P256(),
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled: true,
			Level:   umbra.ObfuscationLevelBasic,
			Mode:    umbra.ObfuscationRandom,
		},
	}

	listener, err := umbra.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	numClients := 5

	// Server: handle concurrent connections
	go func() {
		for i := 0; i < numClients; i++ {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				c.Write(buf[:n])
			}(conn)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	var wg sync.WaitGroup
	errors := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			clientConfig := &umbra.Config{
				Curve: elliptic.P256(),
				Obfuscation: &umbra.ObfuscationConfig{
					Enabled: true,
					Level:   umbra.ObfuscationLevelBasic,
					Mode:    umbra.ObfuscationRandom,
				},
			}

			conn, err := umbra.Dial("tcp", addr, clientConfig)
			if err != nil {
				errors <- fmt.Errorf("client %d dial: %v", id, err)
				return
			}
			defer conn.Close()

			msg := []byte(fmt.Sprintf("Concurrent client %d", id))
			_, err = conn.Write(msg)
			if err != nil {
				errors <- fmt.Errorf("client %d write: %v", id, err)
				return
			}

			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if err != nil {
				errors <- fmt.Errorf("client %d read: %v", id, err)
				return
			}

			if !bytes.Equal(buf[:n], msg) {
				errors <- fmt.Errorf("client %d data mismatch", id)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Fatalf("Concurrent test error: %v", err)
	}

	t.Logf("[ConcurrentObfuscation] PASSED ✓ (%d clients)", numClients)
}

// Test 13: ECDSA cert with Advanced mode
func TestAdvancedECDSACert(t *testing.T) {
	certPEM, keyPEM, err := umbra.GenerateSelfSignedCertECDSA([]string{"test.example.com"})
	if err != nil {
		t.Fatalf("GenerateSelfSignedCertECDSA failed: %v", err)
	}

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
			Domain:    "test.example.com",
			CoverPath: "/ws",
		},
	}
	clientConfig := &umbra.Config{
		Curve: elliptic.P256(),
		TLS: &umbra.TLSConfig{
			ServerName: "test.example.com",
			SkipVerify: true,
		},
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled:   true,
			Level:     umbra.ObfuscationLevelAdvanced,
			Mode:      umbra.ObfuscationWebSocket,
			Domain:    "test.example.com",
			CoverPath: "/ws",
		},
	}
	testEcho(t, serverConfig, clientConfig, "AdvancedECDSACert")
}
