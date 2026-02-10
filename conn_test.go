package umbra_test

import (
	"crypto/elliptic"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/hivecassiny/umbra"
)

// Test_FixedKeys tests using fixed key pairs (server and client use pre-generated keys)
func Test_FixedKeys(t *testing.T) {
	// Generate fixed key pairs
	serverPrivKey, _ := umbra.GenerateKey(nil)
	clientPrivKey, _ := umbra.GenerateKey(nil)

	// Get public keys
	serverPubKey := &serverPrivKey.PublicKey
	clientPubKey := &clientPrivKey.PublicKey

	// Server configuration
	serverConfig := &umbra.Config{
		Curve:           elliptic.P256(),
		PrivateKey:      serverPrivKey,
		PublicKey:       clientPubKey,
		UseEphemeralKey: false,
	}

	// Client configuration
	clientConfig := &umbra.Config{
		Curve:           elliptic.P256(),
		PrivateKey:      clientPrivKey,
		PublicKey:       serverPubKey,
		UseEphemeralKey: false,
	}

	listener, err := umbra.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("Server listen error: %v", err)
	}
	defer listener.Close()
	addr := listener.Addr().String()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		t.Logf("Fixed key server received: %s", string(buf[:n]))
		conn.Write([]byte("Fixed key server response"))
	}()

	time.Sleep(50 * time.Millisecond)

	conn, err := umbra.Dial("tcp", addr, clientConfig)
	if err != nil {
		t.Fatalf("Client dial error: %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("Hello from fixed key client"))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}

	t.Logf("Fixed key client received: %s", string(buf[:n]))
}

// Test_EphemeralKeys tests using ephemeral keys (generate new key for each connection)
func Test_EphemeralKeys(t *testing.T) {
	serverConfig := &umbra.Config{
		Curve:           elliptic.P384(),
		UseEphemeralKey: true,
	}

	listener, err := umbra.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("Server listen error: %v", err)
	}
	defer listener.Close()
	addr := listener.Addr().String()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		eccConn := conn.(*umbra.ECCConn)
		t.Logf("Server ephemeral public key: %x...",
			eccConn.GetPublicKey().X.Bytes()[:10])

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		t.Logf("Ephemeral key server received: %s", string(buf[:n]))
		conn.Write([]byte("Ephemeral key server response"))
	}()

	time.Sleep(50 * time.Millisecond)

	clientConfig := &umbra.Config{
		Curve:           elliptic.P384(),
		UseEphemeralKey: true,
	}

	conn, err := umbra.Dial("tcp", addr, clientConfig)
	if err != nil {
		t.Fatalf("Client dial error: %v", err)
	}
	defer conn.Close()

	t.Logf("Client ephemeral public key: %x...",
		conn.GetPublicKey().X.Bytes()[:10])

	conn.Write([]byte("Hello from ephemeral key client"))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	t.Logf("Ephemeral key client received: %s", string(buf[:n]))
}

// Test_DifferentCurves tests using different elliptic curves
func Test_DifferentCurves(t *testing.T) {
	curves := []elliptic.Curve{
		elliptic.P224(),
		elliptic.P256(),
		elliptic.P384(),
		elliptic.P521(),
	}

	for _, curve := range curves {
		curveName := curve.Params().Name
		t.Run(curveName, func(t *testing.T) {
			config := &umbra.Config{
				Curve: curve,
			}

			listener, err := umbra.Listen("tcp", "127.0.0.1:0", config)
			if err != nil {
				t.Fatalf("Listen failed: %v", err)
			}
			defer listener.Close()
			addr := listener.Addr().String()

			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()

				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				conn.Write([]byte(fmt.Sprintf("Curve %s response", curveName)))
				t.Logf("Curve %s server received: %s", curveName, string(buf[:n]))
			}()

			time.Sleep(50 * time.Millisecond)

			conn, err := umbra.Dial("tcp", addr, config)
			if err != nil {
				t.Fatalf("Dial failed: %v", err)
			}
			defer conn.Close()

			conn.Write([]byte(fmt.Sprintf("Testing curve %s", curveName)))
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				t.Fatalf("Read error: %v", err)
			}
			t.Logf("Curve %s client received: %s", curveName, string(buf[:n]))
		})
	}
}

// Test_PEMKeys tests loading keys from PEM format
func Test_PEMKeys(t *testing.T) {
	privKey, _ := umbra.GenerateKey(nil)

	privKeyPEM, _ := umbra.EncodePrivateKey(privKey)
	pubKeyPEM, _ := umbra.EncodePublicKey(&privKey.PublicKey)

	t.Logf("Private Key PEM:\n%s", privKeyPEM)
	t.Logf("Public Key PEM:\n%s", pubKeyPEM)

	decodedPrivKey, err := umbra.DecodePrivateKey(privKeyPEM)
	if err != nil {
		t.Fatalf("Private key decode error: %v", err)
	}

	decodedPubKey, err := umbra.DecodePublicKey(pubKeyPEM)
	if err != nil {
		t.Fatalf("Public key decode error: %v", err)
	}

	config := &umbra.Config{
		PrivateKey: decodedPrivKey,
		PublicKey:  decodedPubKey,
	}

	listener, err := umbra.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("Listen error: %v", err)
	}
	defer listener.Close()
	addr := listener.Addr().String()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		conn.Write([]byte("PEM key server response"))
		t.Logf("PEM server received: %s", string(buf[:n]))
	}()

	time.Sleep(50 * time.Millisecond)

	conn, err := umbra.Dial("tcp", addr, config)
	if err != nil {
		t.Fatalf("Dial error: %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("Hello from PEM client"))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	t.Logf("PEM client received: %s", string(buf[:n]))
}

// Test_Performance tests performance with concurrent connections
func Test_Performance(t *testing.T) {
	listener, err := umbra.Listen("tcp", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("Listen error: %v", err)
	}
	defer listener.Close()
	addr := listener.Addr().String()

	numClients := 3
	msgsPerClient := 10

	go func() {
		for i := 0; i < numClients; i++ {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}

			go func(conn net.Conn, id int) {
				defer conn.Close()
				start := time.Now()

				buf := make([]byte, 1024)
				for j := 0; j < msgsPerClient; j++ {
					n, err := conn.Read(buf)
					if err != nil {
						break
					}
					conn.Write(buf[:n])

					if j == 0 {
						t.Logf("Connection %d first round-trip: %v", id, time.Since(start))
					}
				}
			}(conn, i)
		}
	}()

	time.Sleep(50 * time.Millisecond)

	done := make(chan bool, numClients)
	for i := 0; i < numClients; i++ {
		go func(clientID int) {
			defer func() { done <- true }()

			conn, err := umbra.Dial("tcp", addr, nil)
			if err != nil {
				t.Errorf("Client %d connection error: %v", clientID, err)
				return
			}
			defer conn.Close()

			buf := make([]byte, 1024)
			for j := 0; j < msgsPerClient; j++ {
				msg := fmt.Sprintf("Client %d message %d", clientID, j)
				conn.Write([]byte(msg))
				conn.Read(buf)
			}

			t.Logf("Client %d completed %d messages", clientID, msgsPerClient)
		}(i)
	}

	for i := 0; i < numClients; i++ {
		<-done
	}
}

// Test_EccSocket tests basic ECC socket communication
func Test_EccSocket(t *testing.T) {
	listener, err := umbra.Listen("tcp", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("Server listen error: %v", err)
	}
	defer listener.Close()
	addr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func(c net.Conn) {
				defer c.Close()

				buffer := make([]byte, 1024)
				for {
					n, err := c.Read(buffer)
					if err != nil {
						if err != io.EOF {
							t.Logf("server Read error: %v", err)
						}
						break
					}

					message := string(buffer[:n])
					t.Logf("Received: %s", message)

					response := fmt.Sprintf("Server response: %s", message)
					_, err = c.Write([]byte(response))
					if err != nil {
						t.Logf("Write error: %v", err)
						break
					}
				}
			}(conn)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	conn, err := umbra.Dial("tcp", addr, nil)
	if err != nil {
		t.Fatalf("Client dial error: %v", err)
	}
	defer conn.Close()

	t.Logf("Connected to %s", conn.RemoteAddr())

	messages := []string{
		"Hello, ECC Socket 1!\n",
		"This is message 2\n",
		"Final message 3\n",
	}

	for _, msg := range messages {
		t.Logf("Sending: %s", msg)
		_, err = conn.Write([]byte(msg))
		if err != nil {
			t.Fatalf("Write error: %v", err)
		}
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			t.Fatalf("client Read error: %v", err)
		}

		t.Logf("Server reply: %s", string(buffer[:n]))
		time.Sleep(100 * time.Millisecond)
	}
}
