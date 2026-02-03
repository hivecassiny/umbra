package examples

import (
	"crypto/elliptic"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/hivecassiny/umbra"
)

// Example 1: Using fixed key pairs (server and client use pre-generated keys)
func ExampleWithFixedKeys() {
	fmt.Println("=== Example 1: Using Fixed Key Pairs ===")

	// Generate fixed key pairs (should be pre-generated and saved in real applications)
	serverPrivKey, _ := umbra.GenerateKey(nil)
	clientPrivKey, _ := umbra.GenerateKey(nil)

	// Get public keys
	serverPubKey := &serverPrivKey.PublicKey
	clientPubKey := &clientPrivKey.PublicKey

	// Server configuration
	serverConfig := &umbra.Config{
		Curve:           elliptic.P256(),
		PrivateKey:      serverPrivKey,
		PublicKey:       clientPubKey, // Optional: pre-set client public key for verification
		UseEphemeralKey: false,        // Use fixed key
	}

	// Client configuration
	clientConfig := &umbra.Config{
		Curve:           elliptic.P256(),
		PrivateKey:      clientPrivKey,
		PublicKey:       serverPubKey, // Pre-set server public key
		UseEphemeralKey: false,
	}

	// Start server
	go func() {
		listener, err := umbra.Listen("tcp", ":8081", serverConfig)
		if err != nil {
			log.Fatal("Server listen error:", err)
		}
		defer listener.Close()

		fmt.Println("Fixed key server listening on :8081")
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal("Accept error:", err)
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			log.Fatal("Read error:", err)
		}

		fmt.Printf("Fixed key server received: %s\n", string(buf[:n]))
		conn.Write([]byte("Fixed key server response"))
	}()

	time.Sleep(100 * time.Millisecond)

	// Start client
	conn, err := umbra.Dial("tcp", "localhost:8081", clientConfig)
	if err != nil {
		log.Fatal("Client dial error:", err)
	}
	defer conn.Close()

	conn.Write([]byte("Hello from fixed key client"))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal("Read error:", err)
	}

	fmt.Printf("Fixed key client received: %s\n", string(buf[:n]))
}

// Example 2: Using ephemeral keys (generate new key for each connection)
func ExampleWithEphemeralKeys() {
	fmt.Println("\n=== Example 2: Using Ephemeral Keys ===")

	// Server configuration - use ephemeral keys
	serverConfig := &umbra.Config{
		Curve:           elliptic.P384(), // Use stronger curve
		UseEphemeralKey: true,            // Force use of ephemeral keys
	}

	go func() {
		listener, err := umbra.Listen("tcp", ":8082", serverConfig)
		if err != nil {
			log.Fatal("Server listen error:", err)
		}
		defer listener.Close()

		fmt.Println("Ephemeral key server listening on :8082")
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal("Accept error:", err)
		}
		defer conn.Close()

		// Display server's ephemeral public key
		eccConn := conn.(*umbra.ECCConn)
		fmt.Printf("Server ephemeral public key: %x...\n",
			eccConn.GetPublicKey().X.Bytes()[:10])

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			log.Fatal("Read error:", err)
		}

		fmt.Printf("Ephemeral key server received: %s\n", string(buf[:n]))
		conn.Write([]byte("Ephemeral key server response"))
	}()

	time.Sleep(100 * time.Millisecond)

	// Client configuration - also use ephemeral keys
	clientConfig := &umbra.Config{
		Curve:           elliptic.P384(),
		UseEphemeralKey: true,
	}

	conn, err := umbra.Dial("tcp", "localhost:8082", clientConfig)
	if err != nil {
		log.Fatal("Client dial error:", err)
	}
	defer conn.Close()

	// Display client's ephemeral public key
	fmt.Printf("Client ephemeral public key: %x...\n",
		conn.GetPublicKey().X.Bytes()[:10])

	conn.Write([]byte("Hello from ephemeral key client"))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal("Read error:", err)
	}

	fmt.Printf("Ephemeral key client received: %s\n", string(buf[:n]))
}

// Example 3: Using different elliptic curves
func ExampleWithDifferentCurves() {
	fmt.Println("\n=== Example 3: Using Different Elliptic Curves ===")

	curves := []elliptic.Curve{
		elliptic.P224(), // Weaker curve (not recommended for production)
		elliptic.P256(), // Common curve
		elliptic.P384(), // Stronger curve
		elliptic.P521(), // Strongest curve
	}

	for i, curve := range curves {
		port := 8090 + i

		config := &umbra.Config{
			Curve:      curve,
			PrivateKey: nil, // Use ephemeral keys
		}

		// Server
		go func(curve elliptic.Curve, port int) {
			listener, err := umbra.Listen("tcp", fmt.Sprintf(":%d", port), config)
			if err != nil {
				log.Printf("Curve server %d failed to start: %v", port, err)
				return
			}
			defer listener.Close()

			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			conn.Write([]byte(fmt.Sprintf("Curve %s response", curve.Params().Name)))

			fmt.Printf("Curve %s server completed communication, received: %s\n", curve.Params().Name, string(buf[:n]))
		}(curve, port)

		time.Sleep(50 * time.Millisecond)

		// Client
		conn, err := umbra.Dial("tcp", fmt.Sprintf("localhost:%d", port), config)
		if err != nil {
			log.Printf("Curve client %d connection failed: %v", port, err)
			continue
		}

		conn.Write([]byte(fmt.Sprintf("Testing curve %s", curve.Params().Name)))
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err == nil {
			fmt.Printf("Curve %s client received: %s\n", curve.Params().Name, string(buf[:n]))
		}
		conn.Close()

		time.Sleep(100 * time.Millisecond)
	}
}

// Example 4: Loading keys from PEM files
func ExampleWithPEMFiles() {
	fmt.Println("\n=== Example 4: PEM Key File Usage ===")

	// Generate and save key pair
	privKey, _ := umbra.GenerateKey(nil)

	// Encode to PEM
	privKeyPEM, _ := umbra.EncodePrivateKey(privKey)
	pubKeyPEM, _ := umbra.EncodePublicKey(&privKey.PublicKey)

	fmt.Printf("Private Key PEM:\n%s\n", privKeyPEM)
	fmt.Printf("Public Key PEM:\n%s\n", pubKeyPEM)

	// Decode from PEM
	decodedPrivKey, err := umbra.DecodePrivateKey(privKeyPEM)
	if err != nil {
		log.Fatal("Private key decode error:", err)
	}

	decodedPubKey, err := umbra.DecodePublicKey(pubKeyPEM)
	if err != nil {
		log.Fatal("Public key decode error:", err)
	}

	// Create configuration using decoded keys
	config := &umbra.Config{
		PrivateKey: decodedPrivKey,
		PublicKey:  decodedPubKey,
	}

	go func() {
		listener, err := umbra.Listen("tcp", ":8083", config)
		if err != nil {
			log.Fatal("PEM server error:", err)
		}
		defer listener.Close()

		fmt.Println("PEM key server listening on :8083")
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		conn.Write([]byte("PEM key server response"))
		fmt.Printf("PEM server received: %s\n", string(buf[:n]))
	}()

	time.Sleep(100 * time.Millisecond)

	conn, err := umbra.Dial("tcp", "localhost:8083", config)
	if err != nil {
		log.Fatal("PEM client error:", err)
	}
	defer conn.Close()

	conn.Write([]byte("Hello from PEM client"))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal("Read error:", err)
	}

	fmt.Printf("PEM client received: %s\n", string(buf[:n]))
}

// Example 5: Performance testing and concurrent connections
func ExamplePerformanceTest() {
	fmt.Println("\n=== Example 5: Performance Test and Concurrency ===")

	// Start performance test server
	go func() {
		listener, err := umbra.Listen("tcp", ":8084", nil)
		if err != nil {
			log.Fatal("Performance test server error:", err)
		}
		defer listener.Close()

		fmt.Println("Performance test server listening on :8084")

		for i := 0; i < 5; i++ {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}

			go func(conn net.Conn, id int) {
				defer conn.Close()
				start := time.Now()

				buf := make([]byte, 1024)
				for j := 0; j < 10; j++ {
					msg := fmt.Sprintf("Message %d from client %d", j, id)
					conn.Write([]byte(msg))

					n, err := conn.Read(buf)
					fmt.Printf("Performance test server:%d received: %s", id, string(buf[:n]))
					if err != nil {
						break
					}

					if j == 0 {
						fmt.Printf("Connection %d first handshake time: %v\n", id, time.Since(start))
					}
				}
			}(conn, i)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Start multiple clients for concurrent testing
	for i := 0; i < 3; i++ {
		go func(clientID int) {
			conn, err := umbra.Dial("tcp", "localhost:8084", nil)
			if err != nil {
				log.Printf("Client %d connection error: %v", clientID, err)
				return
			}
			defer conn.Close()

			buf := make([]byte, 1024)
			for j := 0; j < 10; j++ {
				conn.Write([]byte(fmt.Sprintf("Client %d message %d", clientID, j)))
				conn.Read(buf)
			}

			fmt.Printf("Client %d completed test\n", clientID)
		}(i)
	}

	time.Sleep(2 * time.Second)
}
