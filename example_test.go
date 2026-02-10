package umbra_test

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/hivecassiny/umbra"
)

// ExampleDial demonstrates basic ECC encrypted communication.
func ExampleDial() {
	// Start server
	listener, err := umbra.Listen("tcp", "127.0.0.1:0", nil)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	addr := listener.Addr().String()

	// Server goroutine: echo back received data
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
		conn.Write(buf[:n])
	}()

	time.Sleep(50 * time.Millisecond)

	// Client: connect and send a message
	conn, err := umbra.Dial("tcp", addr, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte("Hello, Umbra!"))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(buf[:n]))
	// Output: Hello, Umbra!
}

// ExampleListen demonstrates creating an ECC encrypted server.
func ExampleListen() {
	listener, err := umbra.Listen("tcp", "127.0.0.1:0", nil)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Echo server
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Println("Read error:", err)
				}
				return
			}
			conn.Write(buf[:n])
		}
	}()

	// Client connects
	conn, err := umbra.Dial("tcp", listener.Addr().String(), nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte("ping"))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	fmt.Println(string(buf[:n]))
	// Output: ping
}

// ExampleGenerateKey demonstrates ECC key generation and PEM encoding.
func ExampleGenerateKey() {
	privKey, err := umbra.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}

	privPEM, err := umbra.EncodePrivateKey(privKey)
	if err != nil {
		log.Fatal(err)
	}

	pubPEM, err := umbra.EncodePublicKey(&privKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Private key PEM length: %d\n", len(privPEM))
	fmt.Printf("Public key PEM length: %d\n", len(pubPEM))

	// Verify round-trip
	decoded, err := umbra.DecodePrivateKey(privPEM)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Keys match: %v\n", decoded.D.Cmp(privKey.D) == 0)
	// Output:
	// Private key PEM length: 227
	// Public key PEM length: 178
	// Keys match: true
}

// ExampleDial_withObfuscation demonstrates connection with traffic obfuscation.
func ExampleDial_withObfuscation() {
	serverConfig := &umbra.Config{
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled: true,
			Level:   umbra.ObfuscationLevelBasic,
			Mode:    umbra.ObfuscationRandom,
		},
	}

	listener, err := umbra.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		conn.Write(buf[:n])
	}()

	time.Sleep(50 * time.Millisecond)

	clientConfig := &umbra.Config{
		Obfuscation: &umbra.ObfuscationConfig{
			Enabled: true,
			Level:   umbra.ObfuscationLevelBasic,
			Mode:    umbra.ObfuscationRandom,
		},
	}

	conn, err := umbra.Dial("tcp", listener.Addr().String(), clientConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte("obfuscated message"))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	fmt.Println(string(buf[:n]))
	// Output: obfuscated message
}

// ExampleDial_withCompression demonstrates connection with data compression.
func ExampleDial_withCompression() {
	config := &umbra.Config{
		Compression: &umbra.CompressionConfig{
			Enabled: true,
			Type:    umbra.CompressionSnappy,
		},
	}

	listener, err := umbra.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		conn.Write(buf[:n])
	}()

	time.Sleep(50 * time.Millisecond)

	conn, err := umbra.Dial("tcp", listener.Addr().String(), config)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// net.Conn interface is used transparently
	var c net.Conn = conn
	c.Write([]byte("compressed data"))
	buf := make([]byte, 1024)
	n, _ := c.Read(buf)
	fmt.Println(string(buf[:n]))
	// Output: compressed data
}
