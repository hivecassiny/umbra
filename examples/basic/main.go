// Basic example demonstrates simple ECC encrypted communication.
//
// Usage:
//
//	go run ./examples/basic/
package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/hivecassiny/umbra"
)

func main() {
	// Start server with default config (auto-generate keys, P-256 curve)
	listener, err := umbra.Listen("tcp", "127.0.0.1:0", nil)
	if err != nil {
		log.Fatal("Listen error:", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	fmt.Printf("✅ ECC Server listening on %s\n\n", addr)

	// Server goroutine: echo back received data
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			return
		}
		defer conn.Close()
		fmt.Printf("📥 New connection from %s\n", conn.RemoteAddr())

		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Println("Read error:", err)
				}
				return
			}
			msg := string(buf[:n])
			fmt.Printf("   Server received: %s\n", msg)

			response := fmt.Sprintf("Echo: %s", msg)
			conn.Write([]byte(response))
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Client: connect and send messages
	conn, err := umbra.Dial("tcp", addr, nil)
	if err != nil {
		log.Fatal("Dial error:", err)
	}
	defer conn.Close()

	// umbra.ECCConn implements net.Conn, so it works with any net.Conn consumer
	var c net.Conn = conn
	fmt.Printf("📤 Connected to %s\n\n", c.RemoteAddr())

	messages := []string{
		"Hello, Umbra!",
		"ECC encrypted message 🔐",
		"你好世界",
	}

	for i, msg := range messages {
		fmt.Printf("   [%d] Sending: %s\n", i+1, msg)
		c.Write([]byte(msg))

		buf := make([]byte, 1024)

		n, err := c.Read(buf)
		if err != nil {
			log.Fatal("Read error:", err)
		}

		fmt.Printf("   [%d] Reply:   %s\n\n", i+1, string(buf[:n]))

		time.Sleep(100 * time.Millisecond)

	}

	fmt.Println("✅ Done!")
}
