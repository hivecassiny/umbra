package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/hivecassiny/umbra"
)

// Server example
func startServer() {
	listener, err := umbra.Listen("tcp", ":8080", nil)
	if err != nil {
		log.Fatal("Server listen error:", err)
	}
	defer listener.Close()

	fmt.Println("ECC Server listening on :8080")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}

		go handleServerConnection(conn)
	}
}

func handleServerConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Printf("New connection from %s\n", conn.RemoteAddr())

	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				log.Println("server Read error:", err)
			}
			break
		}

		message := string(buffer[:n])
		fmt.Printf("Received: %s", message)

		response := fmt.Sprintf("Server response: %s", message)
		_, err = conn.Write([]byte(response))
		if err != nil {
			log.Println("Write error:", err)
			break
		}
	}
}

// Client example
func startClient() {
	time.Sleep(100 * time.Millisecond) // Wait for server to start
	conn, err := umbra.Dial("tcp", "localhost:8080", nil)
	if err != nil {
		log.Fatal("Client dial error:", err)
	}
	defer conn.Close()

	fmt.Printf("Connected to %s\n", conn.RemoteAddr())

	// Send multiple messages for testing
	messages := []string{
		"Hello, ECC Socket 1!\n",
		"This is message 2\n",
		"Final message 3\n",
	}

	for _, msg := range messages {
		fmt.Printf("Sending: %s", msg)
		_, err = conn.Write([]byte(msg))
		if err != nil {
			log.Fatal("Write error:", err)
		}
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			log.Fatal("client Read error:", err)
		}

		fmt.Printf("Server reply: %s", string(buffer[:n]))
		time.Sleep(100 * time.Millisecond)
	}
}

// 1: cd to current path
// 2: use command like this: go test -v -test.run Test_EccSocket
func Test_EccSocket(t *testing.T) {

	// Start the server
	go startServer()
	time.Sleep(1 * time.Second)

	// Start the client
	startClient()
}
