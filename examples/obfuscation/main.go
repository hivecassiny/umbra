// Obfuscation example demonstrates traffic obfuscation with different modes.
//
// Usage:
//
//	go run ./examples/obfuscation/
package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/hivecassiny/umbra"
)

func main() {
	modes := []struct {
		name   string
		mode   umbra.ObfuscationMode
		domain string
		path   string
	}{
		{"Random", umbra.ObfuscationRandom, "", ""},
		{"HTTP", umbra.ObfuscationHTTP, "", ""},
		{"WebSocket", umbra.ObfuscationWebSocket, "example.com", "/ws"},
	}

	for _, m := range modes {
		fmt.Printf("━━━ Testing %s obfuscation ━━━\n", m.name)

		serverConfig := &umbra.Config{
			Obfuscation: &umbra.ObfuscationConfig{
				Enabled:   true,
				Level:     umbra.ObfuscationLevelBasic,
				Mode:      m.mode,
				Domain:    m.domain,
				CoverPath: m.path,
			},
		}

		clientConfig := &umbra.Config{
			Obfuscation: &umbra.ObfuscationConfig{
				Enabled:   true,
				Level:     umbra.ObfuscationLevelBasic,
				Mode:      m.mode,
				Domain:    m.domain,
				CoverPath: m.path,
			},
		}

		listener, err := umbra.Listen("tcp", "127.0.0.1:0", serverConfig)
		if err != nil {
			log.Fatalf("[%s] Listen error: %v", m.name, err)
		}
		defer listener.Close()

		addr := listener.Addr().String()

		var wg sync.WaitGroup
		wg.Add(1)

		// Server
		go func() {
			defer wg.Done()
			conn, err := listener.Accept()
			if err != nil {
				log.Printf("[%s] Accept error: %v", m.name, err)
				return
			}
			defer conn.Close()

			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				log.Printf("[%s] Read error: %v", m.name, err)
				return
			}
			fmt.Printf("  📥 Server received: %s\n", string(buf[:n]))
			conn.Write(buf[:n])
		}()

		time.Sleep(50 * time.Millisecond)

		// Client
		conn, err := umbra.Dial("tcp", addr, clientConfig)
		if err != nil {
			log.Fatalf("[%s] Dial error: %v", m.name, err)
		}

		testMsg := fmt.Sprintf("Hello via %s mode!", m.name)
		conn.Write([]byte(testMsg))

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			log.Fatalf("[%s] Read error: %v", m.name, err)
		}
		fmt.Printf("  📤 Client received: %s\n", string(buf[:n]))

		conn.Close()
		wg.Wait()
		fmt.Printf("  ✅ %s mode PASSED\n\n", m.name)
	}

	fmt.Println("🎉 All obfuscation modes work correctly!")
}
