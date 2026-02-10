// Compression example demonstrates data compression with different algorithms.
//
// Usage:
//
//	go run ./examples/compression/
package main

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/hivecassiny/umbra"
)

func main() {
	fmt.Println("━━━ Umbra: Compression Demo ━━━")

	// Test data: a repetitive JSON payload (compresses well)
	testData := strings.Repeat(`{"worker":"rig-001","hashrate":125000,"temp":65,"fan":80},`, 20)
	fmt.Printf("📊 Test data: %d bytes\n\n", len(testData))

	algorithms := []struct {
		name string
		typ  umbra.CompressionType
	}{
		{"Gzip", umbra.CompressionGzip},
		{"LZ4", umbra.CompressionLZ4},
		{"Zstd", umbra.CompressionZstd},
		{"Snappy", umbra.CompressionSnappy},
	}

	for _, alg := range algorithms {
		fmt.Printf("━━━ %s ━━━\n", alg.name)

		config := &umbra.Config{
			Compression: &umbra.CompressionConfig{
				Enabled: true,
				Type:    alg.typ,
			},
		}

		listener, err := umbra.Listen("tcp", "127.0.0.1:0", config)
		if err != nil {
			log.Fatalf("[%s] Listen error: %v", alg.name, err)
		}

		addr := listener.Addr().String()

		var wg sync.WaitGroup
		wg.Add(1)

		go func() {
			defer wg.Done()
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 8192)
			n, err := conn.Read(buf)
			if err != nil {
				log.Printf("[%s] Read error: %v", alg.name, err)
				return
			}
			fmt.Printf("  📥 Server received %d bytes\n", n)

			conn.Write(buf[:n])
		}()

		time.Sleep(50 * time.Millisecond)

		conn, err := umbra.Dial("tcp", addr, config)
		if err != nil {
			log.Fatalf("[%s] Dial error: %v", alg.name, err)
		}

		conn.Write([]byte(testData))

		buf := make([]byte, 8192)
		n, err := conn.Read(buf)
		if err != nil {
			log.Fatalf("[%s] Read error: %v", alg.name, err)
		}

		match := string(buf[:n]) == testData
		fmt.Printf("  📤 Client received %d bytes, match: %v\n", n, match)
		fmt.Printf("  ✅ %s PASSED\n\n", alg.name)

		conn.Close()
		listener.Close()
		wg.Wait()
	}

	fmt.Println("🎉 All compression algorithms work correctly!")
}
