package umbra

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ObfuscationMode defines the type of traffic obfuscation to use
type ObfuscationMode int

const (
	ObfuscationNone      ObfuscationMode = iota // No obfuscation
	ObfuscationHTTP                             // HTTP traffic obfuscation
	ObfuscationHTTPS                            // HTTPS traffic obfuscation (legacy, same as HTTP)
	ObfuscationRandom                           // Random padding obfuscation
	ObfuscationWebSocket                        // WebSocket frame encapsulation (recommended for DPI bypass)
)

// ObfuscationConfig holds configuration for traffic obfuscation
type ObfuscationConfig struct {
	Enabled bool             // Whether obfuscation is enabled
	Level   ObfuscationLevel // Obfuscation level (Basic or Advanced)
	Mode    ObfuscationMode  // Obfuscation mode to use

	// ===== Basic Mode Parameters =====
	MinPacketSize int // Minimum packet size for padding
	MaxPacketSize int // Maximum packet size for padding
	MinDelayMs    int // Minimum delay in milliseconds
	MaxDelayMs    int // Maximum delay in milliseconds

	// ===== Advanced Mode Parameters =====
	// The following are REQUIRED when Level=ObfuscationLevelAdvanced

	// Domain is the domain you control.
	// IMPORTANT: DPI systems inspect SNI. This domain appears in TLS handshake.
	// Example: "pool.yoursite.com"
	// WARNING: Do NOT use google.com or similar - active probing will detect this.
	Domain string

	// CoverPath is the WebSocket endpoint path.
	// Example: "/ws"
	// Your server should serve a normal website on / and forward /ws to your pool.
	// This helps defeat active probing by GFW.
	CoverPath string
}

// obfuscator interface defines the methods for different obfuscation strategies
type obfuscator interface {
	obfuscate(data []byte) ([]byte, error)
	deobfuscate(data []byte) ([]byte, error)
}

// HTTPObfuscator implements HTTP traffic obfuscation
type HTTPObfuscator struct {
	headers      []string
	isClient     bool
	minDelay     time.Duration
	maxDelay     time.Duration
	headerBuffer *bytes.Buffer
}

// RandomObfuscator implements random padding obfuscation
type RandomObfuscator struct {
	minSize     int
	maxSize     int
	paddingPool *sync.Pool
}

// createObfuscator creates an appropriate obfuscator based on the mode
func createObfuscator(mode ObfuscationMode, config *ObfuscationConfig, isClient bool) obfuscator {
	if config == nil {
		config = defaultObfuscationConfig()
	}

	switch mode {
	case ObfuscationHTTP, ObfuscationHTTPS:
		return newHTTPObfuscator(config, isClient)
	case ObfuscationRandom:
		return newRandomObfuscator(config)
	case ObfuscationWebSocket:
		return newWebSocketObfuscator(config, isClient)
	default:
		return &noopObfuscator{}
	}
}

// newHTTPObfuscator creates a new HTTP obfuscator
func newHTTPObfuscator(config *ObfuscationConfig, isClient bool) *HTTPObfuscator {
	obf := &HTTPObfuscator{
		isClient:     isClient,
		headerBuffer: bytes.NewBuffer(nil),
	}

	// Set delays
	obf.minDelay = time.Duration(config.MinDelayMs) * time.Millisecond
	obf.maxDelay = time.Duration(config.MaxDelayMs) * time.Millisecond

	// Generate appropriate headers
	domain := config.Domain
	if domain == "" {
		domain = "cdn.google.com"
	}

	if isClient {
		obf.headers = []string{
			fmt.Sprintf("POST /v1/data HTTP/1.1\r\n"),
			fmt.Sprintf("Host: %s\r\n", domain),
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n",
			"Content-Type: application/octet-stream\r\n",
			"Accept: */*\r\n",
			"Connection: keep-alive\r\n",
			"Transfer-Encoding: chunked\r\n",
		}
	} else {
		obf.headers = []string{
			"HTTP/1.1 200 OK\r\n",
			"Content-Type: application/octet-stream\r\n",
			"Cache-Control: no-cache\r\n",
			"Connection: keep-alive\r\n",
			"Transfer-Encoding: chunked\r\n",
		}
	}

	return obf
}

// obfuscate implements HTTP traffic obfuscation for outgoing data
func (h *HTTPObfuscator) obfuscate(data []byte) ([]byte, error) {
	h.headerBuffer.Reset()

	// Write headers
	for _, header := range h.headers {
		h.headerBuffer.WriteString(header)
	}

	h.headerBuffer.WriteString("\r\n")

	// Use chunked encoding for better obfuscation
	chunked := h.httpChunkEncode(data)
	result := make([]byte, h.headerBuffer.Len()+len(chunked))
	copy(result, h.headerBuffer.Bytes())
	copy(result[h.headerBuffer.Len():], chunked)

	// Add random delay to simulate real HTTP traffic
	if h.maxDelay > 0 {
		delayMs := h.minDelay + time.Duration(rand.Int63n(int64(h.maxDelay-h.minDelay+1)))
		time.Sleep(delayMs)
	}

	return result, nil
}

// deobfuscate extracts data from HTTP-obfuscated traffic
func (h *HTTPObfuscator) deobfuscate(data []byte) ([]byte, error) {
	// Skip HTTP headers by finding the first empty line
	doubleCRLF := []byte("\r\n\r\n")
	headerEnd := bytes.Index(data, doubleCRLF)
	if headerEnd == -1 {
		return nil, fmt.Errorf("invalid HTTP format")
	}

	bodyStart := headerEnd + len(doubleCRLF)
	body := data[bodyStart:]

	// Handle chunked encoding
	if strings.Contains(strings.ToLower(string(data)), "transfer-encoding: chunked") {
		return h.httpChunkDecode(body)
	}

	return body, nil
}

// httpChunkEncode encodes data using HTTP chunked transfer encoding
func (h *HTTPObfuscator) httpChunkEncode(data []byte) []byte {
	chunkSize := len(data)
	chunkHeader := fmt.Sprintf("%x\r\n", chunkSize)

	totalLen := len(chunkHeader) + chunkSize + len("\r\n0\r\n\r\n")
	result := make([]byte, 0, totalLen)
	result = append(result, chunkHeader...)
	result = append(result, data...)
	result = append(result, "\r\n0\r\n\r\n"...)

	return result
}

// httpChunkDecode decodes HTTP chunked transfer encoding
func (h *HTTPObfuscator) httpChunkDecode(data []byte) ([]byte, error) {
	var result bytes.Buffer
	remaining := data

	for len(remaining) > 0 {
		// Find chunk size line
		lineEnd := bytes.Index(remaining, []byte("\r\n"))
		if lineEnd == -1 {
			break
		}

		chunkSizeStr := string(remaining[:lineEnd])
		chunkSize, err := strconv.ParseInt(chunkSizeStr, 16, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid chunk size: %v", err)
		}

		if chunkSize == 0 {
			break // Last chunk
		}

		chunkStart := lineEnd + 2
		chunkEnd := chunkStart + int(chunkSize)
		if chunkEnd > len(remaining) {
			return nil, fmt.Errorf("incomplete chunk")
		}

		// Extract chunk data
		chunkData := remaining[chunkStart:chunkEnd]
		result.Write(chunkData)

		// Move to next chunk
		nextChunk := chunkEnd + 2 // Skip \r\n after chunk data
		if nextChunk >= len(remaining) {
			break
		}
		remaining = remaining[nextChunk:]
	}

	return result.Bytes(), nil
}

// newRandomObfuscator creates a new random padding obfuscator
func newRandomObfuscator(config *ObfuscationConfig) *RandomObfuscator {
	minSize, maxSize := config.MinPacketSize, config.MaxPacketSize
	if minSize <= 0 {
		minSize = 128
	}
	if maxSize <= minSize {
		maxSize = minSize + 1024
	}

	return &RandomObfuscator{
		minSize: minSize,
		maxSize: maxSize,
		paddingPool: &sync.Pool{
			New: func() interface{} { return make([]byte, maxSize) },
		},
	}
}

// obfuscate adds random padding to data with a length header for recovery.
// Format: [2-byte original length (big-endian)][original data][random padding]
func (r *RandomObfuscator) obfuscate(data []byte) ([]byte, error) {
	targetSize := r.minSize
	if r.maxSize > r.minSize {
		targetSize = r.minSize + rand.Intn(r.maxSize-r.minSize+1)
	}

	// Ensure we have at least 2 bytes for length header + original data
	minRequired := len(data) + 2
	if targetSize < minRequired {
		targetSize = minRequired
	}

	// Check data length fits in uint16
	if len(data) > 65535 {
		return nil, fmt.Errorf("data too large: %d bytes (max 65535)", len(data))
	}

	result := make([]byte, targetSize)
	// Write original data length (big-endian)
	binary.BigEndian.PutUint16(result[:2], uint16(len(data)))
	// Copy original data
	copy(result[2:], data)
	// Fill remaining bytes with random padding
	if paddingLen := targetSize - 2 - len(data); paddingLen > 0 {
		rand.Read(result[2+len(data):])
	}

	return result, nil
}

// deobfuscate removes random padding and extracts original data using length header.
func (r *RandomObfuscator) deobfuscate(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("data too short: need at least 2 bytes for length header")
	}

	originalLen := binary.BigEndian.Uint16(data[:2])
	if int(originalLen) > len(data)-2 {
		return nil, fmt.Errorf("invalid length header: claims %d bytes but only %d available", originalLen, len(data)-2)
	}

	return data[2 : 2+originalLen], nil
}

// noopObfuscator provides a no-operation obfuscator for when obfuscation is disabled
type noopObfuscator struct{}

func (n *noopObfuscator) obfuscate(data []byte) ([]byte, error) {
	return data, nil
}

func (n *noopObfuscator) deobfuscate(data []byte) ([]byte, error) {
	return data, nil
}

// defaultObfuscationConfig returns a default obfuscation configuration
func defaultObfuscationConfig() *ObfuscationConfig {
	return &ObfuscationConfig{
		Enabled:       true,
		Mode:          ObfuscationHTTPS,
		Domain:        "cdn.google.com",
		MinDelayMs:    5,
		MaxDelayMs:    50,
		MinPacketSize: 128,
		MaxPacketSize: 1460,
	}
}
