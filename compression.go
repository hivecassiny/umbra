package umbra

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"

	"github.com/golang/snappy"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

// CompressionType defines the compression algorithm to use.
type CompressionType uint8

const (
	CompressionNone   CompressionType = iota // No compression
	CompressionGzip                          // Gzip - good compression ratio, moderate speed
	CompressionLZ4                           // LZ4 - fastest, good for real-time
	CompressionZstd                          // Zstd - best compression ratio, fast
	CompressionSnappy                        // Snappy - fast, simple
)

// CompressionConfig holds configuration for data compression.
type CompressionConfig struct {
	Enabled bool
	Type    CompressionType
	Level   int // Compression level (algorithm specific, 0 = default)
}

// String returns the name of the compression type.
func (c CompressionType) String() string {
	switch c {
	case CompressionNone:
		return "none"
	case CompressionGzip:
		return "gzip"
	case CompressionLZ4:
		return "lz4"
	case CompressionZstd:
		return "zstd"
	case CompressionSnappy:
		return "snappy"
	default:
		return "unknown"
	}
}

// compressor handles compression and decompression for a specific algorithm.
type compressor interface {
	compress(data []byte) ([]byte, error)
	decompress(data []byte) ([]byte, error)
}

// createCompressor creates a compressor based on the configuration.
func createCompressor(config *CompressionConfig) (compressor, error) {
	if config == nil || !config.Enabled {
		return nil, nil
	}

	switch config.Type {
	case CompressionNone:
		return nil, nil
	case CompressionGzip:
		return newGzipCompressor(config.Level), nil
	case CompressionLZ4:
		return newLZ4Compressor(config.Level), nil
	case CompressionZstd:
		return newZstdCompressor(config.Level)
	case CompressionSnappy:
		return &snappyCompressor{}, nil
	default:
		return nil, fmt.Errorf("unknown compression type: %d", config.Type)
	}
}

// ============================================================================
// Gzip Compressor
// Level: 1 (BestSpeed) to 9 (BestCompression), 0 = DefaultCompression (6)
// ============================================================================

type gzipCompressor struct {
	level int
}

func newGzipCompressor(level int) *gzipCompressor {
	if level <= 0 || level > 9 {
		level = gzip.DefaultCompression
	}
	return &gzipCompressor{level: level}
}

func (g *gzipCompressor) compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, g.level)
	if err != nil {
		return nil, err
	}
	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (g *gzipCompressor) decompress(data []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	return io.ReadAll(gr)
}

// ============================================================================
// LZ4 Compressor
// Level: 0-9 (0 = fast, 9 = high compression)
// ============================================================================

type lz4Compressor struct {
	level lz4.CompressionLevel
}

func newLZ4Compressor(level int) *lz4Compressor {
	var lz4Level lz4.CompressionLevel
	switch {
	case level <= 0:
		lz4Level = lz4.Fast
	case level >= 9:
		lz4Level = lz4.Level9
	default:
		// Map 1-9 to LZ4 levels
		levels := []lz4.CompressionLevel{
			lz4.Fast, lz4.Level1, lz4.Level2, lz4.Level3, lz4.Level4,
			lz4.Level5, lz4.Level6, lz4.Level7, lz4.Level8, lz4.Level9,
		}
		lz4Level = levels[level]
	}
	return &lz4Compressor{level: lz4Level}
}

func (l *lz4Compressor) compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := lz4.NewWriter(&buf)
	zw.Apply(lz4.CompressionLevelOption(l.level))
	if _, err := zw.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (l *lz4Compressor) decompress(data []byte) ([]byte, error) {
	zr := lz4.NewReader(bytes.NewReader(data))
	return io.ReadAll(zr)
}

// ============================================================================
// Zstd Compressor
// Level: 1-22 (1 = fastest, 22 = best compression), 0 = default (3)
// ============================================================================

type zstdCompressor struct {
	encoder *zstd.Encoder
	decoder *zstd.Decoder
}

func newZstdCompressor(level int) (*zstdCompressor, error) {
	// Map level to zstd encoder level
	var encLevel zstd.EncoderLevel
	switch {
	case level <= 0:
		encLevel = zstd.SpeedDefault // Level 3
	case level <= 2:
		encLevel = zstd.SpeedFastest // Level 1
	case level <= 5:
		encLevel = zstd.SpeedDefault // Level 3
	case level <= 10:
		encLevel = zstd.SpeedBetterCompression // Level 7
	default:
		encLevel = zstd.SpeedBestCompression // Level 11+
	}

	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(encLevel))
	if err != nil {
		return nil, err
	}

	decoder, err := zstd.NewReader(nil)
	if err != nil {
		encoder.Close()
		return nil, err
	}

	return &zstdCompressor{
		encoder: encoder,
		decoder: decoder,
	}, nil
}

func (z *zstdCompressor) compress(data []byte) ([]byte, error) {
	return z.encoder.EncodeAll(data, nil), nil
}

func (z *zstdCompressor) decompress(data []byte) ([]byte, error) {
	return z.decoder.DecodeAll(data, nil)
}

// ============================================================================
// Snappy Compressor
// No level control - single fixed algorithm
// ============================================================================

type snappyCompressor struct{}

func (s *snappyCompressor) compress(data []byte) ([]byte, error) {
	return snappy.Encode(nil, data), nil
}

func (s *snappyCompressor) decompress(data []byte) ([]byte, error) {
	decoded, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, errors.New("snappy: failed to decompress data")
	}
	return decoded, nil
}
