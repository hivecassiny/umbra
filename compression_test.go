package umbra

import (
	"bytes"
	"testing"
)

func TestCompressionAlgorithms(t *testing.T) {
	testData := []byte(`{
		"workers_online": 100,
		"workers_offline": 5,
		"platform": "linux",
		"run_time": 86400,
		"version": "1.0.0",
		"coin_infos": [
			{"coin_type": "BTC", "total_client": 50, "total_1_h_hash_rate": 1000000},
			{"coin_type": "ETH", "total_client": 50, "total_1_h_hash_rate": 2000000}
		],
		"cpu_usage": 45.5,
		"memory_usage": 62.3
	}`)

	tests := []struct {
		name   string
		config *CompressionConfig
	}{
		{
			name: "Gzip Default",
			config: &CompressionConfig{
				Enabled: true,
				Type:    CompressionGzip,
				Level:   0, // Default
			},
		},
		{
			name: "Gzip Fast",
			config: &CompressionConfig{
				Enabled: true,
				Type:    CompressionGzip,
				Level:   1,
			},
		},
		{
			name: "Gzip Best",
			config: &CompressionConfig{
				Enabled: true,
				Type:    CompressionGzip,
				Level:   9,
			},
		},
		{
			name: "LZ4 Default",
			config: &CompressionConfig{
				Enabled: true,
				Type:    CompressionLZ4,
				Level:   0,
			},
		},
		{
			name: "LZ4 High",
			config: &CompressionConfig{
				Enabled: true,
				Type:    CompressionLZ4,
				Level:   9,
			},
		},
		{
			name: "Zstd Default",
			config: &CompressionConfig{
				Enabled: true,
				Type:    CompressionZstd,
				Level:   0,
			},
		},
		{
			name: "Zstd Fast",
			config: &CompressionConfig{
				Enabled: true,
				Type:    CompressionZstd,
				Level:   1,
			},
		},
		{
			name: "Zstd Best",
			config: &CompressionConfig{
				Enabled: true,
				Type:    CompressionZstd,
				Level:   19,
			},
		},
		{
			name: "Snappy",
			config: &CompressionConfig{
				Enabled: true,
				Type:    CompressionSnappy,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comp, err := createCompressor(tt.config)
			if err != nil {
				t.Fatalf("createCompressor failed: %v", err)
			}

			// Compress
			compressed, err := comp.compress(testData)
			if err != nil {
				t.Fatalf("compress failed: %v", err)
			}

			// Log compression ratio
			ratio := float64(len(compressed)) / float64(len(testData)) * 100
			t.Logf("Original: %d bytes, Compressed: %d bytes (%.1f%%)",
				len(testData), len(compressed), ratio)

			// Decompress
			decompressed, err := comp.decompress(compressed)
			if err != nil {
				t.Fatalf("decompress failed: %v", err)
			}

			// Verify
			if !bytes.Equal(testData, decompressed) {
				t.Errorf("decompressed data doesn't match original")
			}
		})
	}
}

func TestCompressionNone(t *testing.T) {
	config := &CompressionConfig{
		Enabled: false,
	}
	comp, err := createCompressor(config)
	if err != nil {
		t.Fatalf("createCompressor failed: %v", err)
	}
	if comp != nil {
		t.Error("expected nil compressor for disabled compression")
	}
}

func BenchmarkCompression(b *testing.B) {
	testData := bytes.Repeat([]byte(`{"key": "value", "number": 12345}`), 100)

	benchmarks := []struct {
		name   string
		config *CompressionConfig
	}{
		{"Gzip-1", &CompressionConfig{Enabled: true, Type: CompressionGzip, Level: 1}},
		{"Gzip-6", &CompressionConfig{Enabled: true, Type: CompressionGzip, Level: 6}},
		{"LZ4", &CompressionConfig{Enabled: true, Type: CompressionLZ4}},
		{"Zstd", &CompressionConfig{Enabled: true, Type: CompressionZstd}},
		{"Snappy", &CompressionConfig{Enabled: true, Type: CompressionSnappy}},
	}

	for _, bm := range benchmarks {
		comp, _ := createCompressor(bm.config)

		b.Run(bm.name+"-Compress", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = comp.compress(testData)
			}
		})

		compressed, _ := comp.compress(testData)
		b.Run(bm.name+"-Decompress", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = comp.decompress(compressed)
			}
		})
	}
}
