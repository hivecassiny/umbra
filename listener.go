package umbra

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"net"
	"time"
)

// ECCListener represents a listener that accepts ECC-encrypted connections.
type ECCListener struct {
	listener net.Listener
	config   *Config
}

// Config holds configuration parameters for ECC encryption.
type Config struct {
	Curve           elliptic.Curve
	PrivateKey      *ecdsa.PrivateKey
	PublicKey       *ecdsa.PublicKey
	UseEphemeralKey bool
	Obfuscation     *ObfuscationConfig // Obfuscation configuration
	Compression     *CompressionConfig // Compression configuration
	TLS             *TLSConfig         // TLS configuration for advanced obfuscation
}

// Accept waits for and returns the next encrypted connection to the listener.
func (el *ECCListener) Accept() (net.Conn, error) {
	conn, err := el.listener.Accept()
	if err != nil {
		return nil, err
	}

	eccConn, err := NewConn(conn, el.config, false)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return eccConn, nil
}

// Close closes the listener.
func (el *ECCListener) Close() error {
	return el.listener.Close()
}

// Addr returns the listener's network address.
func (el *ECCListener) Addr() net.Addr {
	return el.listener.Addr()
}

// Dial establishes an encrypted connection to the specified network address.
// It performs a handshake to exchange public keys and derive symmetric encryption keys.
func Dial(network, address string, config *Config) (*ECCConn, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, config, true)
}

// DialTimeout establishes an encrypted connection to the specified network address with timeout.
func DialTimeout(timeout time.Duration, network, address string, config *Config) (*ECCConn, error) {
	conn, err := net.DialTimeout(network, address, timeout)
	if err != nil {
		return nil, err
	}
	return NewConn(conn, config, true)
}

// Listen creates a listener for encrypted connections on the specified network address.
func Listen(network, address string, config *Config) (*ECCListener, error) {
	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = &Config{Curve: elliptic.P256()}
	}

	return &ECCListener{
		listener: listener,
		config:   config,
	}, nil
}
