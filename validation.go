package umbra

import (
	"fmt"
	"strings"
)

// ObfuscationLevel defines the strength of traffic obfuscation
type ObfuscationLevel int

const (
	// ObfuscationLevelBasic provides padding and basic header obfuscation.
	// No special configuration required. Suitable for basic privacy needs.
	ObfuscationLevelBasic ObfuscationLevel = iota

	// ObfuscationLevelAdvanced provides TLS + WebSocket encapsulation.
	// REQUIRES: Domain and TLS configuration.
	// This mode makes traffic appear as legitimate HTTPS WebSocket communication.
	// Use this mode to bypass DPI (Deep Packet Inspection) systems.
	//
	// Required configuration:
	//   - ObfuscationConfig.Domain: A domain you control (e.g., "pool.yoursite.com")
	//   - Config.TLS: TLS certificate configuration
	//
	// IMPORTANT: Do NOT use domains like google.com or cloudflare.com.
	// DPI systems perform active probing - they will connect to verify
	// if your server is actually the claimed domain. If not, your IP may be blocked.
	ObfuscationLevelAdvanced
)

// dangerousDomains are domains that should not be used for SNI spoofing
// because they will be detected by active probing
var dangerousDomains = []string{
	"google.com",
	"googleapis.com",
	"cloudflare.com",
	"amazon.com",
	"amazonaws.com",
	"microsoft.com",
	"azure.com",
	"facebook.com",
	"twitter.com",
	"apple.com",
}

// ValidateConfig validates the configuration and returns user-friendly errors.
// Call this before creating connections to catch configuration errors early.
func ValidateConfig(config *Config, isServer bool) error {
	if config == nil {
		return nil
	}

	// Validate obfuscation config if enabled
	if config.Obfuscation != nil && config.Obfuscation.Enabled {
		if err := validateObfuscationConfig(config, isServer); err != nil {
			return err
		}
	}

	return nil
}

// validateObfuscationConfig validates obfuscation-specific settings
func validateObfuscationConfig(config *Config, isServer bool) error {
	obf := config.Obfuscation

	// Basic mode doesn't require special validation
	if obf.Level == ObfuscationLevelBasic {
		return nil
	}

	// Advanced mode validation
	if obf.Level == ObfuscationLevelAdvanced {
		// Domain is required for advanced mode
		if obf.Domain == "" {
			return fmt.Errorf(`advanced obfuscation mode requires Domain configuration

  Domain is the domain name you control, e.g., "pool.yoursite.com"
  
  Why is this required?
  - The SNI field in TLS handshake will show this domain
  - DPI systems use SNI to identify what website you're connecting to
  - Using your own domain avoids detection by active probing
  
  DO NOT use google.com, cloudflare.com, or similar major domains!
  DPI systems will actively connect to verify if your server really belongs
  to that domain. If not, your IP may be blocked.
  
  Example configuration:
    config.Obfuscation.Domain = "pool.yoursite.com"`)
		}

		// Check for dangerous domains
		domainLower := strings.ToLower(obf.Domain)
		for _, dangerous := range dangerousDomains {
			if strings.Contains(domainLower, dangerous) {
				return fmt.Errorf(`WARNING: Using "%s" as domain is risky

  DPI systems perform active probing:
  1. They detect your TLS connection claims to be "%s"
  2. They connect to the real %s to compare responses
  3. If responses don't match, your IP may be blocked
  
  RECOMMENDATION: Use a domain you own and control.
  
  Steps to set up properly:
  1. Buy a cheap domain (e.g., from Namecheap, $5-10/year)
  2. Point it to your server
  3. Configure Nginx to serve a simple website on /
  4. Use this library for WebSocket connections on /ws`, obf.Domain, obf.Domain, dangerous)
			}
		}

		// TLS is required for advanced mode
		if config.TLS == nil {
			return fmt.Errorf(`advanced obfuscation mode requires TLS configuration

  For SERVER, you need:
    config.TLS = &umbra.TLSConfig{
        CertPEM: "-----BEGIN CERTIFICATE-----...",
        KeyPEM:  "-----BEGIN PRIVATE KEY-----...",
    }
  
  To generate a self-signed certificate:
    certPEM, keyPEM, err := umbra.GenerateSelfSignedCert([]string{"pool.yoursite.com"})
  
  For CLIENT, you need:
    config.TLS = &umbra.TLSConfig{
        ServerName: "pool.yoursite.com",  // Must match server's domain
        SkipVerify: true,                 // For self-signed certs
    }`)
		}

		// Server needs certificate and key
		if isServer {
			if config.TLS.CertPEM == "" || config.TLS.KeyPEM == "" {
				return fmt.Errorf(`server advanced obfuscation requires TLS certificate and key

  Generate a self-signed certificate:
    certPEM, keyPEM, err := umbra.GenerateSelfSignedCert([]string{"pool.yoursite.com"})
    if err != nil {
        log.Fatal(err)
    }
    
    config.TLS = &umbra.TLSConfig{
        CertPEM: certPEM,
        KeyPEM:  keyPEM,
    }
  
  Or use Let's Encrypt for a trusted certificate:
    # certbot certonly --standalone -d pool.yoursite.com
    # Then load /etc/letsencrypt/live/pool.yoursite.com/{fullchain.pem, privkey.pem}`)
			}
		} else {
			// Client needs ServerName
			if config.TLS.ServerName == "" {
				return fmt.Errorf(`client advanced obfuscation requires TLS ServerName

  ServerName is the SNI (Server Name Indication) sent during TLS handshake.
  This MUST match the server's certificate domain.
  
  Example:
    config.TLS = &umbra.TLSConfig{
        ServerName: "pool.yoursite.com",
        SkipVerify: true,  // For self-signed certificates
    }`)
			}
		}
	}

	return nil
}

// ValidateAndExplain validates config and prints explanations if verbose is true.
// Useful for debugging configuration issues.
func ValidateAndExplain(config *Config, isServer bool, verbose bool) error {
	err := ValidateConfig(config, isServer)
	if err != nil {
		return err
	}

	if verbose && config.Obfuscation != nil && config.Obfuscation.Enabled {
		fmt.Println("=== Umbra Configuration Summary ===")
		fmt.Printf("Obfuscation Level: %s\n", obfuscationLevelName(config.Obfuscation.Level))
		fmt.Printf("Obfuscation Mode: %s\n", obfuscationModeName(config.Obfuscation.Mode))

		if config.Obfuscation.Level == ObfuscationLevelAdvanced {
			fmt.Printf("Domain: %s\n", config.Obfuscation.Domain)
			fmt.Printf("TLS Configured: %v\n", config.TLS != nil)
		}
		fmt.Println("==========================================")
	}

	return nil
}

func obfuscationLevelName(level ObfuscationLevel) string {
	switch level {
	case ObfuscationLevelBasic:
		return "Basic (padding and headers)"
	case ObfuscationLevelAdvanced:
		return "Advanced (TLS + WebSocket)"
	default:
		return "Unknown"
	}
}

func obfuscationModeName(mode ObfuscationMode) string {
	switch mode {
	case ObfuscationNone:
		return "None"
	case ObfuscationHTTP:
		return "HTTP"
	case ObfuscationHTTPS:
		return "HTTPS (legacy)"
	case ObfuscationRandom:
		return "Random Padding"
	case ObfuscationWebSocket:
		return "WebSocket"
	default:
		return "Unknown"
	}
}
