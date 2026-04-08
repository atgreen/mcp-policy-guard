// Package tlsconfig builds TLS configurations for mTLS upstream connections.
package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// Options configures TLS for upstream HTTP connections.
type Options struct {
	CertFile string // Client certificate PEM
	KeyFile  string // Client private key PEM
	CAFile   string // CA certificate PEM to verify server
	Insecure bool   // Skip server TLS verification
}

// NewHTTPClient creates an http.Client with the given TLS options.
// If no TLS options are set, returns a plain client.
func NewHTTPClient(opts Options) (*http.Client, error) {
	tlsCfg := &tls.Config{}
	configured := false

	// Client certificate for mTLS
	if opts.CertFile != "" && opts.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
		configured = true
	}

	// Custom CA
	if opts.CAFile != "" {
		caCert, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsCfg.RootCAs = pool
		configured = true
	}

	// Skip verification
	if opts.Insecure {
		tlsCfg.InsecureSkipVerify = true
		configured = true
	}

	transport := &http.Transport{}
	if configured {
		transport.TLSClientConfig = tlsCfg
	}

	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Minute,
	}, nil
}
