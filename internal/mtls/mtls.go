// Package mtls builds an mTLS-capable http.Transport / http.Client for Sluice's
// INTERNAL server-to-server hops to Keystone (the reverse-proxy upstream and the
// OIDC token/JWKS calls).
//
// The client presents a Keyward-issued client certificate (CN=sluice), trusts
// only the Keyward root CA, and pins the expected server name (default
// "keystone"). It is wired only when INTERNAL_MTLS=on; with the toggle off the
// gateway keeps talking plain http://keystone:8080 exactly as before, so a
// misconfiguration or a missing cert degrades to the unchanged behavior rather
// than taking the whole gateway down.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"
)

// DefaultServerName is the SNI / certificate host pinned when none is configured.
// It matches the in-network Docker service name of Keystone.
const DefaultServerName = "keystone"

// Config locates the client certificate material and the trust anchor for the
// internal mTLS hop. All paths are read at build time so a failure (missing or
// malformed file) surfaces immediately to the caller, which then degrades to the
// plain-http path instead of serving with a half-built transport.
type Config struct {
	CertFile   string // client certificate (PEM); Keyward client cert CN=sluice
	KeyFile    string // client private key (PEM) matching CertFile
	CAFile     string // trust anchor (PEM); the Keyward root CA
	ServerName string // expected server name; defaults to DefaultServerName
}

// tlsConfig assembles the *tls.Config from the on-disk material.
func (c Config) tlsConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: load client cert/key: %w", err)
	}
	caPEM, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: read ca %s: %w", c.CAFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("mtls: ca %s contained no usable certificates", c.CAFile)
	}
	serverName := c.ServerName
	if serverName == "" {
		serverName = DefaultServerName
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// Transport clones the standard library's default transport (so connection
// pooling, timeouts, and HTTP/2 stay intact) and pins the mTLS client config
// onto it. The returned transport is safe to share across the reverse proxy and
// the OIDC token/JWKS http.Client.
func (c Config) Transport() (*http.Transport, error) {
	tlsCfg, err := c.tlsConfig()
	if err != nil {
		return nil, err
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("mtls: unexpected default transport type %T", http.DefaultTransport)
	}
	t := base.Clone()
	t.TLSClientConfig = tlsCfg
	return t, nil
}

// Client wraps Transport in an http.Client with the given timeout, used for the
// internal OIDC token exchange and JWKS fetch.
func (c Config) Client(timeout time.Duration) (*http.Client, error) {
	t, err := c.Transport()
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: t, Timeout: timeout}, nil
}
