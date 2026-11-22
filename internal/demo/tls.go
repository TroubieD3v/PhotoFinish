package demo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"
)

// Server and certificate settings.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 15 * time.Second
	idleTimeout       = 60 * time.Second
	maxHeaderBytes    = 16 << 10
	shutdownTimeout   = 5 * time.Second
	certValidity      = 24 * time.Hour
	certBackdate      = time.Minute
)

// certDNSNames and certIPs are the subject alternative names of the demo
// certificate.
var (
	certDNSNames = []string{"localhost", "shop.example.test"}
	certIPs      = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
)

// ValidateAddr returns an error unless host is a loopback address
// (127.0.0.0/8, ::1 or "localhost"), or expose is true. addr must be in
// host:port form either way.
func ValidateAddr(addr string, expose bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", addr, err)
	}
	if expose || isLoopbackHost(host) {
		return nil
	}
	return fmt.Errorf("refusing to listen on %q: the demo shop is intentionally vulnerable to race conditions, "+
		"so it only binds to loopback (127.0.0.1, ::1, localhost) unless exposing it is requested explicitly", addr)
}

// isLoopbackHost reports whether host names the local machine only.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Serve generates a fresh self-signed ECDSA P-256 certificate (SANs:
// localhost, 127.0.0.1, ::1, shop.example.test; valid 24h), listens with TLS
// (NextProtos h2, http/1.1), serves s.Handler() over HTTP/2 until ctx is
// done, then shuts down gracefully (5s). ready, if non-nil, is called once
// with the bound address and the certificate's SHA-256 fingerprint (hex,
// colon-separated) after the listener is bound.
func Serve(ctx context.Context, addr string, s *Shop, ready func(addr, fingerprint string)) error {
	if s == nil {
		return errors.New("serve: nil shop")
	}
	cert, err := selfSignedCert(time.Now())
	if err != nil {
		return fmt.Errorf("generate certificate: %w", err)
	}

	srv := newServer(s, cert)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if ready != nil {
		ready(ln.Addr().String(), fingerprint(cert.Leaf.Raw))
	}

	errc := make(chan error, 1)
	go func() {
		// ServeTLS wraps ln in TLS and enables HTTP/2 for the h2 protocol.
		errc <- srv.ServeTLS(ln, "", "")
	}()

	select {
	case err := <-errc:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		srv.Close()
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// newServer returns the HTTPS server for s with the demo's timeouts and
// limits and a TLS configuration that offers HTTP/2.
func newServer(s *Shop, cert tls.Certificate) *http.Server {
	return &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          s.logger,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
			MinVersion:   tls.VersionTLS12,
		},
	}
}

// selfSignedCert creates a throwaway certificate for the demo shop, valid
// from shortly before now for certValidity.
func selfSignedCert(now time.Time) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "PhotoFinish demo shop", Organization: []string{"PhotoFinish"}},
		NotBefore:             now.Add(-certBackdate),
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              certDNSNames,
		IPAddresses:           certIPs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// fingerprint returns the SHA-256 digest of der as colon-separated uppercase
// hex, the format printed by openssl x509 -fingerprint -sha256.
func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
