// Package certcache mints TLS certificates on demand from a locally generated
// root authority, the way the desktop kernel does for its MITM mode.
//
// The CA private key never leaves this process; leaf certificates share a
// single RSA key to keep issuance fast (a fresh key per host would cost tens of
// milliseconds in RSA key generation alone).
package certcache

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Blue-Frontier/ds-core-go/hostmatch"
)

const (
	certFileName = "ca.crt"
	keyFileName  = "ca.key"
	caLifetime   = 10 * 365 * 24 * time.Hour
	leafLifetime = 365 * 24 * time.Hour
)

// Authority issues leaf certificates for requested hosts.
type Authority struct {
	cert     *x509.Certificate
	caKey    *rsa.PrivateKey
	leafKey  *rsa.PrivateKey
	rootPEM  []byte
	rootPool *x509.CertPool

	mu    sync.RWMutex
	cache map[string]*tls.Certificate
}

// New generates an in-memory authority (used when persistence is not needed).
func New() (*Authority, error) {
	return newAuthority()
}

// Load reads the authority from dir, creating and persisting one if absent.
func Load(dir string) (*Authority, error) {
	certPath := filepath.Join(dir, certFileName)
	keyPath := filepath.Join(dir, keyFileName)

	if _, err := os.Stat(certPath); err == nil {
		return loadFrom(certPath, keyPath)
	}

	a, err := newAuthority()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := a.Save(dir); err != nil {
		return nil, err
	}
	return a, nil
}

// Save writes the CA certificate and key to dir with restrictive permissions.
func (a *Authority) Save(dir string) error {
	certPath := filepath.Join(dir, certFileName)
	keyPath := filepath.Join(dir, keyFileName)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw})
	keyDER, err := x509.MarshalPKCS8PrivateKey(a.caKey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyPEM, 0o600)
}

// RootPEM returns the CA certificate in PEM form (what users install).
func (a *Authority) RootPEM() []byte { return a.rootPEM }

// RootPool returns a pool trusting only this CA (useful for tests).
func (a *Authority) RootPool() *x509.CertPool { return a.rootPool }

// LeafFor returns a cached or freshly minted certificate for host.
func (a *Authority) LeafFor(host string) (*tls.Certificate, error) {
	h := hostmatch.Normalize(host)
	if h == "" {
		return nil, fmt.Errorf("certcache: empty host")
	}

	a.mu.RLock()
	cert, ok := a.cache[h]
	a.mu.RUnlock()
	if ok {
		return cert, nil
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: h},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(leafLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(h); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{h}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &a.leafKey.PublicKey, a.caKey)
	if err != nil {
		return nil, fmt.Errorf("certcache: sign %q: %w", h, err)
	}
	cert = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: a.leafKey}

	a.mu.Lock()
	a.cache[h] = cert
	a.mu.Unlock()
	return cert, nil
}

// GetCertificate implements tls.Config.GetCertificate for a proxy that has to
// pick a certificate based on the client hello.
func (a *Authority) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil || hello.ServerName == "" {
		return nil, fmt.Errorf("certcache: client did not send SNI")
	}
	return a.LeafFor(hello.ServerName)
}

// Cached returns how many leaf certificates are cached (for stats/logging).
func (a *Authority) Cached() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.cache)
}

func newAuthority() (*Authority, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "dev-sidecar-core CA",
			Organization: []string{"dev-sidecar"},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &Authority{
		cert:     cert,
		caKey:    caKey,
		leafKey:  leafKey,
		rootPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		rootPool: pool,
		cache:    map[string]*tls.Certificate{},
	}, nil
}

func loadFrom(certPath, keyPath string) (*Authority, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("certcache: no certificate in %s", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("certcache: no key in %s", keyPath)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	caKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("certcache: CA key is %T, want RSA", parsed)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &Authority{
		cert:     cert,
		caKey:    caKey,
		leafKey:  leafKey,
		rootPEM:  certPEM,
		rootPool: pool,
		cache:    map[string]*tls.Certificate{},
	}, nil
}
