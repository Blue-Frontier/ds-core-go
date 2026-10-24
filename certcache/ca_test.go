package certcache

import (
	"crypto/x509"
	"testing"
)

func TestLeafForHostname(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	leaf, err := a.LeafFor("example.com")
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "example.com" {
		t.Fatalf("DNSNames = %v", cert.DNSNames)
	}
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: a.RootPool()}); err != nil {
		t.Fatalf("leaf does not verify against the CA: %v", err)
	}
}

func TestLeafForIP(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	leaf, err := a.LeafFor("127.0.0.1")
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	cert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "127.0.0.1" {
		t.Fatalf("IPAddresses = %v", cert.IPAddresses)
	}
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "127.0.0.1", Roots: a.RootPool()}); err != nil {
		t.Fatalf("IP leaf does not verify: %v", err)
	}
}

func TestLoadPersistsAuthority(t *testing.T) {
	dir := t.TempDir()
	first, err := Load(dir)
	if err != nil {
		t.Fatalf("Load (create): %v", err)
	}
	second, err := Load(dir)
	if err != nil {
		t.Fatalf("Load (reuse): %v", err)
	}
	if string(first.RootPEM()) != string(second.RootPEM()) {
		t.Fatal("reloaded authority has a different certificate")
	}
	if _, err := second.LeafFor("example.org"); err != nil {
		t.Fatalf("LeafFor after reload: %v", err)
	}
}

func TestCacheReused(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	first, err := a.LeafFor("example.com")
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	second, err := a.LeafFor("example.com")
	if err != nil {
		t.Fatalf("LeafFor: %v", err)
	}
	if first != second {
		t.Fatal("leaf certificates are not cached")
	}
	if a.Cached() != 1 {
		t.Fatalf("Cached() = %d", a.Cached())
	}
}
