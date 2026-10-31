package proxy

import (
	"crypto/tls"
	"io"
	"log/slog"
	"testing"

	"github.com/Blue-Frontier/ds-core-go/certcache"
	"github.com/Blue-Frontier/ds-core-go/config"
)

func newSettingServer(t *testing.T, srvCfg config.Server) *Server {
	t.Helper()
	ca, err := certcache.New()
	if err != nil {
		t.Fatalf("certcache: %v", err)
	}
	s, err := New(&config.Config{Server: srvCfg}, ca, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	return s
}

// The floor is TLS 1.2 because that is what the desktop actually negotiates on
// its connection-close path (verified: www.baidu.com is TLS 1.2 only and answers
// 200 through the desktop proxy).
func TestUpstreamTLSDefaultsToTLS12(t *testing.T) {
	s := newSettingServer(t, config.Server{})
	min, verify := s.upstreamTLS("example.com")
	if min != tls.VersionTLS12 {
		t.Fatalf("min version = %x, want TLS 1.2", min)
	}
	if !verify {
		t.Fatal("verification should default to on")
	}
}

// allowTls12 never raises the floor; a mapping can.
func TestUpstreamTLSAllowTLS12(t *testing.T) {
	off := false
	s := newSettingServer(t, config.Server{Setting: config.Setting{AllowTls12: &off}})
	if min, _ := s.upstreamTLS("example.com"); min != tls.VersionTLS12 {
		t.Fatalf("min version = %x, want TLS 1.2", min)
	}
}

// A per-host mapping wins over the global floor; a disabled entry is ignored.
func TestUpstreamTLSVersionMapping(t *testing.T) {
	s := newSettingServer(t, config.Server{Setting: config.Setting{
		TLSVersionMapping: map[string]config.TLSVersionRule{
			"legacy.example": {Enabled: true, Version: "TLSv1.2"},
			"off.example":    {Enabled: false, Version: "TLSv1.2"},
			"*.example.com":  {Enabled: true, Version: "TLSv1.3"},
		},
	}})

	if min, _ := s.upstreamTLS("legacy.example"); min != tls.VersionTLS12 {
		t.Fatalf("legacy.example min = %x, want TLS 1.2", min)
	}
	if min, _ := s.upstreamTLS("off.example"); min != tls.VersionTLS12 {
		t.Fatalf("disabled mapping must be ignored, got %x", min)
	}
	if min, _ := s.upstreamTLS("www.example.com"); min != tls.VersionTLS13 {
		t.Fatalf("wildcard mapping min = %x, want TLS 1.3", min)
	}
}

func TestVerifySslCanBeDisabled(t *testing.T) {
	off := false
	s := newSettingServer(t, config.Server{Setting: config.Setting{VerifySsl: &off}})
	if _, verify := s.upstreamTLS("example.com"); verify {
		t.Fatal("verifySsl: false should disable upstream verification")
	}
}

func TestScriptSettingGate(t *testing.T) {
	on := true
	s := newSettingServer(t, config.Server{Setting: config.Setting{Script: config.ScriptSetting{Enabled: &on}}})
	if !s.st().scriptEnabled {
		t.Fatal("script.enabled defaults to on")
	}

	off := false
	s2 := newSettingServer(t, config.Server{Setting: config.Setting{Script: config.ScriptSetting{Enabled: &off}}})
	if s2.st().scriptEnabled {
		t.Fatal("script.enabled = false must disable injection")
	}
}
