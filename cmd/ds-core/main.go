// Command ds-core runs the kernel proxy standalone.
//
//	ds-core -config remote_config.json5 -listen 127.0.0.1:31181 -ca-dir ./ca
//
// Install ca-dir/ca.crt in the system or browser trust store to enable
// decryption; without it CONNECT tunnels still work but every HTTPS response
// the client accepts will fail its chain check.
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"

	"github.com/Blue-Frontier/ds-core-go/certcache"
	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/proxy"
)

func main() {
	cfgPath := flag.String("config", "remote_config.json5", "path to the kernel configuration")
	listen := flag.String("listen", "127.0.0.1:31181", "listen address")
	caDir := flag.String("ca-dir", "ca", "directory holding the MITM authority")
	verbose := flag.Bool("v", false, "debug logging")
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("load config", "path", *cfgPath, "err", err)
		os.Exit(1)
	}

	ca, err := certcache.Load(*caDir)
	if err != nil {
		log.Error("load CA", "dir", *caDir, "err", err)
		os.Exit(1)
	}

	srv, err := proxy.New(cfg, ca, log)
	if err != nil {
		log.Error("init proxy", "err", err)
		os.Exit(1)
	}

	sum := sha256.Sum256(ca.RootPEM())
	log.Info("kernel ready",
		"rules", srv.Table.Hosts(),
		"ca", *caDir,
		"ca_sha256", fmt.Sprintf("%x", sum[:]),
	)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Error("listen", "addr", *listen, "err", err)
		os.Exit(1)
	}
	log.Info("listening", "addr", ln.Addr().String())

	httpSrv := &http.Server{Handler: srv}
	if err := httpSrv.Serve(ln); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
