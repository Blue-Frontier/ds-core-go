// Command ds-core runs the kernel proxy standalone.
//
//	ds-core -config remote_config.json5 -listen 127.0.0.1:31191 -ca-dir ./ca
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
	"path/filepath"
	"time"

	"github.com/Blue-Frontier/ds-core-go/certcache"
	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/proxy"
)

func main() {
	cfgPath := flag.String("config", "remote_config.json5", "path to the kernel configuration")
	listen := flag.String("listen", "127.0.0.1:31191", "listen address")
	caDir := flag.String("ca-dir", "ca", "directory holding the MITM authority")
	verbose := flag.Bool("v", false, "debug logging")
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	// Merge the optional layers next to the official config, exactly as the
	// mobile app and the desktop kernel do: personal, then the local layer.
	dir := filepath.Dir(*cfgPath)
	personalPath := filepath.Join(dir, "remote_config_personal.json5")
	userPath := filepath.Join(dir, "user_config.json5")
	load := func() (*config.LoadResult, error) {
		return config.LoadLayers(*cfgPath,
			config.Layer{Name: config.LayerPersonal, Path: personalPath},
			config.Layer{Name: config.LayerUser, Path: userPath},
		)
	}
	loaded, err := load()
	if err != nil {
		log.Error("load config", "path", *cfgPath, "err", err)
		os.Exit(1)
	}
	for _, w := range loaded.Warnings {
		log.Warn("config layer", "warning", w)
	}
	if loaded.Personal.ID != "" || loaded.Personal.Version != 0 {
		log.Info("personal config merged",
			"id", loaded.Personal.ID, "version", loaded.Personal.Version)
	}
	if loaded.User.ID != "" || loaded.User.Version != 0 {
		log.Info("local config merged", "id", loaded.User.ID, "version", loaded.User.Version)
	}
	cfg := loaded.Config

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

	// Re-read both layers when either file changes; the listener stays up.
	srv.Watch(2*time.Second, []string{
		*cfgPath, personalPath, userPath,
		filepath.Join(filepath.Dir(*cfgPath), config.DisabledRulesFile),
	}, func() (*config.Config, error) {
		res, err := load()
		if err != nil {
			return nil, err
		}
		for _, w := range res.Warnings {
			log.Warn("config layer", "warning", w)
		}
		return res.Config, nil
	})

	sum := sha256.Sum256(ca.RootPEM())
	log.Info("kernel ready",
		"rules", srv.Table().Hosts(),
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
