// Package mobile exposes the ds-core kernel as an embeddable library so it can
// run inside an Android companion app (built with `gomobile bind`). The
// companion app lives in a different package than the VpnService app, so its
// upstream traffic is NOT captured by the VpnService (addAllowedApplication
// matches by package), which avoids the in-process self-proxy loop.
//
// Build with:  gomobile bind -target=android/arm64 -androidapi=35 -o kernel ./mobile
package mobile

import "C"

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/Blue-Frontier/ds-core-go/certcache"
	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/proxy"
)

type instance struct {
	srv    *proxy.Server
	srvH   *http.Server
	ln     net.Listener
	file   *os.File
}

var (
	mu      sync.Mutex
	kernels = map[int64]*instance{}
	nextID  int64 = 1
)

// startResult is the JSON returned by StartKernel.
type startResult struct {
	Handle int64  `json:"handle"`
	Error  string `json:"error"`
}

func resultJSON(r startResult) string {
	b, _ := json.Marshal(r)
	return string(b)
}

// StartKernel loads config + CA, listens on listenAddr and serves the proxy in
// the background. Returns JSON `{"handle":N,"error":""}` on success or
// `{"handle":0,"error":"msg"}` on failure. logFile may be "" to discard.
//
//export StartKernel
func StartKernel(configPath, listenAddr, caDir, logFile string) string {
	mu.Lock()
	defer mu.Unlock()

	var out io.Writer = io.Discard
	var f *os.File
	if logFile != "" {
		fh, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return resultJSON(startResult{0, "log: " + err.Error()})
		}
		out = fh
		f = fh
	}
	log := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg, err := config.Load(configPath)
	if err != nil {
		return resultJSON(startResult{0, "config: " + err.Error()})
	}
	ca, err := certcache.Load(caDir)
	if err != nil {
		return resultJSON(startResult{0, "ca: " + err.Error()})
	}
	srv, err := proxy.New(cfg, ca, log)
	if err != nil {
		return resultJSON(startResult{0, "proxy: " + err.Error()})
	}
	sum := sha256.Sum256(ca.RootPEM())
	log.Info("kernel ready", "rules", srv.Table.Hosts(), "ca_sha256", fmt.Sprintf("%x", sum[:]))

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return resultJSON(startResult{0, "listen: " + err.Error()})
	}
	httpSrv := &http.Server{Handler: srv}
	inst := &instance{srv: srv, srvH: httpSrv, ln: ln, file: f}

	id := nextID
	nextID++
	kernels[id] = inst

	go func() {
		if err := httpSrv.Serve(ln); err != nil {
			log.Error("serve stopped", "err", err)
		}
	}()
	log.Info("listening", "addr", ln.Addr().String())
	return resultJSON(startResult{id, ""})
}

// StopKernel shuts the kernel instance down. Returns "" on success.
//
//export StopKernel
func StopKernel(handle int64) string {
	mu.Lock()
	inst, ok := kernels[handle]
	if !ok {
		mu.Unlock()
		return "unknown handle"
	}
	delete(kernels, handle)
	mu.Unlock()

	inst.srvH.Close()
	if inst.file != nil {
		inst.file.Close()
	}
	return ""
}
