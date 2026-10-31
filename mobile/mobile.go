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
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/Blue-Frontier/ds-core-go/certcache"
	"github.com/Blue-Frontier/ds-core-go/config"
	"github.com/Blue-Frontier/ds-core-go/configupdate"
	"github.com/Blue-Frontier/ds-core-go/proxy"
)

type instance struct {
	srv        *proxy.Server
	srvH       *http.Server
	ln         net.Listener
	file       *os.File
	listenAddr string
	ca         *certcache.Authority
	// stopWatch ends the configuration watcher (hot reload).
	stopWatch func()

	// mu guards the layers, which the watcher replaces on reload.
	mu       sync.Mutex
	cfg      *config.Config
	official config.MetaInfo
	personal config.MetaInfo
	user     config.MetaInfo
	sources  map[string]string
	disabled []config.DisabledRule
}

func (i *instance) setLayers(res *config.LoadResult) {
	i.mu.Lock()
	i.cfg, i.official, i.personal, i.user = res.Config, res.Official, res.Personal, res.User
	i.sources = res.Sources
	i.disabled = res.Disabled
	i.mu.Unlock()
}

// summaryJSON renders the current state, so a reload is reflected immediately.
func (i *instance) summaryJSON() string {
	i.mu.Lock()
	cfg, official, personal := i.cfg, i.official, i.personal
	i.mu.Unlock()
	if cfg == nil {
		return `{"error":"no config"}`
	}
	return summaryJSON(i.listenAddr, i.srv, i.ca, cfg, official, personal)
}

var (
	mu      sync.Mutex
	kernels       = map[int64]*instance{}
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

	// The personal and local layers live next to the official config.
	dir := filepath.Dir(configPath)
	personalPath := filepath.Join(dir, "remote_config_personal.json5")
	userPath := filepath.Join(dir, "user_config.json5")
	load := func() (*config.LoadResult, error) {
		return config.LoadLayers(configPath,
			config.Layer{Name: config.LayerPersonal, Path: personalPath},
			config.Layer{Name: config.LayerUser, Path: userPath},
		)
	}

	loaded, err := load()
	if err != nil {
		return resultJSON(startResult{0, "config: " + err.Error()})
	}
	for _, w := range loaded.Warnings {
		log.Warn("config layer", "warning", w)
	}
	cfg := loaded.Config
	if loaded.Personal.ID != "" || loaded.Personal.Version != 0 {
		log.Info("personal config merged",
			"id", loaded.Personal.ID, "version", loaded.Personal.Version)
	}
	if loaded.User.ID != "" || loaded.User.Version != 0 {
		log.Info("local config merged", "id", loaded.User.ID, "version", loaded.User.Version)
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
	log.Info("kernel ready", "rules", srv.Table().Hosts(), "ca_sha256", fmt.Sprintf("%x", sum[:]))

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return resultJSON(startResult{0, "listen: " + err.Error()})
	}
	httpSrv := &http.Server{Handler: srv}
	inst := &instance{srv: srv, srvH: httpSrv, ln: ln, file: f, listenAddr: listenAddr, ca: ca}
	inst.setLayers(loaded)

	// Hot reload: pick up edits to any layer without dropping the listener.
	loadLayers := func() (*config.Config, error) {
		res, err := load()
		if err != nil {
			return nil, err
		}
		for _, w := range res.Warnings {
			log.Warn("config layer", "warning", w)
		}
		inst.setLayers(res)
		return res.Config, nil
	}
	watched := []string{
		configPath,
		personalPath,
		userPath,
		filepath.Join(dir, config.DisabledRulesFile),
	}
	inst.stopWatch = srv.Watch(2*time.Second, watched, loadLayers)

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

// KernelStats returns the traffic counters for a running instance as JSON.
//
//export KernelStats
func KernelStats(handle int64) string {
	mu.Lock()
	inst, ok := kernels[handle]
	mu.Unlock()
	if !ok {
		return `{"error":"unknown handle"}`
	}
	return inst.srv.Stats.Snapshot()
}

// KernelRules lists every configured rule with its source layer and switch
// state, for the rule browser.
//
//export KernelRules
func KernelRules(handle int64) string {
	mu.Lock()
	inst, ok := kernels[handle]
	mu.Unlock()
	if !ok {
		return `{"error":"unknown handle"}`
	}

	inst.mu.Lock()
	cfg, sources, disabled := inst.cfg, inst.sources, inst.disabled
	inst.mu.Unlock()
	if cfg == nil {
		return `{"error":"no config"}`
	}

	off := make(map[string]bool, len(disabled))
	for _, d := range disabled {
		off[d.Host+"\x00"+d.Pattern] = true
	}

	type ruleJSON struct {
		Host    string `json:"host"`
		Pattern string `json:"pattern"`
		Desc    string `json:"desc"`
		Source  string `json:"source"`
		Enabled bool   `json:"enabled"`
	}

	hosts := make([]string, 0, len(cfg.Server.Intercepts))
	for h := range cfg.Server.Intercepts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	out := make([]ruleJSON, 0, 64)
	for _, host := range hosts {
		patterns := make([]string, 0, len(cfg.Server.Intercepts[host]))
		for p := range cfg.Server.Intercepts[host] {
			patterns = append(patterns, p)
		}
		sort.Strings(patterns)
		for _, pattern := range patterns {
			out = append(out, ruleJSON{
				Host:    host,
				Pattern: pattern,
				Desc:    cfg.Server.Intercepts[host][pattern].Desc,
				Source:  sources[host],
				Enabled: !off[host+"\x00"+pattern],
			})
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// SetRuleEnabled records a per-rule switch; the watcher reloads it.
//
//export SetRuleEnabled
func SetRuleEnabled(configPath, host, pattern string, enabled bool) string {
	rules := config.ReadDisabled(configPath)
	kept := make([]config.DisabledRule, 0, len(rules)+1)
	for _, r := range rules {
		if r.Host == host && r.Pattern == pattern {
			continue
		}
		kept = append(kept, r)
	}
	if !enabled {
		kept = append(kept, config.DisabledRule{Host: host, Pattern: pattern})
	}
	if err := config.WriteDisabled(configPath, kept); err != nil {
		return `{"error":"write failed"}`
	}
	return `{"ok":true}`
}

// ValidateConfig reports a parse error in a configuration layer, or "" when it
// is usable.
//
//export ValidateConfig
func ValidateConfig(text string) string {
	if _, err := config.Parse([]byte(text)); err != nil {
		return err.Error()
	}
	return ""
}

// KernelSummary returns a static description of a running instance (listen
// address, rule counts, CA fingerprint) for the settings screen.
//
//export KernelSummary
func KernelSummary(handle int64) string {
	mu.Lock()
	inst, ok := kernels[handle]
	mu.Unlock()
	if !ok {
		return `{"error":"unknown handle"}`
	}
	return inst.summaryJSON()
}

// UpdateConfig downloads a newer published configuration and installs it at
// destPath. Returns JSON: {"status":"updated|current|error",...}.
//
//export UpdateConfig
func UpdateConfig(remoteURL, destPath string) string {
	b, err := json.Marshal(configupdate.Install(remoteURL, destPath))
	if err != nil {
		return `{"status":"error","error":"encode result"}`
	}
	return string(b)
}

// UpdatePersonalConfig downloads the personal layer and always installs it; the
// personal layer carries no version contract, so "newer" does not apply.
//
//export UpdatePersonalConfig
func UpdatePersonalConfig(remoteURL, destPath string) string {
	b, err := json.Marshal(configupdate.InstallUnversioned(remoteURL, destPath))
	if err != nil {
		return `{"status":"error","error":"encode result"}`
	}
	return string(b)
}

// summaryJSON renders the fields the companion app's settings screen shows.
func summaryJSON(listenAddr string, srv *proxy.Server, ca *certcache.Authority, cfg *config.Config, official, personal config.MetaInfo) string {
	sum := sha256.Sum256(ca.RootPEM())
	overwallOn, overwallTargets := srv.OverwallInfo()
	out := map[string]any{
		"overwallOn":      overwallOn,
		"overwallTargets": overwallTargets,
		"listen":          listenAddr,
		"rules":           srv.Table().Hosts(),
		"rulesSkipped":    len(srv.Table().Skipped),
		"rulesRewritten":  len(srv.Table().Rewritten),
		"whiteList":       len(cfg.Server.WhiteList),
		"excludeIp":       len(cfg.Proxy.ExcludeIPList),
		"caSha256":        fmt.Sprintf("%x", sum[:]),
		"configId":        official.ID,
		"configVersion":   official.Version,
		"configUpdate":    official.UpdateLog,
		"configUrl":       cfg.App.RemoteConfig.URL,
		"hasPersonal":     personal.ID != "" || personal.Version != 0,
		"personalId":      personal.ID,
		"personalVersion": personal.Version,
		"personalUpdate":  personal.UpdateLog,
	}
	b, err := json.Marshal(out)
	if err != nil {
		return `{}`
	}
	return string(b)
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
	if inst.stopWatch != nil {
		inst.stopWatch()
	}
	if inst.file != nil {
		inst.file.Close()
	}
	return ""
}

// SetMode applies one of the desktop's modes to the local layer.
//
//export SetMode
func SetMode(configPath, mode string) string {
	if err := config.SetMode(configPath, mode); err != nil {
		return `{"error":"write"}`
	}
	return `{"ok":true}`
}

// CurrentMode reads the mode recorded in the local layer.
//
//export CurrentMode
func CurrentMode(configPath string) string {
	return config.CurrentMode(configPath)
}

// RuleText returns the merged rule block for host as JSON.
//
//export RuleText
func RuleText(configPath, host string) string {
	text, err := config.RuleText(configPath, host)
	if err != nil {
		return "{}"
	}
	return text
}

// SetRuleText writes one host block into the local layer.
//
//export SetRuleText
func SetRuleText(configPath, host, text string) string {
	if err := config.SetRuleText(configPath, host, text); err != nil {
		return `{"error":"parse"}`
	}
	return `{"ok":true}`
}

// ResetRuleText drops the local override for host.
//
//export ResetRuleText
func ResetRuleText(configPath, host string) string {
	if err := config.ResetRuleText(configPath, host); err != nil {
		return `{"error":"write"}`
	}
	return `{"ok":true}`
}
