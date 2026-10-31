// Package configupdate installs a newer published configuration.
//
// The desktop kernel re-downloads its configuration from the URL declared in
// "app.remoteConfig.url" and compares "app.metaInfo.version". The phone does
// the same here, so the logic is testable without cgo or a device.
package configupdate

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/Blue-Frontier/ds-core-go/config"
)

// MaxBytes caps a downloaded configuration.
const MaxBytes = 4 << 20

// Result reports what happened; it is returned to the app as JSON.
type Result struct {
	Status    string `json:"status"` // updated | current | error
	Version   int64  `json:"version,omitempty"`
	ID        string `json:"id,omitempty"`
	UpdateLog string `json:"updateLog,omitempty"`
	Error     string `json:"error,omitempty"`
}

type fetchFunc func(url string) ([]byte, error)

var httpFetch fetchFunc = func(url string) ([]byte, error) {
	cl := &http.Client{Timeout: 20 * time.Second}
	resp, err := cl.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBytes))
	if err != nil {
		return nil, err
	}
	if len(body) == MaxBytes {
		return nil, fmt.Errorf("config larger than %d bytes", MaxBytes)
	}
	return body, nil
}

// Install downloads remoteURL and, when its version is newer than the one in
// destPath, replaces the file atomically. A configuration without a version is
// refused rather than allowed to overwrite a versioned one.
func Install(remoteURL, destPath string) Result {
	body, err := download(remoteURL)
	if err != nil {
		return Result{Status: "error", Error: "download: " + err.Error()}
	}
	return installBytes(body, destPath)
}

// InstallUnversioned always installs a parseable configuration. Personal layers
// carry no version contract, so "newer" does not apply to them.
func InstallUnversioned(remoteURL, destPath string) Result {
	body, err := download(remoteURL)
	if err != nil {
		return Result{Status: "error", Error: "download: " + err.Error()}
	}
	cfg, err := config.Parse(body)
	if err != nil {
		return Result{Status: "error", Error: "parse remote: " + err.Error()}
	}
	if err := writeAtomic(destPath, body); err != nil {
		return Result{Status: "error", Error: err.Error()}
	}
	meta := cfg.App.MetaInfo
	return Result{Status: "updated", Version: meta.Version, ID: meta.ID, UpdateLog: meta.UpdateLog}
}

func download(remoteURL string) ([]byte, error) {
	if remoteURL == "" {
		return nil, fmt.Errorf("no config url")
	}
	return httpFetch(remoteURL)
}

func installBytes(body []byte, destPath string) Result {
	remote, err := config.Parse(body)
	if err != nil {
		return Result{Status: "error", Error: "parse remote: " + err.Error()}
	}
	meta := remote.App.MetaInfo
	if meta.Version == 0 {
		return Result{Status: "error", Error: "remote config has no metaInfo.version"}
	}

	var currentVersion int64
	if cur, err := config.Load(destPath); err == nil {
		currentVersion = cur.App.MetaInfo.Version
	}

	out := Result{Version: meta.Version, ID: meta.ID, UpdateLog: meta.UpdateLog}
	if currentVersion >= meta.Version {
		out.Status = "current"
		return out
	}

	if err := writeAtomic(destPath, body); err != nil {
		return Result{Status: "error", Error: err.Error()}
	}
	out.Status = "updated"
	return out
}

// writeAtomic replaces destPath with body via a temporary file.
func writeAtomic(destPath string, body []byte) error {
	tmp := destPath + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := os.Rename(tmp, destPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install: %w", err)
	}
	return nil
}
