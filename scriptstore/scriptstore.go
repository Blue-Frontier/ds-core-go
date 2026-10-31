// Package scriptstore holds the JavaScript files the kernel injects into HTML
// responses. The desktop kernel ships them in a local directory; here they are
// either registered from the configuration as URLs (fetched lazily and cached
// in memory) or pushed in directly by tests.
//
// Scripts are addressed by an opaque key so an injected tag can reference them
// through the kernel's own /____ds_script____/ path, keeping it same-origin.
package scriptstore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// MaxScriptBytes caps a single script download.
const MaxScriptBytes = 4 << 20

// Fetcher retrieves a script body. It is injectable for tests.
type Fetcher func(url string) ([]byte, error)

// Store caches script bodies by key.
type Store struct {
	mu    sync.Mutex
	src   map[string]string
	body  map[string][]byte
	fetch Fetcher
}

// New builds an empty store. A nil fetcher uses DefaultFetch.
func New(fetch Fetcher) *Store {
	if fetch == nil {
		fetch = DefaultFetch
	}
	return &Store{
		src:   make(map[string]string),
		body:  make(map[string][]byte),
		fetch: fetch,
	}
}

// DefaultFetch downloads a script over plain HTTP(S).
func DefaultFetch(url string) ([]byte, error) {
	cl := &http.Client{Timeout: 15 * time.Second}
	resp, err := cl.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("scriptstore: %s: status %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxScriptBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxScriptBytes {
		return nil, errors.New("scriptstore: script larger than limit")
	}
	return b, nil
}

// KeyFor derives the stable key used in /____ds_script____/<key>.
func KeyFor(url string) string {
	sum := sha256.Sum256([]byte(url))
	return "sk" + hex.EncodeToString(sum[:8]) + ".js"
}

// RegisterURL records a URL under its derived key and returns that key.
func (s *Store) RegisterURL(url string) string {
	key := KeyFor(url)
	s.mu.Lock()
	s.src[key] = url
	s.mu.Unlock()
	return key
}

// Put stores a body directly (tests, bundled scripts).
func (s *Store) Put(key string, body []byte) {
	s.mu.Lock()
	s.body[key] = body
	s.mu.Unlock()
}

// Has reports whether key can be served without a network fetch.
func (s *Store) Has(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.body[key]
	return ok
}

// Registered reports whether key is a known source, fetched or not.
func (s *Store) Registered(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.body[key]; ok {
		return true
	}
	_, ok := s.src[key]
	return ok
}

// Keys lists every registered key.
func (s *Store) Keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.src)+len(s.body))
	seen := make(map[string]bool, len(s.src))
	for k := range s.src {
		seen[k] = true
		out = append(out, k)
	}
	for k := range s.body {
		if !seen[k] {
			out = append(out, k)
		}
	}
	return out
}

// Get returns the script body, fetching and caching it on first use.
func (s *Store) Get(key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if b, ok := s.body[key]; ok {
		return b, nil
	}
	url, ok := s.src[key]
	if !ok {
		return nil, fmt.Errorf("scriptstore: unknown script %q", key)
	}
	b, err := s.fetch(url)
	if err != nil {
		return nil, err
	}
	s.body[key] = b
	return b, nil
}

// IsKey reports whether ref names a stored script rather than a URL or a
// site-relative path (stored keys never contain a slash).
func IsKey(ref string) bool {
	return ref != "" && !strings.Contains(ref, "/")
}
