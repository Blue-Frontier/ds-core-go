// Package config loads dev-sidecar remote configuration files.
//
// The shipped configuration uses JSON5 syntax: // and /* */ comments, single
// quotes and trailing commas. Only that subset is supported, which is enough
// for the files published by the dev-sidecar config pipeline and keeps this
// kernel free of third-party dependencies.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Rule is one intercept rule: a path pattern inside a host block.
type Rule struct {
	// Redirect rewrites the response into a 302 to another host. The value is
	// a prefix without scheme, e.g. "ghp.ci/https://github.com".
	Redirect string `json:"redirect,omitempty"`
	// SNI overrides the server name sent upstream.
	SNI string `json:"sni,omitempty"`
	// Proxy swaps the upstream host (same port) for another one.
	Proxy string `json:"proxy,omitempty"`
	// Backup lists alternative upstream hosts tried when Proxy cannot be dialed.
	Backup StringList `json:"backup,omitempty"`
	// Script lists the scripts injected into matching HTML responses. Entries
	// are absolute URLs, site-relative paths, or keys served by the kernel.
	// The desktop configuration accepts a bare string as well as an array.
	Script StringList `json:"script,omitempty"`
	// TampermonkeyScript is the userscript runtime injected ahead of Script.
	TampermonkeyScript string `json:"tampermonkeyScript,omitempty"`
	// VerifyHost overrides the name the origin chain is checked against. Rules
	// that swap SNI for another real domain need it: the origin answers with
	// that domain's certificate, so checking against the requested host would
	// always fail.
	VerifyHost string   `json:"verifyHost,omitempty"`
	Exclusions []string `json:"exclusions,omitempty"`
	Desc       string   `json:"desc,omitempty"`

	// Abort answers the request locally with an error response (403 by default)
	// instead of contacting the origin.
	Abort *Synthetic `json:"abort,omitempty"`
	// Success answers the request locally with a success response (200 by
	// default), used to stub endpoints.
	Success *Synthetic `json:"success,omitempty"`

	// Options enables the CORS preflight handler. The tunables live next to it,
	// at the rule level, as in the desktop configuration.
	Options             Flag       `json:"options,omitempty"`
	OptionsAllowHeaders StringList `json:"optionsAllowHeaders,omitempty"`
	OptionsAllowMethods StringList `json:"optionsAllowMethods,omitempty"`
	OptionsMaxAge       int        `json:"optionsMaxAge,omitempty"`
	OptionsCredentials  *bool      `json:"optionsCredentials,omitempty"`

	// ResponseReplace rewrites response headers, optionally turning a 200
	// response into a download.
	ResponseReplace *ResponseReplace `json:"responseReplace,omitempty"`
	// RequestReplace rewrites request headers and handles "?DS_DOWNLOAD".
	RequestReplace *RequestReplace `json:"requestReplace,omitempty"`
	// CacheConfig holds the flattened cache* options of the rule.
	CacheConfig
}

// CacheConfig mirrors the desktop's cache* rule options. They do not create a// local store: they rewrite HTTP cache headers and let the kernel answer a
// conditional GET with 304 while the window is still open.
type CacheConfig struct {
	CacheSeconds  int      `json:"cacheSeconds,omitempty"`
	CacheMaxAge   int      `json:"cacheMaxAge,omitempty"`
	Cache         int      `json:"cache,omitempty"`
	CacheMinutes  int      `json:"cacheMinutes,omitempty"`
	CacheHours    int      `json:"cacheHours,omitempty"`
	CacheDays     int      `json:"cacheDays,omitempty"`
	CacheWeeks    int      `json:"cacheWeeks,omitempty"`
	CacheMonths   int      `json:"cacheMonths,omitempty"`
	CacheYears    int      `json:"cacheYears,omitempty"`
	ControlType   string   `json:"cacheControlType,omitempty"`
	Immutable     *bool    `json:"cacheImmutable,omitempty"`
	MinStatus     int      `json:"cacheMinStatusCode,omitempty"`
	MaxStatus     int      `json:"cacheMaxStatusCode,omitempty"`
	ExcludeStatus []string `json:"cacheExcludeStatusCodeList,omitempty"`
}

// MinStatusCode is the lowest status the cache rule applies to (200 default).
func (c CacheConfig) MinStatusCode() int {
	if c.MinStatus > 0 {
		return c.MinStatus
	}
	return 200
}

// MaxStatusCode is the highest status the cache rule applies to (303 default).
func (c CacheConfig) MaxStatusCode() int {
	max := 303
	if c.MaxStatus > 0 {
		max = c.MaxStatus
	}
	if c.MinStatus > 0 && c.MinStatus > max {
		return c.MinStatus
	}
	return max
}

// MaxAge returns the cache lifetime in seconds; 0 means "no cache rule".
func (c CacheConfig) MaxAge() int {
	switch {
	case c.CacheSeconds > 0:
		return c.CacheSeconds
	case c.CacheMaxAge > 0:
		return c.CacheMaxAge
	case c.Cache > 0:
		return c.Cache
	case c.CacheMinutes > 0:
		return c.CacheMinutes * 60
	case c.CacheHours > 0:
		return c.CacheHours * 3600
	case c.CacheDays > 0:
		return c.CacheDays * 86400
	case c.CacheWeeks > 0:
		return c.CacheWeeks * 604800
	case c.CacheMonths > 0:
		return c.CacheMonths * 2592000
	case c.CacheYears > 0:
		return c.CacheYears * 31536000
	}
	return 0
}

// ResponseReplace is the desktop's responseReplace action. Header values may be
// any scalar; the literal "[remove]" deletes that header.
type ResponseReplace struct {
	Headers    map[string]any `json:"headers,omitempty"`
	DoDownload bool           `json:"doDownload,omitempty"`
}

// RequestReplace is the desktop's requestReplace action: header overrides plus
// the "?DS_DOWNLOAD" marker handling.
type RequestReplace struct {
	Headers    map[string]any `json:"headers,omitempty"`
	DoDownload bool           `json:"doDownload,omitempty"`
}

// Synthetic is the body of an "abort" or "success" rule: either the literal
// true, or an object describing the response to return.
type Synthetic struct {
	Enabled bool              `json:"-"`
	Status  int               `json:"status,omitempty"`
	HTML    string            `json:"html,omitempty"`
	JSON    string            `json:"json,omitempty"`
	Script  string            `json:"script,omitempty"`
	CSS     string            `json:"css,omitempty"`
	Text    string            `json:"text,omitempty"`
	Body    string            `json:"body,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

func (s *Synthetic) UnmarshalJSON(b []byte) error {
	switch strings.TrimSpace(string(b)) {
	case "true", `"true"`:
		s.Enabled = true
		return nil
	case "false", `"false"`, "null":
		return nil
	}
	type alias Synthetic
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*s = Synthetic(a)
	s.Enabled = true
	return nil
}

// Flag is a switch that the configuration may write as a boolean or as an
// object; an object means "enabled" (its fields live beside it).
type Flag bool

func (f *Flag) UnmarshalJSON(b []byte) error {
	t := strings.TrimSpace(string(b))
	switch t {
	case "true", `"true"`:
		*f = true
	case "false", `"false"`, "null":
		*f = false
	default:
		*f = Flag(strings.HasPrefix(t, "{"))
	}
	return nil
}

// StringList accepts either a single JSON string or an array of strings and
// keeps the desktop configuration's "bare string means one entry" semantics.
type StringList []string

func (l *StringList) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*l = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s == "" {
			*l = nil
		} else {
			*l = []string{s}
		}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	out := arr[:0]
	for _, v := range arr {
		if v != "" {
			out = append(out, v)
		}
	}
	*l = out
	return nil
}

// Clone returns an independent copy, safe to rewrite without touching the
// parsed configuration.
func (l StringList) Clone() StringList {
	if l == nil {
		return nil
	}
	out := make(StringList, len(l))
	copy(out, l)
	return out
}

// DNSProvider is one entry of "server.dns.providers". Server understands the
// spellings used by the desktop kernel: "https://..." / "http://..." selects
// DNS-over-HTTPS, "tls://..." or "dot://..." DNS-over-TLS, "tcp://..." plain
// DNS over TCP and everything else plain DNS over UDP. sni/servername rewrites
// the TLS ClientHello SNI of the DNS connection itself (the protected DNS
// server sees a different name); it also disables certificate verification,
// matching the desktop kernel's rejectUnauthorized:false.
type DNSProvider struct {
	Server string `json:"server,omitempty"`
	// Host is a legacy alias for Server.
	Host string `json:"host,omitempty"`
	// Type is derived from the server scheme when empty:
	// https/doh/dns-over-https, tls/dot/dns-over-tls, tcp, udp.
	Type string `json:"type,omitempty"`
	// Port defaults to 853 for DoT, 53 for UDP/TCP; DoH uses the URL port.
	Port int `json:"port,omitempty"`
	// Family forces IPv4 (4) or IPv6 (6) connections to the DNS server.
	Family int `json:"family,omitempty"`
	// SNI rewrites the TLS SNI of the DNS connection itself.
	SNI string `json:"sni,omitempty"`
	// ServerName is an alias for SNI.
	ServerName string `json:"servername,omitempty"`
	// ForSNI (or ForSni) marks this provider as the default for hosts that
	// carry an SNI rule but no DNS mapping.
	ForSNI    bool `json:"forSNI,omitempty"`
	ForSni    bool `json:"forSni,omitempty"`
	CacheSize int  `json:"cacheSize,omitempty"`
	// ECH is parsed for configuration compatibility (provider-level ECH kill
	// switch in newer desktop kernels); the Go kernel ignores it for now.
	ECH *bool `json:"ech,omitempty"`
}

// SNIOverride merges the two accepted spellings of the SNI field.
func (p *DNSProvider) SNIOverride() string {
	if p == nil {
		return ""
	}
	if s := strings.TrimSpace(p.SNI); s != "" {
		return s
	}
	return strings.TrimSpace(p.ServerName)
}

// StdServer returns Server, falling back to the legacy Host alias.
func (p *DNSProvider) StdServer() string {
	if p == nil {
		return ""
	}
	if s := strings.TrimSpace(p.Server); s != "" {
		return s
	}
	return strings.TrimSpace(p.Host)
}

// MarkedForSNI merges the two accepted spellings of the forSNI flag.
func (p *DNSProvider) MarkedForSNI() bool {
	if p == nil {
		return false
	}
	return p.ForSNI || p.ForSni
}

// DNSMapping is one "server.dns.mapping" value: either the plain provider name
// ("quad9") or an object form {dns: "name", family: 4}.
type DNSMapping struct {
	DNSName string `json:"dns,omitempty"`
	Family  int    `json:"family,omitempty"`
}

func (m *DNSMapping) UnmarshalJSON(b []byte) error {
	// null keeps the entry empty so it is skipped by consumers.
	if string(b) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		m.DNSName = s
		return nil
	}
	type plain struct {
		DNS    string `json:"dns"`
		Name   string `json:"name"`
		Family int    `json:"family"`
	}
	var o plain
	if err := json.Unmarshal(b, &o); err != nil {
		return err
	}
	m.DNSName = o.DNS
	if m.DNSName == "" {
		m.DNSName = o.Name
	}
	m.Family = o.Family
	return nil
}

// DNS groups the resolution settings.
type DNS struct {
	// Providers names the available DNS servers ("DNS服务管理").
	Providers map[string]*DNSProvider `json:"providers,omitempty"`
	// Mapping selects a provider (by name) per host pattern.
	Mapping map[string]DNSMapping `json:"mapping,omitempty"`
	// SpeedTest pre-measures the listed hosts so the first request starts from
	// a ranked address list instead of learning while the user waits.
	SpeedTest SpeedTest `json:"speedTest,omitempty"`
	// NAT64 synthesises IPv6 addresses for IPv4-only hosts (IPv6-only nets).
	NAT64 NAT64 `json:"nat64,omitempty"`
	// ECH lists the hosts that should be reached with Encrypted Client Hello.
	ECH ECH `json:"ech,omitempty"`
}

// NAT64 is the "DNS64" configuration. An empty prefix disables it, exactly as
// the desktop kernel refuses to convert without one.
type NAT64 struct {
	Enabled bool     `json:"enabled,omitempty"`
	Prefix  string   `json:"prefix,omitempty"`
	Domains []string `json:"domains,omitempty"`
	DNS     string   `json:"dns,omitempty"`
}

// ECH is the Encrypted Client Hello configuration.
type ECH struct {
	Enabled    bool     `json:"enabled,omitempty"`
	Use        bool     `json:"use,omitempty"`
	Domains    []string `json:"domains,omitempty"`
	PublicName string   `json:"publicName,omitempty"`
	DNS        string   `json:"dns,omitempty"`
}

// SpeedTest is the "IP测速" configuration.
type SpeedTest struct {
	Enabled      bool     `json:"enabled,omitempty"`
	Interval     int      `json:"interval,omitempty"`
	HostnameList []string `json:"hostnameList,omitempty"`
	DNSProviders []string `json:"dnsProviders,omitempty"`
}

// IPList is one "preSetIpList" value. The configuration sends either an array
// of addresses, an object whose keys are addresses and whose values merely
// enable them (true / "false" / "0" fine-grained), or null to delete an entry.
type IPList []string

func (l *IPList) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*l = nil
		return nil
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err == nil {
		*l = arr
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	for key, raw := range obj {
		if entryEnabled(raw) {
			*l = append(*l, key)
		}
	}
	return nil
}

// entryEnabled mirrors the desktop kernel's mapToList: anything truthy counts
// except the strings "false" and "0". An object entry carries a description, so
// it is enabled unless it says otherwise — treating it as disabled silently
// emptied the google preset list and cost us the working address.
func entryEnabled(raw json.RawMessage) bool {
	trimmed := string(raw)
	switch trimmed {
	case "true":
		return true
	case "false", "null", "0":
		return false
	}
	if strings.HasPrefix(trimmed, "{") {
		var obj struct {
			Enabled  *bool `json:"enabled"`
			Disabled *bool `json:"disabled"`
		}
		if err := json.Unmarshal(raw, &obj); err == nil {
			if obj.Disabled != nil && *obj.Disabled {
				return false
			}
			if obj.Enabled != nil {
				return *obj.Enabled
			}
		}
		return true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return false
	}
	if s == "" || s == "false" || s == "0" {
		return false
	}
	return true
}

// Server is the "server" section of the configuration.
type Server struct {
	// Intercepts maps host pattern -> path pattern -> rule.
	Intercepts map[string]map[string]Rule `json:"intercepts,omitempty"`
	// PreSetIPList maps host pattern to addresses that bypass resolution.
	PreSetIPList map[string]IPList `json:"preSetIpList,omitempty"`
	DNS          DNS               `json:"dns,omitempty"`
	WhiteList    map[string]bool   `json:"whiteList,omitempty"`
	Compatible   Compatible        `json:"compatible,omitempty"`
	Setting      Setting           `json:"setting,omitempty"`
	// Intercept is the master switch for the rule engine; the "safe" mode
	// turns it off and every request then goes straight to the origin.
	Intercept InterceptSwitch `json:"intercept,omitempty"`
}

// InterceptSwitch mirrors "server.intercept".
type InterceptSwitch struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// EnabledOrDefault reports the switch, defaulting to on like the desktop.
func (s InterceptSwitch) EnabledOrDefault() bool {
	return s.Enabled == nil || *s.Enabled
}

// CloudflareRoute mirrors "server.cloudflareRoute": when a host resolves to a
// Cloudflare address, the kernel dials the preferred endpoint instead.
type CloudflareRoute struct {
	Enabled           bool   `json:"enabled,omitempty"`
	PreferredEndpoint string `json:"preferredEndpoint,omitempty"`
	// Mode is "blacklist" (default: listed domains skip rewriting) or
	// "whitelist" (only listed domains are rewritten).
	Mode    string     `json:"mode,omitempty"`
	Domains StringList `json:"domains,omitempty"`
}

// Setting mirrors "server.setting": request timeouts and TLS behaviour.
type Setting struct {
	// DefaultTimeout bounds the wait for a response, in milliseconds.
	DefaultTimeout int `json:"defaultTimeout,omitempty"`
	// DefaultKeepAliveTimeout is the desktop's pooled-socket idle budget.
	DefaultKeepAliveTimeout int `json:"defaultKeepAliveTimeout,omitempty"`
	// TimeoutMapping overrides the timeout per host pattern.
	TimeoutMapping map[string]HostTimeout `json:"timeoutMapping,omitempty"`
	// TLSVersionMapping pins the TLS version for specific hosts.
	TLSVersionMapping map[string]TLSVersionRule `json:"tlsVersionMapping,omitempty"`
	// VerifySsl switches upstream certificate verification (default true).
	VerifySsl *bool `json:"verifySsl,omitempty"`
	// AllowTls12 lowers the upstream minimum to TLS 1.2; the desktop defaults
	// to TLS 1.3 only.
	AllowTls12 *bool `json:"allowTls12,omitempty"`
	// LowSpeedDelay is the "slow" threshold the desktop UI colours by.
	LowSpeedDelay int `json:"lowSpeedDelay,omitempty"`
	// Script gates the request/response scripting middleware.
	Script ScriptSetting `json:"script,omitempty"`
}

// HostTimeout is one entry of "server.setting.timeoutMapping".
type HostTimeout struct {
	Timeout           int `json:"timeout,omitempty"`
	KeepAliveTimeout  int `json:"keepAliveTimeout,omitempty"`
	FreeSocketTimeout int `json:"freeSocketTimeout,omitempty"`
}

// ScriptSetting mirrors "server.setting.script".
type ScriptSetting struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// EnabledOrDefault reports the switch, defaulting to on like the desktop.
func (s ScriptSetting) EnabledOrDefault() bool {
	return s.Enabled == nil || *s.Enabled
}

// TLSVersionRule accepts both forms the desktop supports: a bare version
// string, or an object with enabled/version so a remote config can ship it
// disabled and let the user switch it on.
type TLSVersionRule struct {
	Enabled bool
	Version string
}

func (t *TLSVersionRule) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		t.Enabled = true
		t.Version = s
		return nil
	}
	var obj struct {
		Enabled *bool  `json:"enabled"`
		Version string `json:"version"`
		Value   string `json:"value"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	t.Enabled = obj.Enabled == nil || *obj.Enabled
	t.Version = obj.Version
	if t.Version == "" {
		t.Version = obj.Value
	}
	return nil
}

// Compatible mirrors "server.compatible": per-target TLS relaxations.
type Compatible struct {
	Request map[string]CompatibleRequest `json:"request,omitempty"`
}

// CompatibleRequest is one per-target compatibility switch.
type CompatibleRequest struct {
	// RejectUnauthorized false disables chain verification for that target.
	RejectUnauthorized *bool `json:"rejectUnauthorized,omitempty"`
	SSL                *bool `json:"ssl,omitempty"`
}

// Proxy is the "proxy" section of the configuration.
type Proxy struct {
	ExcludeIPList map[string]bool `json:"excludeIpList,omitempty"`
}

// App is the "app" section: mostly metadata about the configuration itself.
type App struct {
	RemoteConfig RemoteConfig `json:"remoteConfig,omitempty"`
	MetaInfo     MetaInfo     `json:"metaInfo,omitempty"`
}

// RemoteConfig names where a configuration publishes its updates.
type RemoteConfig struct {
	URL string `json:"url,omitempty"`
}

// MetaInfo identifies a configuration: who published it, when it was edited and
// what changed. The desktop panel shows it in its bottom bar.
type MetaInfo struct {
	ID        string `json:"id,omitempty"`
	Version   int64  `json:"version,omitempty"`
	UpdateLog string `json:"updateLog,omitempty"`
}

// Config is a whole dev-sidecar configuration file.
type Config struct {
	Server Server `json:"server,omitempty"`
	Proxy  Proxy  `json:"proxy,omitempty"`
	Plugin Plugin `json:"plugin,omitempty"`
	App    App    `json:"app,omitempty"`

	// Disabled lists rules switched off from the UI; it is filled by the layer
	// loader and never parsed from a configuration file.
	Disabled []DisabledRule `json:"-"`
}

// Plugin holds the optional plugins; only "overwall" affects the proxy.
type Plugin struct {
	Overwall Overwall `json:"overwall,omitempty"`
}

// Overwall routes matched hosts through a relay server ("over the wall").
type Overwall struct {
	Enabled       bool                      `json:"enabled,omitempty"`
	Targets       map[string]any            `json:"targets,omitempty"`
	Server        map[string]OverwallServer `json:"server,omitempty"`
	ServerDefault map[string]OverwallServer `json:"serverDefault,omitempty"`
}

// OverwallServer is one relay endpoint.
type OverwallServer struct {
	ID       int    `json:"id,omitempty"`
	Port     int    `json:"port,omitempty"`
	Path     string `json:"path,omitempty"`
	Password string `json:"password,omitempty"`
}

// Load reads and parses a configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses configuration bytes.
func Parse(data []byte) (*Config, error) {
	var c Config
	if err := json.Unmarshal(StripJSON5(data), &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &c, nil
}

// StripJSON5 converts the JSON5 subset used by dev-sidecar into JSON:
// comments are removed, single-quoted strings are rewritten and trailing
// commas in objects/arrays are dropped.
func StripJSON5(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			out = append(out, '\n')

		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			i += 2
			for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
				i++
			}
			i++ // sit on the closing '/'
			out = append(out, ' ')

		case c == '"' || c == '\'':
			// Normalize to a double-quoted JSON string. JSON5/JS escapes with
			// no JSON spelling are rewritten, and an unknown escape drops its
			// backslash (JS semantics), which real configs rely on: they contain
			// regexes such as "x\.com" that JSON would reject outright.
			quote := c
			out = append(out, '"')
			for i++; i < len(b); i++ {
				if b[i] == '\\' && i+1 < len(b) {
					esc := b[i+1]
					switch esc {
					case '"', '\\', '/', 'b', 'f', 'n', 'r', 't', 'u':
						out = append(out, b[i], esc)
					case '\'':
						out = append(out, '\'')
					case 'v':
						out = append(out, []byte(`\u000b`)...)
					case '0':
						out = append(out, []byte(`\u0000`)...)
					case 'x':
						if i+3 < len(b) {
							out = append(out, []byte(`\u00`+string(b[i+2])+string(b[i+3]))...)
							i += 3
						} else {
							out = append(out, esc)
							i++
						}
					default:
						out = append(out, esc)
					}
					i++
					continue
				}
				if b[i] == quote {
					break
				}
				if b[i] == '"' {
					out = append(out, '\\')
				}
				out = append(out, b[i])
			}
			out = append(out, '"')

		default:
			out = append(out, c)
		}
	}
	return quoteBareKeys(dropTrailingCommas(out))
}

func dropTrailingCommas(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inString := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inString {
			out = append(out, c)
			if c == '\\' && i+1 < len(b) {
				out = append(out, b[i+1])
				i++
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if c == ',' {
			j := i + 1
			for j < len(b) && isSpace(b[j]) {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

// quoteBareKeys turns JSON5's unquoted object keys into JSON strings. It runs
// after comments are stripped and strings are normalized, so a bare identifier
// is a key only when the previous token is '{' or ',' and the next one is ':'.
// Values such as true/false/null never match, because they follow ':' or '['.
func quoteBareKeys(b []byte) []byte {
	out := make([]byte, 0, len(b)+16)
	inString := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inString {
			out = append(out, c)
			if c == '\\' && i+1 < len(b) {
				out = append(out, b[i+1])
				i++
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if isIdentStart(c) {
			j := len(out) - 1
			for j >= 0 && isSpace(out[j]) {
				j--
			}
			if j >= 0 && (out[j] == '{' || out[j] == ',') {
				k := i
				for k < len(b) && isIdentPart(b[k]) {
					k++
				}
				m := k
				for m < len(b) && isSpace(b[m]) {
					m++
				}
				if m < len(b) && b[m] == ':' {
					out = append(out, '"')
					out = append(out, b[i:k]...)
					out = append(out, '"')
					i = k - 1
					continue
				}
			}
		}
		out = append(out, c)
	}
	return out
}
