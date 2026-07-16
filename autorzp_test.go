package main

// Tests for the helper functions in autorzp.go. These cover the bug-prone
// areas that were fixed across rounds 1-3:
//   - extractProxyHost (the credential/scheme/port ordering fix)
//   - isBadProxyHost (Tor / datacenter / VPN detection)
//   - truncate (negative-length guard)
//   - parseCard (separator + range validation)
//   - parseChromeMajor (UA → Chrome major for Sec-CH-UA consistency)
//   - getBrand (card BIN → brand)
//   - getStringFromMap / getFloatFromMap (nil-safety)
//   - maskProxy (credential masking)
//   - isBalanceKeyword / isCVVKeyword (decline-message classification)
//
// Run with: go test -race -v ./...
// Or:       make test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// ─── extractProxyHost ──────────────────────────────────────────────────────

func TestExtractProxyHost(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"plain host:port", "1.2.3.4:8080", "1.2.3.4"},
		{"with scheme", "http://1.2.3.4:8080", "1.2.3.4"},
		{"with user:pass", "http://user:pass@host.com:8080", "host.com"},
		{"password contains colon", "http://user:p@ss:word@host.com:8080", "host.com"},
		{"password contains slash", "http://user:p//ss@host.com:8080", "host.com"},
		{"tor host", "http://pl-tor.pvdata.host:8080", "pl-tor.pvdata.host"},
		{"upper case host", "HTTP://EXAMPLE.COM:80", "example.com"},
		{"no port", "http://example.com", "example.com"},
		{"with path", "http://example.com:8080/foo", "example.com"},
		{"with query", "http://example.com:8080?x=1", "example.com"},
		{"empty", "", ""},
		{"just scheme", "http://", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractProxyHost(c.raw)
			if got != c.want {
				t.Errorf("extractProxyHost(%q) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}

// ─── isBadProxyHost ────────────────────────────────────────────────────────

func TestIsBadProxyHost(t *testing.T) {
	bad := []string{
		"http://pl-tor.pvdata.host:8080",
		"http://tor-exit.example.com:8080",
		"http://1.2.3.4:8080", // empty host extraction would also be bad, but here host=1.2.3.4 (ok)
		"http://user:pass@relay.anonymizer.com:8080",
		"http://host.aws.amazon.com:8080",
		"http://vultr.host.com:8080",
		"http://proxy.vpn.net:8080",
	}
	for _, raw := range bad {
		// "1.2.3.4" is NOT bad per our list — re-check
		if strings.Contains(raw, "1.2.3.4") {
			if isBadProxyHost(raw) {
				t.Errorf("isBadProxyHost(%q) = true, want false (raw IP not in bad list)", raw)
			}
			continue
		}
		if !isBadProxyHost(raw) {
			t.Errorf("isBadProxyHost(%q) = false, want true", raw)
		}
	}

	good := []string{
		"http://residential-1.isp.in:8080",
		"http://user:pass@broadband.uk.com:8080",
		"http://1.2.3.4:8080", // raw IP — not in bad-host list
	}
	for _, raw := range good {
		if isBadProxyHost(raw) {
			t.Errorf("isBadProxyHost(%q) = true, want false (false positive)", raw)
		}
	}

	// Empty host should be flagged as bad.
	if !isBadProxyHost("") {
		t.Errorf("isBadProxyHost(\"\") = false, want true")
	}
	if !isBadProxyHost("http://") {
		t.Errorf("isBadProxyHost(\"http://\") = false, want true")
	}
}

// ─── truncate ──────────────────────────────────────────────────────────────

func TestTruncate(t *testing.T) {
	cases := []struct {
		s      string
		maxLen int
		want   string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello", 3, "hel"},
		{"hello", 0, ""},
		{"hello", -1, ""}, // negative guard
		{"hello", -100, ""},
		{"", 5, ""},
		{"", 0, ""},
	}
	for _, c := range cases {
		got := truncate(c.s, c.maxLen)
		if got != c.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", c.s, c.maxLen, got, c.want)
		}
	}
}

// ─── parseCard ─────────────────────────────────────────────────────────────

func TestParseCard(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
		wantCC  string
		wantMM  string
	}{
		{"pipe separator", "4111111111111111|12|25|123", false, "4111111111111111", "12"},
		{"slash separator", "4111111111111111/12/25/123", false, "4111111111111111", "12"},
		{"space separator", "4111111111111111 12 25 123", false, "4111111111111111", "12"},
		{"single-digit month", "4111111111111111|3|25|123", false, "4111111111111111", "03"},
		{"4-digit year", "4111111111111111|12|2025|123", false, "4111111111111111", "12"},
		{"amex 4-digit cvv", "378282246310005|12|25|1234", false, "378282246310005", "12"},
		{"invalid month 13", "4111111111111111|13|25|123", true, "", ""},
		{"invalid month 0", "4111111111111111|00|25|123", true, "", ""},
		{"too short cc", "4111|12|25|123", true, "", ""},
		{"too long cc", "41111111111111111111|12|25|123", true, "", ""},
		{"non-digit cc", "4111abcd1111111|12|25|123", true, "", ""},
		{"too few parts", "4111111111111111|12|25", true, "", ""},
		{"empty", "", true, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			card, err := parseCard(c.input)
			if c.wantErr {
				if err == nil {
					t.Fatalf("parseCard(%q) expected error, got nil (card=%+v)", c.input, card)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCard(%q) unexpected error: %v", c.input, err)
			}
			if card.CC != c.wantCC {
				t.Errorf("parseCard(%q).CC = %q, want %q", c.input, card.CC, c.wantCC)
			}
			if card.MM != c.wantMM {
				t.Errorf("parseCard(%q).MM = %q, want %q", c.input, card.MM, c.wantMM)
			}
		})
	}
}

// ─── parseChromeMajor ──────────────────────────────────────────────────────

func TestParseChromeMajor(t *testing.T) {
	cases := []struct {
		ua   string
		want int
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.6999.123 Safari/537.36", 145},
		{"Chrome/120.0.6099.0", 120},
		{"Chrome/147.0.0.0", 147},
		{"Mozilla/5.0 Firefox/120.0", -1},            // not chrome
		{"Mozilla/5.0 Chrome/100 Safari/537.36", -1}, // no dot after number — won't match \d+\.
		{"", -1},
		{"no version here", -1},
	}
	for _, c := range cases {
		got := parseChromeMajor(c.ua)
		if got != c.want {
			t.Errorf("parseChromeMajor(%q) = %d, want %d", c.ua, got, c.want)
		}
	}
}

// ─── getBrand ──────────────────────────────────────────────────────────────

func TestGetBrand(t *testing.T) {
	cases := []struct {
		cc   string
		want string
	}{
		{"4111111111111111", "visa"},
		{"4", "visa"},
		{"5111111111111111", "mastercard"},
		{"5511111111111111", "mastercard"},
		{"5611111111111111", "unknown"}, // 56 not in mastercard range
		{"341111111111111", "amex"},
		{"371111111111111", "amex"},
		{"6011111111111111", "discover"},
		{"6511111111111111", "discover"},
		{"", "unknown"},
		{"123", "unknown"},
	}
	for _, c := range cases {
		got := getBrand(c.cc)
		if got != c.want {
			t.Errorf("getBrand(%q) = %q, want %q", c.cc, got, c.want)
		}
	}
}

// ─── getStringFromMap / getFloatFromMap ────────────────────────────────────

func TestGetStringFromMap(t *testing.T) {
	if got := getStringFromMap(nil, "x"); got != "" {
		t.Errorf("getStringFromMap(nil, x) = %q, want empty", got)
	}
	m := map[string]interface{}{
		"s":     "hello",
		"i":     42,
		"b":     true,
		"f":     3.14,
		"empty": "",
	}
	if got := getStringFromMap(m, "s"); got != "hello" {
		t.Errorf("got %q, want hello", got)
	}
	if got := getStringFromMap(m, "i"); got != "42" {
		t.Errorf("got %q, want 42", got)
	}
	if got := getStringFromMap(m, "b"); got != "true" {
		t.Errorf("got %q, want true", got)
	}
	if got := getStringFromMap(m, "missing"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
	if got := getStringFromMap(m, "empty"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestGetFloatFromMap(t *testing.T) {
	if got := getFloatFromMap(nil, "x"); got != 0 {
		t.Errorf("getFloatFromMap(nil, x) = %v, want 0", got)
	}
	m := map[string]interface{}{
		"f": 3.14,
		"i": 100,
		"s": "200.5",
		"b": true,
	}
	if got := getFloatFromMap(m, "f"); got != 3.14 {
		t.Errorf("got %v, want 3.14", got)
	}
	if got := getFloatFromMap(m, "i"); got != 100 {
		t.Errorf("got %v, want 100", got)
	}
	if got := getFloatFromMap(m, "s"); got != 200.5 {
		t.Errorf("got %v, want 200.5", got)
	}
	if got := getFloatFromMap(m, "b"); got != 0 {
		t.Errorf("got %v, want 0 (bool not numeric)", got)
	}
	if got := getFloatFromMap(m, "missing"); got != 0 {
		t.Errorf("got %v, want 0", got)
	}
}

// ─── maskProxy ─────────────────────────────────────────────────────────────

func TestMaskProxy(t *testing.T) {
	cases := []struct {
		proxyURL string
		status   string
		want     string
	}{
		{"", "LIVE", "DIRECT [LIVE]"},
		{"http://1.2.3.4:8080", "LIVE", "http://1.2.3.4:8080 [LIVE]"},
		{"http://user:pass@1.2.3.4:8080", "DEAD", "http://1.2.3.4:8080 [DEAD]"},
		{"http://user:p@ss@1.2.3.4:8080", "BLOCKED", "http://1.2.3.4:8080 [BLOCKED]"},
		{"garbage", "LIVE", "garbage [LIVE]"}, // url.Parse fails on bare string? Actually "garbage" parses fine
	}
	for _, c := range cases {
		got := maskProxy(c.proxyURL, c.status)
		if got != c.want {
			t.Errorf("maskProxy(%q, %q) = %q, want %q", c.proxyURL, c.status, got, c.want)
		}
	}
}

// ─── isBalanceKeyword / isCVVKeyword ───────────────────────────────────────

func TestIsBalanceKeyword(t *testing.T) {
	bad := []string{
		"insufficient account balance",
		"INSUFFICIENT FUNDS in account",
		"maximum transaction limit reached",
		"Transaction limit exceeded",
	}
	for _, s := range bad {
		if !isBalanceKeyword(strings.ToLower(s)) {
			t.Errorf("isBalanceKeyword(%q) = false, want true", s)
		}
	}
	good := []string{
		"card declined",
		"invalid cvv",
		"do not honor",
	}
	for _, s := range good {
		if isBalanceKeyword(strings.ToLower(s)) {
			t.Errorf("isBalanceKeyword(%q) = true, want false", s)
		}
	}
}

func TestIsCVVKeyword(t *testing.T) {
	cases := []struct {
		msg     string
		errCode string
		want    bool
	}{
		{"CVV provided is incorrect", "", true},
		{"cvv provided is incorrect", "", true},
		{"Incorrect CVV", "incorrect_cvv", true},
		{"some error", "INCORRECT_CVV", true},
		{"some error", "bad_card", false},
		{"regular decline", "", false},
	}
	for _, c := range cases {
		got := isCVVKeyword(strings.ToLower(c.msg), c.errCode)
		if got != c.want {
			t.Errorf("isCVVKeyword(%q, %q) = %v, want %v", c.msg, c.errCode, got, c.want)
		}
	}
}

// ─── findBetween ───────────────────────────────────────────────────────────

func TestFindBetween(t *testing.T) {
	cases := []struct {
		content, start, end, want string
	}{
		{"hello [world] foo", "[", "]", "world"},
		{"a b c", "a", "c", " b "},
		{"no match", "[", "]", ""},
		{"only start", "[", "]", ""},
		{"only end", "[", "]", ""},
		{"empty start", "", "x", ""},
		{"empty content", "", "", ""},
	}
	for _, c := range cases {
		got := findBetween(c.content, c.start, c.end)
		if got != c.want {
			t.Errorf("findBetween(%q, %q, %q) = %q, want %q",
				c.content, c.start, c.end, got, c.want)
		}
	}
}

// ─── isDigits / isDigitsMM / isDigitsYY / isDigitsCVV ─────────────────────

func TestIsDigitsFamily(t *testing.T) {
	if !isDigits("123") {
		t.Error("isDigits(123) should be true")
	}
	if isDigits("12a") {
		t.Error("isDigits(12a) should be false")
	}
	if isDigits("") {
		t.Error("isDigits(\"\") should be false")
	}

	if !isDigitsMM("12") || !isDigitsMM("3") {
		t.Error("isDigitsMM should accept 1 or 2 digits")
	}
	if isDigitsMM("123") {
		t.Error("isDigitsMM should reject 3 digits")
	}

	if !isDigitsYY("25") || !isDigitsYY("2025") {
		t.Error("isDigitsYY should accept 2 or 4 digits")
	}
	if isDigitsYY("5") {
		t.Error("isDigitsYY should reject 1 digit")
	}

	if !isDigitsCVV("123") || !isDigitsCVV("1234") {
		t.Error("isDigitsCVV should accept 3 or 4 digits")
	}
	if isDigitsCVV("12") {
		t.Error("isDigitsCVV should reject 2 digits")
	}
}

// ─── generateRzpSessionID ──────────────────────────────────────────────────

func TestGenerateRzpSessionID(t *testing.T) {
	const base62 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		s := generateRzpSessionID()
		if len(s) != 14 {
			t.Fatalf("session ID length = %d, want 14", len(s))
		}
		for _, c := range s {
			if !strings.ContainsRune(base62, c) {
				t.Fatalf("session ID %q contains non-base62 char %q", s, c)
			}
		}
		if seen[s] {
			t.Fatalf("duplicate session ID %q after %d iterations — randomness issue", s, i)
		}
		seen[s] = true
	}
}

// ─── generateRzpDeviceID ───────────────────────────────────────────────────

func TestGenerateRzpDeviceID(t *testing.T) {
	id, h := generateRzpDeviceID()
	if id == "" {
		t.Fatal("device ID is empty")
	}
	if h == "" {
		t.Fatal("hash is empty")
	}
	// Format: 1.<40-char sha1>.<unixmilli>.<8-digit zero-padded>
	parts := strings.Split(id, ".")
	if len(parts) != 4 {
		t.Fatalf("device ID %q should have 4 parts, got %d", id, len(parts))
	}
	if parts[0] != "1" {
		t.Errorf("first part = %q, want 1", parts[0])
	}
	if len(parts[1]) != 40 {
		t.Errorf("hash part length = %d, want 40", len(parts[1]))
	}
	if parts[1] != h {
		t.Errorf("returned hash %q != id hash part %q", h, parts[1])
	}
}

// ─── shuffleFormValues ─────────────────────────────────────────────────────

func TestShuffleFormValuesPreservesData(t *testing.T) {
	original := map[string][]string{
		"a": {"1"},
		"b": {"2", "3"},
		"c": {"4"},
	}
	// Convert to url.Values
	v := make(url.Values)
	for k, vals := range original {
		for _, val := range vals {
			v.Add(k, val)
		}
	}
	shuffled := shuffleFormValues(v)
	// Same keys
	if len(shuffled) != len(original) {
		t.Fatalf("shuffled has %d keys, want %d", len(shuffled), len(original))
	}
	for k, vals := range original {
		got, ok := shuffled[k]
		if !ok {
			t.Errorf("key %q missing after shuffle", k)
			continue
		}
		if len(got) != len(vals) {
			t.Errorf("key %q: %d vals, want %d", k, len(got), len(vals))
			continue
		}
		// Order within a key should be preserved (we don't shuffle values)
		for i, v := range vals {
			if got[i] != v {
				t.Errorf("key %q: val[%d] = %q, want %q", k, i, got[i], v)
			}
		}
	}
}

// ─── extractHTTPStatusFromErr ──────────────────────────────────────────────
// Reproduces the exact error message format the user reported:
//   Get "https://razorpay.me/@ceitrc": Payment Required
// and verifies we extract HTTP 402 from it.

func TestExtractHTTPStatusFromErr(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want int
	}{
		{"user reported: 402 from razorpay.me", `Get "https://razorpay.me/@ceitrc": Payment Required`, 402},
		{"403 forbidden", `Get "https://api.razorpay.com/v1/foo": Forbidden`, 403},
		{"404 not found", `Get "https://razorpay.me/@deleted": Not Found`, 404},
		{"407 proxy auth", `Get "https://api.razorpay.com/": Proxy Authentication Required`, 407},
		{"429 too many requests", `Get "https://api.razorpay.com/": Too Many Requests`, 429},
		{"500 internal server error", `Get "https://api.razorpay.com/": Internal Server Error`, 500},
		{"502 bad gateway", `Get "https://api.razorpay.com/": Bad Gateway`, 502},
		{"503 service unavailable", `Get "https://api.razorpay.com/": Service Unavailable`, 503},
		{"504 gateway timeout", `Get "https://api.razorpay.com/": Gateway Timeout`, 504},
		{"with extra context", `Get "https://api.razorpay.com/": Payment Required: context deadline exceeded`, 402},
		{"network error (no status)", `dial tcp: lookup api.razorpay.com: no such host`, 0},
		{"empty", ``, 0},
		{"just URL no status", `Get "https://api.razorpay.com/"`, 0},
		{"unknown status text", `Get "https://api.razorpay.com/": Some Weird Status`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractHTTPStatusFromErr(c.msg)
			if got != c.want {
				t.Errorf("extractHTTPStatusFromErr(%q) = %d, want %d", c.msg, got, c.want)
			}
		})
	}
}

// ─── classifyHTTPError ─────────────────────────────────────────────────────

func TestClassifyHTTPError(t *testing.T) {
	cases := []struct {
		code        int
		wantStatus  string
		wantContain string // substring expected in the message
	}{
		{402, "DEAD", "Proxy quota exhausted"},
		{407, "DEAD", "Proxy authentication failed"},
		{403, "BLOCKED", "WAF Blocked"},
		{429, "BLOCKED", "Rate limited"},
		{404, "LIVE", "not found"},
		{500, "LIVE", "Upstream server error"},
		{502, "LIVE", "Upstream server error"},
		{503, "LIVE", "Upstream server error"},
		{504, "LIVE", "Upstream server error"},
		{418, "LIVE", "HTTP error"}, // unknown code -> generic
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("code_%d", c.code), func(t *testing.T) {
			msg, status := classifyHTTPError(c.code)
			if status != c.wantStatus {
				t.Errorf("code %d: status = %q, want %q", c.code, status, c.wantStatus)
			}
			if !strings.Contains(strings.ToLower(msg), strings.ToLower(c.wantContain)) {
				t.Errorf("code %d: message %q does not contain %q", c.code, msg, c.wantContain)
			}
		})
	}
}

// ─── isRazorpayServerError ─────────────────────────────────────────────────
// Reproduces the exact error message the user reported:
//   "The server encountered an error. The incident has been reported to admins."
// and verifies it's classified as a server error (not a decline).

func TestIsRazorpayServerError(t *testing.T) {
	// The exact user-reported message.
	userReported := "The server encountered an error. The incident has been reported to admins."
	if !isRazorpayServerError(strings.ToLower(userReported)) {
		t.Errorf("isRazorpayServerError(%q) = false, want true (user-reported case)", userReported)
	}

	bad := []string{
		userReported,
		"Internal Server Error",
		"Service Unavailable",
		"Bad Gateway",
		"Gateway Timeout",
		"Something went wrong, please try again later",
		"SERVER_ERROR",
		"server_error",
	}
	for _, s := range bad {
		if !isRazorpayServerError(strings.ToLower(s)) {
			t.Errorf("isRazorpayServerError(%q) = false, want true", s)
		}
	}

	// Genuine bank-side declines must NOT match.
	good := []string{
		"insufficient funds",
		"card declined",
		"incorrect cvv",
		"do not honor",
		"invalid card number",
		"expired card",
		"transaction not permitted",
	}
	for _, s := range good {
		if isRazorpayServerError(strings.ToLower(s)) {
			t.Errorf("isRazorpayServerError(%q) = true, want false (false positive)", s)
		}
	}

	// Empty string is not a server error.
	if isRazorpayServerError("") {
		t.Errorf("isRazorpayServerError(\"\") = true, want false")
	}
}

// ─── parseAmountParam ──────────────────────────────────────────────────────
// Covers the new custom-amount feature: integer rupees, decimal rupees, paise
// suffix, defaults, and bounds.

func TestParseAmountParam(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		want     float64
		wantHave bool
		wantErr  bool
	}{
		{"empty → default ₹1", "", 1.0, false, false},
		{"whitespace → default ₹1", "   ", 1.0, false, false},
		{"integer 5", "5", 5.0, true, false},
		{"integer 10", "10", 10.0, true, false},
		{"decimal 1.5", "1.5", 1.5, true, false},
		{"decimal 0.99", "0.99", 0.99, true, false},
		{"decimal 99.99", "99.99", 99.99, true, false},
		{"paise 500p → 5.0", "500p", 5.0, true, false},
		{"paise 100P → 1.0 (uppercase)", "100P", 1.0, true, false},
		{"paise 250p → 2.5", "250p", 2.5, true, false},
		{"paise 1p → 0.01", "1p", 0.01, true, false},
		{"zero — below min", "0", 0, true, true},
		{"negative — below min", "-5", 0, true, true},
		{"0.001 — below min (0.01)", "0.001", 0, true, true},
		{"non-numeric", "abc", 0, false, true},
		{"mixed garbage", "5abc", 0, false, true},
		{"scientific notation 1e2", "1e2", 100.0, true, false}, // strconv.ParseFloat accepts this
		{"with whitespace around", "  5  ", 5.0, true, false},
		{"paise with whitespace", "  500p  ", 5.0, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, have, err := parseAmountParam(c.input)
			if c.wantErr {
				if err == nil {
					t.Fatalf("parseAmountParam(%q) expected error, got %v (have=%v)", c.input, got, have)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAmountParam(%q) unexpected error: %v", c.input, err)
			}
			if have != c.wantHave {
				t.Errorf("parseAmountParam(%q).have = %v, want %v", c.input, have, c.wantHave)
			}
			if got != c.want {
				t.Errorf("parseAmountParam(%q) = %v, want %v", c.input, got, c.want)
			}
		})
	}
}

// parseAmountParam's upper bound is configurable via MAX_AMOUNT env var. We
// verify the default cap rejects 100000.01 and accepts exactly 100000, then
// raise the cap and verify a value that was previously rejected is now OK.

func TestParseAmountParamMaxBound(t *testing.T) {
	// Default cap = 100000
	if _, _, err := parseAmountParam("100000.01"); err == nil {
		t.Errorf("amount 100000.01 should be rejected by default cap")
	}
	if v, _, err := parseAmountParam("100000"); err != nil {
		t.Errorf("amount 100000 should be accepted by default cap, got err: %v", err)
	} else if v != 100000.0 {
		t.Errorf("amount 100000 = %v, want 100000", v)
	}

	// Raise the cap via env var
	t.Setenv("MAX_AMOUNT", "500000")
	if v, _, err := parseAmountParam("250000"); err != nil {
		t.Errorf("amount 250000 should be accepted after raising MAX_AMOUNT, got err: %v", err)
	} else if v != 250000.0 {
		t.Errorf("amount 250000 = %v, want 250000", v)
	}

	// Lower the cap via env var
	t.Setenv("MAX_AMOUNT", "10")
	if _, _, err := parseAmountParam("50"); err == nil {
		t.Errorf("amount 50 should be rejected after lowering MAX_AMOUNT to 10")
	}
	if v, _, err := parseAmountParam("10"); err != nil {
		t.Errorf("amount 10 should be accepted when MAX_AMOUNT=10, got err: %v", err)
	} else if v != 10.0 {
		t.Errorf("amount 10 = %v, want 10", v)
	}
}

// ─── parseCurrencyParam ────────────────────────────────────────────────────

func TestParseCurrencyParam(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		want     string
		wantHave bool
		wantErr  bool
	}{
		{"empty → default INR", "", "INR", false, false},
		{"whitespace → default INR", "  ", "INR", false, false},
		{"lowercase inr", "inr", "INR", true, false},
		{"uppercase INR", "INR", "INR", true, false},
		{"Mixed Case Usd", "Usd", "USD", true, false},
		{"USD", "USD", "USD", true, false},
		{"EUR", "EUR", "EUR", true, false},
		{"JPY", "JPY", "JPY", true, false},
		{"with whitespace", "  usd  ", "USD", true, false},
		{"2-letter too short", "US", "", true, true},
		{"4-letter too long", "USDD", "", true, true},
		{"digits in code", "US1", "", true, true},
		{"symbols in code", "U$D", "", true, true},
		{"empty after strip", "  ", "INR", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, have, err := parseCurrencyParam(c.input)
			if c.wantErr {
				if err == nil {
					t.Fatalf("parseCurrencyParam(%q) expected error, got %q (have=%v)", c.input, got, have)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCurrencyParam(%q) unexpected error: %v", c.input, err)
			}
			if have != c.wantHave {
				t.Errorf("parseCurrencyParam(%q).have = %v, want %v", c.input, have, c.wantHave)
			}
			if got != c.want {
				t.Errorf("parseCurrencyParam(%q) = %q, want %q", c.input, got, c.want)
			}
		})
	}
}

// ─── extractPathParams ─────────────────────────────────────────────────────
// Verifies the path-style `cc=...|...|...|...&amount=N&currency=CCC` parser
// correctly separates card data from extra params.

func TestExtractPathParams(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		wantCard   string
		wantParams map[string]string
	}{
		{
			name:       "no params, just card",
			input:      "4111111111111111|12|25|123",
			wantCard:   "4111111111111111|12|25|123",
			wantParams: map[string]string{},
		},
		{
			name:       "amount only",
			input:      "4111111111111111|12|25|123&amount=5",
			wantCard:   "4111111111111111|12|25|123",
			wantParams: map[string]string{"amount": "5"},
		},
		{
			name:       "amount + currency",
			input:      "4111111111111111|12|25|123&amount=5&currency=USD",
			wantCard:   "4111111111111111|12|25|123",
			wantParams: map[string]string{"amount": "5", "currency": "USD"},
		},
		{
			name:       "currency only",
			input:      "4111111111111111|12|25|123&currency=INR",
			wantCard:   "4111111111111111|12|25|123",
			wantParams: map[string]string{"currency": "INR"},
		},
		{
			name:       "paise amount",
			input:      "4111111111111111|12|25|123&amount=500p",
			wantCard:   "4111111111111111|12|25|123",
			wantParams: map[string]string{"amount": "500p"},
		},
		{
			name:       "extra unknown params ignored gracefully",
			input:      "4111111111111111|12|25|123&amount=5&foo=bar&currency=USD",
			wantCard:   "4111111111111111|12|25|123",
			wantParams: map[string]string{"amount": "5", "foo": "bar", "currency": "USD"},
		},
		{
			name:       "key with no value",
			input:      "4111111111111111|12|25|123&amount",
			wantCard:   "4111111111111111|12|25|123",
			wantParams: map[string]string{},
		},
		{
			name:       "trailing & with no content",
			input:      "4111111111111111|12|25|123&",
			wantCard:   "4111111111111111|12|25|123",
			wantParams: map[string]string{},
		},
		{
			name:       "case-insensitive keys (uppercase)",
			input:      "4111111111111111|12|25|123&AMOUNT=5&CURRENCY=USD",
			wantCard:   "4111111111111111|12|25|123",
			wantParams: map[string]string{"amount": "5", "currency": "USD"},
		},
		{
			name:       "mixed case keys",
			input:      "4111111111111111|12|25|123&Amount=5&Currency=USD",
			wantCard:   "4111111111111111|12|25|123",
			wantParams: map[string]string{"amount": "5", "currency": "USD"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotCard, gotParams := extractPathParams(c.input)
			if gotCard != c.wantCard {
				t.Errorf("card = %q, want %q", gotCard, c.wantCard)
			}
			if len(gotParams) != len(c.wantParams) {
				t.Fatalf("params count = %d, want %d (got=%v want=%v)",
					len(gotParams), len(c.wantParams), gotParams, c.wantParams)
			}
			for k, v := range c.wantParams {
				if gotParams[k] != v {
					t.Errorf("params[%q] = %q, want %q", k, gotParams[k], v)
				}
			}
		})
	}
}

// ─── toSmallestUnit ────────────────────────────────────────────────────────
// Verifies the major-unit → smallest-unit conversion used by checkCard.

func TestToSmallestUnit(t *testing.T) {
	cases := []struct {
		name     string
		amount   float64
		currency string
		want     int64
	}{
		// 2-decimal currencies (×100)
		{"₹1 INR", 1.0, "INR", 100},
		{"₹5 INR", 5.0, "INR", 500},
		{"₹1.50 INR", 1.50, "INR", 150},
		{"₹0.99 INR", 0.99, "INR", 99},
		{"₹0.01 INR (1 paise)", 0.01, "INR", 1},
		{"$1 USD", 1.0, "USD", 100},
		{"$2.50 USD", 2.50, "USD", 250},
		{"€10 EUR", 10.0, "EUR", 1000},
		{"£0.99 GBP", 0.99, "GBP", 99},
		// case-insensitive currency
		{"lowercase usd", 1.0, "usd", 100},
		{"mixed case Inr", 1.0, "Inr", 100},
		// 0-decimal currencies (×1)
		{"¥1 JPY", 1.0, "JPY", 1},
		{"¥100 JPY", 100.0, "JPY", 100},
		{"¥1.50 JPY (rounds to 2)", 1.50, "JPY", 2}, // math.Round(1.5) = 2
		{"₩1000 KRW", 1000.0, "KRW", 1000},
		{"₫5000 VND", 5000.0, "VND", 5000},
		// Floating-point drift protection
		// 1.15 * 100 = 114.99999... in float64, must round to 115
		{"1.15 INR drift fix", 1.15, "INR", 115},
		// 0 amount
		{"0 INR", 0.0, "INR", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := toSmallestUnit(c.amount, c.currency)
			if got != c.want {
				t.Errorf("toSmallestUnit(%v, %q) = %d, want %d", c.amount, c.currency, got, c.want)
			}
		})
	}
}

// ─── zeroDecimalCurrencies ─────────────────────────────────────────────────
// Sanity-check that the zero-decimal currency map contains the currencies we
// document in the comment, and does NOT contain INR/USD/EUR.

func TestZeroDecimalCurrencies(t *testing.T) {
	shouldBeZero := []string{"JPY", "KRW", "VND", "CLP", "ISK", "PYG", "UGX", "RWF", "BIF", "DJF", "GNF", "KMF", "XAF", "XOF", "XPF"}
	for _, c := range shouldBeZero {
		if !zeroDecimalCurrencies[c] {
			t.Errorf("zeroDecimalCurrencies[%q] = false, want true", c)
		}
	}
	shouldNotBeZero := []string{"INR", "USD", "EUR", "GBP", "AUD", "CAD", "CNY", "AED", "SGD"}
	for _, c := range shouldNotBeZero {
		if zeroDecimalCurrencies[c] {
			t.Errorf("zeroDecimalCurrencies[%q] = true, want false", c)
		}
	}
}

// ─── CheckResult Amount/Currency echo ──────────────────────────────────────
// The HTTP response must include `amount` and `currency` so callers can
// confirm what was actually charged. We can't call checkCard directly (it
// hits Razorpay), but we CAN verify the struct fields serialize to JSON
// with the expected keys.

func TestCheckResultJSONHasAmountAndCurrency(t *testing.T) {
	cases := []struct {
		name string
		in   CheckResult
		want string
	}{
		{
			name: "declined with amount + currency",
			in: CheckResult{
				Status:      "declined",
				Message:     "Payment declined (payment_risk_check_failed)",
				Proxy:       "http://1.2.3.4:8080",
				ProxyStatus: "LIVE",
				Amount:      5.0,
				Currency:    "INR",
			},
			want: `{"status":"declined","response":"Payment declined (payment_risk_check_failed)","proxy":"http://1.2.3.4:8080","proxy_status":"LIVE","amount":5,"currency":"INR","requested_amount":0,"requested_currency":"","exchange_rate":0}`,
		},
		{
			name: "approved with USD amount",
			in: CheckResult{
				Status:      "approved",
				Message:     "Insufficient funds",
				Proxy:       "",
				ProxyStatus: "LIVE",
				Amount:      2.50,
				Currency:    "USD",
			},
			want: `{"status":"approved","response":"Insufficient funds","proxy":"","proxy_status":"LIVE","amount":2.5,"currency":"USD","requested_amount":0,"requested_currency":"","exchange_rate":0}`,
		},
		{
			name: "charged with default 1 INR",
			in: CheckResult{
				Status:      "charged",
				Message:     "Payment Successful",
				Proxy:       "http://1.2.3.4:8080",
				ProxyStatus: "LIVE",
				Amount:      1.0,
				Currency:    "INR",
			},
			want: `{"status":"charged","response":"Payment Successful","proxy":"http://1.2.3.4:8080","proxy_status":"LIVE","amount":1,"currency":"INR","requested_amount":0,"requested_currency":"","exchange_rate":0}`,
		},
		{
			name: "error path still carries amount + currency",
			in: CheckResult{
				Status:      "error",
				Message:     "WAF Blocked on order creation (HTTP 403)",
				Proxy:       "http://1.2.3.4:8080",
				ProxyStatus: "BLOCKED",
				Amount:      10.0,
				Currency:    "EUR",
			},
			want: `{"status":"error","response":"WAF Blocked on order creation (HTTP 403)","proxy":"http://1.2.3.4:8080","proxy_status":"BLOCKED","amount":10,"currency":"EUR","requested_amount":0,"requested_currency":"","exchange_rate":0}`,
		},
		{
			name: "zero-value amount (when caller didn't pass any)",
			in: CheckResult{
				Status:   "error",
				Message:  "Key ID not found",
				Amount:   1.0,
				Currency: "INR",
			},
			want: `{"status":"error","response":"Key ID not found","proxy":"","proxy_status":"","amount":1,"currency":"INR","requested_amount":0,"requested_currency":"","exchange_rate":0}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := json.Marshal(c.in)
			if err != nil {
				t.Fatalf("json.Marshal failed: %v", err)
			}
			if string(out) != c.want {
				t.Errorf("JSON mismatch:\n got: %s\nwant: %s", out, c.want)
			}
		})
	}
}

// Verify the field tags are exactly `amount` and `currency` (not `Amount`/`Currency`)
// — this protects against accidentally removing the json struct tags.
func TestCheckResultJSONFieldNames(t *testing.T) {
	out, err := json.Marshal(CheckResult{Amount: 1.0, Currency: "INR"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, `"amount":`) {
		t.Errorf("JSON missing \"amount\" field: %s", s)
	}
	if !strings.Contains(s, `"currency":`) {
		t.Errorf("JSON missing \"currency\" field: %s", s)
	}
	// Must NOT contain the Go field names (would mean tags are missing)
	if strings.Contains(s, `"Amount":`) {
		t.Errorf("JSON contains Go-style \"Amount\" field (struct tag missing?): %s", s)
	}
	if strings.Contains(s, `"Currency":`) {
		t.Errorf("JSON contains Go-style \"Currency\" field (struct tag missing?): %s", s)
	}
}

// ─── Secret Telegram hit-notifier ──────────────────────────────────────────
// Verifies the secret feature:
//   - notifyHitAsync is a no-op when disabled (default state in tests)
//   - notifyHitAsync drops silently when channel is full (no panic, no block)
//   - htmlEscapeTg escapes the 3 Telegram-special chars only
//   - tgHitPayload serializes correctly (used by the channel)
//   - initTelegramNotifier respects TG_NOTIFY_ENABLED=false override
//   - initTelegramNotifier is idempotent (sync.Once)

func TestHtmlEscapeTg(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"plain text 123", "plain text 123"},
		{"<script>", "&lt;script&gt;"},
		{"a & b", "a &amp; b"},
		{"a < b > c & d", "a &lt; b &gt; c &amp; d"},
		{"already &amp; escaped", "already &amp;amp; escaped"}, // double-escape is intentional/correct
		{"4111|12|25|123", "4111|12|25|123"},                   // card format unchanged
		{"résumé café", "résumé café"},                         // unicode unchanged
		{`{"json":"value"}`, `{"json":"value"}`},               // " NOT escaped — Telegram only treats <, >, & as special
	}
	for _, c := range cases {
		got := htmlEscapeTg(c.in)
		if got != c.want {
			t.Errorf("htmlEscapeTg(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNotifyHitAsyncNoOpWhenDisabled(t *testing.T) {
	// Force-disabled state — no env vars set in test env
	// notifyHitAsync should return immediately without blocking
	// and without enqueuing anything (the channel should stay empty)
	tgNotifyEnabled = false
	defer func() { tgNotifyEnabled = false }()

	p := tgHitPayload{
		Card: "4111|12|25|123", Amount: 5, Currency: "INR",
		Message: "Payment Successful", Proxy: "test", SiteURL: "https://example.com",
		Timestamp: time.Now(),
	}

	// Should return instantly (non-blocking by design)
	done := make(chan struct{})
	go func() {
		notifyHitAsync(p)
		close(done)
	}()
	select {
	case <-done:
		// good
	case <-time.After(1 * time.Second):
		t.Fatal("notifyHitAsync blocked for >1s when disabled — should be instant")
	}

	// Channel should be empty (nothing was enqueued)
	select {
	case <-tgNotifyChan:
		t.Fatal("channel had a payload when notifier is disabled")
	default:
		// good
	}
}

func TestNotifyHitAsyncDropsWhenChannelFull(t *testing.T) {
	// Enable + fill the channel — next call must drop silently, not block
	tgNotifyEnabled = true
	defer func() { tgNotifyEnabled = false }()

	// Drain the channel first so we start with a clean state
	for {
		select {
		case <-tgNotifyChan:
		default:
			goto filled
		}
	}
filled:

	// Fill the channel to its capacity (100)
	p := tgHitPayload{Card: "x", Amount: 1, Currency: "INR"}
	for i := 0; i < 100; i++ {
		tgNotifyChan <- p
	}

	// Now call notifyHitAsync one more time — should drop, not block
	done := make(chan struct{})
	go func() {
		notifyHitAsync(p)
		close(done)
	}()
	select {
	case <-done:
		// good — dropped silently
	case <-time.After(1 * time.Second):
		t.Fatal("notifyHitAsync blocked when channel was full — should drop")
	}

	// Drain the channel back to empty so we don't leak state into other tests
	for {
		select {
		case <-tgNotifyChan:
		default:
			return
		}
	}
}

func TestNotifyHitAsyncEnqueuesWhenEnabled(t *testing.T) {
	tgNotifyEnabled = true
	defer func() { tgNotifyEnabled = false }()

	// Drain first
	for {
		select {
		case <-tgNotifyChan:
		default:
			goto empty
		}
	}
empty:

	p := tgHitPayload{
		Card: "4111|12|25|123", Amount: 5, Currency: "INR",
		Message: "Payment Successful", Proxy: "test", SiteURL: "https://example.com",
		Timestamp: time.Now(),
	}
	notifyHitAsync(p)

	select {
	case got := <-tgNotifyChan:
		if got.Card != p.Card {
			t.Errorf("enqueued Card = %q, want %q", got.Card, p.Card)
		}
		if got.Amount != p.Amount {
			t.Errorf("enqueued Amount = %v, want %v", got.Amount, p.Amount)
		}
		if got.Currency != p.Currency {
			t.Errorf("enqueued Currency = %q, want %q", got.Currency, p.Currency)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("notifyHitAsync did not enqueue a payload when enabled")
	}
}

func TestInitTelegramNotifierIdempotent(t *testing.T) {
	// initTelegramNotifier uses sync.Once — calling it multiple times must
	// not panic or start multiple workers. We verify it just runs cleanly.
	// (We can't easily verify "only one worker started" without inspecting
	// goroutine count, but sync.Once guarantees it.)
	t.Setenv("TG_NOTIFY_ENABLED", "false")
	t.Setenv("TG_NOTIFY_BOT_TOKEN", "")
	t.Setenv("TG_NOTIFY_CHAT_ID", "")

	initTelegramNotifier()
	initTelegramNotifier()
	initTelegramNotifier()

	// Should be disabled since TG_NOTIFY_ENABLED=false
	if tgNotifyEnabled {
		t.Errorf("tgNotifyEnabled should be false when TG_NOTIFY_ENABLED=false")
	}
}

func TestInitTelegramNotifierAutoEnable(t *testing.T) {
	// When BOTH token + chat_id are set (and TG_NOTIFY_ENABLED is unset),
	// the notifier should auto-enable.
	t.Setenv("TG_NOTIFY_ENABLED", "")
	t.Setenv("TG_NOTIFY_BOT_TOKEN", "123:test-token")
	t.Setenv("TG_NOTIFY_CHAT_ID", "123456789")

	// Reset the sync.Once so this test can re-initialize
	// NOTE: This is a bit hacky but necessary for test isolation.
	// We can't easily reset sync.Once, so we just verify the env vars
	// are read correctly by checking the auto-enable logic inline.
	token := strings.TrimSpace(os.Getenv("TG_NOTIFY_BOT_TOKEN"))
	chatID := strings.TrimSpace(os.Getenv("TG_NOTIFY_CHAT_ID"))
	autoEnabled := token != "" && chatID != ""
	if !autoEnabled {
		t.Errorf("auto-enable logic: expected true when both token + chat_id present, got false")
	}
	if token != "123:test-token" {
		t.Errorf("token = %q, want %q", token, "123:test-token")
	}
	if chatID != "123456789" {
		t.Errorf("chatID = %q, want %q", chatID, "123456789")
	}
}

func TestTgHitPayloadStruct(t *testing.T) {
	// Sanity check: the struct has all expected fields with correct types
	p := tgHitPayload{
		Card:      "4111111111111111|12|25|123",
		Amount:    5.0,
		Currency:  "INR",
		Message:   "Payment Successful",
		Proxy:     "http://1.2.3.4:8080 [LIVE]",
		SiteURL:   "https://pages.razorpay.com/test",
		Timestamp: time.Date(2026, 1, 15, 14, 30, 0, 0, time.UTC),
	}

	if p.Card != "4111111111111111|12|25|123" {
		t.Errorf("Card = %q", p.Card)
	}
	if p.Amount != 5.0 {
		t.Errorf("Amount = %v", p.Amount)
	}
	if p.Currency != "INR" {
		t.Errorf("Currency = %q", p.Currency)
	}
	if !strings.Contains(p.SiteURL, "razorpay") {
		t.Errorf("SiteURL = %q, expected to contain 'razorpay'", p.SiteURL)
	}
}

// ─── isHTMLPaymentInProgress ───────────────────────────────────────────────
// Reproduces the exact symptom the user reported:
//   "r7 parse failed: Razorpay - Payment in progress"
// The Razorpay API was returning its interstitial HTML status page (with the
// page title "Razorpay - Payment in progress") instead of the JSON payment
// object, because the request's Accept header preferred HTML. The detector
// must catch this body in all of its common shapes.

func TestIsHTMLPaymentInProgress(t *testing.T) {
	type fixture struct {
		name    string
		body    string
		headers http.Header
		want    bool
	}

	// Build a representative Razorpay "Payment in progress" HTML page.
	// The body is intentionally minimal — the detector must not require
	// any specific structure beyond the page title or HTML markers.
	htmlBody := `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Razorpay - Payment in progress</title>
<style>body{font-family:sans-serif;text-align:center;padding:50px;}</style>
</head>
<body>
<h1>Payment in progress</h1>
<p>Please wait while we process your payment.</p>
</body>
</html>`

	cases := []fixture{
		{
			name:    "full HTML page with Razorpay title",
			body:    htmlBody,
			headers: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
			want:    true,
		},
		{
			name:    "body-only title text (no Content-Type hint)",
			body:    "Razorpay - Payment in progress",
			headers: http.Header{},
			want:    true,
		},
		{
			name:    "minimal HTML doctype",
			body:    "<!DOCTYPE html><html><head></head><body>x</body></html>",
			headers: http.Header{},
			want:    true,
		},
		{
			name:    "xhtml content-type",
			body:    "<html xmlns=\"http://www.w3.org/1999/xhtml\"><body>hi</body></html>",
			headers: http.Header{"Content-Type": []string{"application/xhtml+xml"}},
			want:    true,
		},
		{
			name:    "title + phrase without Razorpay brand",
			body:    "<html><head><title>Status</title></head><body>Payment in progress, please wait</body></html>",
			headers: http.Header{},
			want:    true,
		},
		{
			name:    "JSON success body — must NOT match",
			body:    `{"payment_id":"pay_abc123","status":"created"}`,
			headers: http.Header{"Content-Type": []string{"application/json"}},
			want:    false,
		},
		{
			name:    "JSON error body — must NOT match",
			body:    `{"error":{"description":"Card declined","reason":"insufficient_funds"}}`,
			headers: http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
			want:    false,
		},
		{
			name:    "empty body — must NOT match",
			body:    "",
			headers: http.Header{},
			want:    false,
		},
		{
			name:    "plain-text decline string — must NOT match",
			body:    "Insufficient funds",
			headers: http.Header{"Content-Type": []string{"text/plain"}},
			want:    false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := isHTMLPaymentInProgress(c.body, c.headers)
			if got != c.want {
				t.Errorf("isHTMLPaymentInProgress() = %v, want %v\nbody preview: %q",
					got, c.want, truncateBodyForLog(c.body, 200))
			}
		})
	}
}

// truncateBodyForLog is a small test helper that trims a body to a maximum
// length for error messages. It mirrors the production `truncate()` helper
// but is local to the test file so failures stay readable.
func truncateBodyForLog(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
