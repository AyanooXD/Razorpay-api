# AutoRazorpay (Go)

High-throughput card-checker service built on top of Razorpay's standard
checkout flow. Listens on HTTP, takes `cc|mm|yy|cvv` from the URL, runs the
card through a real Razorpay payment page, and returns the bank / WAF
response as JSON.

> ⚠️ **Legal notice**: This tool may violate Razorpay's Terms of Service.
> Use only against payment pages you own or have explicit written permission
> to test. The maintainers take no responsibility for misuse.

---

## Quick start

```bash
# 1. Build & run locally
make run

# 2. Hit the endpoint (default ₹1.00 INR charge)
curl "http://localhost:7070/razorpay/cc=4111111111111111%7C12%7C25%7C123"

# 3. Charge a CUSTOM amount (₹5 INR)
curl "http://localhost:7070/razorpay/cc=4111111111111111%7C12%7C25%7C123?amount=5"

# 4. Charge a CUSTOM amount + currency ($2 USD)
curl "http://localhost:7070/razorpay/cc=4111111111111111%7C12%7C25%7C123?amount=2&currency=USD"

# 5. Pass amount in paise directly (500p = ₹5)
curl "http://localhost:7070/razorpay/cc=4111111111111111%7C12%7C25%7C123?amount=500p"

# 6. Health check
curl http://localhost:7070/health
```

## Files

| File              | Purpose                                                        |
| ----------------- | ------------------------------------------------------------- |
| `autorzp.go`      | Main application (HTTP server + Razorpay flow)                |
| `autorzp_test.go` | Unit tests for the helpers (`go test -race ./...`)            |
| `sites.txt`       | Razorpay payment page URLs (one per line, `#` for comments)   |
| `px.txt`          | Proxy list. Format: `host:port:user:pass` or `host:port`      |
| `live.txt`        | Auto-generated at runtime — log of approved/charged cards     |
| `Dockerfile`      | Multi-stage build → ~15 MB final image                        |
| `railway.json`    | Railway.app deployment config (uses Dockerfile + /health)     |
| `Makefile`        | Common dev tasks (`make help` to list)                        |
| `go.mod`          | Go module definition (Go 1.22+)                               |

## Configuration (env vars)

| Variable          | Default       | Description                                        |
| ----------------- | ------------- | -------------------------------------------------- |
| `PORT`            | `7070`        | HTTP listen port                                   |
| `PROXY_FILE`      | `px.txt`      | Path to proxy list file                            |
| `SITES_FILE`      | `sites.txt`   | Path to Razorpay URLs file                         |
| `LIVE_FILE`       | `live.txt`    | Path to approved-cards log file                    |
| `MAX_CONCURRENT`  | `120`         | Max simultaneous card checks (semaphore capacity)  |
| `MAX_AMOUNT`      | `100000`      | Per-check upper bound on `amount` (in major units) |

## Endpoints

| Method | Path                                                | Description                                          |
| ------ | --------------------------------------------------- | ---------------------------------------------------- |
| GET    | `/health`                                           | Health probe (returns JSON)                          |
| GET    | `/razorpay/cc={cc\|mm\|yy\|cvv}`                    | Run a card check with default ₹1.00 INR charge       |
| GET    | `/razorpay/cc={cc\|mm\|yy\|cvv}?amount=N`           | Run a card check with a CUSTOM amount (₹N INR)       |
| GET    | `/razorpay/cc={cc\|mm\|yy\|cvv}?amount=N&currency=CCC` | Run a card check with custom amount + currency   |

### Custom amount & currency

By default the API charges **₹1.00 INR** (100 paise) to the card. You can
override this on a per-request basis with two optional parameters:

| Parameter | Required | Default | Format                                          | Example            |
| --------- | -------- | ------- | ----------------------------------------------- | ------------------ |
| `amount`  | no       | `1`     | Major units (integer or decimal) **or** `Np` for paise | `5`, `2.50`, `500p` |
| `currency`| no       | `INR`   | 3-letter ISO 4217 code (case-insensitive)        | `INR`, `usd`, `Eur` |

**Examples:**

```bash
# Default: ₹1.00 INR
curl "http://localhost:7070/razorpay/cc=4111...|12|25|123"

# Charge ₹5 INR
curl "http://localhost:7070/razorpay/cc=4111...|12|25|123?amount=5"

# Charge ₹5.50 INR
curl "http://localhost:7070/razorpay/cc=4111...|12|25|123?amount=5.50"

# Charge $2 USD (200 cents)
curl "http://localhost:7070/razorpay/cc=4111...|12|25|123?amount=2&currency=USD"

# Pass amount in paise directly (500p = ₹5)
curl "http://localhost:7070/razorpay/cc=4111...|12|25|123?amount=500p"

# Path-style (works without `?` — useful for clients that escape `?`)
curl "http://localhost:7070/razorpay/cc=4111...|12|25|123&amount=10&currency=EUR"
```

**Precedence** (highest first):

1. URL query string (`?amount=5&currency=INR`)
2. Path-embedded (`/razorpay/cc=...|...|...|...&amount=5&currency=INR`)
3. Built-in defaults (`1.00 INR`)

**Bounds:**

- Minimum: `0.01` (1 paise / 1 cent) — anything smaller can't be expressed.
- Maximum: `100000` (configurable via `MAX_AMOUNT` env var).

**Currency handling:**

- 2-decimal currencies (INR, USD, EUR, GBP, AUD, …) — amount is multiplied
  by 100 before being sent to Razorpay (so `amount=5` → `500` paise/cents).
- 0-decimal currencies (JPY, KRW, VND, CLP, ISK, …) — amount is sent as-is
  (so `amount=100` JPY → `100` yen, not 10000).
- Floating-point drift is handled with `math.Round` (so `1.15 * 100`
  correctly becomes `115`, not `114.99999…`).

### Response format

```json
{
  "status":   "approved|declined|charged|error",
  "response": "Insufficient funds (insufficient_funds)",
  "proxy":    "http://1.2.3.4:8080 [LIVE]",
  "amount":   5,
  "currency": "INR"
}
```

The `amount` and `currency` fields echo back the values that were actually
attempted on the card (in major units — `5` = ₹5, not 500 paise). They are
present on EVERY response, including errors and WAF blocks, so you can always
confirm what was charged.

## Development

```bash
make help           # list all targets
make build          # build binary into ./bin/autorzp
make run            # go run with PORT=7070
make test           # run tests with -race
make test-short     # skip integration tests
make lint           # go vet + gofmt check
make coverage       # HTML coverage report
make docker-build   # build autorzp:latest
make docker-run     # run container on :7070
make clean          # remove build artifacts
```

## Docker

```bash
docker build -t autorzp:latest .
docker run --rm -p 7070:7070 \
  -v "$(pwd)/live.txt:/app/live.txt" \
  autorzp:latest
```

The image includes a `HEALTHCHECK` that hits `/health` every 30s.

## Deployment (Railway.app)

1. Push this repo to GitHub.
2. In Railway: **New Project → Deploy from GitHub repo**.
3. Railway auto-detects `railway.json` → builds via `Dockerfile`.
4. Set any of the env vars above in Railway's Variables tab.
5. The `/health` endpoint is wired as the healthcheck — Railway restarts
   the container automatically if it starts failing.

## What's been fixed

The original repo had a number of critical bugs that have been resolved
across multiple rounds of fixes. See `git log` for the full history.
Highlights:

- **gzip decompression** — Go doesn't auto-decompress when the caller sets
  `Accept-Encoding` explicitly. We now decompress manually based on
  `Content-Encoding`.
- **UA / Sec-CH-UA consistency** — both headers are now derived from the
  same Chrome major version (per request) to avoid trivial WAF
  fingerprinting.
- **Retry fallthrough** — when all proxy-switch retries were skipped, the
  code used to fall through and try to parse the original 403 HTML as
  JSON. Now it correctly returns `BLOCKED`.
- **Slowloris protection** — `ReadHeaderTimeout` was missing entirely.
- **Graceful shutdown** — SIGINT/SIGTERM now drain in-flight requests.
- **Semaphore timeout** — when at capacity, clients get a `503` after 30s
  instead of hanging forever.
- **Panic recovery** — one bad request can no longer kill the goroutine.
- **Proxy host extraction** — credentials containing `:` or `//` no longer
  confuse the bad-host filter.
- **Crypto-rand fallbacks** — every `rand.Int` / `rand.Read` call now has
  a fallback path so a `/dev/urandom` failure can't nil-deref the server.
- **Custom charge amount & currency** — previously the API always charged
  exactly ₹1.00 INR. The `/razorpay/cc=...` endpoint now accepts optional
  `amount` and `currency` query (or path-embedded) parameters so users can
  charge any amount in any supported ISO 4217 currency. Zero-decimal
  currencies (JPY, KRW, VND, …) are handled correctly, and floating-point
  drift is fixed via `math.Round`. Full bounds validation rejects negative
  / oversized amounts with a clear error message.

### Round 4 (2026-08-02) — Real-time audit + fixes

A full re-audit against the live Razorpay / Chrome / uTLS / exchange-rate
ecosystem as of August 2026 surfaced and fixed:

- **Outdated BUILD hash** — the previous `BUILD` constant
  (`309175090e8afce78fc5e908a94a10676ce15aa5`) was rotated out of Razorpay's
  `checkout.js` (verified by fetching `checkout.razorpay.com/v1/checkout.js`
  live). Updated to the current hash
  (`11d0fb998d397102511c6c304e4f8565aaad29b3`).
- **Stale Chrome major range** — `randInt(135, 150)` produced User-Agent
  strings claiming Chrome 135–150, which no real browser has run since
  early 2025. Current stable Chrome is 151 (released 2026-07-27). Range
  updated to `randInt(145, 152)`. Using a stale Chrome version is a
  trivial WAF fingerprint signal.
- **Zero-decimal currency bug** — `forceAmount := math.Round(amountINR * 100)`
  hardcoded a ×100 multiplier, sending `10000` instead of `100` for
  `amount=100 JPY`. This would cause every JPY/KRW/VND/etc. charge to be
  100× too large. Fixed by using the already-defined `toSmallestUnit()`
  helper, which respects the ISO 4217 zero-decimal currency list.
- **session_token regex case-sensitivity** — `sessionTokenRe` used
  `[A-F0-9]{40,}` which only matched uppercase hex. If Razorpay ever
  emits a lowercase token, the entire flow would fail with "Session token
  not found". Updated to `[a-fA-F0-9]{40,}` for case-insensitive matching.
- **Variable shadowing `net/url` package** — `tgSendOne` declared a local
  `url := "https://api.telegram.org/..."` which shadowed the imported
  `url` package. This compiled today but was a bug magnet — any future
  edit that adds `url.QueryEscape` or similar inside `tgSendOne` would
  silently call the string method instead of the package function.
  Renamed to `apiURL`.
- **Fragile proxy CONNECT parsing** — the previous code read only 1024
  bytes of the proxy's CONNECT response and used substring search for
  ` 200 ` to detect success. This fails if (a) the proxy sends > 1024
  bytes of headers, (b) TCP fragments the response across reads, or
  (c) a future HTTP status code collides with the substring. Replaced
  with proper `http.ReadResponse` + `bufio.Reader` parsing, plus a new
  `bufConn` wrapper that preserves any bytes the bufio reader buffered
  past the response headers (which belong to the TLS handshake).
- **Dead code removal** — `getProxyTransport`, `proxyClientCache`,
  `proxyClientMutex`, `genSecChUA`, and `var _ = genSecChUA` were
  defined but never called. Removed to reduce maintenance surface.
- **Misleading `getStringFromMap` comment** — the doc claimed non-string
  types were returned as `""`, but the code (and tests) actually coerce
  them to strings via `fmt.Sprintf("%v", v)`. Updated the comment to
  match the actual behavior, and clarified that `nil` is the only type
  that returns `""`.
- **`getEnvDefault` whitespace handling** — a stray whitespace env var
  like `PROXY_FILE=" "` would be returned as-is and cause a confusing
  "no such file" error. Now trims whitespace before checking emptiness.
- **`filepath` parameter shadowing** — `loadProxies(filepath string)` and
  `loadSites(filepath string)` shadowed the `filepath` package name.
  Renamed to `path` to prevent future bugs if anyone adds
  `filepath.Join` / `filepath.Clean` calls inside.
- **live.txt crash safety** — `liveWriterGoroutine` now calls `f.Sync()`
  after every flush so a SIGKILL or power loss can no longer lose up to
  2 seconds of buffered writes.
- **Test coverage** — added 9 new tests for the round-4 changes:
  `TestBufConnReadsPrefixFirst`, `TestBufConnReadsAllPrefixInOneCall`,
  `TestBufConnEmptyPrefixFallsThrough`, `TestBufConnClosePropagates`,
  `TestSessionTokenReUppercase`, `TestSessionTokenReLowercase`,
  `TestSessionTokenReMixedCase`, `TestSessionTokenReSingleQuote`,
  `TestSessionTokenReTooShort`.

Verified live (2026-08-02) — all endpoints still active:
`api.razorpay.com/v1/standard_checkout/payments/create/checkout`,
`api.razorpay.com/v2/standard_checkout/preferences`,
`api.razorpay.com/v1/checkout/public`,
`lumberjack.razorpay.com/v2/m/logz`,
`lumberjack.razorpay.com/v2/logz`. Currency APIs: `api.frankfurter.dev`
(canonical — `.app` is a 301 redirect to `.dev`), `open.er-api.com/v6`,
`api.exchangerate-api.com/v4` (soft-deprecated, still works). uTLS
v1.8.2 is current; `HelloChrome_Auto` aliases to `HelloChrome_133`.

Plus a full unit-test suite (`autorzp_test.go`) covering the bug-prone
helpers and the new amount/currency parsing logic.

## License

Provided as-is for educational / authorized-testing purposes only.
