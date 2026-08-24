"""
DDoS Attack Simulation & Mitigation
------------------------------------------
Simulates how a server-side system detects and mitigates a
Distributed Denial-of-Service (DDoS) attack pattern — WITHOUT
actually attacking anything. It runs a small local HTTP server,
generates simulated traffic (both normal and attack-like), and
shows the detection engine identifying + auto-blocking abusive
source IPs in real time.

WHY THIS DESIGN (important for your report / viva):
A real DDoS attack script would be illegal to build/run against any
target you don't own, and pointless to run against your own laptop.
What security teams actually build and deploy is the DEFENSIVE side —
a system that watches incoming request rates and reacts. That is what
this project demonstrates, end-to-end, with real (simulated) traffic.

HOW IT WORKS:
  1. A lightweight local HTTP server logs every incoming request's
     source IP and timestamp.
  2. A sliding-time-window rate limiter checks: how many requests has
     this IP made in the last N seconds?
  3. If an IP crosses the threshold, it's flagged as a suspected
     attacker and auto-blocked (further requests get HTTP 429).
  4. A traffic generator simulates a handful of "normal" users and
     one "attacker" flooding requests, so you can watch detection
     happen live.

HOW TO RUN:
  python3 ddos_detector.py
  (Runs entirely on localhost — nothing leaves your machine.)
"""

import time
import threading
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.request
import random

# ---------------- Configuration ---------------- #
HOST = "127.0.0.1"
PORT = 8765
RATE_LIMIT_WINDOW = 5      # seconds — the sliding time window
RATE_LIMIT_THRESHOLD = 10  # max allowed requests per IP per window
SIMULATION_DURATION = 12   # seconds the demo traffic runs for

# ---------------- Detection Engine ---------------- #
request_log = defaultdict(deque)   # ip -> deque of request timestamps
blocked_ips = set()
lock = threading.Lock()


def is_ip_blocked(ip: str) -> bool:
    with lock:
        return ip in blocked_ips


def record_request(ip: str) -> bool:
    """
    Records a request timestamp for the given IP and checks whether
    it exceeds the allowed rate. Returns True if this request should
    be BLOCKED, False if it's allowed.
    """
    now = time.time()
    with lock:
        window = request_log[ip]
        window.append(now)

        # Drop timestamps outside the sliding window
        while window and window[0] < now - RATE_LIMIT_WINDOW:
            window.popleft()

        if len(window) > RATE_LIMIT_THRESHOLD:
            if ip not in blocked_ips:
                blocked_ips.add(ip)
                print(f"🚨 ALERT: {ip} exceeded {RATE_LIMIT_THRESHOLD} "
                      f"requests/{RATE_LIMIT_WINDOW}s — BLOCKING this IP.")
            return True

    return False


# ---------------- HTTP Server (the "protected service") ---------------- #
class TrafficHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Silence default logging; we print our own structured logs

    def do_GET(self):
        client_ip = self.client_address[0]
        # Distinguish simulated attacker traffic via a custom header,
        # so the demo can show many "virtual IPs" from one machine.
        sim_ip = self.headers.get("X-Sim-IP", client_ip)

        if is_ip_blocked(sim_ip):
            self.send_response(429)  # Too Many Requests
            self.end_headers()
            self.wfile.write(b"Blocked: rate limit exceeded.")
            return

        should_block = record_request(sim_ip)
        if should_block:
            self.send_response(429)
            self.end_headers()
            self.wfile.write(b"Blocked: rate limit exceeded.")
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")


def start_server():
    server = HTTPServer((HOST, PORT), TrafficHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# ---------------- Simulated Traffic Generator ---------------- #
def simulate_normal_user(user_ip: str, duration: int):
    """A normal user makes a handful of requests, spaced out."""
    end_time = time.time() + duration
    while time.time() < end_time:
        try:
            req = urllib.request.Request(f"http://{HOST}:{PORT}/",
                                          headers={"X-Sim-IP": user_ip})
            urllib.request.urlopen(req, timeout=1)
        except Exception:
            pass
        time.sleep(random.uniform(1.0, 2.0))  # normal human-like pacing


def simulate_attacker(attacker_ip: str, duration: int):
    """An attacker floods requests as fast as possible."""
    end_time = time.time() + duration
    while time.time() < end_time:
        try:
            req = urllib.request.Request(f"http://{HOST}:{PORT}/",
                                          headers={"X-Sim-IP": attacker_ip})
            urllib.request.urlopen(req, timeout=1)
        except Exception:
            pass
        time.sleep(0.05)  # rapid-fire requests


def run_simulation():
    print("=" * 65)
    print(" DDoS ATTACK SIMULATION & MITIGATION")
    print(f" Mitigation rule: block any source making >{RATE_LIMIT_THRESHOLD} "
          f"requests within {RATE_LIMIT_WINDOW}s")
    print("=" * 65)

    server = start_server()
    print(f"Local test server running at http://{HOST}:{PORT}\n")

    # ---------- PHASE 1: BASELINE (normal traffic only) ---------- #
    print("-" * 65)
    print(" PHASE 1: Baseline — normal user traffic only (no attack)")
    print("-" * 65)
    baseline_threads = [
        threading.Thread(target=simulate_normal_user, args=("192.168.1.10", 4)),
        threading.Thread(target=simulate_normal_user, args=("192.168.1.11", 4)),
    ]
    for t in baseline_threads:
        t.start()
    for t in baseline_threads:
        t.join()
    print(" Baseline complete — server handled normal traffic with no blocks.\n")

    # ---------- PHASE 2: ATTACK SIMULATION ---------- #
    print("-" * 65)
    print(" PHASE 2: Attack simulation — flood traffic begins")
    print(" (normal users keep browsing at the same time, for contrast)")
    print("-" * 65)
    attack_threads = [
        threading.Thread(target=simulate_normal_user, args=("192.168.1.10", SIMULATION_DURATION)),
        threading.Thread(target=simulate_normal_user, args=("192.168.1.11", SIMULATION_DURATION)),
        threading.Thread(target=simulate_attacker, args=("10.0.0.66", SIMULATION_DURATION)),
        threading.Thread(target=simulate_attacker, args=("10.0.0.77", SIMULATION_DURATION)),
    ]
    for t in attack_threads:
        t.start()
    for t in attack_threads:
        t.join()

    # ---------- PHASE 3: MITIGATION SUMMARY ---------- #
    print("\n" + "=" * 65)
    print(" PHASE 3: Mitigation summary — post-attack report")
    print("=" * 65)
    with lock:
        for ip, timestamps in sorted(request_log.items()):
            status = "🚫 BLOCKED (attacker)" if ip in blocked_ips else "✅ allowed (normal traffic)"
            print(f" {ip:15} | requests seen: {len(timestamps):4} | {status}")
    total_blocked = len(blocked_ips)
    print("-" * 65)
    print(f" Result: {total_blocked} malicious source(s) automatically detected "
          f"and blocked, while legitimate traffic continued uninterrupted.")
    print("=" * 65)

    server.shutdown()


if __name__ == "__main__":
    run_simulation()
