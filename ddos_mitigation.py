"""
========================================================
    CODTECH IT SOLUTIONS - INTERNSHIP PROJECT
========================================================
Name      : Aditya Jain
Intern ID : CITS2742
Company   : CodTech IT Solutions
Domain    : Cyber Security & Ethical Hacking
Task      : Task 1 - DDoS Attack Simulation & Mitigation
========================================================

DISCLAIMER:
    This tool is built strictly for EDUCATIONAL purposes as
    part of a cyber security internship. It simulates traffic
    against an in-memory "virtual server" model and never sends
    any real network packets. Do not repurpose this code to
    target real machines, servers, or networks.
========================================================
"""

import threading
import time
import random
import datetime
from collections import deque, Counter


# ============================================================
#  CONFIGURATION
# ============================================================
class Config:
    VIRTUAL_SERVER = "127.0.0.1:8080"      # purely symbolic, no real socket is opened
    MAX_REQ_PER_WINDOW = 8                 # allowed requests per IP within WINDOW_SECONDS
    WINDOW_SECONDS = 1.0                   # sliding window size for rate detection
    BLOCK_SECONDS = 25                     # how long an offending IP stays blacklisted
    STATS_REFRESH = 2                      # seconds between live stat printouts


# ============================================================
#  TRAFFIC SOURCE — generates a believable mix of attacker
#  and legitimate client IPs for the simulation
# ============================================================
class TrafficSource:
    def __init__(self):
        self.attackers = [
            "203.0.113.4", "203.0.113.9", "198.51.100.22"
        ]
        self.legit_clients = [
            f"10.10.{random.randint(0, 255)}.{random.randint(1, 254)}"
            for _ in range(25)
        ]

    def next_ip(self):
        # Attack traffic dominates during a flood, same as real DDoS patterns
        if random.random() < 0.75:
            return random.choice(self.attackers)
        return random.choice(self.legit_clients)


# ============================================================
#  MITIGATION ENGINE — sliding-window rate limiter + blacklist
# ============================================================
class MitigationEngine:
    def __init__(self, config: Config):
        self.cfg = config
        self.history = {}          # ip -> deque[timestamps]
        self.blacklist = {}        # ip -> unblock_at (epoch)
        self.events = []           # human-readable log lines
        self._lock = threading.Lock()

    def _log(self, message: str):
        line = f"[{self._now()}] {message}"
        self.events.append(line)
        print(f"  {line}")

    @staticmethod
    def _now():
        return datetime.datetime.now().strftime("%H:%M:%S")

    def is_blacklisted(self, ip: str) -> bool:
        with self._lock:
            expiry = self.blacklist.get(ip)
            if expiry is None:
                return False
            if time.time() >= expiry:
                del self.blacklist[ip]   # sentence served, release it
                return False
            return True

    def evaluate(self, ip: str) -> bool:
        """Returns True if request is allowed, False if it trips the rate limit."""
        now = time.time()
        with self._lock:
            window = self.history.setdefault(ip, deque())
            window.append(now)

            # drop anything outside the sliding window
            while window and now - window[0] > self.cfg.WINDOW_SECONDS:
                window.popleft()

            if len(window) > self.cfg.MAX_REQ_PER_WINDOW:
                if ip not in self.blacklist:
                    self.blacklist[ip] = now + self.cfg.BLOCK_SECONDS
                    self._log(
                        f"BLACKLISTED {ip:<16} -> {len(window)} req/"
                        f"{self.cfg.WINDOW_SECONDS:.0f}s (limit {self.cfg.MAX_REQ_PER_WINDOW}), "
                        f"blocked {self.cfg.BLOCK_SECONDS}s"
                    )
                return False
            return True

    def active_blocks(self):
        with self._lock:
            return dict(self.blacklist)


# ============================================================
#  VIRTUAL SERVER — the thing being "attacked"
# ============================================================
class VirtualServer:
    def __init__(self, mitigation: MitigationEngine):
        self.mitigation = mitigation
        self.total = 0
        self.served = 0
        self.dropped = 0
        self.source_count = Counter()
        self._lock = threading.Lock()

    def receive(self, ip: str):
        with self._lock:
            self.total += 1
            self.source_count[ip] += 1

        if self.mitigation.is_blacklisted(ip):
            with self._lock:
                self.dropped += 1
            return "DROPPED (blacklisted)"

        if self.mitigation.evaluate(ip):
            with self._lock:
                self.served += 1
            return "SERVED"
        else:
            with self._lock:
                self.dropped += 1
            return "DROPPED (rate-limit)"

    def snapshot(self):
        with self._lock:
            return {
                "total": self.total,
                "served": self.served,
                "dropped": self.dropped,
            }


# ============================================================
#  ATTACK SIMULATOR — fires concurrent "requests" at the server
# ============================================================
class AttackSimulator:
    def __init__(self, server: VirtualServer, source: TrafficSource):
        self.server = server
        self.source = source
        self.running = False

    def run(self, duration: int, rps: int):
        self.running = True
        deadline = time.time() + duration
        print(f"\n  >> SIMULATION STARTED against {Config.VIRTUAL_SERVER}")
        print(f"  >> Target rate : {rps} requests/sec for {duration}s")
        print(f"  >> Mitigation  : sliding-window rate limit "
              f"({Config.MAX_REQ_PER_WINDOW} req/{Config.WINDOW_SECONDS:.0f}s/IP)\n")

        while self.running and time.time() < deadline:
            batch = []
            for _ in range(rps):
                ip = self.source.next_ip()
                t = threading.Thread(target=self.server.receive, args=(ip,), daemon=True)
                batch.append(t)
                t.start()
            for t in batch:
                t.join(timeout=0.1)
            time.sleep(1)

        self.running = False
        print("\n  >> Simulation finished.")

    def stop(self):
        self.running = False


# ============================================================
#  LIVE MONITOR — periodic stats while the attack runs
# ============================================================
class LiveMonitor:
    def __init__(self, server: VirtualServer, mitigation: MitigationEngine, simulator: AttackSimulator):
        self.server = server
        self.mitigation = mitigation
        self.simulator = simulator

    def run(self):
        while self.simulator.running:
            time.sleep(Config.STATS_REFRESH)
            if not self.simulator.running:
                break
            snap = self.server.snapshot()
            blocked_ips = len(self.mitigation.active_blocks())
            drop_rate = (snap["dropped"] / snap["total"] * 100) if snap["total"] else 0
            print(
                f"\n  -- LIVE -- total={snap['total']:<6} served={snap['served']:<6} "
                f"dropped={snap['dropped']:<6} drop_rate={drop_rate:5.1f}%  "
                f"blacklisted_ips={blocked_ips}"
            )


# ============================================================
#  REPORTING
# ============================================================
class ReportBuilder:
    def __init__(self, server: VirtualServer, mitigation: MitigationEngine):
        self.server = server
        self.mitigation = mitigation

    def render(self) -> str:
        snap = self.server.snapshot()
        blocks = self.mitigation.active_blocks()
        lines = []
        lines.append("=" * 62)
        lines.append("           DDoS SIMULATION & MITIGATION REPORT")
        lines.append("=" * 62)
        lines.append(f"Intern        : Aditya Jain (CITS2742)")
        lines.append(f"Generated     : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Target        : {Config.VIRTUAL_SERVER}")
        lines.append("-" * 62)
        lines.append(f"Total Requests   : {snap['total']}")
        lines.append(f"Served           : {snap['served']}")
        lines.append(f"Dropped          : {snap['dropped']}")
        if snap["total"]:
            lines.append(f"Drop Rate        : {snap['dropped']/snap['total']*100:.1f}%")
            lines.append(f"Serve Rate       : {snap['served']/snap['total']*100:.1f}%")
        lines.append("-" * 62)
        lines.append("Top Source IPs by Volume:")
        for ip, count in self.server.source_count.most_common(5):
            lines.append(f"   {ip:<18} {count} requests")
        lines.append("-" * 62)
        lines.append("Currently Blacklisted IPs:")
        if blocks:
            for ip, expiry in blocks.items():
                remaining = max(0, int(expiry - time.time()))
                lines.append(f"   {ip:<18} unblocks in {remaining}s")
        else:
            lines.append("   (none)")
        lines.append("-" * 62)
        lines.append("Mitigation Events (most recent 10):")
        for entry in self.mitigation.events[-10:]:
            lines.append(f"   {entry}")
        lines.append("=" * 62)
        return "\n".join(lines)

    def save(self, path: str = None):
        if path is None:
            path = f"ddos_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(path, "w") as f:
            f.write(self.render() + "\n")
        return path


# ============================================================
#  MITIGATION REFERENCE (informational menu item)
# ============================================================
MITIGATION_NOTES = """
  DDoS MITIGATION TECHNIQUES (REFERENCE)
  ---------------------------------------
  1. Rate limiting       - cap requests per IP within a time window
  2. IP blacklisting      - temporarily block IPs that exceed the cap
  3. Traffic filtering    - drop traffic matching known attack signatures
  4. Load balancing       - spread incoming load across multiple servers
  5. CDN / edge shielding - absorb volumetric attacks at the edge (e.g. Cloudflare)
  6. CAPTCHA / challenge  - separate human clients from bots under load
  7. Anycast routing      - distribute attack traffic across global PoPs
"""


# ============================================================
#  CLI / ORCHESTRATION
# ============================================================
def run_scenario(duration: int, rps: int):
    mitigation = MitigationEngine(Config)
    server = VirtualServer(mitigation)
    source = TrafficSource()
    simulator = AttackSimulator(server, source)
    monitor = LiveMonitor(server, mitigation, simulator)

    monitor_thread = threading.Thread(target=monitor.run, daemon=True)
    monitor_thread.start()

    simulator.run(duration=duration, rps=rps)
    time.sleep(Config.STATS_REFRESH + 0.5)

    report = ReportBuilder(server, mitigation)
    print("\n" + report.render())

    choice = input("\n  Save this report to a file? (y/n): ").strip().lower()
    if choice == "y":
        path = report.save()
        print(f"  Saved -> {path}")


def main_menu():
    banner = f"""
{'=' * 62}
   DDoS ATTACK SIMULATION & MITIGATION TOOL
   CodTech IT Solutions - Cyber Security Internship
   Intern: Aditya Jain | ID: CITS2742
{'=' * 62}

  DISCLAIMER: Simulates traffic against an in-memory virtual
  server only. No real network requests are sent. For
  educational use within this internship task only.
"""
    print(banner)

    while True:
        print("\n  [1] Quick simulation   (15s, 40 req/s)")
        print("  [2] Standard simulation (30s, 60 req/s)")
        print("  [3] Custom simulation")
        print("  [4] Show mitigation techniques (reference)")
        print("  [5] Exit")

        choice = input("\n  Choose an option (1-5): ").strip()

        if choice == "1":
            run_scenario(duration=15, rps=40)
        elif choice == "2":
            run_scenario(duration=30, rps=60)
        elif choice == "3":
            try:
                d = int(input("  Duration in seconds: ").strip())
                r = int(input("  Requests per second: ").strip())
                run_scenario(duration=d, rps=r)
            except ValueError:
                print("  Invalid input - please enter integers.")
        elif choice == "4":
            print(MITIGATION_NOTES)
        elif choice == "5":
            print("\n  Exiting. Stay secure!\n")
            break
        else:
            print("  Invalid choice, try again.")


if __name__ == "__main__":
    main_menu()
