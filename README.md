# Task 1 — DDoS Attack Simulation & Mitigation

**Intern:** Aditya Jain
**Intern ID:** CITS2742
**Company:** CodTech IT Solutions
**Domain:** Cyber Security & Ethical Hacking

## Overview

This project simulates a Distributed Denial of Service (DDoS) attack against an
in-memory "virtual server" and demonstrates a mitigation strategy based on
**sliding-window rate limiting** and **temporary IP blacklisting**.

No real network traffic is sent — all "requests" are simulated function calls
inside the script, making it safe to run anywhere without affecting any real
host or network.

## How It Works

1. **Traffic Source** — generates a realistic mix of a small number of
   high-volume "attacker" IPs and many low-volume "legitimate" IPs.
2. **Virtual Server** — receives simulated requests and routes them through
   the mitigation engine before counting them as served or dropped.
3. **Mitigation Engine** — tracks a sliding 1-second window of request
   timestamps per IP. Any IP that exceeds the configured threshold
   (default: 8 requests/second) is blacklisted for 25 seconds.
4. **Live Monitor** — prints running stats (served/dropped/blacklisted) every
   2 seconds while a simulation is active.
5. **Report Builder** — produces a final summary report (and can save it to a
   `.txt` file) showing total requests, drop rate, top source IPs, and a log
   of mitigation events.

## Mitigation Techniques Demonstrated

- Rate limiting (sliding window, per-IP)
- IP blacklisting with automatic timed release
- Traffic source analysis (top talkers)

The tool's in-app menu (`[4]`) also lists broader real-world mitigation
techniques (CDN/edge shielding, load balancing, CAPTCHA challenges, anycast
routing) as reference material beyond what this simulation implements.

## Usage

```bash
python3 ddos_mitigation.py
```

Menu options:

```
[1] Quick simulation    (15s, 40 req/s)
[2] Standard simulation (30s, 60 req/s)
[3] Custom simulation   (choose your own duration / rate)
[4] Show mitigation techniques (reference)
[5] Exit
```

## Sample Output

```
[17:23:31] BLACKLISTED 198.51.100.22    -> 9 req/1s (limit 8), blocked 25s
[17:23:31] BLACKLISTED 203.0.113.4      -> 9 req/1s (limit 8), blocked 25s

==============================================================
           DDoS SIMULATION & MITIGATION REPORT
==============================================================
Total Requests   : 600
Served           : 192
Dropped          : 408
Drop Rate        : 68.0%
```

## Disclaimer

This tool is for **educational purposes only**, built as part of a cyber
security internship task. It does not send real network traffic and must
not be adapted to target real systems.

## Requirements

- Python 3.8+
- No external dependencies (uses only the standard library)
