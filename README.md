# 🛡️ Lightweight IDS — Python / Scapy

A beginner-friendly, portfolio-grade **Intrusion Detection System** built entirely in Python.  
It sniffs live network traffic on Linux and raises alerts for common attack patterns — no heavy frameworks, no databases, just Python + Scapy.

---

## Features

| Feature | Detail |
|---|---|
| **Real-time sniffing** | IP, TCP, ICMP traffic via Scapy |
| **ICMP Flood detection** | Counts ICMP packets per source IP in a rolling time window |
| **Port Scan detection** | Tracks distinct destination ports contacted by one IP |
| **Suspicious port flagging** | 21 FTP · 23 Telnet · 4444 Backdoor · RDP · and more |
| **File logging** | All alerts saved to `alerts.log` |
| **Configurable thresholds** | Tune sensitivity at the top of the script |
| **No external DB** | Pure in-memory state — simple and portable |

---

## Requirements

- **OS**: Linux (raw socket sniffing requires Linux kernel)
- **Python**: 3.8 or newer
- **Library**: [Scapy](https://scapy.net/)
- **Privileges**: Must be run as `root` (or with `CAP_NET_RAW`)

---

## Installation

```bash
# 1. Clone or download the project
git clone https://github.com/yourname/lightweight-ids.git
cd lightweight-ids

# 2. (Recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install Scapy
pip install scapy
```

---

## Usage

```bash
# Basic — sniff on the default interface
sudo python3 ids.py

# Specify a network interface
sudo python3 ids.py --iface eth0
sudo python3 ids.py --iface wlan0

# Custom BPF pre-filter (reduces noise)
sudo python3 ids.py --iface eth0 --filter "tcp or icmp"

# Help
python3 ids.py --help
```

> **Why sudo?**  
> Packet sniffing requires opening a raw socket, which is a privileged operation on Linux.

---

## Example Output

```
=================================================================
   🛡️  Lightweight IDS — Python / Scapy
=================================================================
   Interface  : eth0
   Log file   : alerts.log
   ICMP flood : 10 pkts / 5s
   Port scan  : 15 ports / 10s
   Watching   : 10 flagged ports
=================================================================
   Started at : 2025-04-25 14:30:00
   Press Ctrl+C to stop.
=================================================================

[2025-04-25 14:30:12] INFO     IDS engine starting — waiting for packets …
[2025-04-25 14:30:45] WARNING  🔴 ICMP FLOOD DETECTED | src=192.168.1.50 | 12 packets in 5s
[2025-04-25 14:31:02] WARNING  🟠 PORT SCAN DETECTED  | src=10.0.0.15 | 17 ports in 10s | ports=[22, 23, 80, 443, 3306, ...]
[2025-04-25 14:31:10] WARNING  🟡 SUSPICIOUS PORT     | src=10.0.0.15 → dst=192.168.1.1:4444 | Metasploit default reverse shell
```

---

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│                  Live Network Traffic                   │
└───────────────────────┬─────────────────────────────────┘
                        │  Scapy sniff() with BPF filter
                        ▼
              process_packet(packet)
                        │
          ┌─────────────┼─────────────────┐
          │             │                 │
          ▼             ▼                 ▼
    ICMP layer?    TCP layer?         IP only?
          │             │                 │
          ▼             ▼               (skip)
  detect_icmp_    detect_port_
     flood()         scan()
                       │
                       ▼
              detect_suspicious_
                  port()
                       │
                       ▼
              ┌────────────────┐
              │  ALERT logged  │  → console + alerts.log
              └────────────────┘
```

### Detection Logic

**ICMP Flood**  
Maintains a rolling list of timestamps for each source IP. If more than `ICMP_FLOOD_THRESHOLD` (default: 10) pings arrive within `ICMP_TIME_WINDOW` (default: 5 s), an alert fires. Once alerted, the IP is suppressed until activity drops below half the threshold — preventing alert spam.

**Port Scan**  
Tracks the set of distinct destination ports each source IP has contacted. If an IP touches more than `PORT_SCAN_THRESHOLD` (default: 15) unique ports within `PORT_SCAN_TIME_WINDOW` (default: 10 s), a scan alert is raised.

**Suspicious Ports**  
A hardcoded dictionary maps well-known risky port numbers to a human-readable description. Any TCP connection to one of these ports generates a one-time alert per source-port pair.

---

## Tuning Thresholds

Open `ids.py` and edit the constants at the top:

```python
ICMP_FLOOD_THRESHOLD  = 10    # packets
ICMP_TIME_WINDOW      = 5     # seconds

PORT_SCAN_THRESHOLD   = 15    # unique destination ports
PORT_SCAN_TIME_WINDOW = 10    # seconds

SUSPICIOUS_PORTS = {
    21:   "FTP (plaintext file transfer)",
    23:   "Telnet (plaintext remote shell)",
    4444: "Metasploit default reverse shell",
    # add your own ...
}
```

---

## Testing It Locally

```bash
# Terminal 1 — start the IDS
sudo python3 ids.py --iface lo

# Terminal 2 — simulate an ICMP flood
ping -f 127.0.0.1

# Terminal 3 — simulate a port scan (requires nmap)
nmap -p 1-100 127.0.0.1
```

---

## Project Structure

```
lightweight-ids/
├── ids.py          # Main IDS script (single-file)
├── alerts.log      # Generated at runtime
└── README.md
```

---

## Limitations & Next Steps

This is an educational/portfolio project. For production use consider:

- Persistent storage (SQLite / PostgreSQL) for historical analysis  
- A web dashboard (Flask/FastAPI) for real-time visualization  
- Whitelist support for trusted IPs  
- Email/Slack alerting integration  
- Running as a systemd service for always-on monitoring  

---

## License

MIT — free to use, modify, and include in your portfolio.
