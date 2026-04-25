#!/usr/bin/env python3
"""
================================================================================
  Lightweight Intrusion Detection System (IDS)
  Author  : You (portfolio project)
  License : MIT
  Requires: Python 3.8+, scapy, Linux, root privileges
================================================================================
  Run with:
      sudo python3 ids.py
      sudo python3 ids.py --iface eth0
================================================================================
"""

import argparse
import logging
import sys
import time
from collections import defaultdict
from datetime import datetime

# ---------------------------------------------------------------------------
# Guard: scapy must be installed
# ---------------------------------------------------------------------------
try:
    from scapy.all import IP, TCP, ICMP, sniff
except ImportError:
    sys.exit(
        "[FATAL] scapy is not installed.\n"
        "        Install it with:  pip install scapy\n"
        "        Then re-run:      sudo python3 ids.py"
    )

# ============================================================================
#  CONFIGURABLE DETECTION THRESHOLDS
#  Tune these values to adjust sensitivity without touching the logic below.
# ============================================================================

# ICMP flood: how many ICMP packets from one IP within TIME_WINDOW triggers alert
ICMP_FLOOD_THRESHOLD = 10          # packets
ICMP_TIME_WINDOW     = 5           # seconds

# Port scan: how many *distinct* ports one IP touches within TIME_WINDOW
PORT_SCAN_THRESHOLD  = 15          # unique destination ports
PORT_SCAN_TIME_WINDOW = 10         # seconds

# Ports considered inherently suspicious / high-risk
SUSPICIOUS_PORTS = {
    21:   "FTP (plaintext file transfer)",
    22:   "SSH (brute-force target)",
    23:   "Telnet (plaintext remote shell)",
    25:   "SMTP (mail relay abuse)",
    3389: "RDP (remote desktop, brute-force target)",
    4444: "Metasploit default reverse shell",
    5555: "Android Debug Bridge / common backdoor",
    6666: "IRC / common malware C2",
    6667: "IRC / common malware C2",
    9001: "Tor relay (default)",
}

# File where alerts are saved (set to None to disable file logging)
LOG_FILE = "alerts.log"

# ============================================================================
#  LOGGING SETUP
# ============================================================================

def setup_logging(log_file: str | None) -> logging.Logger:
    """Configure console + optional file logging."""
    logger = logging.getLogger("IDS")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        fmt="[%(asctime)s] %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Always log to console
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(fmt)
    logger.addHandler(console)

    # Optionally log to file
    if log_file:
        try:
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.INFO)
            fh.setFormatter(fmt)
            logger.addHandler(fh)
            logger.info(f"Alerts will also be written to → {log_file}")
        except OSError as exc:
            logger.warning(f"Could not open log file '{log_file}': {exc}")

    return logger


logger = setup_logging(LOG_FILE)

# ============================================================================
#  IN-MEMORY STATE TRACKING
#  All data lives in plain dicts/lists — no database needed.
# ============================================================================

# { src_ip: [timestamp, timestamp, ...] }
icmp_tracker: dict[str, list[float]] = defaultdict(list)

# { src_ip: {dst_port: timestamp, ...} }
port_scan_tracker: dict[str, dict[int, float]] = defaultdict(dict)

# Keep track of IPs we've already alerted about (avoids alert spam)
alerted_icmp_flood:  set[str] = set()
alerted_port_scan:   set[str] = set()


# ============================================================================
#  HELPER UTILITIES
# ============================================================================

def now() -> float:
    """Return current Unix timestamp."""
    return time.time()


def ts_str() -> str:
    """Human-readable timestamp for inline messages."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def purge_old(timestamps: list[float], window: float) -> list[float]:
    """Remove timestamps older than `window` seconds."""
    cutoff = now() - window
    return [t for t in timestamps if t > cutoff]


def purge_old_ports(ports: dict[int, float], window: float) -> dict[int, float]:
    """Remove port entries older than `window` seconds."""
    cutoff = now() - window
    return {p: t for p, t in ports.items() if t > cutoff}


# ============================================================================
#  DETECTION FUNCTIONS
# ============================================================================

def detect_icmp_flood(src_ip: str) -> None:
    """
    Track ICMP packets per source IP.
    Alert when count exceeds ICMP_FLOOD_THRESHOLD within ICMP_TIME_WINDOW.
    After the first alert the IP is suppressed until the window resets,
    preventing log spam.
    """
    icmp_tracker[src_ip].append(now())
    icmp_tracker[src_ip] = purge_old(icmp_tracker[src_ip], ICMP_TIME_WINDOW)

    count = len(icmp_tracker[src_ip])

    if count >= ICMP_FLOOD_THRESHOLD and src_ip not in alerted_icmp_flood:
        alerted_icmp_flood.add(src_ip)
        logger.warning(
            f"🔴 ICMP FLOOD DETECTED | src={src_ip} | "
            f"{count} packets in {ICMP_TIME_WINDOW}s"
        )
    elif count < ICMP_FLOOD_THRESHOLD // 2:
        # Allow re-alerting once activity drops back below half threshold
        alerted_icmp_flood.discard(src_ip)


def detect_port_scan(src_ip: str, dst_port: int) -> None:
    """
    Track how many distinct destination ports one IP contacts.
    Alert when PORT_SCAN_THRESHOLD unique ports are hit within PORT_SCAN_TIME_WINDOW.
    """
    port_scan_tracker[src_ip][dst_port] = now()
    port_scan_tracker[src_ip] = purge_old_ports(
        port_scan_tracker[src_ip], PORT_SCAN_TIME_WINDOW
    )

    unique_ports = len(port_scan_tracker[src_ip])

    if unique_ports >= PORT_SCAN_THRESHOLD and src_ip not in alerted_port_scan:
        alerted_port_scan.add(src_ip)
        ports_list = sorted(port_scan_tracker[src_ip].keys())
        logger.warning(
            f"🟠 PORT SCAN DETECTED  | src={src_ip} | "
            f"{unique_ports} ports in {PORT_SCAN_TIME_WINDOW}s | "
            f"ports={ports_list[:10]}{'...' if len(ports_list) > 10 else ''}"
        )
    elif unique_ports < PORT_SCAN_THRESHOLD // 2:
        alerted_port_scan.discard(src_ip)


def detect_suspicious_port(src_ip: str, dst_ip: str, dst_port: int) -> None:
    """
    Alert when traffic targets a port flagged as inherently risky.
    Each unique (src_ip, dst_port) pair is alerted only once per session
    to avoid repeated noise.
    """
    if dst_port in SUSPICIOUS_PORTS:
        key = f"{src_ip}:{dst_port}"
        # Use a simple set on the function attribute to track already-seen pairs
        if key not in detect_suspicious_port._seen:
            detect_suspicious_port._seen.add(key)
            reason = SUSPICIOUS_PORTS[dst_port]
            logger.warning(
                f"🟡 SUSPICIOUS PORT     | src={src_ip} → dst={dst_ip}:{dst_port} "
                f"| {reason}"
            )

# One-time initialisation of the seen-set (function-level static equivalent)
detect_suspicious_port._seen: set[str] = set()


# ============================================================================
#  PACKET HANDLER  (called by scapy for every captured packet)
# ============================================================================

def process_packet(packet) -> None:
    """
    Entry point for every captured packet.
    Only packets with an IP layer are processed; others are silently dropped.
    """
    # We only care about IP traffic
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # ── ICMP ─────────────────────────────────────────────────────────────────
    if packet.haslayer(ICMP):
        detect_icmp_flood(src_ip)
        return  # ICMP has no ports — nothing else to check

    # ── TCP ──────────────────────────────────────────────────────────────────
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport

        detect_port_scan(src_ip, dst_port)
        detect_suspicious_port(src_ip, dst_ip, dst_port)


# ============================================================================
#  STARTUP BANNER
# ============================================================================

def print_banner(iface: str) -> None:
    """Print a clean startup banner to the console."""
    print()
    print("=" * 65)
    print("   🛡️  Lightweight IDS — Python / Scapy")
    print("=" * 65)
    print(f"   Interface  : {iface or 'default (all)' }")
    print(f"   Log file   : {LOG_FILE or 'disabled'}")
    print(f"   ICMP flood : {ICMP_FLOOD_THRESHOLD} pkts / {ICMP_TIME_WINDOW}s")
    print(f"   Port scan  : {PORT_SCAN_THRESHOLD} ports / {PORT_SCAN_TIME_WINDOW}s")
    print(f"   Watching   : {len(SUSPICIOUS_PORTS)} flagged ports")
    print("=" * 65)
    print(f"   Started at : {ts_str()}")
    print("   Press Ctrl+C to stop.")
    print("=" * 65)
    print()


# ============================================================================
#  MAIN
# ============================================================================

def main() -> None:
    # ── CLI argument parsing ─────────────────────────────────────────────────
    parser = argparse.ArgumentParser(
        description="Lightweight Python IDS — real-time packet analysis"
    )
    parser.add_argument(
        "--iface", "-i",
        default=None,
        help="Network interface to sniff on (e.g. eth0, wlan0). "
             "Omit to use scapy's default.",
    )
    parser.add_argument(
        "--filter", "-f",
        default="ip",
        help="BPF filter string passed to scapy (default: 'ip'). "
             "Example: 'tcp or icmp'",
    )
    args = parser.parse_args()

    # ── Root check ───────────────────────────────────────────────────────────
    import os
    if os.geteuid() != 0:
        sys.exit(
            "[FATAL] This script must be run as root.\n"
            "        Try:  sudo python3 ids.py"
        )

    print_banner(args.iface)
    logger.info("IDS engine starting — waiting for packets …")

    # ── Start sniffing ───────────────────────────────────────────────────────
    try:
        sniff(
            iface=args.iface,           # None → scapy picks default interface
            filter=args.filter,         # BPF filter (kernel-level pre-filter)
            prn=process_packet,         # callback for every matching packet
            store=False,                # don't keep packets in RAM
        )
    except KeyboardInterrupt:
        print()
        logger.info("IDS stopped by user (Ctrl+C). Goodbye.")
    except PermissionError:
        sys.exit("[FATAL] Permission denied. Run with sudo.")
    except Exception as exc:
        logger.error(f"Unexpected error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
