"""
core/analyzer.py
----------------
Stateful detection engine.
Detects:
  • Port scans  (high port-count from a single source within a time window)
  • ARP spoofing (IP → MAC table mismatch)
  • Traffic spikes (sudden packet-rate surges)
"""

import time
import threading
import logging
from collections import defaultdict, deque

import config
from database.logger import log_alert

log = logging.getLogger("scantrap.analyzer")

# ─────────────────────────────────────────────────────────────────────────────
# Shared state (thread-safe via lock)
# ─────────────────────────────────────────────────────────────────────────────
_lock = threading.Lock()

# Port-scan tracker: src_ip → {"times": deque[float], "ports": set}
_port_scan: dict = defaultdict(lambda: {"times": deque(), "ports": set()})
_port_scan_alerted: set = set()   # IPs that already triggered an alert this window

# ARP table: ip → mac
_arp_table: dict = {}

# Traffic-spike tracker: deque of packet timestamps
_pkt_times: deque = deque()
_last_spike_alert: float = 0.0

# Shared stats (read by Flask dashboard)
stats = {
    "total_packets": 0,
    "pps": 0.0,
    "port_scans": 0,
    "arp_spoofs": 0,
    "traffic_spikes": 0,
}

# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def analyze(packet):
    """Entry point called for every captured packet."""
    with _lock:
        _update_pps(packet)
        _check_arp(packet)
        _check_port_scan(packet)


def get_stats() -> dict:
    with _lock:
        return dict(stats)


# ─────────────────────────────────────────────────────────────────────────────
# Detection helpers
# ─────────────────────────────────────────────────────────────────────────────

def _update_pps(packet):
    """Track packets per second and fire alert on spike."""
    global _last_spike_alert

    now = time.time()
    stats["total_packets"] += 1
    _pkt_times.append(now)

    # Remove timestamps older than the measurement window
    cutoff = now - config.TRAFFIC_SPIKE_WINDOW
    while _pkt_times and _pkt_times[0] < cutoff:
        _pkt_times.popleft()

    pps = len(_pkt_times) / config.TRAFFIC_SPIKE_WINDOW
    stats["pps"] = round(pps, 1)

    if pps > config.TRAFFIC_SPIKE_THRESHOLD and (now - _last_spike_alert) > 30:
        _last_spike_alert = now
        stats["traffic_spikes"] += 1
        src_ip = _extract_src_ip(packet) or "Unknown"
        log_alert(src_ip, "Traffic Spike", f"{pps:.0f} pps exceeds threshold {config.TRAFFIC_SPIKE_THRESHOLD}")


def _check_arp(packet):
    """Detect ARP spoofing via IP–MAC mapping table."""
    try:
        from scapy.layers.l2 import ARP
    except ImportError:
        return

    if not packet.haslayer(ARP):
        return

    arp = packet[ARP]
    if arp.op != 2:          # 2 = ARP reply (is-at)
        return

    src_ip  = arp.psrc
    src_mac = arp.hwsrc

    if not src_ip or not src_mac:
        return

    if src_ip in _arp_table:
        if _arp_table[src_ip] != src_mac:
            stats["arp_spoofs"] += 1
            log_alert(
                src_ip,
                "ARP Spoofing",
                f"MAC changed {_arp_table[src_ip]} → {src_mac}",
            )
    _arp_table[src_ip] = src_mac


def _check_port_scan(packet):
    """Detect threshold-based TCP port scans."""
    try:
        from scapy.layers.inet import IP, TCP
    except ImportError:
        return

    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return

    src_ip   = packet[IP].src
    dst_port = packet[TCP].dport
    now      = time.time()
    cutoff   = now - config.PORT_SCAN_WINDOW

    tracker = _port_scan[src_ip]

    # Expire old entries
    while tracker["times"] and tracker["times"][0] < cutoff:
        tracker["times"].popleft()

    tracker["times"].append(now)
    tracker["ports"].add(dst_port)

    # If we've seen enough distinct ports AND already alerted → reset
    if src_ip in _port_scan_alerted:
        if len(tracker["ports"]) < config.PORT_SCAN_THRESHOLD // 2:
            _port_scan_alerted.discard(src_ip)
        return

    if len(tracker["ports"]) >= config.PORT_SCAN_THRESHOLD:
        _port_scan_alerted.add(src_ip)
        stats["port_scans"] += 1
        log_alert(
            src_ip,
            "Port Scan",
            f"{len(tracker['ports'])} distinct ports in {config.PORT_SCAN_WINDOW}s",
        )
        # Reset for next window
        tracker["times"].clear()
        tracker["ports"].clear()


def _extract_src_ip(packet) -> str | None:
    try:
        from scapy.layers.inet import IP
        if packet.haslayer(IP):
            return packet[IP].src
    except Exception:
        pass
    return None
