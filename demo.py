"""
demo.py – Preview the Scantrap dashboard without root/Scapy
===========================================================
Injects fake alerts and simulated traffic into the database so you
can see the full UI without a real network interface.

Run:
    python3 demo.py

Then open:  http://127.0.0.1:5000
"""

import time
import random
import threading
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")

from database.logger import init_db, log_alert
from core.analyzer   import stats
from web.app         import run_server

SAMPLE_IPS = [
    "192.168.1.42", "10.0.0.5", "172.16.0.99",
    "192.168.100.7", "10.10.10.10", "192.168.1.200",
]

ATTACK_TEMPLATES = [
    ("Port Scan",      lambda ip: f"{random.randint(20,80)} distinct ports in 10s"),
    ("ARP Spoofing",   lambda ip: f"MAC changed aa:bb:cc:dd:ee:ff → {':'.join(f'{random.randint(0,255):02x}' for _ in range(6))}"),
    ("Traffic Spike",  lambda ip: f"{random.randint(600, 1500)} pps exceeds threshold 500"),
]


def _simulate_traffic():
    """Tick fake PPS and inject occasional alerts."""
    tick = 0
    while True:
        # Simulate varying PPS
        pps = 50 + 40 * abs(
            (tick % 60) / 30 - 1
        ) + random.gauss(0, 8)
        stats["pps"] = round(max(pps, 0), 1)
        stats["total_packets"] = stats.get("total_packets", 0) + int(pps)

        # Random alert every ~8 seconds
        if tick % 8 == 0 and random.random() < 0.7:
            attack_type, detail_fn = random.choice(ATTACK_TEMPLATES)
            src_ip = random.choice(SAMPLE_IPS)
            log_alert(src_ip, attack_type, detail_fn(src_ip))

            # Keep cumulative stat counters in sync
            key_map = {
                "Port Scan":     "port_scans",
                "ARP Spoofing":  "arp_spoofs",
                "Traffic Spike": "traffic_spikes",
            }
            k = key_map.get(attack_type)
            if k:
                stats[k] = stats.get(k, 0) + 1

        tick += 1
        time.sleep(1)


if __name__ == "__main__":
    print("\n  ⬡ Scantrap IDS – DEMO MODE  ⬡")
    print("  Dashboard: http://127.0.0.1:5000\n")
    init_db()
    t = threading.Thread(target=_simulate_traffic, daemon=True)
    t.start()
    run_server()
