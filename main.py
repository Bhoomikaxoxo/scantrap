"""
main.py – Scantrap IDS entry point
===================================
Run as root (required for raw packet capture):
    sudo python3 main.py

Environment variables:
    SCANTRAP_IFACE   Override the network interface (e.g. eth0, en0, wlan0)
"""

import sys
import logging
import threading

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("scantrap")

# ── Imports ─────────────────────────────────────────────────────────────────
import config
from database.logger import init_db
from core.sniffer   import start_sniffer
from web.app        import run_server

# ── Banner ──────────────────────────────────────────────────────────────────
BANNER = """
  ╔══════════════════════════════════════╗
  ║   ⬡  S C A N T R A P   I D S  ⬡    ║
  ║   Mini Network Intrusion Detection   ║
  ╚══════════════════════════════════════╝
"""

def main():
    print(BANNER)
    log.info("Initialising database …")
    init_db()

    log.info("Starting packet sniffer …")
    sniffer_thread = start_sniffer()

    log.info("Starting Flask dashboard on http://%s:%d", config.FLASK_HOST, config.FLASK_PORT)
    log.info("Open your browser at  http://127.0.0.1:%d", config.FLASK_PORT)

    try:
        run_server()   # blocks – Flask/SocketIO main loop
    except KeyboardInterrupt:
        log.info("Shutting down – goodbye.")
        sys.exit(0)


if __name__ == "__main__":
    main()
