"""
core/sniffer.py
---------------
Thin wrapper around Scapy's sniff() that feeds packets into the analyzer.
Runs in its own daemon thread so the Flask server can share the process.
"""

import threading
import logging
import sys

import config
from core.analyzer import analyze

log = logging.getLogger("scantrap.sniffer")


def _sniff_loop(iface):
    """Blocking Scapy sniff call – executed in a background thread."""
    try:
        from scapy.all import sniff
    except ImportError:
        log.critical("Scapy is not installed. Run: pip install scapy")
        sys.exit(1)

    log.info("Sniffing on interface: %s", iface or "<auto>")
    kwargs = dict(prn=analyze, store=False)
    if iface:
        kwargs["iface"] = iface

    sniff(**kwargs)


def start_sniffer():
    """
    Start the packet-capture loop in a background daemon thread.
    Returns the thread object.
    """
    t = threading.Thread(target=_sniff_loop, args=(config.NETWORK_INTERFACE,),
                         daemon=True, name="scantrap-sniffer")
    t.start()
    log.info("Sniffer thread started (tid=%s)", t.ident)
    return t
