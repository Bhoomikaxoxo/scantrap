# =============================================================================
# Scantrap IDS – Configuration
# =============================================================================

import os

# ------------------------------------------------------------------
# Database
# ------------------------------------------------------------------
DB_PATH = os.path.join(os.path.dirname(__file__), "data", "ids_alerts.db")

# ------------------------------------------------------------------
# Network Interface
# Autodetect at runtime; override by setting env var SCANTRAP_IFACE
# Common values: "eth0", "wlan0", "en0" (macOS), "lo" (loopback)
# ------------------------------------------------------------------
NETWORK_INTERFACE = os.environ.get("SCANTRAP_IFACE", None)  # None = Scapy auto-select

# ------------------------------------------------------------------
# Detection Thresholds
# ------------------------------------------------------------------
PORT_SCAN_THRESHOLD = 20        # distinct destination ports within window
PORT_SCAN_WINDOW    = 10        # seconds to look back for port scan

TRAFFIC_SPIKE_THRESHOLD = 500   # packets per second before alert
TRAFFIC_SPIKE_WINDOW    = 5     # seconds to measure PPS over

ARP_REQUIRE_GRATUITOUS = False  # if True, only alert on unsolicited ARP replies

# ------------------------------------------------------------------
# Flask Dashboard
# ------------------------------------------------------------------
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5002
FLASK_DEBUG = False

# ------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------
LOG_TO_CONSOLE = True
LOG_LEVEL      = "INFO"   # DEBUG | INFO | WARNING | ERROR
