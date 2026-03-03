"""
database/logger.py
------------------
Handles SQLite initialisation and alert persistence.
"""

import sqlite3
import os
import logging
from datetime import datetime

import config

log = logging.getLogger("scantrap.db")

# Ensure data directory exists
os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)


def _connect():
    """Return a new SQLite connection with row_factory set."""
    conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they do not yet exist."""
    conn = _connect()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            src_ip      TEXT    NOT NULL,
            attack_type TEXT    NOT NULL,
            details     TEXT
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)
    """)
    conn.commit()
    conn.close()
    log.info("Database initialised at %s", config.DB_PATH)


def log_alert(src_ip: str, attack_type: str, details: str = ""):
    """
    Persist a security alert to the database and optionally print
    a coloured message to the terminal.
    """
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # Terminal output (colour-coded)
    if config.LOG_TO_CONSOLE:
        RED    = "\033[91m"
        YELLOW = "\033[93m"
        RESET  = "\033[0m"
        colour = RED if attack_type != "Traffic Spike" else YELLOW
        print(
            f"{colour}[!] ALERT {timestamp} | {attack_type:<20} | {src_ip:<18} | {details}{RESET}"
        )

    # Persist
    try:
        conn = _connect()
        conn.execute(
            "INSERT INTO alerts (timestamp, src_ip, attack_type, details) VALUES (?, ?, ?, ?)",
            (timestamp, src_ip, attack_type, details),
        )
        conn.commit()
        conn.close()
    except sqlite3.Error as exc:
        log.error("DB write failed: %s", exc)


def get_recent_alerts(limit: int = 100):
    """Return the most recent *limit* alerts as a list of dicts."""
    try:
        conn = _connect()
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except sqlite3.Error as exc:
        log.error("DB read failed: %s", exc)
        return []


def get_alert_counts():
    """Return per-attack-type counts as a dict."""
    try:
        conn = _connect()
        rows = conn.execute(
            "SELECT attack_type, COUNT(*) as cnt FROM alerts GROUP BY attack_type"
        ).fetchall()
        conn.close()
        return {r["attack_type"]: r["cnt"] for r in rows}
    except sqlite3.Error as exc:
        log.error("DB read failed: %s", exc)
        return {}
