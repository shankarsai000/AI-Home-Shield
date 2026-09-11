"""
storage/database.py

SQLite-backed local persistence for AI Home Shield.

Architecture ref: Section 9 — "SQLite: devices, baselines, scores, actions.
Configurable. Fast local state."

Tables:
  - devices:    Device inventory with risk scores
  - baselines:  Baseline snapshots
  - actions:    Enforcement action history
  - scores:     Home Shield Score history
  - events:     SOC timeline events
"""

import os
import json
import sqlite3
import threading
import time
from datetime import datetime
from typing import Dict, Any, List, Optional


_DEFAULT_DB = os.path.join("data", "shield.db")


class ShieldDatabase:
    """Thread-safe SQLite database for local state persistence."""

    def __init__(self, db_path: str = _DEFAULT_DB):
        self.db_path = db_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._init_tables()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_tables(self):
        with self._lock:
            conn = self._get_conn()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS devices (
                        ip TEXT PRIMARY KEY,
                        device_name TEXT,
                        mac TEXT,
                        vendor TEXT,
                        device_type TEXT,
                        open_ports TEXT,
                        firmware_status TEXT,
                        risk_score INTEGER DEFAULT 0,
                        risk_level TEXT DEFAULT 'LOW',
                        risk_reasons TEXT,
                        last_seen TEXT,
                        updated_at TEXT
                    );

                    CREATE TABLE IF NOT EXISTS baselines (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        device_ip TEXT,
                        baseline_type TEXT,
                        baseline_data TEXT,
                        created_at TEXT,
                        updated_at TEXT
                    );

                    CREATE TABLE IF NOT EXISTS actions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        action_type TEXT NOT NULL,
                        target TEXT NOT NULL,
                        confidence REAL,
                        signals TEXT,
                        policy_result TEXT,
                        outcome TEXT,
                        verified INTEGER DEFAULT 0,
                        dry_run INTEGER DEFAULT 0,
                        created_at TEXT
                    );

                    CREATE TABLE IF NOT EXISTS scores (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        score INTEGER NOT NULL,
                        delta INTEGER DEFAULT 0,
                        reason TEXT,
                        created_at TEXT
                    );

                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        label TEXT,
                        target TEXT,
                        details TEXT,
                        severity TEXT DEFAULT 'INFO',
                        timestamp REAL,
                        created_at TEXT
                    );
                """)
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Devices
    # ------------------------------------------------------------------
    def upsert_device(self, device: Dict[str, Any]):
        """Insert or update a device record."""
        now = datetime.now().isoformat()
        ports_json = json.dumps(device.get("open_ports", []))
        reasons_json = json.dumps(device.get("risk_reasons", []))

        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT INTO devices (ip, device_name, mac, vendor, device_type,
                                         open_ports, firmware_status, risk_score,
                                         risk_level, risk_reasons, last_seen, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        device_name=excluded.device_name,
                        mac=excluded.mac,
                        vendor=excluded.vendor,
                        device_type=excluded.device_type,
                        open_ports=excluded.open_ports,
                        firmware_status=excluded.firmware_status,
                        risk_score=excluded.risk_score,
                        risk_level=excluded.risk_level,
                        risk_reasons=excluded.risk_reasons,
                        last_seen=excluded.last_seen,
                        updated_at=excluded.updated_at
                """, (
                    device.get("ip", ""),
                    device.get("device_name", ""),
                    device.get("mac", ""),
                    device.get("vendor", ""),
                    device.get("device_type", ""),
                    ports_json,
                    device.get("firmware_status", "UNKNOWN"),
                    device.get("risk_score", 0),
                    device.get("risk_level", "LOW"),
                    reasons_json,
                    device.get("last_seen", now),
                    now,
                ))
                conn.commit()
            finally:
                conn.close()

    def upsert_devices(self, devices: List[Dict[str, Any]]):
        """Batch upsert multiple devices."""
        for d in devices:
            self.upsert_device(d)

    def get_all_devices(self) -> List[Dict[str, Any]]:
        """Return all devices."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute("SELECT * FROM devices ORDER BY risk_score DESC").fetchall()
                result = []
                for row in rows:
                    d = dict(row)
                    d["open_ports"] = json.loads(d.get("open_ports", "[]"))
                    d["risk_reasons"] = json.loads(d.get("risk_reasons", "[]"))
                    result.append(d)
                return result
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def log_action(
        self,
        action_type: str,
        target: str,
        confidence: float = 0.0,
        signals: Optional[Dict] = None,
        policy_result: str = "",
        outcome: str = "",
        verified: bool = False,
        dry_run: bool = False,
    ):
        """Record an enforcement action."""
        now = datetime.now().isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT INTO actions (action_type, target, confidence, signals,
                                         policy_result, outcome, verified, dry_run, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    action_type, target, confidence,
                    json.dumps(signals or {}),
                    policy_result, outcome,
                    1 if verified else 0,
                    1 if dry_run else 0,
                    now,
                ))
                conn.commit()
            finally:
                conn.close()

    def get_recent_actions(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Scores
    # ------------------------------------------------------------------
    def log_score(self, score: int, delta: int = 0, reason: str = ""):
        now = datetime.now().isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "INSERT INTO scores (score, delta, reason, created_at) VALUES (?, ?, ?, ?)",
                    (score, delta, reason, now),
                )
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------
    def log_event(
        self,
        event_type: str,
        label: str = "",
        target: str = "",
        details: str = "",
        severity: str = "INFO",
    ):
        now = datetime.now().isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT INTO events (event_type, label, target, details,
                                        severity, timestamp, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (event_type, label, target, details, severity, time.time(), now))
                conn.commit()
            finally:
                conn.close()

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_score_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM scores ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_baseline(self) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute("SELECT * FROM baselines ORDER BY id DESC LIMIT 50").fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_stats(self) -> Dict[str, int]:
        """Return counts of rows in each table."""
        stats = {"devices": 0, "actions": 0, "baselines": 0, "scores": 0, "events": 0}
        with self._lock:
            conn = self._get_conn()
            try:
                for table in stats.keys():
                    row = conn.execute(f"SELECT COUNT(*) as cnt FROM {table}").fetchone()
                    if row:
                        stats[table] = row["cnt"]
                return stats
            finally:
                conn.close()

    # Convenience aliases
    def save_devices(self, devices: List[Dict[str, Any]]):
        return self.upsert_devices(devices)

    def get_devices(self) -> List[Dict[str, Any]]:
        return self.get_all_devices()

    def save_score(self, score: int, delta: int = 0, reason: str = ""):
        return self.log_score(score=score, delta=delta, reason=reason)

    def save_action(self, action_type: str, target: str, outcome: str = "SUCCESS", verified: bool = False, details: str = "", **kwargs):
        return self.log_action(action_type=action_type, target=target, outcome=outcome, verified=verified, **kwargs)

    def save_event(self, event_type: str, label: str = "", target: str = "", details: str = "", severity: str = "INFO", **kwargs):
        return self.log_event(event_type=event_type, label=label, target=target, details=details, severity=severity)
