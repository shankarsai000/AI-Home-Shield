"""
security/allowlist.py

Persistent allowlist of protected IPs/devices that must never be
blocked or quarantined.  JSON file-backed for simplicity.

Architecture ref: Section 7 - "Protected allowlist: Prevent critical
trusted devices from blind blocking."
"""

import json
import os
import threading
from typing import List, Dict, Any, Optional
from datetime import datetime


_DEFAULT_PATH = os.path.join("security", "allowlist.json")


class Allowlist:
    """Thread-safe, file-backed allowlist of protected network entities."""

    def __init__(self, path: str = _DEFAULT_PATH):
        self.path = path
        self._lock = threading.Lock()
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _load(self):
        if not os.path.exists(self.path):
            # Seed with sensible defaults
            self._entries = {
                "127.0.0.1": {
                    "label": "Localhost",
                    "added": datetime.now().isoformat(),
                    "reason": "System default",
                },
            }
            self._save()
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self._entries = json.load(f)
        except Exception:
            self._entries = {}

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._entries, f, indent=2)
        except Exception:
            pass  # fail-safe

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def add(self, ip: str, label: str = "", reason: str = "") -> bool:
        """Add an IP to the allowlist. Returns True if newly added."""
        ip = ip.strip()
        with self._lock:
            if ip in self._entries:
                return False
            self._entries[ip] = {
                "label": label or ip,
                "added": datetime.now().isoformat(),
                "reason": reason,
            }
            self._save()
            return True

    def remove(self, ip: str) -> bool:
        """Remove an IP from the allowlist. Returns True if it existed."""
        ip = ip.strip()
        with self._lock:
            if ip not in self._entries:
                return False
            del self._entries[ip]
            self._save()
            return True

    def is_protected(self, ip: str) -> bool:
        """Check whether an IP is on the allowlist."""
        return ip.strip() in self._entries

    def list_all(self) -> List[Dict[str, Any]]:
        """Return all allowlisted entries as a list of dicts."""
        with self._lock:
            return [
                {"ip": ip, **info}
                for ip, info in self._entries.items()
            ]

    def count(self) -> int:
        return len(self._entries)
