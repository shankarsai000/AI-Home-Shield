"""
storage/evidence.py

Structured evidence store for SOC events.

Architecture ref: Section 9 — "Append-only event log: SOC events.
Days/weeks retention. Audit trail."

Consolidates the various log files into one structured event store.
"""

import json
import os
import threading
import time
from datetime import datetime
from typing import Dict, Any, List, Optional


_DEFAULT_LOG = os.path.join("logs", "evidence.jsonl")


class EvidenceStore:
    """Structured, append-only evidence store for SOC events."""

    def __init__(self, path: str = _DEFAULT_LOG):
        self.path = path
        self._lock = threading.Lock()
        self._ensure_file()

    def _ensure_file(self):
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            if not os.path.exists(self.path):
                with open(self.path, "w") as f:
                    pass
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------
    def record(
        self,
        event_type: str,
        source: str = "",
        target: str = "",
        evidence: Optional[Dict[str, Any]] = None,
        confidence: float = 0.0,
        action: str = "",
        outcome: str = "",
        severity: str = "INFO",
    ):
        """Append a structured SOC event."""
        record = {
            "timestamp": datetime.now().isoformat(),
            "unix_ts": time.time(),
            "event_type": event_type,
            "source": source,
            "target": target,
            "evidence": evidence or {},
            "confidence": round(confidence, 4),
            "action": action,
            "outcome": outcome,
            "severity": severity,
        }
        with self._lock:
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, default=str) + "\n")
            except Exception:
                pass

    append_event = record

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------
    def query_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return the most recent events (newest first)."""
        entries = []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except Exception:
            return []
        return list(reversed(entries[-limit:]))

    def query_by_type(self, event_type: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent events of a specific type."""
        all_entries = self.query_recent(limit=500)
        filtered = [e for e in all_entries if e.get("event_type") == event_type]
        return filtered[:limit]

    def query_by_severity(self, severity: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent events of a specific severity."""
        all_entries = self.query_recent(limit=500)
        filtered = [e for e in all_entries if e.get("severity") == severity]
        return filtered[:limit]

    def query_time_range(
        self,
        start_ts: float,
        end_ts: Optional[float] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        """Return events within a time range."""
        if end_ts is None:
            end_ts = time.time()
        all_entries = self.query_recent(limit=2000)
        filtered = [
            e for e in all_entries
            if start_ts <= e.get("unix_ts", 0) <= end_ts
        ]
        return filtered[:limit]

    def count(self) -> int:
        """Return total event count."""
        count = 0
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        count += 1
        except Exception:
            pass
        return count

    def query_events(
        self,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Filter events by severity and/or type."""
        entries = self.query_recent(limit=500)
        if severity:
            entries = [e for e in entries if e.get("severity") == severity]
        if event_type:
            entries = [e for e in entries if e.get("event_type") == event_type]
        return entries[:limit]

    def get_stats(self) -> Dict[str, Any]:
        """Return summary statistics for the evidence store."""
        return {
            "total_events": self.count(),
            "path": self.path,
        }
