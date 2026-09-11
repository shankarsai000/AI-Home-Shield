"""
security/audit.py

Append-only structured audit trail.  Every decision, action, and
verification is logged with timestamp, evidence, action, outcome,
and policy decision.

Architecture ref: Section 7 - "Audit trail: Explain every decision.
Timestamp + evidence + action + outcome."
"""

import json
import os
import threading
from datetime import datetime
from typing import Dict, Any, List, Optional


_DEFAULT_LOG = os.path.join("logs", "audit_trail.jsonl")


class AuditTrail:
    """Append-only JSON Lines audit log for all security decisions."""

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

    def _append(self, record: Dict[str, Any]):
        """Thread-safe append of one JSON line."""
        with self._lock:
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, default=str) + "\n")
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def log_decision(
        self,
        action_type: str,
        target: str,
        signals: Dict[str, Any],
        confidence: float,
        policy_result: str,
        reason: str = "",
    ):
        """Log an orchestrator/safety-gate decision."""
        self._append({
            "event": "DECISION",
            "timestamp": datetime.now().isoformat(),
            "action_type": action_type,
            "target": target,
            "signals": signals,
            "confidence": round(confidence, 4),
            "policy_result": policy_result,
            "reason": reason,
        })

    def log_action(
        self,
        action_type: str,
        target: str,
        result: Optional[Dict[str, Any]] = None,
        dry_run: bool = False,
        **kwargs,
    ):
        """Log an enforcement action that was executed."""
        action_result = result if result is not None else kwargs
        self._append({
            "event": "ACTION",
            "timestamp": datetime.now().isoformat(),
            "action_type": action_type,
            "target": target,
            "result": action_result,
            "dry_run": dry_run,
            **kwargs,
        })

    def log_verification(
        self,
        action_type: str,
        target: str,
        verified: bool,
        details: str = "",
    ):
        """Log a post-action verification result."""
        self._append({
            "event": "VERIFICATION",
            "timestamp": datetime.now().isoformat(),
            "action_type": action_type,
            "target": target,
            "verified": verified,
            "details": details,
        })

    def query_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return the most recent audit entries (newest first)."""
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
        """Return recent entries of a specific event type."""
        all_entries = self.query_recent(limit=500)
        filtered = [e for e in all_entries if e.get("event") == event_type]
        return filtered[:limit]
