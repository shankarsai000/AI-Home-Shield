"""
agents/network_state_agent.py

Time-indexed network state representation.

Architecture ref: Section 5 — "Build a time-indexed network state
representation. Encode state sequences with a temporal model."

Section 19 — "Traffic understanding: Time-indexed network-state
representation."
"""

import time
from collections import deque
from typing import Dict, Any, List, Optional
from datetime import datetime


class NetworkStateAgent:
    """
    Maintains a time-indexed representation of the network's
    security state.

    The state vector includes:
      - Active flow count and threat distribution
      - Device risk summary
      - Anomaly counts (device + network)
      - Session probability statistics
      - Deception event indicators
      - Home Shield Score

    The agent maintains a sliding window of state snapshots
    for temporal analysis and attack forecasting.
    """

    def __init__(self, window_size: int = 60, snapshot_interval: float = 5.0):
        """
        Args:
            window_size: Maximum number of state snapshots to retain
            snapshot_interval: Minimum seconds between snapshots
        """
        self.window_size = window_size
        self.snapshot_interval = snapshot_interval
        self._history: deque = deque(maxlen=window_size)
        self._current_state: Dict[str, Any] = {}
        self._last_snapshot_time: float = 0

    # ------------------------------------------------------------------
    # State update
    # ------------------------------------------------------------------
    def update_state(
        self,
        active_flows: int = 0,
        attack_flows: int = 0,
        benign_flows: int = 0,
        avg_attack_prob: float = 0.0,
        max_attack_prob: float = 0.0,
        session_label: str = "BenignTraffic",
        session_prob: float = 0.0,
        session_persistence: int = 0,
        device_count: int = 0,
        max_device_risk: int = 0,
        avg_device_risk: float = 0.0,
        critical_devices: int = 0,
        high_risk_devices: int = 0,
        device_anomalies: int = 0,
        network_anomalies: int = 0,
        honeypot_hits: int = 0,
        honeytoken_trips: int = 0,
        blocked_ips: int = 0,
        quarantined_devices: int = 0,
        home_shield_score: int = 75,
    ):
        """
        Update the current network state.  Automatically takes a
        snapshot if enough time has elapsed since the last one.
        """
        now = time.time()

        self._current_state = {
            "timestamp": now,
            "time_str": datetime.now().strftime("%H:%M:%S"),
            # Flow metrics
            "active_flows": active_flows,
            "attack_flows": attack_flows,
            "benign_flows": benign_flows,
            "attack_ratio": (
                attack_flows / max(active_flows, 1)
            ),
            "avg_attack_prob": round(avg_attack_prob, 4),
            "max_attack_prob": round(max_attack_prob, 4),
            # Session metrics
            "session_label": session_label,
            "session_prob": round(session_prob, 4),
            "session_persistence": session_persistence,
            # Device metrics
            "device_count": device_count,
            "max_device_risk": max_device_risk,
            "avg_device_risk": round(avg_device_risk, 2),
            "critical_devices": critical_devices,
            "high_risk_devices": high_risk_devices,
            # Anomaly metrics
            "device_anomalies": device_anomalies,
            "network_anomalies": network_anomalies,
            # Deception metrics
            "honeypot_hits": honeypot_hits,
            "honeytoken_trips": honeytoken_trips,
            # Response metrics
            "blocked_ips": blocked_ips,
            "quarantined_devices": quarantined_devices,
            # Overall score
            "home_shield_score": home_shield_score,
            # Derived threat level
            "threat_level": self._compute_threat_level(
                avg_attack_prob, session_prob, device_anomalies,
                network_anomalies, honeypot_hits + honeytoken_trips,
            ),
        }

        # Auto-snapshot
        if now - self._last_snapshot_time >= self.snapshot_interval:
            self._history.append(dict(self._current_state))
            self._last_snapshot_time = now

    def _compute_threat_level(
        self,
        avg_attack_prob: float,
        session_prob: float,
        device_anomalies: int,
        network_anomalies: int,
        deception_events: int,
    ) -> str:
        """Derive an overall threat level from component signals."""
        score = 0
        if avg_attack_prob > 0.7:
            score += 3
        elif avg_attack_prob > 0.3:
            score += 1

        if session_prob > 0.9:
            score += 3
        elif session_prob > 0.5:
            score += 1

        score += min(device_anomalies, 3)
        score += min(network_anomalies, 3)
        score += min(deception_events * 2, 4)

        if score >= 8:
            return "CRITICAL"
        elif score >= 5:
            return "HIGH"
        elif score >= 2:
            return "MEDIUM"
        return "LOW"

    # ------------------------------------------------------------------
    # State retrieval
    # ------------------------------------------------------------------
    def get_current_state(self) -> Dict[str, Any]:
        """Return the latest network state snapshot."""
        if not self._current_state:
            return {
                "timestamp": time.time(),
                "threat_level": "LOW",
                "message": "No state data yet",
            }
        return dict(self._current_state)

    def get_state_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Return state history (oldest first)."""
        history = list(self._history)
        if limit:
            history = history[-limit:]
        return history

    def get_trend(self, metric: str, window: int = 10) -> Dict[str, Any]:
        """
        Compute a simple trend for a metric over the last N snapshots.

        Returns:
            {
                "metric": str,
                "values": list,
                "direction": "rising" | "falling" | "stable",
                "avg": float,
                "current": float,
            }
        """
        history = list(self._history)[-window:]
        values = [s.get(metric, 0) for s in history]

        if not values:
            return {"metric": metric, "values": [], "direction": "stable", "avg": 0, "current": 0}

        avg = sum(values) / len(values)
        current = values[-1] if values else 0

        # Simple trend detection
        if len(values) >= 3:
            recent_avg = sum(values[-3:]) / 3
            older_avg = sum(values[:max(1, len(values) - 3)]) / max(1, len(values) - 3)
            if recent_avg > older_avg * 1.2:
                direction = "rising"
            elif recent_avg < older_avg * 0.8:
                direction = "falling"
            else:
                direction = "stable"
        else:
            direction = "stable"

        return {
            "metric": metric,
            "values": values,
            "direction": direction,
            "avg": round(avg, 4),
            "current": current,
        }
