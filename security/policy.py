"""
security/policy.py

PolicyGate — the mandatory safety gate between the orchestrator and
enforcement actions.

Architecture ref: Section 7 — "High-impact actions must pass through a
policy gate. The raw output of an AI model must never invoke a firewall
command directly."

Controls implemented:
  - Allowlist check
  - Confidence threshold
  - Multi-signal confirmation (2-of-3)
  - Action rate limiter
  - Dry-run mode
  - Safe Mode / Autonomous Mode
"""

import time
import threading
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from security.allowlist import Allowlist


@dataclass
class PolicyDecision:
    """Result of a policy evaluation."""
    approved: bool
    reason: str
    dry_run: bool = False
    signals_present: int = 0
    confidence: float = 0.0


class PolicyGate:
    """
    All enforcement actions must be evaluated by this gate before execution.

    Signals for multi-signal confirmation:
      - ml_detection:  Perception/session score above threshold
      - baseline_anomaly:  BaselineAgent deviation detected
      - deception_hit:  Honeypot or honeytoken trip
    """

    def __init__(
        self,
        allowlist: Optional[Allowlist] = None,
        confidence_threshold: float = 0.7,
        high_impact_threshold: float = 0.9,
        rate_limit_window: int = 60,
        rate_limit_max: int = 10,
        require_multi_signal: bool = True,
        min_signals: int = 2,
        dry_run: bool = False,
    ):
        self.allowlist = allowlist or Allowlist()
        self.confidence_threshold = confidence_threshold
        self.high_impact_threshold = high_impact_threshold
        self.rate_limit_window = rate_limit_window
        self.rate_limit_max = rate_limit_max
        self.require_multi_signal = require_multi_signal
        self.min_signals = min_signals
        self.dry_run = dry_run

        # Modes
        self.safe_mode = False       # True = suppress all automated actions
        self.autonomous_mode = True  # False = alert only, no auto-execute

        # Rate limiter state: {target_ip: [timestamps]}
        self._action_history: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Mode controls
    # ------------------------------------------------------------------
    def set_safe_mode(self, enabled: bool):
        self.safe_mode = enabled

    def set_autonomous_mode(self, enabled: bool):
        self.autonomous_mode = enabled

    def set_dry_run(self, enabled: bool):
        self.dry_run = enabled

    # ------------------------------------------------------------------
    # Core evaluation
    # ------------------------------------------------------------------
    def evaluate(
        self,
        action_type: str,
        target: str,
        confidence: float,
        signals: Dict[str, bool],
    ) -> PolicyDecision:
        """
        Evaluate whether a proposed action should be approved.

        Args:
            action_type: "BLOCK_IP", "QUARANTINE", "ALERT", etc.
            target: IP address or device identifier
            confidence: Overall confidence score (0.0 - 1.0)
            signals: Dict of signal_name -> bool indicating presence
                     e.g. {"ml_detection": True, "baseline_anomaly": True,
                            "deception_hit": False}

        Returns:
            PolicyDecision with approved/denied + reason
        """
        signals_present = sum(1 for v in signals.values() if v)

        # -- 1. Safe Mode blocks everything --
        if self.safe_mode:
            return PolicyDecision(
                approved=False,
                reason="Safe Mode active — all automated actions suppressed",
                dry_run=self.dry_run,
                signals_present=signals_present,
                confidence=confidence,
            )

        # -- 2. Non-autonomous mode only allows ALERTs --
        if not self.autonomous_mode and action_type != "ALERT":
            return PolicyDecision(
                approved=False,
                reason="Autonomous Mode disabled — only alerts are permitted",
                dry_run=self.dry_run,
                signals_present=signals_present,
                confidence=confidence,
            )

        # -- 3. ALERTs are always approved (low-impact) --
        if action_type == "ALERT":
            return PolicyDecision(
                approved=True,
                reason="Alerts are always permitted",
                dry_run=self.dry_run,
                signals_present=signals_present,
                confidence=confidence,
            )

        # -- 4. Allowlist check --
        if self.allowlist.is_protected(target):
            return PolicyDecision(
                approved=False,
                reason=f"Target {target} is on the protected allowlist",
                dry_run=self.dry_run,
                signals_present=signals_present,
                confidence=confidence,
            )

        # -- 5. Confidence threshold --
        is_high_impact = action_type in ("BLOCK_IP", "QUARANTINE")
        threshold = self.high_impact_threshold if is_high_impact else self.confidence_threshold
        if confidence < threshold:
            return PolicyDecision(
                approved=False,
                reason=f"Confidence {confidence:.3f} below threshold {threshold:.3f} for {action_type}",
                dry_run=self.dry_run,
                signals_present=signals_present,
                confidence=confidence,
            )

        # -- 6. Multi-signal confirmation for high-impact --
        if is_high_impact and self.require_multi_signal:
            if signals_present < self.min_signals:
                return PolicyDecision(
                    approved=False,
                    reason=(
                        f"High-impact action requires {self.min_signals} signals, "
                        f"only {signals_present} present: {signals}"
                    ),
                    dry_run=self.dry_run,
                    signals_present=signals_present,
                    confidence=confidence,
                )

        # -- 7. Rate limiter --
        if not self._rate_limit_ok(target):
            return PolicyDecision(
                approved=False,
                reason=f"Rate limit exceeded for {target} ({self.rate_limit_max} actions per {self.rate_limit_window}s)",
                dry_run=self.dry_run,
                signals_present=signals_present,
                confidence=confidence,
            )

        # -- 8. Record action and approve --
        self._record_action(target)

        return PolicyDecision(
            approved=True,
            reason=f"Policy approved: confidence={confidence:.3f}, signals={signals_present}/{len(signals)}",
            dry_run=self.dry_run,
            signals_present=signals_present,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # Rate limiter
    # ------------------------------------------------------------------
    def _rate_limit_ok(self, target: str) -> bool:
        now = time.time()
        with self._lock:
            history = self._action_history.get(target, [])
            # Prune old entries
            history = [t for t in history if now - t < self.rate_limit_window]
            self._action_history[target] = history
            return len(history) < self.rate_limit_max

    def _record_action(self, target: str):
        now = time.time()
        with self._lock:
            if target not in self._action_history:
                self._action_history[target] = []
            self._action_history[target].append(now)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def get_status(self) -> Dict[str, Any]:
        return {
            "safe_mode": self.safe_mode,
            "autonomous_mode": self.autonomous_mode,
            "dry_run": self.dry_run,
            "confidence_threshold": self.confidence_threshold,
            "high_impact_threshold": self.high_impact_threshold,
            "rate_limit_window": self.rate_limit_window,
            "rate_limit_max": self.rate_limit_max,
            "require_multi_signal": self.require_multi_signal,
            "min_signals": self.min_signals,
            "allowlist_count": self.allowlist.count(),
        }
