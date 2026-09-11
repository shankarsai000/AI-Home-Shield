"""
agents/safety_agent.py

Wraps the PolicyGate for the agent ecosystem.  Evaluates proposed actions,
enforces rate limiting, confidence thresholds, and multi-signal confirmation.

Architecture ref: Section 7 — "The autonomous loop is deliberately
constrained. A model can recommend; the policy engine authorizes."
"""

import time
from typing import Dict, Any, List, Optional
from datetime import datetime

from security.policy import PolicyGate, PolicyDecision
from security.allowlist import Allowlist
from security.audit import AuditTrail


class SafetyAgent:
    """
    Agent-layer wrapper around the PolicyGate.

    Provides:
      - Action evaluation with multi-signal evidence
      - Rate limit tracking per IP/device/time window
      - Confidence threshold enforcement
      - 2-of-3 (or N-of-M) confirmation for high-impact actions
      - Action history for preventing storms
      - Mode management (safe/autonomous/dry-run)
    """

    def __init__(
        self,
        policy_gate: Optional[PolicyGate] = None,
        audit_trail: Optional[AuditTrail] = None,
    ):
        self.policy_gate = policy_gate or PolicyGate()
        self.audit_trail = audit_trail or AuditTrail()
        self._action_log: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------
    def evaluate_action(
        self,
        action_type: str,
        target: str,
        confidence: float,
        ml_detection: bool = False,
        baseline_anomaly: bool = False,
        deception_hit: bool = False,
        session_persistence: bool = False,
        forecast_signal: bool = False,
    ) -> PolicyDecision:
        """
        Evaluate whether an action should be approved.

        Uses multi-signal confirmation from the PDF:
          - ML detection (perception/session)
          - Baseline anomaly
          - Deception hit (honeypot/honeytoken)
          - Session persistence (optional boost)
          - Forecast signal (optional boost)

        Returns PolicyDecision.
        """
        signals = {
            "ml_detection": ml_detection,
            "baseline_anomaly": baseline_anomaly,
            "deception_hit": deception_hit,
        }

        decision = self.policy_gate.evaluate(
            action_type=action_type,
            target=target,
            confidence=confidence,
            signals=signals,
        )

        # Log the decision
        self.audit_trail.log_decision(
            action_type=action_type,
            target=target,
            signals={
                **signals,
                "session_persistence": session_persistence,
                "forecast_signal": forecast_signal,
            },
            confidence=confidence,
            policy_result="APPROVED" if decision.approved else "DENIED",
            reason=decision.reason,
        )

        # Track in internal log
        self._action_log.append({
            "time": time.time(),
            "action_type": action_type,
            "target": target,
            "approved": decision.approved,
            "reason": decision.reason,
            "confidence": confidence,
        })
        # Keep last 500 entries
        self._action_log = self._action_log[-500:]

        return decision

    # ------------------------------------------------------------------
    # Mode controls (delegate to PolicyGate)
    # ------------------------------------------------------------------
    def set_safe_mode(self, enabled: bool):
        self.policy_gate.set_safe_mode(enabled)

    def set_autonomous_mode(self, enabled: bool):
        self.policy_gate.set_autonomous_mode(enabled)

    def set_dry_run(self, enabled: bool):
        self.policy_gate.set_dry_run(enabled)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def get_safety_status(self) -> Dict[str, Any]:
        gate_status = self.policy_gate.get_status()
        recent = self._action_log[-20:]
        approved_count = sum(1 for a in recent if a.get("approved"))
        denied_count = sum(1 for a in recent if not a.get("approved"))

        return {
            **gate_status,
            "recent_approved": approved_count,
            "recent_denied": denied_count,
            "total_evaluations": len(self._action_log),
        }

    def get_recent_decisions(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Return recent action evaluations."""
        return list(reversed(self._action_log[-limit:]))
