"""
agents/orchestrator_agent.py

Decision Plane & Orchestrator Agent.

Architecture ref: Section 7 — "The autonomous loop is deliberately constrained.
  A model can recommend; the policy engine authorizes; the enforcement adapter executes;
  verification confirms the outcome."

Section 12 — "End-to-End Threat Lifecycle (Steps 8-12):
  8. ORCHESTRATOR PROPOSES ACTION
  9. SAFETY GATE AUTHORIZES / DENIES
  10. FIREWALL / QUARANTINE EXECUTES
  11. VERIFICATION CONFIRMS OUTCOME
  12. SOC TIMELINE + XAI + SCORE UPDATE"
"""

import time
from typing import List, Dict, Any, Optional

from security.policy import PolicyGate, PolicyDecision
from security.audit import AuditTrail
from agents.safety_agent import SafetyAgent


class OrchestratorAgent:
    """
    Central coordinator of the decision plane. Correlates multi-signal inputs:
      - PerceptionAgent & SessionAggregationAgent (ML detection + persistence)
      - BaselineAgent (behavioral anomaly confirmation)
      - Deception layer (honeypots & honeytokens)
      - NetworkStateAgent & AttackForecastingAgent (predictive intelligence)
      - RiskAgent (device exposure posture)

    Proposes candidate enforcement actions and routes them through the SafetyAgent / PolicyGate.
    """

    def __init__(
        self,
        safety_agent: Optional[SafetyAgent] = None,
        audit_trail: Optional[AuditTrail] = None,
        autonomous: bool = True,
    ):
        self.safety_agent = safety_agent or SafetyAgent()
        self.audit_trail = audit_trail or AuditTrail()
        self.autonomous = autonomous
        self._action_history: List[Dict[str, Any]] = []

    def evaluate_and_decide(
        self,
        session_prob: float = 0.0,
        session_label: str = "BenignTraffic",
        persistence: int = 0,
        devices: Optional[List[Dict[str, Any]]] = None,
        honeypot_events: Optional[List[Dict[str, Any]]] = None,
        honeytoken_trips: Optional[List[Dict[str, Any]]] = None,
        baseline_deviations: Optional[List[Dict[str, Any]]] = None,
        forecast_result: Optional[Dict[str, Any]] = None,
        active_flows: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Synthesizes all signals, evaluates candidate actions against the PolicyGate,
        and returns authorized actions plus suppressed actions.

        Returns:
            {
                "authorized_actions": List[Dict],
                "denied_actions": List[Dict],
                "alerts": List[Dict],
                "threat_summary": str,
                "multi_signals": Dict[str, bool],
            }
        """
        devices = devices or []
        honeypot_events = honeypot_events or []
        honeytoken_trips = honeytoken_trips or []
        baseline_deviations = baseline_deviations or []
        active_flows = active_flows or []
        forecast_result = forecast_result or {}

        authorized_actions: List[Dict[str, Any]] = []
        denied_actions: List[Dict[str, Any]] = []
        alerts: List[Dict[str, Any]] = []

        is_attack_session = (
            str(session_label).strip().lower() not in ("benigntraffic", "benign", "normal", "safe", "none", "0")
        )

        # 1. Evaluate Deception Triggers (Honeypot / Honeytoken)
        # Deception provides the highest confidence corroboration
        deception_hit = bool(honeypot_events or honeytoken_trips)
        for ev in honeypot_events:
            ip = ev.get("attacker_ip")
            if ip:
                candidate = {
                    "type": "BLOCK_IP",
                    "ip": ip,
                    "target": ip,
                    "reason": f"Honeypot triggered on port {ev.get('port', 9999)}",
                    "severity": "CRITICAL",
                    "confidence": 0.95,
                }
                decision = self.safety_agent.evaluate_action(
                    action_type="BLOCK_IP",
                    target=ip,
                    confidence=0.95,
                    ml_detection=is_attack_session,
                    baseline_anomaly=bool(baseline_deviations),
                    deception_hit=True,
                )
                if decision.approved:
                    authorized_actions.append({**candidate, "policy_reason": decision.reason, "dry_run": decision.dry_run})
                else:
                    denied_actions.append({**candidate, "denied_reason": decision.reason})

        for trip in honeytoken_trips:
            source = trip.get("source_ip") or trip.get("ip") or "unknown"
            token_id = trip.get("token_id", "canary")
            alerts.append({
                "type": "ALERT",
                "severity": "CRITICAL",
                "message": f"Honeytoken '{token_id}' accessed by {source}",
            })
            if source != "unknown":
                decision = self.safety_agent.evaluate_action(
                    action_type="BLOCK_IP",
                    target=source,
                    confidence=0.92,
                    deception_hit=True,
                )
                if decision.approved:
                    authorized_actions.append({
                        "type": "BLOCK_IP",
                        "ip": source,
                        "target": source,
                        "reason": f"Honeytoken {token_id} trip detected",
                        "severity": "CRITICAL",
                        "policy_reason": decision.reason,
                        "dry_run": decision.dry_run,
                    })
                else:
                    denied_actions.append({
                        "type": "BLOCK_IP",
                        "ip": source,
                        "reason": f"Honeytoken trip, policy denied: {decision.reason}",
                    })

        # 2. Evaluate Session Threat and Flow Persistence
        has_baseline_anomaly = bool(baseline_deviations)
        has_ml_attack = is_attack_session and (session_prob >= 0.70)

        # Multi-signal determination
        signals = {
            "ml_detection": has_ml_attack,
            "session_persistence": persistence >= 3,
            "baseline_anomaly": has_baseline_anomaly,
            "deception_hit": deception_hit,
            "forecast_elevated": forecast_result.get("future_threat_level") in ["HIGH", "CRITICAL"],
        }

        # Calculate synthesized confidence
        signal_weights = (
            (0.35 if signals["ml_detection"] else 0.0)
            + (0.15 if signals["session_persistence"] else 0.0)
            + (0.20 if signals["baseline_anomaly"] else 0.0)
            + (0.30 if signals["deception_hit"] else 0.0)
        )
        combined_confidence = round(min(1.0, max(session_prob * 0.5 + signal_weights, session_prob if has_ml_attack else 0.1)), 3)

        if has_ml_attack:
            alerts.append({
                "type": "ALERT",
                "severity": "HIGH" if session_prob >= 0.90 else "MEDIUM",
                "message": f"Session Threat: {session_label} (prob={session_prob:.2f}, persistence={persistence})",
            })

            # Check if attack involves high-risk device requiring isolation/quarantine
            if devices:
                sorted_devices = sorted(devices, key=lambda d: d.get("risk_score", 0), reverse=True)
                highest_device = sorted_devices[0]
                target_ip = highest_device.get("ip")

                if target_ip and (session_prob >= 0.85 or (session_prob >= 0.75 and deception_hit)):
                    candidate_quarantine = {
                        "type": "QUARANTINE",
                        "device_ip": target_ip,
                        "target": target_ip,
                        "device_name": highest_device.get("device_name", "Unknown"),
                        "reason": f"Session attack {session_label} (prob={session_prob:.2f}) targeting asset with risk {highest_device.get('risk_score', 0)}",
                        "severity": "CRITICAL" if session_prob >= 0.95 else "HIGH",
                        "confidence": combined_confidence,
                    }

                    decision = self.safety_agent.evaluate_action(
                        action_type="QUARANTINE",
                        target=target_ip,
                        confidence=combined_confidence,
                        ml_detection=True,
                        baseline_anomaly=has_baseline_anomaly,
                        deception_hit=deception_hit,
                        session_persistence=signals["session_persistence"],
                        forecast_signal=signals["forecast_elevated"],
                    )

                    if decision.approved:
                        authorized_actions.append({
                            **candidate_quarantine,
                            "policy_reason": decision.reason,
                            "dry_run": decision.dry_run,
                        })
                    else:
                        denied_actions.append({
                            **candidate_quarantine,
                            "denied_reason": decision.reason,
                        })

        # 3. Forecast-guided preventive posture
        if forecast_result and forecast_result.get("future_threat_level") == "CRITICAL" and not authorized_actions:
            alerts.append({
                "type": "ALERT",
                "severity": "HIGH",
                "message": f"Predictive Warning: Projected transition to {forecast_result.get('predicted_stage')} (confidence: {forecast_result.get('confidence')})",
            })

        threat_summary = (
            f"Active attack detected: {session_label}" if has_ml_attack
            else "Deception decoy triggered" if deception_hit
            else "Baseline anomaly detected" if has_baseline_anomaly
            else "Normal network operation"
        )

        result = {
            "timestamp": time.time(),
            "authorized_actions": authorized_actions,
            "denied_actions": denied_actions,
            "alerts": alerts,
            "threat_summary": threat_summary,
            "multi_signals": signals,
            "combined_confidence": combined_confidence,
        }
        self._action_history.append(result)
        return result


def decide_actions(
    session_prob: float,
    session_label: str,
    devices: List[Dict],
    honeypot_events: List[Dict],
    autonomous: bool = True,
    policy_gate: Optional[PolicyGate] = None,
) -> List[Dict]:
    """
    Backward-compatible decision entry point that routes through the OrchestratorAgent
    and PolicyGate.
    """
    if not autonomous:
        return []

    safety = SafetyAgent(policy_gate=policy_gate) if policy_gate else None
    orch = OrchestratorAgent(safety_agent=safety, autonomous=autonomous)
    res = orch.evaluate_and_decide(
        session_prob=session_prob,
        session_label=session_label,
        devices=devices,
        honeypot_events=honeypot_events,
    )

    # Return list of combined actions and alerts in legacy format
    actions = list(res.get("authorized_actions", []))
    for alert in res.get("alerts", []):
        actions.append(alert)

    return actions
