"""
agents/response_agent.py

Enforcement & Response Execution Layer.

Architecture ref: Section 7 — "High-impact actions must pass through a policy gate."
Section 8 — "Response Sequence:
  1. Receive approved action
  2. Validate target against allowlist and current state
  3. Apply firewall/quarantine rule
  4. Record command/result
  5. Verify traffic suppression
  6. Emit SOC event
  7. Update Home Shield Score and device state"
"""

import json
import os
import time
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

from security.audit import AuditTrail
from security.policy import PolicyGate
from agents.safety_agent import SafetyAgent
from agents.verification_agent import VerificationAgent
from agents.firewall_agent import FirewallAgent


ALERT_LOG = "logs/alerts.log"


def log_alert(message: str, severity: str = "INFO"):
    """Append-only text log for basic alerts."""
    try:
        os.makedirs(os.path.dirname(ALERT_LOG), exist_ok=True)
    except Exception:
        pass
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] severity={severity} msg={message}\n"
    try:
        with open(ALERT_LOG, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass


class ResponseAgent:
    """
    Executes authorized enforcement actions through FirewallAgent, performs
    post-action verification via VerificationAgent, and writes structured evidence
    to AuditTrail and logs.
    """

    def __init__(
        self,
        firewall_agent: Optional[FirewallAgent] = None,
        safety_agent: Optional[SafetyAgent] = None,
        verification_agent: Optional[VerificationAgent] = None,
        audit_trail: Optional[AuditTrail] = None,
    ):
        self.firewall = firewall_agent or FirewallAgent()
        self.safety = safety_agent or SafetyAgent()
        self.verification = verification_agent or VerificationAgent()
        self.audit = audit_trail or AuditTrail()

    def execute_block(
        self,
        ip: str,
        reason: str = "",
        confidence: float = 0.9,
        bypass_policy: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute an IP block with policy evaluation and post-action verification.
        """
        # Step 1: Policy validation (unless explicitly bypassed by human operator)
        if not bypass_policy:
            decision = self.safety.evaluate_action(
                action_type="BLOCK_IP",
                target=ip,
                confidence=confidence,
                deception_hit=True if "honeypot" in reason.lower() else False,
            )
            if not decision.approved:
                log_alert(f"Block IP {ip} rejected by policy: {decision.reason}", severity="WARNING")
                return {
                    "ok": False,
                    "target": ip,
                    "action": "BLOCK_IP",
                    "executed": False,
                    "reason": f"Policy rejected: {decision.reason}",
                    "verified": False,
                }
            dry_run = decision.dry_run
        else:
            dry_run = False

        # Step 2: Enforcement execution
        firewall_res = self.firewall.block_ip(ip, reason=reason, dry_run=dry_run)

        # Step 3: Post-action verification
        if not dry_run and firewall_res.get("ok"):
            verification_res = self.verification.verify_block(ip)
        else:
            verification_res = {"verified": True, "method": "dry_run_or_simulation", "details": "Simulated/dry-run verified"}

        # Step 4: Record audit log
        self.audit.log_action(
            action_type="BLOCK_IP",
            target=ip,
            command=firewall_res.get("cmd", ""),
            outcome="SUCCESS" if firewall_res.get("ok") else "FAILED",
            verified=verification_res.get("verified", False),
            details=f"Reason: {reason}; Msg: {firewall_res.get('message', '')}",
        )

        log_alert(f"Attacker IP blocked: {ip} | {firewall_res.get('message', '')}", severity="CRITICAL")

        return {
            "ok": firewall_res.get("ok", False),
            "target": ip,
            "action": "BLOCK_IP",
            "executed": True,
            "dry_run": dry_run,
            "firewall_result": firewall_res,
            "verification": verification_res,
        }

    def execute_quarantine(
        self,
        device_ip: str,
        reason: str = "",
        confidence: float = 0.9,
        bypass_policy: bool = False,
    ) -> Dict[str, Any]:
        """
        Execute device quarantine with policy validation and verification.
        """
        if not bypass_policy:
            decision = self.safety.evaluate_action(
                action_type="QUARANTINE",
                target=device_ip,
                confidence=confidence,
            )
            if not decision.approved:
                log_alert(f"Quarantine for {device_ip} rejected by policy: {decision.reason}", severity="WARNING")
                return {
                    "ok": False,
                    "target": device_ip,
                    "action": "QUARANTINE",
                    "executed": False,
                    "reason": f"Policy rejected: {decision.reason}",
                    "verified": False,
                }
            dry_run = decision.dry_run
        else:
            dry_run = False

        # Apply isolation via firewall rule or logical isolation
        firewall_res = self.firewall.block_ip(device_ip, reason=f"Quarantine: {reason}", dry_run=dry_run)
        verification_res = self.verification.verify_quarantine(device_ip)

        self.audit.log_action(
            action_type="QUARANTINE",
            target=device_ip,
            command=firewall_res.get("cmd", ""),
            outcome="SUCCESS" if firewall_res.get("ok") else "FAILED",
            verified=verification_res.get("verified", False),
            details=f"Reason: {reason}",
        )

        log_alert(f"Device quarantined: {device_ip} (Reason: {reason})", severity="HIGH")

        return {
            "ok": firewall_res.get("ok", False),
            "target": device_ip,
            "action": "QUARANTINE",
            "executed": True,
            "dry_run": dry_run,
            "firewall_result": firewall_res,
            "verification": verification_res,
        }


# ----------------------------------------------------------------------
# Backward-compatible helper functions
# ----------------------------------------------------------------------
def quarantine_device(device_ip: str, quarantine_list: List[str], reason: str = "") -> List[str]:
    if device_ip not in quarantine_list:
        quarantine_list.append(device_ip)
        log_alert(f"Device quarantined: {device_ip} ({reason})", severity="HIGH")
    return quarantine_list


def block_attacker_ip(attacker_ip: str, blocked_list: List[str], reason: str = "") -> List[str]:
    if attacker_ip not in blocked_list:
        blocked_list.append(attacker_ip)
        log_alert(f"Attacker IP blocked: {attacker_ip} ({reason})", severity="CRITICAL")
    return blocked_list


def agentic_response(
    session_prob: float,
    session_label: str,
    devices: List[Dict],
    quarantine_list: List[str],
    blocked_list: List[str],
    response_agent: Optional[ResponseAgent] = None,
) -> Tuple[List[str], List[str]]:
    """
    Autonomous response policy:
    - If session_prob >= 0.90 AND label not benign -> quarantine highest risk device
    """
    is_attack = (str(session_label).lower() != "benigntraffic") and (str(session_label).lower() != "benign")

    if is_attack and session_prob >= 0.90:
        if devices:
            highest = sorted(devices, key=lambda d: d.get("risk_score", 0), reverse=True)[0]
            dev_ip = highest.get("ip")
            if dev_ip and dev_ip not in quarantine_list:
                if response_agent:
                    res = response_agent.execute_quarantine(
                        device_ip=dev_ip,
                        reason=f"Session attack {session_label} prob={session_prob:.2f}",
                        confidence=session_prob,
                    )
                    if res.get("ok"):
                        quarantine_list.append(dev_ip)
                else:
                    quarantine_list = quarantine_device(dev_ip, quarantine_list, reason=f"{session_label} prob={session_prob}")

    return quarantine_list, blocked_list
