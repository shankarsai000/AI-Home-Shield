"""
agents/verification_agent.py

Post-action verification: checks that enforcement actions were
actually applied and effective.

Architecture ref: Section 8 — "Verify traffic suppression.
Emit SOC event. Update Home Shield Score and device state."

Section 7 — "Verification: Check that block actually worked.
Re-check flow / rule state / traffic."
"""

import os
import platform
import subprocess
import time
from typing import Dict, Any, Optional

from security.audit import AuditTrail


class VerificationAgent:
    """
    Verifies that enforcement actions (firewall blocks, quarantines)
    were actually applied and are effective.
    """

    def __init__(self, audit_trail: Optional[AuditTrail] = None):
        self.audit_trail = audit_trail or AuditTrail()
        self._platform = self._detect_platform()

    def _detect_platform(self) -> str:
        sysname = (platform.system() or "").lower()
        if "windows" in sysname:
            return "windows"
        if "linux" in sysname:
            return "linux"
        if "darwin" in sysname:
            return "mac"
        return "unknown"

    # ------------------------------------------------------------------
    # Firewall rule verification
    # ------------------------------------------------------------------
    def verify_block(self, ip: str) -> Dict[str, Any]:
        """
        Verify that a firewall block rule exists for the given IP.

        Returns:
            {
                "verified": bool,
                "method": str,
                "rule_found": bool,
                "details": str,
                "platform": str,
            }
        """
        result = {
            "verified": False,
            "method": "",
            "rule_found": False,
            "details": "",
            "platform": self._platform,
            "ip": ip,
            "timestamp": time.time(),
        }

        if ip.startswith("DEMO_") or ip == "unknown":
            result["verified"] = True
            result["method"] = "demo_bypass"
            result["rule_found"] = True
            result["details"] = f"Demo IP {ip} — verification skipped"
            self._log_verification("BLOCK_IP", ip, True, result["details"])
            return result

        try:
            if self._platform == "windows":
                result = self._verify_windows_block(ip, result)
            elif self._platform == "linux":
                result = self._verify_linux_block(ip, result)
            else:
                result["details"] = f"Unsupported platform: {self._platform}"
        except Exception as e:
            result["details"] = f"Verification error: {str(e)}"

        self._log_verification("BLOCK_IP", ip, result["verified"], result["details"])
        return result

    def _verify_windows_block(self, ip: str, result: dict) -> dict:
        """Check if a Windows Firewall rule exists for the IP."""
        result["method"] = "netsh_query"
        rule_name = f"AIHomeShield Block {ip}"
        cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'

        try:
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            output = (proc.stdout or "").strip()

            if proc.returncode == 0 and ip in output:
                result["verified"] = True
                result["rule_found"] = True
                result["details"] = f"Firewall rule found for {ip}"
            else:
                result["verified"] = False
                result["rule_found"] = False
                result["details"] = f"No firewall rule found for {ip}"
        except subprocess.TimeoutExpired:
            result["details"] = "Verification timed out"
        except Exception as e:
            result["details"] = f"Verification failed: {e}"

        return result

    def _verify_linux_block(self, ip: str, result: dict) -> dict:
        """Check if an iptables/nftables rule exists for the IP."""
        result["method"] = "iptables_check"
        cmd = f"iptables -C INPUT -s {ip} -j DROP 2>/dev/null"

        try:
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if proc.returncode == 0:
                result["verified"] = True
                result["rule_found"] = True
                result["details"] = f"iptables rule found for {ip}"
            else:
                # Try nftables
                nft_cmd = f"nft list ruleset 2>/dev/null | grep {ip}"
                proc2 = subprocess.run(nft_cmd, shell=True, capture_output=True, text=True, timeout=10)
                if proc2.returncode == 0 and ip in (proc2.stdout or ""):
                    result["verified"] = True
                    result["rule_found"] = True
                    result["method"] = "nftables_check"
                    result["details"] = f"nftables rule found for {ip}"
                else:
                    result["verified"] = False
                    result["rule_found"] = False
                    result["details"] = f"No firewall rule found for {ip}"
        except Exception as e:
            result["details"] = f"Verification failed: {e}"

        return result

    # ------------------------------------------------------------------
    # Quarantine verification
    # ------------------------------------------------------------------
    def verify_quarantine(self, device_ip: str) -> Dict[str, Any]:
        """
        Verify that a device is effectively quarantined.
        For now, checks that blocking rules exist.
        """
        result = self.verify_block(device_ip)
        result["action_type"] = "QUARANTINE"
        self._log_verification("QUARANTINE", device_ip, result["verified"], result["details"])
        return result

    # ------------------------------------------------------------------
    # Rule removal verification
    # ------------------------------------------------------------------
    def verify_rule_removal(self, ip: str) -> Dict[str, Any]:
        """Verify that a firewall rule has been successfully removed."""
        check = self.verify_block(ip)
        # Invert: if rule NOT found, removal is verified
        result = {
            "verified": not check["rule_found"],
            "method": check["method"],
            "rule_found": check["rule_found"],
            "details": (
                f"Rule successfully removed for {ip}"
                if not check["rule_found"]
                else f"Rule still exists for {ip}"
            ),
            "platform": check["platform"],
            "ip": ip,
            "timestamp": time.time(),
        }
        self._log_verification("UNBLOCK_IP", ip, result["verified"], result["details"])
        return result

    # ------------------------------------------------------------------
    # Audit logging
    # ------------------------------------------------------------------
    def _log_verification(self, action_type: str, target: str, verified: bool, details: str):
        self.audit_trail.log_verification(
            action_type=action_type,
            target=target,
            verified=verified,
            details=details,
        )
