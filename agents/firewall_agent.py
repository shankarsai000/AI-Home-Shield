import os
import platform
import subprocess
import time
from typing import Tuple


class FirewallAgent:
    def __init__(self, log_path: str = "logs/firewall.log"):
        self.log_path = log_path
        try:
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        except Exception:
            pass

    def _platform_tag(self) -> str:
        sysname = (platform.system() or "").lower()
        if "windows" in sysname:
            return "windows"
        if "darwin" in sysname or "mac" in sysname:
            return "mac"
        if "linux" in sysname:
            return "linux"
        return "linux"

    def _is_valid_ipv4(self, ip: str) -> bool:
        if not isinstance(ip, str):
            return False
        s = ip.strip()
        parts = s.split(".")
        if len(parts) != 4:
            return False
        try:
            nums = [int(p) for p in parts]
        except Exception:
            return False
        for n in nums:
            if n < 0 or n > 255:
                return False
        return True

    def _log(self, entry: dict):
        try:
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        except Exception:
            pass

        try:
            line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {entry}\n"
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            pass

    def _run_cmd(self, cmd: str, dry_run: bool) -> Tuple[bool, str]:
        if dry_run:
            return True, ""
        try:
            p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            ok = p.returncode == 0
            out = (p.stdout or "").strip()
            err = (p.stderr or "").strip()
            combined = (out + "\n" + err).strip()
            return ok, combined
        except Exception as e:
            return False, str(e)

    def block_ip(self, ip: str, reason: str = "", dry_run: bool = False) -> dict:
        plat = self._platform_tag()
        requires_admin = plat == "windows"

        # Special handling for demo IPs
        if ip.startswith("DEMO_") or ip == "unknown":
            res = {
                "ok": True,
                "platform": plat,
                "cmd": "",
                "message": f"Demo IP {ip} marked as blocked (simulation)",
                "error": "",
                "requires_admin": False,
            }
            self._log({"action": "block", "ip": ip, "reason": reason, **res})
            return res

        if not self._is_valid_ipv4(ip):
            res = {
                "ok": False,
                "platform": plat,
                "cmd": "",
                "message": "Invalid IPv4 address",
                "error": "",
                "requires_admin": False,
            }
            self._log({"action": "block", "ip": ip, "reason": reason, **res})
            return res

        if plat != "windows":
            res = {
                "ok": False,
                "platform": plat,
                "cmd": "",
                "message": "Unsupported platform for blocking in this demo build",
                "error": "",
                "requires_admin": False,
            }
            self._log({"action": "block", "ip": ip, "reason": reason, **res})
            return res

        rule_name = f"AIHomeShield Block {ip}"
        cmd_in = (
            f'netsh advfirewall firewall add rule name="{rule_name}" '
            f"dir=in action=block remoteip={ip}"
        )
        cmd_out = (
            f'netsh advfirewall firewall add rule name="{rule_name}" '
            f"dir=out action=block remoteip={ip}"
        )
        cmd = cmd_in + " && " + cmd_out

        ok1, out1 = self._run_cmd(cmd_in, dry_run=dry_run)
        ok2, out2 = self._run_cmd(cmd_out, dry_run=dry_run)
        ok = bool(ok1 and ok2)
        err = ""
        if not ok:
            err = (out1 + "\n" + out2).strip()

        err_lower = (err or "").lower()
        if (not ok) and ("requires elevation" in err_lower or "run as administrator" in err_lower or "elevation" in err_lower):
            msg = f"Firewall rule failed for {ip} (requires Administrator)"
        elif (not ok) and ("already exists" in err_lower or "no rules match" not in err_lower and "exists" in err_lower):
            msg = f"Firewall rule already exists for {ip}" if not dry_run else f"Dry run: would block {ip} (in/out)"
            ok = True
        elif dry_run:
            msg = f"Dry run: would block {ip} (in/out)"
        else:
            msg = f"Firewall rule applied for {ip}" if ok else f"Firewall rule failed for {ip}"

        res = {
            "ok": ok,
            "platform": plat,
            "cmd": cmd,
            "message": msg,
            "error": err,
            "requires_admin": requires_admin,
        }
        self._log({"action": "block", "ip": ip, "reason": reason, **res})
        return res

    def unblock_ip(self, ip: str, dry_run: bool = False) -> dict:
        plat = self._platform_tag()
        requires_admin = plat == "windows"

        if not self._is_valid_ipv4(ip):
            res = {
                "ok": False,
                "platform": plat,
                "cmd": "",
                "message": "Invalid IPv4 address",
                "error": "",
                "requires_admin": False,
            }
            self._log({"action": "unblock", "ip": ip, **res})
            return res

        if plat != "windows":
            res = {
                "ok": False,
                "platform": plat,
                "cmd": "",
                "message": "Unsupported platform for blocking in this demo build",
                "error": "",
                "requires_admin": False,
            }
            self._log({"action": "unblock", "ip": ip, **res})
            return res

        rule_name = f"AIHomeShield Block {ip}"
        cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'

        ok, out = self._run_cmd(cmd, dry_run=dry_run)
        err = "" if ok else (out or "")

        if dry_run:
            msg = f"Dry run: would delete firewall rule for {ip}"
        else:
            msg = f"Firewall rule removed for {ip}" if ok else f"Firewall rule removal failed for {ip}"

        res = {
            "ok": ok,
            "platform": plat,
            "cmd": cmd,
            "message": msg,
            "error": err,
            "requires_admin": requires_admin,
        }
        self._log({"action": "unblock", "ip": ip, **res})
        return res

    def status(self) -> dict:
        plat = self._platform_tag()
        requires_admin = plat == "windows"

        if plat != "windows":
            res = {
                "ok": False,
                "platform": plat,
                "cmd": "",
                "message": "Unsupported platform for blocking in this demo build",
                "error": "",
                "requires_admin": False,
            }
            self._log({"action": "status", **res})
            return res

        cmd = "netsh advfirewall show allprofiles"
        ok, out = self._run_cmd(cmd, dry_run=False)
        err = "" if ok else (out or "")
        msg = "Firewall status retrieved" if ok else "Firewall status failed"

        res = {
            "ok": ok,
            "platform": plat,
            "cmd": cmd,
            "message": msg,
            "error": err,
            "requires_admin": requires_admin,
        }
        self._log({"action": "status", **res})
        return res
