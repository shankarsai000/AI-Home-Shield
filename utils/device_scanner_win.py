"""
utils/device_scanner_win.py

Windows / Cross-Platform Device & Port Scanner using Nmap + Npcap.

Architecture ref: Section 3 & 4 — LAN Discovery and Device Inventory.
Uses ARP ping scan (-sn -PR) with Npcap driver for fast Layer 2 discovery on the local LAN.
"""

import os
import re
import shutil
import socket
import subprocess
import time
import ipaddress
from datetime import datetime
from typing import List, Dict, Optional

try:
    import psutil
except ImportError:
    psutil = None


def find_nmap_path() -> str:
    """Find the path to the nmap executable on Windows or Linux."""
    # 1. Check system PATH
    p = shutil.which("nmap")
    if p and os.path.exists(p):
        return p

    # 2. Check common Windows installation paths
    candidates = [
        os.path.expanduser("~/nmap.exe"),
        r"C:\Users\shank\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c

    return "nmap"


def get_default_subnet() -> str:
    """
    Dynamically detect the active local LAN IPv4 subnet (e.g., 172.21.6.0/24).
    """
    try:
        # Route probe to external IP to get active local adapter IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        if psutil:
            for iface_name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address == local_ip:
                        netmask = addr.netmask or "255.255.255.0"
                        net = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
                        return str(net)

        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        pass

    return "172.21.6.0/24"


def _valid_target_spec(target: str) -> bool:
    target = target.strip()
    if re.search(r"[;&|`$<>]", target):
        return False
    # CIDR (e.g. 172.21.6.0/24)
    if re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$", target):
        return True
    # Single IP (e.g. 172.21.6.1)
    if re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})$", target):
        return True
    # IP range (e.g. 172.21.6.1-50 or 172.21.6.1-172.21.6.50)
    if re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3})*)$", target):
        return True
    return False


def _valid_cidr(cidr: str) -> bool:
    return _valid_target_spec(cidr)


def _valid_ip(ip: str) -> bool:
    return _valid_target_spec(ip)


def _fallback_arp_scan() -> List[Dict]:
    """Fallback: parse Windows arp -a table if Nmap is inaccessible."""
    devices = []
    try:
        res = subprocess.run("arp -a", shell=True, capture_output=True, text=True, timeout=5)
        out = res.stdout or ""
        now = datetime.utcnow().isoformat()
        for line in out.splitlines():
            line = line.strip()
            # Match IPv4 and MAC
            m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+(\w+)", line)
            if m:
                ip = m.group(1)
                mac = m.group(2).replace("-", ":").upper()
                typ = m.group(3).lower()
                # Skip broadcast and multicast
                if typ == "dynamic" and not ip.endswith(".255") and not ip.startswith("224.") and not ip.startswith("239."):
                    devices.append({
                        "ip": ip,
                        "mac": mac,
                        "vendor": "Local ARP device",
                        "status": "up",
                        "last_seen": now,
                    })
    except Exception:
        pass
    return devices


def discover_devices(subnet: Optional[str] = None) -> List[Dict]:
    """Run an ARP discovery scan using Nmap + Npcap (-sn -PR --min-rate 300).

    Returns list of dicts: {ip, mac, vendor, status, last_seen}
    """
    if not subnet:
        subnet = get_default_subnet()
    subnet = subnet.strip()

    if not _valid_cidr(subnet):
        raise ValueError(f"Invalid subnet/CIDR: {subnet}")

    nmap_bin = find_nmap_path()
    # Use -sn -PR with --min-rate 300 for fast Layer-2 ARP response gathering
    cmd = f'"{nmap_bin}" -sn -PR --min-rate 300 {subnet} --reason'

    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        out = res.stdout or ""
    except Exception:
        out = ""

    lines = out.splitlines()
    devices = []
    current = {}

    ip_re = re.compile(r"Nmap scan report for .*?(\d+\.\d+\.\d+\.\d+)")
    mac_re = re.compile(r"MAC Address:\s*([0-9A-Fa-f:]+)\s*\(?([^)]*)\)?")
    status_re = re.compile(r"Host is (up|down)")

    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue

        m = ip_re.search(ln)
        if m:
            if current:
                current.setdefault("mac", "")
                current.setdefault("vendor", "Unknown")
                current.setdefault("status", "up")
                current.setdefault("last_seen", datetime.utcnow().isoformat())
                devices.append(current)
                current = {}

            current = {"ip": m.group(1)}
            continue

        m = status_re.search(ln)
        if m and current:
            current["status"] = m.group(1)
            continue

        m = mac_re.search(ln)
        if m and current:
            current["mac"] = m.group(1)
            vendor = m.group(2).strip() if m.group(2) else "Unknown"
            current["vendor"] = vendor
            continue

    if current:
        current.setdefault("mac", "")
        current.setdefault("vendor", "Unknown")
        current.setdefault("status", "up")
        current.setdefault("last_seen", datetime.utcnow().isoformat())
        devices.append(current)

    # If Nmap returned no devices (e.g. permission or network isolate), fall back to ARP table
    if not devices:
        devices = _fallback_arp_scan()

    now = datetime.utcnow().isoformat()
    for d in devices:
        if "last_seen" not in d or not d["last_seen"]:
            d["last_seen"] = now
        if not d.get("vendor"):
            d["vendor"] = "Unknown"

    return devices


def scan_ports(ip: str) -> List[Dict]:
    """Run a safe TCP connect scan for top ports and parse open ports.

    Returns list of dicts: {port: int, service: str}
    """
    ip = ip.strip()
    if not _valid_ip(ip):
        raise ValueError(f"Invalid IP address: {ip}")

    nmap_bin = find_nmap_path()
    cmd = f'"{nmap_bin}" -sT -Pn --top-ports 50 --open {ip}'

    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
        out = res.stdout or ""
    except Exception:
        return []

    ports = []
    # parse lines like: "22/tcp open  ssh"
    port_re = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)")
    for line in out.splitlines():
        line = line.strip()
        m = port_re.match(line)
        if m:
            port = int(m.group(1))
            service = m.group(3)
            ports.append({"port": port, "service": service})

    return ports
