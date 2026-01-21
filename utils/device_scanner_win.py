import subprocess
import re
import time
from datetime import datetime
from typing import List, Dict


def _valid_cidr(cidr: str) -> bool:
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$", cidr.strip())
    if not m:
        return False
    ip = m.group(1)
    mask = int(m.group(2))
    if not (0 <= mask <= 32):
        return False
    parts = ip.split(".")
    for p in parts:
        try:
            v = int(p)
        except Exception:
            return False
        if v < 0 or v > 255:
            return False
    return True


def _valid_ip(ip: str) -> bool:
    m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})$", ip.strip())
    if not m:
        return False
    parts = ip.split(".")
    for p in parts:
        try:
            v = int(p)
        except Exception:
            return False
        if v < 0 or v > 255:
            return False
    return True


def discover_devices(subnet: str = "172.24.118.0/24") -> List[Dict]:
    """Run a safe ARP discovery using nmap -sn -PR <subnet>/24 --reason and parse results.

    Returns list of dicts: {ip, mac, vendor, status, last_seen}
    """
    subnet = subnet.strip()
    if not _valid_cidr(subnet):
        raise ValueError(f"Invalid subnet/CIDR: {subnet}")

    cmd = f"nmap -sn -PR {subnet} --reason"

    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    except Exception:
        return []

    out = res.stdout or ""
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
            # start of new host
            if current:
                # finalize previous
                current.setdefault("mac", "")
                current.setdefault("vendor", "")
                current.setdefault("status", "unknown")
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
            vendor = m.group(2).strip() if m.group(2) else ""
            current["vendor"] = vendor
            continue

        # lines with "is up" and latency sometimes include reason
        # ignore other lines

    if current:
        current.setdefault("mac", "")
        current.setdefault("vendor", "")
        current.setdefault("status", "unknown")
        current.setdefault("last_seen", datetime.utcnow().isoformat())
        devices.append(current)

    # ensure last_seen exists
    now = datetime.utcnow().isoformat()
    for d in devices:
        if "last_seen" not in d or not d["last_seen"]:
            d["last_seen"] = now

    return devices


def scan_ports(ip: str) -> List[Dict]:
    """Run a safe TCP connect scan for top ports and parse open ports.

    Returns list of dicts: {port: int, service: str}
    """
    ip = ip.strip()
    if not _valid_ip(ip):
        raise ValueError(f"Invalid IP address: {ip}")

    cmd = f"nmap -sT -Pn --top-ports 50 --open {ip}"

    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    except Exception:
        return []

    out = res.stdout or ""
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
# utils/device_scanner_win.py

import subprocess
import re
from datetime import datetime

def run_cmd(cmd):
    """Run a shell command and return output safely."""
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        shell=True
    )
    return result.stdout

def discover_devices(subnet="172.24.118.0/24"):
    """
    Safe device discovery using Nmap ARP scan.
    Returns list of devices with IP, MAC, last_seen.
    """
    cmd = f"nmap -sn -PR {subnet} --reason"
    out = run_cmd(cmd)

    devices = []
    current_ip = None

    for line in out.splitlines():
        line = line.strip()

        # Example: Nmap scan report for 172.24.118.144
        m_ip = re.search(r"Nmap scan report for ([0-9.]+)", line)
        if m_ip:
            current_ip = m_ip.group(1)
            devices.append({
                "ip": current_ip,
                "mac": "N/A",
                "vendor": "Unknown",
                "status": "UP",
                "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })
            continue

        # Example: MAC Address: D6:0C:EE:A1:97:DB (Unknown)
        m_mac = re.search(r"MAC Address:\s*([0-9A-F:]+)\s*\((.*)\)", line, re.I)
        if m_mac and devices:
            devices[-1]["mac"] = m_mac.group(1).upper()
            devices[-1]["vendor"] = m_mac.group(2)

    return devices

def scan_ports(ip):
    """
    Safe port scan using TCP connect scan (no raw packets).
    Returns list of open ports (port, service).
    """
    cmd = f"nmap -sT -Pn --top-ports 50 --open {ip}"
    out = run_cmd(cmd)

    ports = []
    for line in out.splitlines():
        line = line.strip()
        # Example: 53/tcp open  domain
        m = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line)
        if m:
            ports.append({
                "port": int(m.group(1)),
                "service": m.group(2)
            })
    return ports
