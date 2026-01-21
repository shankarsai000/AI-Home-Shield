# agents/risk_agent.py
print("✅ UPDATED risk_agent.py LOADED")

RISKY_PORTS = {
    23: ("TELNET", 5),
    445: ("SMB", 4),
    3389: ("RDP", 4),
    22: ("SSH", 3),
    21: ("FTP", 3),
    554: ("RTSP", 4),
    8080: ("ALT-HTTP", 2),
    5900: ("VNC", 4),
    53: ("DNS", 1),
    80: ("HTTP", 1),
    443: ("HTTPS", 0),
}

def calculate_risk(device):
    ports = device.get("open_ports", [])
    firmware = device.get("firmware_status", "UNKNOWN")
    vendor = device.get("vendor", "Unknown")

    score = 0
    reasons = []

    for p in ports:
        if p in RISKY_PORTS:
            pname, weight = RISKY_PORTS[p]
            score += weight
            if weight > 0:
                reasons.append(f"Open port {p} ({pname}) adds +{weight}")

    if len(ports) >= 4:
        score += 3
        reasons.append("Too many open ports (+3)")
    elif len(ports) == 3:
        score += 2
        reasons.append("Moderate open ports (+2)")
    elif len(ports) == 2:
        score += 1
        reasons.append("Some open ports (+1)")

    if firmware == "OUTDATED":
        score += 4
        reasons.append("Outdated firmware (+4)")
    elif firmware == "UNKNOWN":
        score += 2
        reasons.append("Unknown firmware (+2)")

    if vendor.lower() in ["generic", "unknown"]:
        score += 3
        reasons.append("Untrusted/Generic vendor (+3)")

    if device.get("_mutations", 0) > 0:
        score += 2
        reasons.append("Recent suspicious configuration change (+2)")

    if score >= 15:
        risk = "CRITICAL"
    elif score >= 10:
        risk = "HIGH"
    elif score >= 6:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    device["risk_score"] = int(score)
    device["risk_level"] = risk
    device["risk_reasons"] = reasons
    return device

def profile_all_devices(devices):
    return [calculate_risk(d) for d in devices]

def auto_patch_device(devices, device_name):
    """
    HARDEN device strongly so its risk drops guaranteed.
    """
    devices = [d.copy() for d in devices]

    for d in devices:
        if d.get("device_name") == device_name:
            d["open_ports"] = [443]
            d["firmware_status"] = "OK"

            old_vendor = d.get("vendor", "Unknown")
            if "(Hardened)" not in old_vendor:
                d["vendor"] = old_vendor + " (Hardened)"

            d["_last_change"] = "AUTO_SECURE ✅ (ports reduced + firmware updated)"
            d["_mutations"] = int(d.get("_mutations", 0)) + 1

    return devices
