import json
import os
from datetime import datetime


ALERT_LOG = "logs/alerts.log"


def log_alert(message, severity="INFO"):
    os.makedirs("logs", exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] severity={severity} msg={message}\n"
    with open(ALERT_LOG, "a") as f:
        f.write(line)


def quarantine_device(device_ip, quarantine_list):
    if device_ip not in quarantine_list:
        quarantine_list.append(device_ip)
        log_alert(f"Device quarantined: {device_ip}", severity="HIGH")
    return quarantine_list


def block_attacker_ip(attacker_ip, blocked_list):
    if attacker_ip not in blocked_list:
        blocked_list.append(attacker_ip)
        log_alert(f"Attacker IP blocked: {attacker_ip}", severity="CRITICAL")
    return blocked_list


def agentic_response(session_prob, session_label, devices, quarantine_list, blocked_list):
    """
    Simple autonomous response policy:
    - If session_prob >= 0.98 AND label not benign -> quarantine highest risk device
    - If honeypot event exists -> block attacker IP (done via UI part)
    """
    # Treat any non-benign label as attack
    is_attack = (str(session_label).lower() != "benigntraffic") and (str(session_label).lower() != "benign")

    if is_attack and session_prob >= 0.98:
        # Pick highest risk device from devices
        if devices:
            highest = sorted(devices, key=lambda d: d.get("risk_score", 0), reverse=True)[0]
            quarantine_list = quarantine_device(highest["ip"], quarantine_list)
            log_alert(f"AUTO RESPONSE triggered due to {session_label} prob={session_prob}", severity="HIGH")

    return quarantine_list, blocked_list
