from typing import List, Dict


def decide_actions(session_prob: float, session_label: str, devices: List[Dict], honeypot_events: List[Dict], autonomous: bool = True) -> List[Dict]:
    """
    Orchestrator that returns a list of actions in the required format.

    Output actions use keys:
      - {"type": "ALERT", "severity": "HIGH", "message": "..."}
      - {"type": "QUARANTINE", "device_ip": "1.2.3.4", "reason": "..."}
      - {"type": "BLOCK_IP", "ip": "9.9.9.9", "reason": "..."}

    Policy (hackathon-safe):
      - If session_label != 'BenignTraffic' and session_prob >= 0.98 -> quarantine highest risk device
      - If honeypot event present -> block attacker IP
      - Otherwise -> emit an ALERT
    """
    actions: List[Dict] = []
    if not autonomous:
        return actions

    # Block IPs from honeypot events first
    for ev in honeypot_events:
        ip = ev.get("attacker_ip")
        if ip:
            actions.append({"type": "BLOCK_IP", "ip": ip, "reason": "Honeypot triggered"})
            actions.append({"type": "ALERT", "severity": "HIGH", "message": f"Honeypot triggered by {ip}"})

    # Session-based decision
    if str(session_label).lower() != "benigntraffic" and session_prob >= 0.98:
        # quarantine highest risk device
        if devices:
            highest = sorted(devices, key=lambda d: d.get("risk_score", 0), reverse=True)[0]
            actions.append({
                "type": "QUARANTINE",
                "device_ip": highest.get("ip"),
                "reason": f"Session {session_label} prob={session_prob}",
            })
            actions.append({"type": "ALERT", "severity": "CRITICAL", "message": f"Auto-quarantine {highest.get('device_name')} ({highest.get('ip')})"})
    else:
        # non-actionable session -> low-priority alert
        actions.append({"type": "ALERT", "severity": "LOW", "message": f"Session observed: {session_label} prob={session_prob}"})

    return actions
