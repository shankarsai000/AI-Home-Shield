"""agents/health_agent.py

Provides a simple agent health check utility for the AI Home Shield demo.
Uses psutil when available; falls back to stdlib for event-rate calculation.
"""
from datetime import datetime
from typing import Dict
import os

try:
    import psutil
except Exception:
    psutil = None


def _parse_alert_timestamps(log_path: str, max_lines: int = 500):
    """Parse timestamps from alerts.log lines. Returns list of datetimes (may be empty)."""
    if not os.path.exists(log_path):
        return []
    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[-max_lines:]
    except Exception:
        return []

    ts_list = []
    for ln in lines:
        # expected format: [YYYY-MM-DD HH:MM:SS] ...
        if ln.startswith("["):
            try:
                ts_str = ln.split("]")[0].lstrip("[")
                ts = datetime.strptime(ts_str.strip(), "%Y-%m-%d %H:%M:%S")
                ts_list.append(ts)
            except Exception:
                continue
    return ts_list


def get_agent_health(alert_log_path: str = "logs/alerts.log") -> Dict:
    """Return a health dict.

    Fields:
      cpu_percent, memory_percent, event_rate, status, reasons(list)
    """
    reasons = []

    # CPU and memory
    if psutil:
        try:
            cpu = psutil.cpu_percent(interval=0.1)
        except Exception:
            cpu = 0.0
            reasons.append("cpu-read-failed")
        try:
            memory = psutil.virtual_memory().percent
        except Exception:
            memory = 0.0
            reasons.append("memory-read-failed")
    else:
        cpu = 0.0
        memory = 0.0
        reasons.append("psutil-missing")

    # Event rate: compute from alerts log timestamps
    ts_list = _parse_alert_timestamps(alert_log_path, max_lines=1000)
    event_rate = 0.0
    if len(ts_list) >= 2:
        elapsed = (max(ts_list) - min(ts_list)).total_seconds()
        if elapsed <= 0:
            event_rate = float(len(ts_list))
        else:
            event_rate = len(ts_list) / elapsed
    elif len(ts_list) == 1:
        event_rate = 1.0 / max(1.0, (datetime.now() - ts_list[0]).total_seconds())

    # Determine status
    status = "OK"
    # thresholds (tunable)
    if cpu >= 90 or memory >= 92 or event_rate >= 20:
        status = "CRITICAL"
        reasons.append("high-resource-or-event-rate")
    elif cpu >= 70 or memory >= 80 or event_rate >= 5:
        status = "WARN"
        reasons.append("elevated-resource-or-event-rate")

    return {
        "cpu_percent": float(round(cpu, 2)),
        "memory_percent": float(round(memory, 2)),
        "event_rate": float(round(event_rate, 3)),
        "status": status,
        "reasons": reasons,
    }
