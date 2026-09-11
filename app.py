import os

import time
import re
import random
import shutil
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

try:
    from utils.device_scanner_win import discover_devices, scan_ports, get_default_subnet, find_nmap_path
    _scanner_import_error = None
except Exception as _e:
    _scanner_import_error = _e

    def discover_devices(*args, **kwargs):
        return []

    def scan_ports(*args, **kwargs):
        return []

    def get_default_subnet():
        return "172.21.6.0/24"

    def find_nmap_path():
        return "nmap"

from agents.discovery_agent import discover_devices_demo, mutate_devices
from agents.risk_agent import profile_all_devices, auto_patch_device, RISKY_PORTS
from agents.perception_agent import PerceptionAgent
from agents.session_agent import SessionAggregationAgent
from agents.deception_agent import start_honeypot_in_background
from agents.health_agent import get_agent_health

from agents.response_agent import (
    agentic_response,
    quarantine_device,
    block_attacker_ip,
    log_alert,
    ResponseAgent,
)
from agents.orchestrator_agent import decide_actions, OrchestratorAgent
from agents.safety_agent import SafetyAgent
from agents.verification_agent import VerificationAgent
from agents.network_state_agent import NetworkStateAgent
from agents.attack_forecasting_agent import AttackForecastingAgent
from security.allowlist import Allowlist
from security.audit import AuditTrail
from security.policy import PolicyGate
from storage.database import ShieldDatabase
from storage.evidence import EvidenceStore
from capture.packet_capture import PacketCaptureAdapter
from capture.flow_builder import FlowBuilder
from capture.feature_extractor import FeatureExtractor
from agents.flow_tracker_agent import NetworkFlowTracker

try:
    from utils.attack_demo import get_local_ip, demo_honeypot_burst, demo_port_scan_burst, demo_http_burst
    _attack_demo_import_error = None
except Exception as _e:
    _attack_demo_import_error = _e
    def get_local_ip(*args, **kwargs):
        return "127.0.0.1"
    def demo_honeypot_burst(*args, **kwargs):
        return {"ok": False, "message": "Attack demo unavailable", "error": str(_attack_demo_import_error), "stats": {}}
    def demo_port_scan_burst(*args, **kwargs):
        return {"ok": False, "message": "Attack demo unavailable", "error": str(_attack_demo_import_error), "stats": {}}
    def demo_http_burst(*args, **kwargs):
        return {"ok": False, "message": "Attack demo unavailable", "error": str(_attack_demo_import_error), "stats": {}}

try:
    from agents.firewall_agent import FirewallAgent
    _firewall_import_error = None
except Exception as _e:
    _firewall_import_error = _e

    class FirewallAgent:
        def __init__(self, *args, **kwargs):
            pass

        def block_ip(self, ip: str, reason: str = "", dry_run: bool = False) -> dict:
            return {
                "ok": False,
                "platform": "linux",
                "cmd": "",
                "message": "Firewall agent unavailable",
                "error": repr(_firewall_import_error),
                "requires_admin": True,
            }

        def unblock_ip(self, ip: str, dry_run: bool = False) -> dict:
            return {
                "ok": False,
                "platform": "linux",
                "cmd": "",
                "message": "Firewall agent unavailable",
                "error": repr(_firewall_import_error),
                "requires_admin": True,
            }

        def status(self) -> dict:
            return {
                "ok": False,
                "platform": "linux",
                "cmd": "",
                "message": "Firewall agent unavailable",
                "error": repr(_firewall_import_error),
            }

try:
    from agents.honeytoken_agent import HoneytokenAgent
    _honeytoken_import_error = None
except Exception as _e:
    _honeytoken_import_error = _e

    class HoneytokenAgent:
        def __init__(self, *args, **kwargs):
            pass

        def create_tokens(self, base_dir: str = "honeytokens") -> list:
            return []

        def list_tokens(self) -> list:
            return []

        def check_trips(self) -> list:
            return []

        def manual_trip(self, token_id: str) -> dict:
            return {"ok": False, "message": "Honeytoken agent unavailable"}

        def status(self) -> dict:
            return {"num_tokens": 0, "base_dir": "honeytokens", "last_check_time": 0, "error": repr(_honeytoken_import_error)}

try:
    from agents.baseline_agent import BaselineAgent
    _baseline_import_error = None
except Exception as _e:
    _baseline_import_error = _e

    class BaselineAgent:
        def __init__(self, *args, **kwargs):
            pass

        def update_device_baseline(self, devices: list) -> dict:
            return {"devices_updated": 0, "baselines_total": 0}

        def detect_device_anomalies(self, devices: list) -> list:
            return []

        def update_network_baseline(self, flow_info: dict, session_info: dict) -> dict:
            return {"updated": False}

        def detect_network_anomalies(self, flow_info: dict, session_info: dict) -> list:
            return []

        def get_baseline_summary(self) -> dict:
            return {"device_count": 0, "total_anomalies": 0, "network_baseline_age": 0, "last_check": 0}


# Helper: collect consolidated happenings
def collect_happenings(limit: int = 50):
    happenings = {}
    # Alerts
    try:
        with open("logs/alerts.log", "r") as f:
            alerts = f.readlines()[-limit:]
    except Exception:
        alerts = []
    happenings["alerts"] = list(reversed([a.strip() for a in alerts]))

    # Honeypot
    try:
        with open("logs/honeypot.log", "r") as f:
            hlines = f.readlines()[-limit:]
    except Exception:
        hlines = []
    happenings["honeypot_events"] = list(reversed([h.strip() for h in hlines]))

    # Blocked / Quarantined
    happenings["blocked_ips"] = list(st.session_state.get("blocked_ips", []))
    happenings["quarantined_devices"] = list(st.session_state.get("quarantined_devices", []))

    # Suppressed actions
    happenings["suppressed_actions"] = list(reversed(st.session_state.get("suppressed_actions", [])[-limit:]))

    # Monitored flows
    happenings["monitored_flows"] = list(reversed(st.session_state.get("monitored_flows", [])[-limit:]))

    # Demo results
    happenings["demo_results"] = list(reversed(st.session_state.get("demo_results", [])[-limit:]))

    # Top 5 risky devices
    try:
        df_all = pd.DataFrame(st.session_state.get("devices", []))
        top5 = df_all.sort_values("risk_score", ascending=False).head(5)
        happenings["top5_devices"] = top5[["device_name", "ip", "risk_level", "risk_score"]].to_dict(orient="records")
    except Exception:
        happenings["top5_devices"] = []

    return happenings


def safe_block_ip(ip: str, reason: str = "", bypass_policy: bool = False) -> dict:
    try:
        resp_agent = st.session_state.get("response_agent")
        if resp_agent:
            res = resp_agent.execute_block(ip, reason=reason, bypass_policy=bypass_policy)
            fw_res = res.get("firewall_result", {})
            if not fw_res:
                return {"ok": res.get("ok", False), "message": res.get("reason", ""), "requires_admin": False}
            return fw_res
        agent = st.session_state.get("firewall_agent", None)
        if agent is None:
            raise RuntimeError("firewall_agent not initialized")
        return agent.block_ip(ip, reason=reason)
    except Exception as e:
        return {
            "ok": False,
            "platform": "linux",
            "cmd": "",
            "message": f"Firewall block failed: {e}",
            "error": str(e),
            "requires_admin": True,
        }


# =========================
# PAGE CONFIG
# =========================
st.set_page_config(page_title="AI Home Shield", layout="wide")
st.title("🛡️ AI Home Shield — Agentic IoT Security")
st.caption("Discovery + Risk + Session Threat Detection + Deception + Auto Response")


# -------------------------
# Helpers
# -------------------------
@st.cache_data
def load_demo_flows():
    """Generate balanced synthetic flows for demo - 70% benign, 30% attacks"""
    os.makedirs("data", exist_ok=True)
    
    feature_cols = None
    try:
        import json as _json
        with open("models/feature_columns.json", "r", encoding="utf-8") as ff:
            feature_cols = _json.load(ff)
    except Exception:
        feature_cols = None

    labels = ["BenignTraffic", "Mirai", "DDoS", "PortScan"]
    n_rows = 1000
    import random as _rand
    _rand.seed(42)
    rows = []

    if feature_cols:
        for _ in range(n_rows):
            r = {c: _rand.random() for c in feature_cols}
            # 70% benign, 30% attacks (Mirai 12%, DDoS 12%, PortScan 6%)
            r["label"] = _rand.choices(labels, weights=[0.70, 0.12, 0.12, 0.06])[0]
            rows.append(r)
    else:
        cols = ["feature1", "feature2", "feature3"]
        for _ in range(n_rows):
            r = {c: _rand.random() for c in cols}
            r["label"] = _rand.choices(labels, weights=[0.70, 0.12, 0.12, 0.06])[0]
            rows.append(r)

    df_sample = pd.DataFrame(rows)
    return df_sample


def extract_attacker_ip_from_flow(flow: dict) -> str:
    for k in ("attacker_ip", "src_ip", "source_ip", "src", "ip"):
        if k in flow and isinstance(flow[k], str) and re.match(r"^\d+\.\d+\.\d+\.\d+$", flow[k]):
            return flow[k]
    for v in flow.values():
        if isinstance(v, str):
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", v)
            if m:
                return m.group(1)
    return "unknown"


# =========================
# Top banner status
# =========================
def _system_status():
    now = time.time()
    quarantined = st.session_state.get("quarantined_devices", [])
    blocked = st.session_state.get("blocked_ips", [])
    last_attack = st.session_state.get("last_attack_time", 0)
    if quarantined or blocked:
        return "MITIGATING", "🟠"
    if now - last_attack < 30:
        return "UNDER ATTACK", "🔴"
    return "SAFE", "🟢"


status_label, status_emoji = _system_status()
st.markdown(f"**System Status:** {status_emoji} **{status_label}**")
if st.session_state.get("demo_mode", False):
    st.success("Demo Mode ON ✅")

def _is_attack_label(label: str) -> bool:
    s = str(label or "").strip().lower()
    return s not in ("benign", "benigntraffic", "normal", "safe", "0", "none", "")

def _push_timeline_event(ev_type: str, label: str = "", target: str = "", details: str = ""):
    ts = time.time()
    st.session_state.soc_timeline.append(
        {
            "ts": ts,
            "time": time.strftime("%H:%M:%S", time.localtime(ts)),
            "type": str(ev_type),
            "label": str(label),
            "target": str(target),
            "details": str(details),
        }
    )
    st.session_state.soc_timeline = st.session_state.soc_timeline[-200:]


def _xai_reasons(flow: dict, flow_pred: dict, session_pred: dict):
    reasons = []
    keys = list(flow.keys()) if isinstance(flow, dict) else []
    lower_keys = {k.lower(): k for k in keys if isinstance(k, str)}

    def _get_first(candidates):
        for ck in candidates:
            k = lower_keys.get(ck)
            if k is not None:
                try:
                    return float(flow.get(k, 0))
                except Exception:
                    return None
        return None

    pkt_rate = _get_first(["packet_rate", "pkt_rate", "pkts_per_sec", "pps", "flow_pkts_s", "pkt_s", "packets_per_second"])
    if pkt_rate is not None and pkt_rate > 1000:
        reasons.append("high packet rate")

    dur = _get_first(["flow_duration", "duration", "flow_dur", "dur"])
    if dur is not None and dur > 60:
        reasons.append("abnormal flow duration")

    sport = _get_first(["src_port", "sport", "source_port"])
    dport = _get_first(["dst_port", "dport", "dest_port", "destination_port"])
    if dport is not None and (dport in (23, 2323, 445, 3389, 5900, 1900) or dport > 49152):
        reasons.append("suspicious port pattern")
    if sport is not None and sport > 49152 and dport is not None and dport > 49152:
        if "suspicious port pattern" not in reasons:
            reasons.append("suspicious port pattern")

    syn = _get_first(["syn", "syn_count", "tcp_syn", "syn_flag_cnt"])
    if syn is not None and syn > 50:
        reasons.append("SYN flood-like behavior")

    sess_prob = float(session_pred.get("session_prob", 0) or 0)
    persistence = int(session_pred.get("persistence", 0) or 0)
    if sess_prob >= 0.9 and persistence >= 3:
        reasons.append("persistent high-confidence attack across session window")

    if not reasons:
        reasons.append("anomalous traffic signature detected")

    return reasons[:4]


def _compute_home_shield_score() -> int:
    now = time.time()
    devices = st.session_state.get("devices", []) or []
    blocked = len(st.session_state.get("blocked_ips", []) or [])
    quarantined = len(st.session_state.get("quarantined_devices", []) or [])
    events = st.session_state.get("security_events", []) or []
    auto_secures = sum(1 for e in events if e.get("type") == "AUTO_SECURE")

    timeline = st.session_state.get("soc_timeline", []) or []
    recent_attacks = sum(1 for e in timeline if e.get("type") == "ATTACK" and (now - float(e.get("ts", 0) or 0)) < 60)

    risk_penalty = 0
    try:
        if devices:
            max_risk = max(float(d.get("risk_score", 0) or 0) for d in devices)
            risk_penalty = min(25, int(max_risk / 4))
    except Exception:
        risk_penalty = 0

    score = 75
    score += min(12, blocked * 2)
    score += min(12, quarantined * 3)
    score += min(8, auto_secures * 2)
    score -= min(30, recent_attacks * 12)
    if now - float(st.session_state.get("last_attack_time", 0) or 0) < 30:
        score -= 10
    score -= risk_penalty
    return max(0, min(100, int(score)))


def _update_score_metric(adjustment: int = 0):
    current_score = _compute_home_shield_score()
    # Apply adjustment if provided
    current_score = max(0, min(100, current_score + adjustment))
    prev_score = int(st.session_state.get("last_security_score", current_score) or 0)
    delta_score = int(current_score - prev_score)
    st.session_state.last_security_score = current_score
    try:
        score_placeholder.metric("Home Shield Score", f"{current_score}/100", delta=f"{delta_score:+d}")
    except Exception:
        st.metric("Home Shield Score", f"{current_score}/100", delta=f"{delta_score:+d}")


score_placeholder = st.empty()


# =========================
# SIDEBAR
# =========================
st.sidebar.header("⚙️ Controls")
page = st.sidebar.radio(
    "Go to",
    [
        "📡 Devices & Risk",
        "⚡ Threat Monitor",
        "🔮 Attack Forecasting",
        "🛡️ Policy & Safety",
        "🧠 Response + Deception",
        "📁 Evidence",
        "🚀 One-Click Demo",
    ],
)

st.sidebar.divider()
st.sidebar.subheader("Threat Monitor")
window_seconds = st.sidebar.slider("Session Window (seconds)", 3, 20, 5)
speed = st.sidebar.slider("Replay Speed (flows/sec)", 1, 50, 10)

st.sidebar.divider()
st.sidebar.subheader("Device Simulation")
auto_refresh = st.sidebar.checkbox("🔄 Enable Real-time Device Simulation", value=False)
refresh_seconds = st.sidebar.slider("Refresh interval (sec)", 1, 10, 3)

st.sidebar.divider()
st.sidebar.subheader("Agent & Safety Controls")
autonomous_mode = st.sidebar.checkbox("Autonomous Mode", value=True)
dry_run_mode = st.sidebar.checkbox("🧪 Dry-Run Mode (Simulate Enforcement)", value=False)

if st.sidebar.button("🎛️ Demo Mode: Start Monitoring + Honeypot + Simulation"):
    st.session_state.monitoring = True
    st.session_state.honeypot_started = True
    st.session_state.auto_refresh = True
    st.session_state.demo_mode = True
    try:
        start_honeypot_in_background(port=9999)
    except Exception:
        pass

safe_mode_setting = st.sidebar.selectbox("Safe Mode", ["AUTO", "ON", "OFF"], index=0)

health = get_agent_health(alert_log_path="logs/alerts.log")
with st.sidebar.expander("Agent Health"):
    st.metric("CPU%", f"{health['cpu_percent']}%")
    st.metric("Memory%", f"{health['memory_percent']}%")
    st.metric("Event rate (ev/s)", f"{health['event_rate']}")
    st.write("Status:", health["status"])
    if health.get("reasons"):
        st.write("Reasons:")
        for r in health.get("reasons"):
            st.write("-", r)

col_force_1, col_force_2 = st.sidebar.columns([2, 1])
with col_force_1:
    if st.button("🔒 Force Safe Mode"):
        st.session_state.force_safe_mode = True
with col_force_2:
    if st.button("🔓 Clear Force"):
        st.session_state.force_safe_mode = False

if safe_mode_setting == "ON":
    safe_mode_active = True
elif safe_mode_setting == "OFF":
    safe_mode_active = False
else:
    safe_mode_active = True if health.get("status") == "CRITICAL" else False

if st.session_state.get("force_safe_mode", False):
    safe_mode_active = True

if safe_mode_active:
    st.error("⚠️ SAFE MODE ACTIVE — automated blocking/quarantine suppressed")

with st.sidebar.expander("Debug", expanded=False):
    try:
        st.write("Script:", os.path.abspath(__file__))
    except Exception:
        st.write("Script:", "unknown")
    st.write("CWD:", os.getcwd())
    st.write("Nmap:", shutil.which("nmap") or "NOT FOUND")
    if _scanner_import_error is None:
        st.write("Scanner import:", "OK")
    else:
        st.write("Scanner import:", repr(_scanner_import_error))

# Honeytokens section
st.sidebar.divider()
st.sidebar.subheader("🍯 Honeytokens")

if st.sidebar.button("Create Honeytokens"):
    agent = st.session_state.get("honeytoken_agent")
    if agent:
        with st.sidebar:
            with st.spinner("Creating honeytokens..."):
                tokens = agent.create_tokens()
                if tokens:
                    st.success(f"Created {len(tokens)} honeytokens")
                else:
                    st.info("Honeytokens already exist")
    else:
        st.sidebar.error("Honeytoken agent not available")

if st.sidebar.button("Check Trips"):
    agent = st.session_state.get("honeytoken_agent")
    if agent:
        with st.sidebar:
            with st.spinner("Checking for trips..."):
                trips = agent.check_trips()
                if trips:
                    st.error(f"Detected {len(trips)} honeytoken trips!")
                    for trip in trips:
                        st.sidebar.warning(f"🚨 {trip['filename']} accessed")
                        # Add to timeline
                        _push_timeline_event(
                            "HONEYTOKEN_TRIP",
                            label="HONEYTOKEN",
                            target=trip['filename'],
                            details=f"Token ID: {trip['token_id']} - {trip['reason']}"
                        )
                        # Update score (small negative impact)
                        _update_score_metric(-2)
                        # Show red banner
                        st.sidebar.error(f"🚨 HONEYTOKEN TRIP: {trip['filename']}")
                        # Auto-block if autonomous mode
                        if autonomous_mode:
                            ip = "DEMO_ATTACKER"  # Use demo IP when real IP unknown
                            fw = safe_block_ip(ip, reason=f"Honeytoken trip: {trip['filename']}")
                            if fw.get('ok'):
                                st.sidebar.success(f"🧱 Auto-blocked {ip}")
                                _push_timeline_event("BLOCK_IP", label="AUTO", target=ip, details="Honeytoken trip auto-block")
                            else:
                                st.sidebar.warning(f"Firewall block failed for {ip}: {fw.get('message')}")
                else:
                    st.success("No honeytoken trips detected")
    else:
        st.sidebar.error("Honeytoken agent not available")

# Token list and manual trip
agent = st.session_state.get("honeytoken_agent")
if agent:
    tokens = agent.list_tokens()
    if tokens:
        token_options = {f"{t['filename']} ({t['token_id']})": t['token_id'] for t in tokens}
        selected_token = st.sidebar.selectbox("Select Token", options=list(token_options.keys()), index=0)
        token_id = token_options[selected_token]
        
        if st.sidebar.button("Manual Trip (Demo)"):
            result = agent.manual_trip(token_id)
            if result.get('ok'):
                trip = result['trip']
                st.sidebar.error(f"🚨 Manual trip triggered for {trip['filename']}")
                # Add to timeline
                _push_timeline_event(
                    "HONEYTOKEN_TRIP",
                    label="HONEYTOKEN",
                    target=trip['filename'],
                    details=f"Manual demo trip - Token ID: {trip['token_id']}"
                )
                # Update score
                _update_score_metric(-2)
                # Show red banner
                st.sidebar.error(f"🚨 HONEYTOKEN TRIP: {trip['filename']} (DEMO)")
                # Auto-block if autonomous mode
                if autonomous_mode:
                    ip = "DEMO_ATTACKER"
                    fw = safe_block_ip(ip, reason=f"Manual honeytoken trip: {trip['filename']}")
                    if fw.get('ok'):
                        st.sidebar.success(f"🧱 Auto-blocked {ip}")
                        _push_timeline_event("BLOCK_IP", label="AUTO", target=ip, details="Manual honeytoken trip auto-block")
                    else:
                        st.sidebar.warning(f"Firewall block failed for {ip}: {fw.get('message')}")
            else:
                st.sidebar.error(f"Manual trip failed: {result.get('message')}")

if st.sidebar.button("📋 List All Happenings"):
    st.session_state.happenings = collect_happenings(limit=50)
    st.session_state.show_happenings = True


# =========================
# INIT STATE
# =========================
if "devices" not in st.session_state:
    st.session_state.devices = profile_all_devices(discover_devices_demo())

if "devices_tick" not in st.session_state:
    st.session_state.devices_tick = 0

if "monitoring" not in st.session_state:
    st.session_state.monitoring = False

if "blocked_ips" not in st.session_state:
    st.session_state.blocked_ips = []

if "quarantined_devices" not in st.session_state:
    st.session_state.quarantined_devices = []

if "honeypot_started" not in st.session_state:
    st.session_state.honeypot_started = False

if "honeypot_pos" not in st.session_state:
    st.session_state.honeypot_pos = 0

if "honeypot_events" not in st.session_state:
    st.session_state.honeypot_events = []

if "last_attack_time" not in st.session_state:
    st.session_state.last_attack_time = 0

if "demo_mode" not in st.session_state:
    st.session_state.demo_mode = False

if "suppressed_actions" not in st.session_state:
    st.session_state.suppressed_actions = []

if "force_safe_mode" not in st.session_state:
    st.session_state.force_safe_mode = False

if "demo_results" not in st.session_state:
    st.session_state.demo_results = []

if "monitored_flows" not in st.session_state:
    st.session_state.monitored_flows = []

if "soc_timeline" not in st.session_state:
    st.session_state.soc_timeline = []

if "security_events" not in st.session_state:
    st.session_state.security_events = []

if "last_security_score" not in st.session_state:
    st.session_state.last_security_score = 0

if "last_attack_popup_ts" not in st.session_state:
    st.session_state.last_attack_popup_ts = 0.0

if "last_attack_xai" not in st.session_state:
    st.session_state.last_attack_xai = {}

if "alert_sound" not in st.session_state:
    st.session_state.alert_sound = True

if "firewall_agent" not in st.session_state or st.session_state.get("firewall_agent") is None:
    try:
        st.session_state.firewall_agent = FirewallAgent()
    except Exception:
        st.session_state.firewall_agent = None

if "honeytoken_agent" not in st.session_state or st.session_state.get("honeytoken_agent") is None:
    try:
        st.session_state.honeytoken_agent = HoneytokenAgent()
    except Exception:
        st.session_state.honeytoken_agent = None

if "baseline_agent" not in st.session_state or st.session_state.get("baseline_agent") is None:
    try:
        st.session_state.baseline_agent = BaselineAgent()
    except Exception:
        st.session_state.baseline_agent = None

if "allowlist" not in st.session_state:
    st.session_state.allowlist = Allowlist()

if "audit_trail" not in st.session_state:
    st.session_state.audit_trail = AuditTrail()

if "policy_gate" not in st.session_state:
    st.session_state.policy_gate = PolicyGate(allowlist=st.session_state.allowlist)

if "shield_db" not in st.session_state:
    st.session_state.shield_db = ShieldDatabase()

if "evidence_store" not in st.session_state:
    st.session_state.evidence_store = EvidenceStore()

if "safety_agent" not in st.session_state:
    st.session_state.safety_agent = SafetyAgent(
        policy_gate=st.session_state.policy_gate,
        audit_trail=st.session_state.audit_trail,
    )

if "verification_agent" not in st.session_state:
    st.session_state.verification_agent = VerificationAgent(audit_trail=st.session_state.audit_trail)

if "network_state_agent" not in st.session_state:
    st.session_state.network_state_agent = NetworkStateAgent()

if "attack_forecasting_agent" not in st.session_state:
    st.session_state.attack_forecasting_agent = AttackForecastingAgent()

if "response_agent" not in st.session_state:
    st.session_state.response_agent = ResponseAgent(
        firewall_agent=st.session_state.firewall_agent,
        safety_agent=st.session_state.safety_agent,
        verification_agent=st.session_state.verification_agent,
        audit_trail=st.session_state.audit_trail,
    )

if "orchestrator_agent" not in st.session_state:
    st.session_state.orchestrator_agent = OrchestratorAgent(
        safety_agent=st.session_state.safety_agent,
        audit_trail=st.session_state.audit_trail,
    )

if "packet_capture" not in st.session_state:
    st.session_state.packet_capture = PacketCaptureAdapter()

if "flow_builder" not in st.session_state:
    st.session_state.flow_builder = FlowBuilder()

if "feature_extractor" not in st.session_state:
    st.session_state.feature_extractor = FeatureExtractor()

if "last_forecast" not in st.session_state:
    st.session_state.last_forecast = {}

try:
    os.makedirs("logs", exist_ok=True)
    if not os.path.exists("logs/honeypot.log"):
        open("logs/honeypot.log", "w").close()
    if not os.path.exists("logs/alerts.log"):
        open("logs/alerts.log", "w").close()
except Exception:
    pass

_update_score_metric()


# ✅ Convert scan list -> internal schema
def convert_scan_to_internal_devices(scan_list):
    converted = []
    for i, d in enumerate(scan_list, start=1):
        ip = d.get("ip", "N/A")
        vendor = d.get("vendor", "Unknown")
        mac = d.get("mac", "N/A")
        if vendor and vendor != "Unknown":
            dev_name = f"{vendor} Device ({ip.split('.')[-1]})"
        elif ip.endswith(".1"):
            dev_name = f"Default Gateway ({ip})"
        else:
            dev_name = f"Host_{ip.replace('.', '_')}"

        converted.append({
            "device_name": dev_name,
            "ip": ip,
            "vendor": vendor,
            "mac": mac,
            "open_ports": [],
            "firmware_status": "unknown",
            "_mutations": 0,
            "_last_change": "Discovered via Nmap + Npcap",
        })
    return converted


# =========================
# PAGE 1: DEVICES & RISK
# =========================
if page == "📡 Devices & Risk":
    st.subheader("📡 IoT Device Discovery & Risk Profiling")

    st.markdown("### 🔁 Device Source Mode")
    device_source = st.radio(
        "Choose device inventory source",
        ["🔵 Demo Devices (Simulated)", "🟢 Real Scan Devices (Nmap)"],
        horizontal=True,
        key="device_source_mode",
    )

    detected_subnet = get_default_subnet()
    subnet = detected_subnet

    # ✅ Real Scan Mode controls
    if device_source == "🟢 Real Scan Devices (Nmap)":
        nmap_bin = find_nmap_path()
        st.success(f"🟢 **Nmap & Npcap Engine Active**: `{nmap_bin}`")
        st.caption(f"Auto-detected local LAN subnet: `{detected_subnet}`. Supports CIDRs (e.g. `172.21.6.0/24`) or IP ranges (e.g. `172.21.6.1-50`).")
        subnet = st.text_input("Subnet / Target IP specification", value=detected_subnet)

        c1, c2 = st.columns([1, 1])
        scan_now = c1.button("🔍 Scan Devices Now (Nmap ARP)")
        auto_scan_refresh = c2.toggle("🔁 Auto refresh (15s)", value=False)

        if "real_scan_devices" not in st.session_state:
            st.session_state.real_scan_devices = []

        if scan_now or auto_scan_refresh:
            with st.spinner(f"Scanning {subnet} with Nmap + Npcap..."):
                try:
                    scanned = discover_devices(subnet=subnet)
                except Exception as e:
                    st.error(f"Device discovery failed: {e}")
                    scanned = []
                st.session_state.real_scan_devices = profile_all_devices(
                    convert_scan_to_internal_devices(scanned)
                )
                st.session_state.devices = st.session_state.real_scan_devices
                if st.session_state.get("shield_db") and st.session_state.devices:
                    st.session_state.shield_db.save_devices(st.session_state.devices)
                st.success(f"Discovered {len(scanned)} active device(s) on {subnet}!")

        if auto_scan_refresh:
            time.sleep(15)
            st.rerun()

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("🔄 Reset Devices"):
            if device_source == "🟢 Real Scan Devices (Nmap)":
                try:
                    scanned = discover_devices(subnet=subnet)
                except Exception as e:
                    st.error(f"Device discovery failed: {e}")
                    scanned = []
                st.session_state.devices = profile_all_devices(
                    convert_scan_to_internal_devices(scanned)
                )
                st.success("✅ Reset done (Real Scan)")
            else:
                st.session_state.devices = profile_all_devices(discover_devices_demo())
                st.success("✅ Reset done (Demo Mode)")

            st.session_state.devices_tick = 0
            st.rerun()

    with col2:
        if device_source == "🔵 Demo Devices (Simulated)":
            st.write("✅ Demo mode simulates device changes (ports/firmware).")
        else:
            st.write("✅ Real Scan mode shows real devices in your network.")

    with col3:
        st.caption(f"Tick: **{st.session_state.devices_tick}**")

    # ✅ Auto mutation ONLY in demo mode
    if device_source == "🔵 Demo Devices (Simulated)" and auto_refresh:
        time.sleep(refresh_seconds)
        st.session_state.devices_tick += 1
        st.session_state.devices = mutate_devices(st.session_state.devices)
        st.session_state.devices = profile_all_devices(st.session_state.devices)
        
        # Update baselines and detect anomalies
        baseline_agent = st.session_state.get("baseline_agent")
        if baseline_agent:
            try:
                baseline_agent.update_device_baseline(st.session_state.devices)
                anomalies = baseline_agent.detect_device_anomalies(st.session_state.devices)
                
                # Store anomalies for display
                if "device_anomalies" not in st.session_state:
                    st.session_state.device_anomalies = []
                st.session_state.device_anomalies = anomalies[-10:]  # Keep last 10
                
                # Add anomalies to timeline and update score
                for anomaly in anomalies:
                    _push_timeline_event(
                        "ANOMALY",
                        label=anomaly["anomaly_type"],
                        target=anomaly["target"],
                        details=f"{anomaly['details']} | Severity: {anomaly['severity']}"
                    )
                    # Reduce score for HIGH severity anomalies
                    if anomaly["severity"] == "HIGH":
                        _update_score_metric(-3)
            except Exception as e:
                pass  # Silent fail to avoid crashes
        
        st.rerun()

    devices = st.session_state.devices
    df = pd.DataFrame(devices)

    if df.empty:
        st.info("No devices found.")
    else:
        if "_mutations" not in df.columns:
            df["_mutations"] = 0
        if "_last_change" not in df.columns:
            df["_last_change"] = ""

        df["open_ports"] = df["open_ports"].apply(
            lambda x: ", ".join(map(str, x)) if isinstance(x, list) else str(x)
        )

        tag_map = {
            "LOW": "🟢 LOW",
            "MEDIUM": "🟡 MEDIUM",
            "HIGH": "🟠 HIGH",
            "CRITICAL": "🔴 CRITICAL",
        }
        df["risk_tag"] = df["risk_level"].map(tag_map).fillna(df["risk_level"])

        highest = df.sort_values("risk_score", ascending=False).iloc[0]
        st.warning(
            f"🚨 Highest Risk Device: **{highest['device_name']}** ({highest['ip']}) "
            f"→ **{highest['risk_level']}** (Score: {highest['risk_score']})"
        )

        if st.button("🛠 Auto Secure Highest Risk Device"):
            target_device_name = highest["device_name"]
            st.session_state.devices = auto_patch_device(st.session_state.devices, target_device_name)
            st.session_state.devices = profile_all_devices(st.session_state.devices)
            st.success(f"✅ Auto-secured: {target_device_name}")
            log_alert(f"Auto-secured device: {target_device_name}", severity="INFO")
            st.session_state.security_events.append({"ts": time.time(), "type": "AUTO_SECURE", "target": target_device_name})
            _push_timeline_event("AUTO_SECURE", label="", target=target_device_name, details="Device hardened")
            st.rerun()

        changed = df[df["_last_change"] != ""] if not df.empty else pd.DataFrame()
        if not changed.empty:
            last = changed.iloc[-1]
            st.info(
                f"🔁 Latest Change: **{last['device_name']}** → {last['_last_change']} "
                f"| mutations={last['_mutations']}"
            )

        display_cols = [
            "device_name", "ip", "mac", "vendor", "open_ports",
            "firmware_status", "risk_level", "risk_tag", "risk_score",
            "_mutations", "_last_change"
        ]
        display_df = df.copy()
        for c in display_cols:
            if c not in display_df.columns:
                display_df[c] = ""

        st.dataframe(display_df[display_cols], use_container_width=True)

        st.divider()
        st.markdown("### ⚡ Port Scan (Real Scan Mode Only)")

        if device_source == "🟢 Real Scan Devices (Nmap)":
            ip_list = display_df["ip"].tolist()
            target_ip = st.selectbox("Select IP to scan ports", ip_list)

            if st.button("🧪 Scan Top-50 Ports (Safe)"):
                try:
                    ports_result = scan_ports(target_ip)
                except Exception as e:
                    st.error(f"Port scan failed: {e}")
                    ports_result = []
                open_ports = [p["port"] for p in ports_result]

                for d in st.session_state.devices:
                    if d.get("ip") == target_ip:
                        d["open_ports"] = open_ports
                        d["_last_change"] = f"Ports scanned: {open_ports}"
                        break

                st.session_state.devices = profile_all_devices(st.session_state.devices)

                st.success(f"✅ Port scan complete for {target_ip}")
                st.dataframe(pd.DataFrame(ports_result), use_container_width=True)
                st.rerun()
        else:
            st.info("Port scan is disabled in Demo Mode ✅")

    st.subheader("✅ Quarantined Devices")
    st.write(st.session_state.quarantined_devices if st.session_state.quarantined_devices else "None")

    st.subheader("⛔ Blocked IPs")
    st.write(st.session_state.blocked_ips if st.session_state.blocked_ips else "None")

    # Baseline Anomalies Section
    st.subheader("📌 Baseline Anomalies")
    anomalies = st.session_state.get("device_anomalies", [])
    if anomalies:
        for anomaly in anomalies:
            severity_color = "🔴" if anomaly["severity"] == "HIGH" else "🟡"
            st.markdown(f"{severity_color} **{anomaly['anomaly_type']}** - {anomaly['device_name']} ({anomaly['target']})")
            st.caption(anomaly['details'])
            st.caption(f"Recommended: {', '.join(anomaly['recommended_action'])}")
            st.divider()
    else:
        st.info("No baseline anomalies detected")


# =========================
# PAGE 2: THREAT MONITOR
# =========================
if page == "⚡ Threat Monitor":
    st.subheader("⚡ Live Threat Monitor (Replay CICIoT flows)")

    st.sidebar.checkbox("🔔 Alert sound", value=bool(st.session_state.get("alert_sound", True)), key="alert_sound")

    alert_popup = st.empty()

    # Create a placeholder for dynamic timeline updates
    timeline_placeholder = st.empty()
    
    with timeline_placeholder.container():
        with st.expander("🧭 SOC Timeline", expanded=False):
            tl = st.session_state.get("soc_timeline", []) or []
            if tl:
                st.dataframe(pd.DataFrame(tl[-30:][::-1]), use_container_width=True)
            else:
                st.write("No timeline events yet.")
    
    # Function to update timeline dynamically
    def _update_timeline():
        with timeline_placeholder.container():
            with st.expander("🧭 SOC Timeline", expanded=False):
                tl = st.session_state.get("soc_timeline", []) or []
                if tl:
                    st.dataframe(pd.DataFrame(tl[-30:][::-1]), use_container_width=True)
                else:
                    st.write("No timeline events yet.")

    with st.expander("🧾 Explain Why Attack (XAI)", expanded=False):
        xai = st.session_state.get("last_attack_xai", {}) or {}
        if xai:
            st.write("Last alert:", xai.get("time"))
            st.write("Session label:", xai.get("session_label"))
            st.write("Session prob:", xai.get("session_prob"))
            rs = xai.get("reasons", []) or []
            if rs:
                for r in rs:
                    st.write("-", r)
        else:
            st.write("No active attack explanation.")

    colA, colB = st.columns(2)
    with colA:
        if st.button("▶ Start Monitoring"):
            st.session_state.monitoring = True
            st.session_state.last_attack_popup_ts = 0.0
    with colB:
        if st.button("⏹ Stop Monitoring"):
            st.session_state.monitoring = False
            st.warning("Stopped.")

    # Network Anomalies Section
    st.subheader("🌐 Network Anomalies")
    network_anomalies = st.session_state.get("network_anomalies", [])
    if network_anomalies:
        for anomaly in network_anomalies:
            severity_color = "🔴" if anomaly["severity"] == "HIGH" else "🟡"
            st.markdown(f"{severity_color} **{anomaly['anomaly_type']}**")
            st.caption(anomaly['details'])
            st.caption(f"Recommended: {', '.join(anomaly['recommended_action'])}")
            st.divider()
    else:
        st.info("No network anomalies detected")

    # Device Flow Tracking Section
    st.subheader("📊 Device Flow Tracking")
    with st.expander("Track Network Flows from Devices", expanded=False):
        devices_list = st.session_state.get("devices", [])
        
        if devices_list:
            st.info("Monitor network flows from discovered devices in real-time")
            
            col1, col2 = st.columns(2)
            with col1:
                track_device = st.selectbox(
                    "Select device to track flows",
                    options=[f"{d.get('device_name')} ({d.get('ip')})" for d in devices_list]
                )
            
            with col2:
                track_duration = st.slider("Capture duration (seconds)", 5, 60, 30)
            
            if st.button("🔍 Capture Device Flows"):
                try:
                    tracker = NetworkFlowTracker(capture_duration=track_duration)
                    
                    # Extract selected device IP
                    device_ip = track_device.split("(")[-1].rstrip(")")
                    device_name = track_device.split(" (")[0]
                    
                    with st.spinner(f"Capturing flows from {device_name}..."):
                        flow_info = tracker.track_flows_from_device(device_ip, device_name, track_duration)
                    
                    st.session_state.device_flows = flow_info
                    
                    # Display flow statistics
                    st.success(f"✓ Captured {flow_info['total_flows']} flows")
                    
                    col1, col2, col3, col4 = st.columns(4)
                    col1.metric("Total Flows", flow_info['total_flows'])
                    col2.metric("Outbound", len(flow_info['outbound_flows']))
                    col3.metric("Inbound", len(flow_info['inbound_flows']))
                    col4.metric("Suspicious", len(flow_info['suspicious_flows']))
                    
                    # Protocol distribution
                    if flow_info['protocol_stats']:
                        st.markdown("**Protocol Distribution:**")
                        proto_df = pd.DataFrame(
                            list(flow_info['protocol_stats'].items()),
                            columns=["Protocol", "Count"]
                        ).sort_values("Count", ascending=False)
                        st.bar_chart(proto_df.set_index("Protocol"))
                    
                    # Port distribution
                    if flow_info['port_stats']:
                        st.markdown("**Top Ports:**")
                        port_df = pd.DataFrame(
                            sorted(flow_info['port_stats'].items(), key=lambda x: x[1], reverse=True)[:10],
                            columns=["Port", "Count"]
                        )
                        st.bar_chart(port_df.set_index("Port"))
                    
                    # Suspicious flows
                    if flow_info['suspicious_flows']:
                        st.warning(f"⚠️ {len(flow_info['suspicious_flows'])} Suspicious Flows Detected")
                        susp_df = pd.DataFrame([
                            {
                                "Flow": f"{s['flow']['local']} → {s['flow']['remote']}",
                                "Reason": s['reason'],
                                "Severity": s['severity']
                            }
                            for s in flow_info['suspicious_flows'][:10]
                        ])
                        st.dataframe(susp_df, use_container_width=True)
                
                except Exception as e:
                    st.error(f"Flow capture failed: {e}")
            
            # Display last captured flows if available
            if "device_flows" in st.session_state and st.session_state.device_flows:
                flows = st.session_state.device_flows
                st.markdown("**Last Captured Flows:**")
                
                if flows.get('outbound_flows'):
                    with st.expander(f"Outbound Flows ({len(flows['outbound_flows'])})", expanded=False):
                        outbound_df = pd.DataFrame(flows['outbound_flows'][:20])
                        if not outbound_df.empty:
                            st.dataframe(outbound_df[['local', 'remote', 'state']], use_container_width=True)
                
                if flows.get('inbound_flows'):
                    with st.expander(f"Inbound Flows ({len(flows['inbound_flows'])})", expanded=False):
                        inbound_df = pd.DataFrame(flows['inbound_flows'][:20])
                        if not inbound_df.empty:
                            st.dataframe(inbound_df[['local', 'remote', 'state']], use_container_width=True)
        else:
            st.info("No devices available. Discover devices first on the 📡 Devices & Risk page.")

    # ==========================================
    # ATTACK DEMO (REAL-TIME) SECTION
    # ==========================================
    with st.expander("⚡ Attack Demo (Real-Time - Same PC)", expanded=False):
        st.markdown("""
        **Generate attack-like traffic on the same machine for demo/testing.**
        
        - *Honeypot Burst*: Rapid connections to honeypot (default: 127.0.0.1:9999)
        - *Port Scan Burst*: Connection attempts to multiple ports
        - *HTTP Burst*: Multiple HTTP requests
        
        ⚠️ **Note**: Honeypot must be running on target host/port
        """)
        
        col_host, col_port = st.columns(2)
        with col_host:
            default_host = get_local_ip()
            attack_target_host = st.text_input("Target Host", value=default_host, help="Local IP or 127.0.0.1")
        with col_port:
            attack_honeypot_port = st.number_input("Honeypot Port", value=9999, min_value=1, max_value=65535)
        
        col_count, col_delay = st.columns(2)
        with col_count:
            attack_count = st.slider("Connection Count (max 200)", min_value=5, max_value=200, value=30)
        with col_delay:
            attack_delay_ms = st.slider("Delay Between Attempts (ms)", min_value=5, max_value=500, value=20)
        
        col_btn1, col_btn2, col_btn3 = st.columns(3)
        
        # Honeypot Burst
        with col_btn1:
            if st.button("🎯 Trigger Honeypot Burst", key="btn_honeypot_burst"):
                with st.spinner("🔄 Honeypot burst in progress..."):
                    result = demo_honeypot_burst(
                        host=attack_target_host,
                        port=attack_honeypot_port,
                        count=attack_count,
                        delay_ms=attack_delay_ms
                    )
                
                if result.get("ok"):
                    st.success(f"✅ {result['message']}")
                    stats = result.get("stats", {})
                    col_s1, col_s2, col_s3 = st.columns(3)
                    col_s1.metric("Successful Hits", stats.get("successful", 0))
                    col_s2.metric("Failed", stats.get("failed", 0))
                    col_s3.metric("Avg Latency", f"{stats.get('avg_latency_ms', 0):.1f} ms")
                    
                    # Log to SOC Timeline
                    _push_timeline_event(
                        "ATTACK_DEMO_TRIGGERED",
                        label="HONEYPOT_BURST",
                        target=f"{attack_target_host}:{attack_honeypot_port}",
                        details=f"Hits: {stats.get('successful', 0)}, Duration: {stats.get('duration_seconds', 0):.2f}s"
                    )
                    _update_timeline()  # Refresh timeline display
                else:
                    st.warning(f"⚠️ {result['message']}")
                    if result.get("error"):
                        st.caption(f"Error: {result['error']}")
        
        # Port Scan Burst
        with col_btn2:
            if st.button("🔍 Trigger Port Scan Burst", key="btn_port_scan_burst"):
                with st.spinner("🔄 Port scan in progress..."):
                    result = demo_port_scan_burst(
                        host=attack_target_host,
                        ports=[21, 22, 23, 80, 443, 9999, 3389, 5900],
                        delay_ms=attack_delay_ms
                    )
                
                if result.get("ok"):
                    st.success(f"✅ {result['message']}")
                    stats = result.get("stats", {})
                    col_s1, col_s2 = st.columns(2)
                    col_s1.metric("Open Ports", len(stats.get("open_ports", [])))
                    col_s2.metric("Closed Ports", len(stats.get("closed_ports", [])))
                    if stats.get("open_ports"):
                        st.caption(f"📍 Open: {', '.join(map(str, stats['open_ports']))}")
                    
                    # Log to SOC Timeline
                    _push_timeline_event(
                        "ATTACK_DEMO_TRIGGERED",
                        label="PORT_SCAN_BURST",
                        target=attack_target_host,
                        details=f"Open: {stats.get('open_ports', [])}, Duration: {stats.get('duration_seconds', 0):.2f}s"
                    )
                    _update_timeline()  # Refresh timeline display
                else:
                    st.warning(f"⚠️ {result['message']}")
        
        # HTTP Burst
        with col_btn3:
            if st.button("🌐 Trigger HTTP Burst", key="btn_http_burst"):
                with st.spinner("🔄 HTTP burst in progress..."):
                    result = demo_http_burst(
                        url="http://example.com",
                        count=attack_count,
                        delay_ms=attack_delay_ms
                    )
                
                if result.get("ok"):
                    st.success(f"✅ {result['message']}")
                    stats = result.get("stats", {})
                    col_s1, col_s2 = st.columns(2)
                    col_s1.metric("Successful Requests", stats.get("successful", 0))
                    col_s2.metric("Failed", stats.get("failed", 0))
                    
                    # Log to SOC Timeline
                    _push_timeline_event(
                        "ATTACK_DEMO_TRIGGERED",
                        label="HTTP_BURST",
                        target="http://example.com",
                        details=f"Requests: {stats.get('successful', 0)}, Duration: {stats.get('duration_seconds', 0):.2f}s"
                    )
                    _update_timeline()  # Refresh timeline display
                else:
                    st.warning(f"⚠️ {result['message']}")
    
    # ==========================================
    
    force_attack_demo = st.checkbox("🎭 Force attack demo (inject periodic attacks)", value=False)

    flows_df = load_demo_flows()
    LABEL_COL = "label"

    if LABEL_COL not in flows_df.columns:
        st.error("❌ sample_flows.csv must contain 'label' column")
        st.stop()

    X_df = flows_df.drop(columns=[LABEL_COL])

    @st.cache_resource
    def load_agents(window_seconds):
        perception = PerceptionAgent()
        session_agent = SessionAggregationAgent(window_seconds=window_seconds)
        return perception, session_agent

    perception, session_agent = load_agents(window_seconds)

    m1, m2, m3, m4 = st.columns(4)
    metric_flow_prob = m1.empty()
    metric_flow_label = m2.empty()
    metric_session_prob = m3.empty()
    metric_session_label = m4.empty()

    st.divider()
    feed = st.empty()

    if st.session_state.monitoring:
        st.success("✅ Monitoring started")
        logs = []

        for i in range(len(X_df)):
            flow = X_df.iloc[i].to_dict()
            try:
                gt_label = str(flows_df.iloc[i][LABEL_COL])
            except Exception:
                gt_label = "BenignTraffic"

            if force_attack_demo:
                burst_len = max(5, int(speed * window_seconds) + 1)
                cycle = burst_len * 3
                in_burst = (i % cycle) < burst_len
                gt_label = "PortScan" if in_burst else "BenignTraffic"

            flow["label"] = gt_label

            flow_pred = perception.predict_flow(flow)
            session_pred = session_agent.update(flow_pred["attack_prob"], flow_pred["label"])

            # Update network baseline and detect anomalies
            baseline_agent = st.session_state.get("baseline_agent")
            if baseline_agent:
                try:
                    # Prepare flow info for baseline
                    flow_info = {
                        "flow_rate": 1.0 / speed if speed > 0 else 1.0,  # flows per second
                        "avg_prob": flow_pred["attack_prob"]
                    }
                    
                    # Update baseline
                    baseline_agent.update_network_baseline(flow_info, session_pred)
                    
                    # Detect network anomalies
                    network_anomalies = baseline_agent.detect_network_anomalies(flow_info, session_pred)
                    
                    # Store and display network anomalies
                    if network_anomalies:
                        if "network_anomalies" not in st.session_state:
                            st.session_state.network_anomalies = []
                        st.session_state.network_anomalies = network_anomalies[-5:]  # Keep last 5
                        
                        # Add to timeline
                        for anomaly in network_anomalies:
                            _push_timeline_event(
                                "ANOMALY",
                                label=anomaly["anomaly_type"],
                                target=anomaly["target"],
                                details=f"{anomaly['details']} | Severity: {anomaly['severity']}"
                            )
                            # Reduce score for HIGH severity anomalies
                            if anomaly["severity"] == "HIGH":
                                _update_score_metric(-3)
                except Exception:
                    pass  # Silent fail to avoid crashes

            attack_now = _is_attack_label(session_pred.get("session_label"))
            if attack_now:
                st.session_state.last_attack_time = time.time()
                reasons = _xai_reasons(flow, flow_pred, session_pred)
                st.session_state.last_attack_xai = {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time())),
                    "session_label": session_pred.get("session_label"),
                    "session_prob": session_pred.get("session_prob"),
                    "reasons": reasons,
                }

                msg = f"🚨 ATTACK DETECTED: {session_pred.get('session_label')} | prob={session_pred.get('session_prob')}"
                alert_popup.error(msg)

                do_alert = (time.time() - float(st.session_state.get("last_attack_popup_ts", 0) or 0)) > 3
                if do_alert:
                    st.session_state.last_attack_popup_ts = time.time()
                    _push_timeline_event("ATTACK", label=session_pred.get("session_label"), target="", details="; ".join(reasons))
                    try:
                        log_alert(
                            f"ATTACK DETECTED: session_label={session_pred.get('session_label')} prob={session_pred.get('session_prob')} reasons={'; '.join(reasons)}",
                            severity="CRITICAL",
                        )
                    except Exception:
                        pass

                    try:
                        if hasattr(st, "toast"):
                            st.toast(msg, icon="🚨")
                    except Exception:
                        pass

                    if st.session_state.get("alert_sound", True):
                        beeped = False
                        try:
                            import winsound

                            winsound.Beep(880, 200)
                            beeped = True
                        except Exception:
                            beeped = False

                        if not beeped:
                            components.html(
                                """
                                <script>
                                try {
                                  const AudioContext = window.AudioContext || window.webkitAudioContext;
                                  const ctx = new AudioContext();
                                  const o = ctx.createOscillator();
                                  const g = ctx.createGain();
                                  o.type = 'sine';
                                  o.frequency.value = 880;
                                  g.gain.setValueAtTime(0.0001, ctx.currentTime);
                                  g.gain.exponentialRampToValueAtTime(0.2, ctx.currentTime + 0.02);
                                  g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.18);
                                  o.connect(g);
                                  g.connect(ctx.destination);
                                  o.start();
                                  o.stop(ctx.currentTime + 0.2);
                                } catch(e) {}
                                </script>
                                """,
                                height=0,
                            )

                    _update_score_metric()
            else:
                alert_popup.empty()

            try:
                with open("logs/honeypot.log", "r") as hf:
                    hf.seek(st.session_state.honeypot_pos)
                    new_lines = hf.readlines()
                    st.session_state.honeypot_pos = hf.tell()
                    for ln in new_lines:
                        m = re.search(r"attacker_ip=([0-9\.]+)", ln)
                        if m:
                            attacker_ip = m.group(1)
                            ev = {"time": ln.split("]")[0].strip("["), "attacker_ip": attacker_ip, "raw": ln}
                            st.session_state.honeypot_events.append(ev)
                            if not safe_mode_active:
                                st.session_state.blocked_ips = block_attacker_ip(attacker_ip, st.session_state.blocked_ips)
                                fw = safe_block_ip(attacker_ip, reason="honeypot_hit")
                                if fw.get("ok"):
                                    st.success(f"🧱 Firewall blocked: {attacker_ip}")
                                else:
                                    st.warning(
                                        f"Firewall block failed for {attacker_ip}: {fw.get('message')} | {fw.get('error') or ''}"
                                    )

                                st.session_state.security_events.append({"ts": time.time(), "type": "BLOCK_IP", "target": attacker_ip})
                                _push_timeline_event(
                                    "BLOCK_IP",
                                    label="",
                                    target=attacker_ip,
                                    details=f"honeypot_hit ok={fw.get('ok')} msg={fw.get('message')}",
                                )
                                log_alert(f"Auto-blocked from honeypot: {attacker_ip}", severity="CRITICAL")
                                _update_score_metric()
                            else:
                                entry = {"time": time.time(), "type": "BLOCK_IP", "target": attacker_ip, "reason": "Safe Mode"}
                                st.session_state.suppressed_actions.append(entry)
                                log_alert(f"Suppressed auto-block for {attacker_ip} due to Safe Mode", severity="WARN")
            except Exception:
                pass

            target_device = None
            devices_list = st.session_state.devices
            if devices_list:
                if random.random() < 0.5:
                    target_device = sorted(devices_list, key=lambda d: d.get("risk_score", 0), reverse=True)[0]
                else:
                    vulnerable = [d for d in devices_list if any(p in RISKY_PORTS for p in d.get("open_ports", []))]
                    if vulnerable:
                        target_device = random.choice(vulnerable)
                    else:
                        target_device = sorted(devices_list, key=lambda d: d.get("risk_score", 0), reverse=True)[0]

            if target_device:
                metric_session_label.write(f"Target Device: {target_device.get('device_name')} ({target_device.get('ip')})")

            metric_flow_prob.metric("Flow Attack Prob", round(flow_pred["attack_prob"], 4))
            metric_flow_label.metric("Flow Label", flow_pred["label"])
            metric_session_prob.metric("Session Prob", session_pred["session_prob"])
            metric_session_label.metric("Session Label", session_pred["session_label"])

            if not safe_mode_active:
                st.session_state.quarantined_devices, st.session_state.blocked_ips = agentic_response(
                    session_prob=session_pred["session_prob"],
                    session_label=session_pred["session_label"],
                    devices=st.session_state.devices,
                    quarantine_list=st.session_state.quarantined_devices,
                    blocked_list=st.session_state.blocked_ips,
                )
            else:
                entry = {"time": time.time(), "type": "AGENTIC_RESPONSE", "target": session_pred.get("session_label"), "reason": "Safe Mode"}
                st.session_state.suppressed_actions.append(entry)
                log_alert(
                    f"Suppressed agentic_response due to Safe Mode. session_label={session_pred.get('session_label')} prob={session_pred.get('session_prob')}",
                    severity="WARN",
                )

            try:
                actions = decide_actions(
                    session_prob=session_pred["session_prob"],
                    session_label=session_pred["session_label"],
                    devices=st.session_state.devices,
                    honeypot_events=st.session_state.honeypot_events,
                    autonomous=autonomous_mode,
                )
            except Exception:
                actions = []

            for act in actions:
                t = act.get("type")
                if t == "QUARANTINE" and act.get("device_ip"):
                    if not safe_mode_active:
                        st.session_state.quarantined_devices = quarantine_device(act.get("device_ip"), st.session_state.quarantined_devices)
                        st.session_state.security_events.append({"ts": time.time(), "type": "QUARANTINE", "target": act.get("device_ip")})
                        _push_timeline_event("QUARANTINE", label="", target=act.get("device_ip"), details="Orchestrator")
                        log_alert(f"Orchestrator quarantined {act.get('device_ip')}", severity="HIGH")
                        _update_score_metric()
                    else:
                        entry = {"time": time.time(), "type": "QUARANTINE", "target": act.get("device_ip"), "reason": "Safe Mode"}
                        st.session_state.suppressed_actions.append(entry)
                        log_alert(f"Suppressed orchestrator QUARANTINE for {act.get('device_ip')} due to Safe Mode", severity="WARN")
                elif t == "BLOCK_IP" and act.get("ip"):
                    if not safe_mode_active:
                        st.session_state.blocked_ips = block_attacker_ip(act.get("ip"), st.session_state.blocked_ips)
                        fw = safe_block_ip(act.get("ip"), reason="orchestrator_block")
                        if fw.get("ok"):
                            st.success(f"🧱 Firewall blocked: {act.get('ip')}")
                        else:
                            st.warning(
                                f"Firewall block failed for {act.get('ip')}: {fw.get('message')} | {fw.get('error') or ''}"
                            )

                        st.session_state.security_events.append({"ts": time.time(), "type": "BLOCK_IP", "target": act.get("ip")})
                        _push_timeline_event(
                            "BLOCK_IP",
                            label="",
                            target=act.get("ip"),
                            details=f"orchestrator ok={fw.get('ok')} msg={fw.get('message')}",
                        )
                        log_alert(f"Orchestrator blocked IP {act.get('ip')}", severity="CRITICAL")
                        _update_score_metric()
                    else:
                        entry = {"time": time.time(), "type": "BLOCK_IP", "target": act.get("ip"), "reason": "Safe Mode"}
                        st.session_state.suppressed_actions.append(entry)
                        log_alert(f"Suppressed orchestrator BLOCK_IP for {act.get('ip')} due to Safe Mode", severity="WARN")
                elif t == "ALERT":
                    sev = act.get("severity", "INFO")
                    msg = act.get("message", "Orchestrator alert")
                    log_alert(msg, severity=sev)

            if session_pred.get("session_prob", 0) > 0.9:
                st.session_state.last_attack_time = time.time()

            logs.append({
                "Flow_Label": flow_pred["label"],
                "Flow_Prob": round(flow_pred["attack_prob"], 4),
                "Session_Label": session_pred["session_label"],
                "Session_Prob": session_pred["session_prob"],
                "Persistence": session_pred.get("persistence", 0),
            })

            # Update time-indexed NetworkStateAgent & AttackForecastingAgent (Architecture Sections 5 & 19)
            net_agent = st.session_state.get("network_state_agent")
            if net_agent:
                try:
                    recent_attacks = sum(1 for l in logs[-20:] if _is_attack_label(l.get("Flow_Label")))
                    current_score = _compute_home_shield_score()
                    net_agent.update_state(
                        active_flows=len(logs),
                        attack_flows=recent_attacks,
                        benign_flows=max(0, len(logs) - recent_attacks),
                        avg_attack_prob=float(flow_pred["attack_prob"]),
                        max_attack_prob=float(max([l.get("Flow_Prob", 0) for l in logs[-20:]] or [flow_pred["attack_prob"]])),
                        session_label=str(session_pred["session_label"]),
                        session_prob=float(session_pred["session_prob"]),
                        session_persistence=int(session_pred.get("persistence", 0)),
                        device_count=len(st.session_state.get("devices", [])),
                        max_device_risk=max([d.get("risk_score", 0) for d in st.session_state.get("devices", [])] or [0]),
                        device_anomalies=len(st.session_state.get("device_anomalies", [])),
                        network_anomalies=len(st.session_state.get("network_anomalies", [])),
                        honeypot_hits=len(st.session_state.get("honeypot_events", [])),
                        blocked_ips=len(st.session_state.get("blocked_ips", [])),
                        quarantined_devices=len(st.session_state.get("quarantined_devices", [])),
                        home_shield_score=current_score,
                    )
                    forecaster = st.session_state.get("attack_forecasting_agent")
                    if forecaster:
                        st.session_state.last_forecast = forecaster.forecast(network_state_agent=net_agent)
                    if st.session_state.get("shield_db"):
                        st.session_state.shield_db.save_score(current_score)
                except Exception:
                    pass

            feed.dataframe(pd.DataFrame(logs[-15:]), use_container_width=True)
            time.sleep(1 / speed)

            if not st.session_state.monitoring:
                break
    else:
        st.info("Click ▶ Start Monitoring to begin demo replay.")


# =========================
# PAGE 3: ATTACK FORECASTING (Architecture Section 5 & 10)
# =========================
if page == "🔮 Attack Forecasting":
    st.subheader("🔮 Predictive Intelligence & Attack Progression Forecasting")
    st.caption("Architecture Ref: Section 5 & 10 — Time-Indexed State Sequences, ATT&CK Mapping & Horizon Projections")

    forecaster = st.session_state.get("attack_forecasting_agent")
    net_state = st.session_state.get("network_state_agent")

    forecast = st.session_state.get("last_forecast", {})
    if not forecast and forecaster and net_state:
        forecast = forecaster.forecast(network_state_agent=net_state)
        st.session_state.last_forecast = forecast

    pred_stage = forecast.get("predicted_stage", "BENIGN_NORMAL")
    pred_prob = forecast.get("probability", 0.0)
    conf = forecast.get("confidence", 0.0)
    uncertainty = forecast.get("uncertainty", 0.0)
    future_level = forecast.get("future_threat_level", "LOW")
    mitre_tech = forecast.get("mitre_technique", "None (Baseline)")
    posture = forecast.get("recommended_posture", "STANDARD_BASELINE")

    k1, k2, k3, k4 = st.columns(4)
    level_color = "🔴" if future_level == "CRITICAL" else "🟠" if future_level == "HIGH" else "🟡" if future_level == "MEDIUM" else "🟢"
    k1.metric("Predicted Threat Level", f"{level_color} {future_level}")
    k2.metric("Predicted ATT&CK Stage", pred_stage.replace("_", " "))
    k3.metric("Progression Confidence", f"{conf * 100:.1f}%", delta=f"Uncertainty: {uncertainty * 100:.1f}%", delta_color="inverse")
    k4.metric("Forecast Horizon", forecast.get("horizon", "30s"))

    st.markdown("---")

    st.markdown("### 🗺️ Threat Progression Trajectory (MITRE ATT&CK Stages)")
    stages = ["BENIGN_NORMAL", "RECONNAISSANCE", "INITIAL_ACCESS", "LATERAL_MOVEMENT", "DENIAL_OF_SERVICE", "DATA_EXFILTRATION"]
    stage_cols = st.columns(len(stages))
    for idx, (col, s_name) in enumerate(zip(stage_cols, stages)):
        is_current = (s_name == pred_stage)
        badge_border = "2px solid #ef4444" if (is_current and s_name != "BENIGN_NORMAL") else "2px solid #10b981" if is_current else "1px solid #334155"
        badge_bg = "rgba(239, 68, 68, 0.15)" if (is_current and s_name != "BENIGN_NORMAL") else "rgba(16, 185, 129, 0.15)" if is_current else "rgba(30, 41, 59, 0.5)"
        status_marker = "📍 ACTIVE" if is_current else f"Stage {idx+1}"
        
        with col:
            st.markdown(
                f"""
                <div style="border: {badge_border}; background: {badge_bg}; border-radius: 8px; padding: 10px; text-align: center; margin-bottom: 8px;">
                    <div style="font-size: 0.75rem; color: #94a3b8;">{status_marker}</div>
                    <div style="font-weight: 600; font-size: 0.85rem; margin-top: 4px;">{s_name.replace('_', ' ')}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

    st.caption(f"**Current Mapping:** `{mitre_tech}` | **Recommended Posture:** `{posture}`")

    st.markdown("---")

    c_left, c_right = st.columns([3, 2])

    with c_left:
        st.markdown("### 📊 Softmax Stage Probability Distribution")
        probs = forecast.get("stage_probabilities", {})
        if probs:
            prob_df = pd.DataFrame([
                {"ATT&CK Stage": k.replace("_", " "), "Probability (%)": round(v * 100, 2)}
                for k, v in probs.items()
            ]).set_index("ATT&CK Stage")
            st.bar_chart(prob_df, use_container_width=True)
        else:
            st.info("No probability distribution available yet.")

    with c_right:
        st.markdown("### ⏱️ Multi-Horizon Forecasts")
        horizons_data = forecast.get("horizons", {})
        if horizons_data:
            hz_rows = []
            for h_label, h_info in horizons_data.items():
                hz_rows.append({
                    "Horizon": h_label,
                    "Projected Stage": h_info.get("stage", pred_stage),
                    "Attack Prob": f"{h_info.get('projected_prob', 0) * 100:.1f}%",
                })
            st.dataframe(pd.DataFrame(hz_rows), use_container_width=True)
        else:
            st.write("Horizon forecasts generating...")

        st.markdown("### 🛡️ Recommended Preventive Posture")
        if future_level in ["CRITICAL", "HIGH"]:
            st.error(f"⚠️ **Action Required:** {posture}\n\n*Forecasting model advises preemptive rate-limiting or asset isolation to prevent progression to {pred_stage}.*")
        else:
            st.success(f"✅ **Normal Posture:** {posture}\n\n*No imminent attack progression detected. Continual passive telemetry ingestion active.*")

    st.markdown("---")

    col_ev, col_hist = st.columns(2)

    with col_ev:
        st.markdown("### 🧾 Forecast Evidence & Indicators")
        ev_list = forecast.get("evidence", [])
        if ev_list:
            for ev in ev_list:
                st.markdown(f"- 🔎 **{ev}**")
        else:
            st.write("No anomaly indicators currently active.")

    with col_hist:
        st.markdown("### 📈 Time-Series State Trajectory")
        if net_state:
            history = net_state.get_state_history(limit=20)
            if history:
                hist_df = pd.DataFrame([
                    {
                        "Time": h.get("time_str", ""),
                        "Attack Prob": h.get("avg_attack_prob", 0.0),
                        "Attack Ratio": h.get("attack_ratio", 0.0),
                        "Shield Score": h.get("home_shield_score", 75) / 100.0,
                    }
                    for h in history
                ]).set_index("Time")
                st.line_chart(hist_df, use_container_width=True)
            else:
                st.info("Run threat monitoring or trigger an attack demo to build temporal state history.")
        else:
            st.info("Network state history accumulating...")

    st.markdown("---")
    with st.expander("🧪 Interactive Forecast Simulation (Demo Scenarios)", expanded=False):
        st.markdown("Test how the forecasting engine dynamically projects attack progression stages based on simulated input signals:")
        sc1, sc2, sc3 = st.columns(3)
        if sc1.button("🎯 Scenario: Port Scan Reconnaissance"):
            if forecaster and net_state:
                sim_state = {
                    "attack_ratio": 0.15,
                    "avg_attack_prob": 0.45,
                    "session_prob": 0.60,
                    "session_label": "PortScan",
                    "network_anomalies": 3,
                    "device_anomalies": 0,
                    "honeypot_hits": 0,
                    "threat_level": "MEDIUM",
                }
                st.session_state.last_forecast = forecaster.forecast(current_state=sim_state)
                st.rerun()

        if sc2.button("💥 Scenario: DDoS Flood Progression"):
            if forecaster and net_state:
                sim_state = {
                    "attack_ratio": 0.85,
                    "avg_attack_prob": 0.95,
                    "session_prob": 0.98,
                    "session_label": "DDoS_UDP_Flood",
                    "network_anomalies": 5,
                    "device_anomalies": 2,
                    "honeypot_hits": 1,
                    "threat_level": "CRITICAL",
                }
                st.session_state.last_forecast = forecaster.forecast(current_state=sim_state)
                st.rerun()

        if sc3.button("🍯 Scenario: Honeytoken Lateral Movement"):
            if forecaster and net_state:
                sim_state = {
                    "attack_ratio": 0.20,
                    "avg_attack_prob": 0.55,
                    "session_prob": 0.70,
                    "session_label": "Mirai_Lateral",
                    "network_anomalies": 1,
                    "device_anomalies": 1,
                    "honeypot_hits": 2,
                    "honeytoken_trips": 1,
                    "threat_level": "HIGH",
                }
                st.session_state.last_forecast = forecaster.forecast(current_state=sim_state)
                st.rerun()


# =========================
# PAGE 4: POLICY & SAFETY (Architecture Section 7)
# =========================
if page == "🛡️ Policy & Safety":
    st.subheader("🛡️ Policy Gate & Safety Controls")
    st.caption("Architecture Ref: Section 7 — Mandatory Safety Gate Between Orchestrator and Enforcement Actions. High-impact actions must pass through a policy gate. Raw AI output never executes firewall commands directly.")

    policy_gate = st.session_state.get("policy_gate")
    allowlist = st.session_state.get("allowlist")
    audit_trail = st.session_state.get("audit_trail")
    safety_agent = st.session_state.get("safety_agent")

    st.markdown("### ⚙️ 7-Layer Safety Controls Status")
    sc_col1, sc_col2, sc_col3, sc_col4 = st.columns(4)

    with sc_col1:
        st.markdown("**1. Safe Mode**")
        st.write("Status:", "🔴 ACTIVE" if safe_mode_active else "🟢 INACTIVE")
        st.caption("Suppresses all auto-enforcement when system health is degraded")

    with sc_col2:
        st.markdown("**2. Autonomous Mode**")
        st.write("Status:", "🟢 ENABLED" if autonomous_mode else "⚪ DISABLED")
        st.caption("Authorizes closed-loop firewall/quarantine responses")

    with sc_col3:
        st.markdown("**3. Protected Allowlist**")
        p_count = len(allowlist.list_all()) if allowlist else 0
        st.write("Status:", f"🛡️ {p_count} Protected IPs")
        st.caption("Critical devices immune from blind blocks/isolation")

    with sc_col4:
        st.markdown("**4. Dry-Run Mode**")
        st.write("Status:", "🧪 SIMULATION ONLY" if dry_run_mode else "⚡ LIVE ENFORCEMENT")
        st.caption("Validates policies without modifying system firewall")

    sc_col5, sc_col6, sc_col7, sc_col8 = st.columns(4)
    with sc_col5:
        st.markdown("**5. Multi-Signal Confirmation**")
        st.write("Requirement:", "2-of-3 Signals")
        st.caption("Requires ML + Baseline + Deception corroboration")

    with sc_col6:
        st.markdown("**6. Action Rate Limiter**")
        st.write("Limit:", "Max 10 / 60s")
        st.caption("Prevents cascade action storms and network partition")

    with sc_col7:
        st.markdown("**7. Verification Agent**")
        st.write("Status:", "Active (Post-Action)")
        st.caption("Validates firewall rule existence and traffic suppression")

    with sc_col8:
        st.markdown("**Threshold Setting**")
        new_thresh = st.slider("Confidence Gate", 0.50, 0.99, float(policy_gate.confidence_threshold if policy_gate else 0.70), 0.05)
        if policy_gate:
            policy_gate.confidence_threshold = new_thresh

    st.markdown("---")

    st.markdown("### 📋 Protected Allowlist Management")
    al_c1, al_c2 = st.columns([3, 2])

    with al_c1:
        if allowlist:
            items = allowlist.list_all()
            if items:
                al_df = pd.DataFrame(items)
                st.dataframe(al_df, use_container_width=True)
            else:
                st.info("Allowlist is empty. Add trusted router, server, or gateway IPs below.")
        else:
            st.info("Allowlist not initialized")

    with al_c2:
        with st.form("add_allowlist_form"):
            st.markdown("**Add Protected IP**")
            new_ip = st.text_input("IPv4 Address", placeholder="e.g. 192.168.1.1")
            new_label = st.text_input("Device Label", placeholder="e.g. Core Home Gateway")
            new_reason = st.text_input("Protection Reason", placeholder="Critical infrastructure")
            submit_al = st.form_submit_button("➕ Add to Allowlist")
            if submit_al:
                if new_ip and allowlist:
                    allowlist.add(new_ip, label=new_label, reason=new_reason)
                    st.success(f"Added {new_ip} to protected allowlist")
                    st.rerun()

        if allowlist and allowlist.list_all():
            ip_to_del = st.selectbox("Remove from allowlist", options=[item["ip"] for item in allowlist.list_all()])
            if st.button("🗑️ Remove Selected"):
                allowlist.remove(ip_to_del)
                st.success(f"Removed {ip_to_del}")
                st.rerun()

    st.markdown("---")

    st.markdown("### 🧪 Policy Gate Live Evaluator (Interactive Test)")
    st.caption("Simulate candidate actions to see how the Policy Gate authorizes or suppresses enforcement:")
    
    pe_col1, pe_col2, pe_col3 = st.columns(3)
    with pe_col1:
        test_action = st.selectbox("Proposed Action Type", ["BLOCK_IP", "QUARANTINE", "RATE_LIMIT"])
        test_ip = st.text_input("Target IP", value="192.168.1.55")
    with pe_col2:
        test_conf = st.slider("Signal Confidence", 0.10, 1.00, 0.85, 0.05)
        st.markdown("**Active Evidence Signals:**")
        sig_ml = st.checkbox("ML Detection (Perception/Session)", value=True)
        sig_base = st.checkbox("Baseline Anomaly Deviation", value=True)
        sig_decep = st.checkbox("Deception Hit (Honeypot/Honeytoken)", value=False)
    with pe_col3:
        st.markdown("**Evaluation Result:**")
        if policy_gate:
            signals = {"ml_detection": sig_ml, "baseline_anomaly": sig_base, "deception_hit": sig_decep}
            decision = policy_gate.evaluate(action_type=test_action, target=test_ip, confidence=test_conf, signals=signals)
            if decision.approved:
                st.success(f"✅ **APPROVED**\n\nReason: {decision.reason}\nSignals: {decision.signals_present}/3 present\nDry-run: {decision.dry_run}")
            else:
                st.error(f"⛔ **DENIED**\n\nReason: {decision.reason}\nSignals: {decision.signals_present}/3 present")

    st.markdown("---")

    st.markdown("### 📜 Append-Only Policy Audit Trail")
    st.caption("Architecture ref: Section 7 & Section 9 — Every decision logged with timestamp, evidence, action, outcome, policy decision, confidence.")
    if audit_trail:
        recent_records = audit_trail.query_recent(limit=30)
        if recent_records:
            audit_df = pd.DataFrame(recent_records)
            st.dataframe(audit_df, use_container_width=True)
        else:
            st.info("Audit log is currently empty. Actions evaluated by the Policy Gate will record here.")
    else:
        st.info("Audit trail module active.")


# =========================
# PAGE 5: RESPONSE + DECEPTION
# =========================
if page == "🧠 Response + Deception":
    st.subheader("🧠 Response + Deception Layer")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 😈 Honeypot (Deception)")

        if st.button("🚀 Start Honeypot Server (Port 9999)"):
            if not st.session_state.honeypot_started:
                start_honeypot_in_background(port=9999)
                st.session_state.honeypot_started = True
                st.success("✅ Honeypot started on port 9999")
                log_alert("Honeypot started on port 9999", severity="INFO")
            else:
                st.info("Honeypot already running ✅")

        st.caption(
            "💡 Simulate hit using:\n"
            "`python -c \"import socket; s=socket.socket(); s.connect(('127.0.0.1',9999)); s.send(b'hi'); s.close()\"`"
        )

    with col2:
        st.markdown("### ⚡ Manual Response Actions")

        attacker_ip = st.text_input("Attacker IP to block", value="192.168.1.66")
        device_ip = st.text_input("Device IP to quarantine", value="192.168.1.12")

        c1, c2 = st.columns(2)
        with c1:
            if st.button("⛔ Block IP"):
                st.session_state.blocked_ips = block_attacker_ip(attacker_ip, st.session_state.blocked_ips)
                fw = safe_block_ip(attacker_ip, reason="manual_block")
                if fw.get("ok"):
                    st.success(f"🧱 Firewall blocked: {attacker_ip}")
                else:
                    st.warning(
                        f"Firewall block failed for {attacker_ip}: {fw.get('message')} | {fw.get('error') or ''}"
                    )

                st.success(f"✅ Blocked IP: {attacker_ip}")
                st.session_state.security_events.append({"ts": time.time(), "type": "BLOCK_IP", "target": attacker_ip})
                _push_timeline_event(
                    "BLOCK_IP",
                    label="",
                    target=attacker_ip,
                    details=f"manual ok={fw.get('ok')} msg={fw.get('message')}",
                )
                _update_score_metric()

        with c2:
            if st.button("🔒 Quarantine Device"):
                st.session_state.quarantined_devices = quarantine_device(device_ip, st.session_state.quarantined_devices)
                st.success(f"✅ Quarantined device: {device_ip}")
                st.session_state.security_events.append({"ts": time.time(), "type": "QUARANTINE", "target": device_ip})
                _push_timeline_event("QUARANTINE", label="", target=device_ip, details="Manual")
                _update_score_metric()

    st.divider()

    st.markdown("### 📌 Honeypot Logs")
    try:
        with open("logs/honeypot.log", "r") as f:
            lines = f.readlines()[-15:]
        if lines:
            st.code("".join(lines))
        else:
            st.info("No honeypot events yet.")
    except Exception as e:
        st.error(f"Could not read honeypot.log: {e}")

    st.divider()

    st.markdown("### 🧾 Alert / Memory Logs")
    try:
        with open("logs/alerts.log", "r") as f:
            lines = f.readlines()[-20:]
        if lines:
            st.code("".join(lines))
        else:
            st.info("No alerts yet.")
    except Exception as e:
        st.error(f"Could not read alerts.log: {e}")


# =========================
# PAGE 6: EVIDENCE & PERSISTENCE (Architecture Section 9)
# =========================
if page == "📁 Evidence":
    st.subheader("📁 Evidence & Persistence Panel — For Judges & SOC Auditors")
    st.caption("Architecture Ref: Section 9 — Local Data, Evidence & Service Layout: SQLite (devices, baselines, scores, actions) + Append-only SOC Event Store + Audit Trail")

    ev_tab1, ev_tab2, ev_tab3, ev_tab4, ev_tab5 = st.tabs([
        "🗄️ SQLite Database",
        "📜 Structured Audit Trail",
        "📋 SOC Event Store",
        "🧾 Real-time Text Logs",
        "⛔ Mitigation Inventory",
    ])

    shield_db = st.session_state.get("shield_db")
    audit_trail = st.session_state.get("audit_trail")
    evidence_store = st.session_state.get("evidence_store")

    with ev_tab1:
        st.markdown("### 🗄️ SQLite Local Persistence (`data/shield.db`)")
        st.caption("Architecture Ref: Section 9 — 'SQLite: devices, baselines, scores, actions. Fast local state.'")
        if shield_db:
            db_stats = shield_db.get_stats()
            s1, s2, s3, s4, s5 = st.columns(5)
            s1.metric("Persisted Devices", db_stats.get("devices", 0))
            s2.metric("Enforcement Actions", db_stats.get("actions", 0))
            s3.metric("Baseline Records", db_stats.get("baselines", 0))
            s4.metric("Security Events", db_stats.get("events", 0))
            s5.metric("Score History", db_stats.get("scores", 0))

            table_view = st.selectbox("Select SQLite Table to Inspect", ["devices", "actions", "events", "scores", "baselines"])
            if table_view == "devices":
                devs = shield_db.get_devices()
                if devs:
                    st.dataframe(pd.DataFrame(devs), use_container_width=True)
                else:
                    st.info("No devices in SQLite database yet. Click 'Sync Current Inventory' below.")
            elif table_view == "actions":
                acts = shield_db.get_recent_actions(limit=50)
                if acts:
                    st.dataframe(pd.DataFrame(acts), use_container_width=True)
                else:
                    st.info("No enforcement actions stored in SQLite yet.")
            elif table_view == "events":
                evts = shield_db.get_recent_events(limit=50)
                if evts:
                    st.dataframe(pd.DataFrame(evts), use_container_width=True)
                else:
                    st.info("No security events stored in SQLite yet.")
            elif table_view == "scores":
                scs = shield_db.get_score_history(limit=50)
                if scs:
                    st.dataframe(pd.DataFrame(scs), use_container_width=True)
                else:
                    st.info("No scores stored in SQLite yet.")
            elif table_view == "baselines":
                bls = shield_db.get_baseline()
                if bls:
                    st.dataframe(pd.DataFrame(bls), use_container_width=True)
                else:
                    st.info("No baseline records stored in SQLite yet.")

            if st.button("🔄 Sync Active Inventory to SQLite"):
                devices_to_save = st.session_state.get("devices", [])
                if devices_to_save:
                    shield_db.save_devices(devices_to_save)
                    st.success(f"Synced {len(devices_to_save)} devices into SQLite data/shield.db")
                    st.rerun()
        else:
            st.warning("ShieldDatabase module not available.")

    with ev_tab2:
        st.markdown("### 📜 Append-Only Audit Trail (`security/audit.py`)")
        st.caption("Architecture Ref: Section 7 — 'Audit trail: Explain every decision. Timestamp + evidence + action + outcome.'")
        if audit_trail:
            audits = audit_trail.query_recent(limit=50)
            if audits:
                st.dataframe(pd.DataFrame(audits), use_container_width=True)
            else:
                st.info("No audit trail entries recorded yet. Actions evaluated by SafetyAgent/PolicyGate will appear here.")
        else:
            st.info("AuditTrail module active.")

    with ev_tab3:
        st.markdown("### 📋 Structured SOC Evidence Store (`storage/evidence.py`)")
        st.caption("Architecture Ref: Section 9 — 'Append-only event log: SOC events. Days/weeks retention. Audit trail.'")
        if evidence_store:
            ev_stats = evidence_store.get_stats()
            st.write(f"Total structured events stored: **{ev_stats.get('total_events', 0)}**")
            severity_filter = st.selectbox("Filter by severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
            sev_arg = None if severity_filter == "ALL" else severity_filter
            ev_records = evidence_store.query_events(severity=sev_arg, limit=50)
            if ev_records:
                st.dataframe(pd.DataFrame(ev_records), use_container_width=True)
            else:
                st.info("No structured SOC events matching the filter.")
        else:
            st.info("EvidenceStore module active.")

    with ev_tab4:
        st.markdown("### 🧾 Text Logs & Diagnostics")
        col_log1, col_log2 = st.columns(2)
        with col_log1:
            st.markdown("**Recent Alerts (`logs/alerts.log`)**")
            try:
                with open("logs/alerts.log", "r") as f:
                    alerts = f.readlines()[-25:]
                if alerts:
                    st.code("".join(alerts))
                else:
                    st.info("No alerts logged yet.")
            except Exception as e:
                st.error(f"Could not read alerts.log: {e}")

        with col_log2:
            st.markdown("**Honeypot Hits (`logs/honeypot.log`)**")
            try:
                with open("logs/honeypot.log", "r") as f:
                    hlines = f.readlines()[-25:]
                if hlines:
                    st.code("".join(hlines))
                else:
                    st.info("No honeypot events yet.")
            except Exception as e:
                st.error(f"Could not read honeypot.log: {e}")

    with ev_tab5:
        st.markdown("### ⛔ Active Mitigations & Safe Mode Status")
        m_c1, m_c2 = st.columns(2)
        with m_c1:
            st.markdown("**Blocked Attacker IPs:**")
            if st.session_state.blocked_ips:
                st.dataframe(pd.DataFrame([{"Blocked IP": ip} for ip in st.session_state.blocked_ips]), use_container_width=True)
            else:
                st.write("No active IP blocks.")

        with m_c2:
            st.markdown("**Quarantined Devices:**")
            if st.session_state.quarantined_devices:
                st.dataframe(pd.DataFrame([{"Quarantined IP": q} for q in st.session_state.quarantined_devices]), use_container_width=True)
            else:
                st.write("No quarantined devices.")

        st.markdown("---")
        st.markdown("### 🚫 Suppressed Actions (Safe Mode)")
        if st.session_state.suppressed_actions:
            dfsa = pd.DataFrame(st.session_state.suppressed_actions)
            if "time" in dfsa.columns:
                dfsa["time"] = dfsa["time"].apply(
                    lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))
                    if isinstance(t, (int, float))
                    else t
                )
            st.dataframe(dfsa, use_container_width=True)
            if st.button("Clear Suppressed Actions"):
                st.session_state.suppressed_actions = []
                st.rerun()
        else:
            st.write("No actions suppressed.")

        st.markdown("---")
        st.markdown("### 📊 Device Risk Posture (Top 5)")
        try:
            df_all = pd.DataFrame(st.session_state.devices)
            top5 = df_all.sort_values("risk_score", ascending=False).head(5)
            st.dataframe(top5[["device_name", "ip", "risk_level", "risk_score"]].reset_index(drop=True), use_container_width=True)
        except Exception:
            st.info("No device data available")


# =========================
# PAGE 5: ONE-CLICK DEMO
# =========================
if page == "🚀 One-Click Demo":
    st.subheader("🚀 One-Click Demo — Run Full Pipeline End-to-End")

    st.markdown(
        "Click the button to run the full offline demo: Perception → Session Aggregation → Severity → Actions (Auto-block / Monitor / Quarantine)."
    )

    flows_df = load_demo_flows()
    LABEL_COL = "label"
    if LABEL_COL not in flows_df.columns:
        st.error("❌ sample_flows.csv must contain 'label' column")

    demo_col1, demo_col2 = st.columns([1, 2])
    with demo_col2:
        st.write("Demo will process sample flows and update blocklist / quarantine / alerts.")

    st.markdown("**Inject synthetic attacks into the sample flows (optional)**")
    inject = st.checkbox("Inject attacks into sample flows", value=False)
    if inject:
        attack_pct = st.slider("Attack percentage (%) to inject into benign flows", 1, 50, 10)
        attack_types = st.multiselect("Attack types to inject", options=["Mirai", "DDoS", "PortScan"], default=["Mirai", "DDoS"])
        if st.button("⚠️ Inject Attacks Now"):
            try:
                df_copy = flows_df.copy()
                benign_idx = df_copy[df_copy.get(LABEL_COL, "").str.contains("Benign", na=False)].index.tolist()
                import random as _rand
                _rand.seed(42)
                n_inject = max(1, int(len(df_copy) * (attack_pct / 100.0)))
                if n_inject > len(benign_idx):
                    n_inject = len(benign_idx)
                chosen = _rand.sample(benign_idx, n_inject) if benign_idx else []
                for idx in chosen:
                    chosen_attack = _rand.choice(attack_types) if attack_types else "Mirai"
                    df_copy.at[idx, LABEL_COL] = chosen_attack
                    attacker_ip = f"203.0.113.{_rand.randint(2, 250)}"
                    df_copy.at[idx, "attacker_ip"] = attacker_ip
                    df_copy.at[idx, "src_ip"] = attacker_ip
                    df_copy.at[idx, "source_ip"] = attacker_ip
                    for col in df_copy.select_dtypes(include=["number"]).columns:
                        try:
                            df_copy.at[idx, col] = df_copy.at[idx, col] * _rand.uniform(1.5, 3.0)
                        except Exception:
                            pass
                st.session_state.injected_flows = df_copy
                st.success(f"Injected {len(chosen)} attack flows ({attack_pct}%).")
            except Exception as e:
                st.error(f"Injection failed: {e}")

    if st.session_state.get("injected_flows") is not None:
        flows_df = st.session_state.get("injected_flows")

    use_range = st.checkbox("🧭 Run on specific index range (pick before Run)", value=False)
    start_idx = None
    end_idx = None
    if use_range:
        start_idx = st.number_input("Start index (1-based)", min_value=1, max_value=len(flows_df), value=1, step=1)
        end_idx = st.number_input("End index (inclusive)", min_value=1, max_value=len(flows_df), value=min(500, len(flows_df)), step=1)
        if start_idx > end_idx:
            tmp = start_idx
            start_idx = end_idx
            end_idx = tmp
        st.write(f"Selected flows: {start_idx} → {end_idx} (count={end_idx - start_idx + 1})")

    run = st.button("✅ RUN FULL DEMO NOW")
    if run and LABEL_COL not in flows_df.columns:
        st.error("Cannot run demo: sample_flows.csv missing required 'label' column")
        run = False

    if run:
        if use_range and start_idx is not None and end_idx is not None:
            flows_df = flows_df.iloc[start_idx - 1 : end_idx].reset_index(drop=True)

        fast_mode = st.checkbox("⚡ Fast Prototype Mode (sample & speed up)", value=True)
        max_samples = st.slider("Max demo samples (fast mode)", 100, 5000, 1000, step=100) if fast_mode else len(flows_df)

        if fast_mode and len(flows_df) > max_samples:
            proportions = flows_df[LABEL_COL].value_counts(normalize=True)
            alloc = (proportions * max_samples).round().astype(int)
            diff = max_samples - alloc.sum()
            if diff != 0:
                largest = alloc.idxmax()
                alloc[largest] = alloc[largest] + diff

            parts = []
            for label, n in alloc.items():
                group = flows_df[flows_df[LABEL_COL] == label]
                n = min(n, len(group))
                if n > 0:
                    parts.append(group.sample(n=n, random_state=42))
            sampled_df = pd.concat(parts, ignore_index=True)
            X_df = sampled_df.reset_index(drop=True)
        else:
            X_df = flows_df.reset_index(drop=True)

        perception = PerceptionAgent()
        session_agent = SessionAggregationAgent(window_seconds=window_seconds)

        total = len(X_df)
        progress = st.progress(0)
        status = st.empty()

        low_count = med_count = high_count = 0
        results = []

        preds = None
        if fast_mode:
            try:
                flows_list = X_df.to_dict(orient="records")
                chunk_size = 2000
                all_preds = []
                for s in range(0, len(flows_list), chunk_size):
                    chunk = flows_list[s : s + chunk_size]
                    all_preds.extend(perception.predict_batch(chunk))
                preds = all_preds
            except Exception:
                preds = None

        for i in range(total):
            status.text(f"Processing flow {i+1}/{total} ...")
            flow = X_df.iloc[i].to_dict()
            if preds is not None:
                flow_pred = preds[i]
            else:
                try:
                    flow_pred = perception.predict_flow(flow)
                except Exception:
                    flow_pred = {"attack_prob": 0.0, "label": "BenignTraffic"}

            session_pred = session_agent.update(flow_pred.get("attack_prob", 0.0), flow_pred.get("label", "BenignTraffic"))
            session_prob = session_pred.get("session_prob", 0.0)
            persistence = session_pred.get("persistence", 0)
            session_label = session_pred.get("session_label", "Unknown")

            aggressive_demo = st.session_state.get("aggressive_demo", None)
            if aggressive_demo is None:
                aggressive_demo = False  # Default to False to respect actual data
            
            # Determine severity based on actual predictions, not aggressive mode
            ap = float(flow_pred.get("attack_prob", 0.0))
            flow_label = flow_pred.get("label", "Unknown")
            
            # Debug: Show first few predictions
            if i < 5:
                st.write(f"Debug Flow {i+1}: label={flow_label}, attack_prob={ap:.3f}")
            
            # Use more reasonable thresholds:
            # HIGH: > 0.7 (high confidence attack)
            # MED: 0.3 - 0.7 (moderate concern)
            # LOW: < 0.3 (mostly benign)
            if ap > 0.7:
                severity = "HIGH"; high_count += 1
            elif ap >= 0.3:
                severity = "MED"; med_count += 1
            else:
                severity = "LOW"; low_count += 1

            attacker_ip = extract_attacker_ip_from_flow(flow)

            action = "NONE"
            if severity == "HIGH":
                if not safe_mode_active:
                    st.session_state.blocked_ips = block_attacker_ip(attacker_ip, st.session_state.blocked_ips)
                    fw = safe_block_ip(attacker_ip, reason="auto_block_high")
                    if fw.get("ok"):
                        st.success(f"🧱 Firewall blocked: {attacker_ip}")
                    else:
                        st.warning(
                            f"Firewall block failed for {attacker_ip}: {fw.get('message')} | {fw.get('error') or ''}"
                        )

                    action = "AUTO_BLOCK_IP"
                    log_alert(f"Auto-blocked {attacker_ip} (HIGH). session_prob={session_prob:.3f}, persistence={persistence}", severity="CRITICAL")
                else:
                    action = "SUPPRESSED_AUTO_BLOCK"
                    st.session_state.suppressed_actions.append({"time": time.time(), "type": "AUTO_BLOCK", "target": attacker_ip, "reason": "Safe Mode"})
                    log_alert(f"Suppressed auto-block for {attacker_ip} due to Safe Mode.", severity="WARN")

                try:
                    devices = st.session_state.get("devices", [])
                    if devices:
                        highest_dev = max(devices, key=lambda d: d.get("risk_score", 0))
                        if not safe_mode_active:
                            st.session_state.quarantined_devices = quarantine_device(highest_dev.get("ip"), st.session_state.quarantined_devices)
                            log_alert(f"Auto-quarantined {highest_dev.get('device_name')} ({highest_dev.get('ip')}) due to HIGH severity", severity="HIGH")
                        else:
                            st.session_state.suppressed_actions.append({"time": time.time(), "type": "QUARANTINE", "target": highest_dev.get("ip"), "reason": "Safe Mode"})
                            log_alert(f"Suppressed auto-quarantine due to Safe Mode.", severity="WARN")
                except Exception:
                    pass

            elif severity == "MED":
                st.session_state.monitored_flows.append({
                    "time": time.time(),
                    "attacker_ip": attacker_ip,
                    "session_prob": session_prob,
                    "persistence": persistence,
                    "session_label": session_label,
                })
                action = "MONITOR"
                log_alert(f"Monitoring flow from {attacker_ip} (MED severity). session_prob={session_prob:.3f}", severity="INFO")

            results.append({
                "flow_index": i,
                "flow_label": flow_pred.get("label", ""),
                "session_label": session_label,
                "session_prob": round(session_prob, 4),
                "persistence": persistence,
                "severity": severity,
                "attacker_ip": attacker_ip,
                "action": action,
            })

            st.session_state.demo_results = (st.session_state.demo_results + results)[-500:]
            progress.progress(int(((i + 1) / total) * 100))
            time.sleep(0.02)

        status.text("Demo complete.")
        st.success(f"Processed {total} flows — LOW: {low_count}, MED: {med_count}, HIGH: {high_count}")

    st.divider()
    st.markdown("### Summary Metrics")
    all_dr = pd.DataFrame(st.session_state.demo_results) if st.session_state.demo_results else pd.DataFrame()
    if not all_dr.empty:
        counts = all_dr["severity"].value_counts().to_dict()
        st.write(f"LOW: {counts.get('LOW',0)}  |  MED: {counts.get('MED',0)}  |  HIGH: {counts.get('HIGH',0)}")
        st.markdown("### Last 50 Results")
        dr = all_dr.tail(50)
        st.dataframe(dr[["flow_index","flow_label","session_label","session_prob","persistence","severity","attacker_ip","action"]], use_container_width=True)
    else:
        st.info("No demo results yet. Run the demo to populate results.")

    st.divider()
    st.markdown("### ⛔ Blocked IPs")
    st.write(st.session_state.blocked_ips if st.session_state.blocked_ips else "None")

    st.markdown("### 🔭 Monitored (MED) Flows Watchlist")
    try:
        mf = pd.DataFrame(st.session_state.monitored_flows[-50:]) if st.session_state.monitored_flows else pd.DataFrame()
        if not mf.empty:
            st.dataframe(mf[["time","attacker_ip","session_prob","persistence","session_label"]], use_container_width=True)
        else:
            st.write("None")
    except Exception:
        st.write("None")

    st.divider()
    st.markdown("### 🚫 Suppressed Actions (Safe Mode)")
    try:
        sa = pd.DataFrame(st.session_state.suppressed_actions[-50:]) if st.session_state.suppressed_actions else pd.DataFrame()
        if not sa.empty:
            if "time" in sa.columns:
                sa["time"] = sa["time"].apply(lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if isinstance(t, (int, float)) else t)
            st.dataframe(sa, use_container_width=True)
        else:
            st.write("None")
    except Exception:
        st.write("None")
