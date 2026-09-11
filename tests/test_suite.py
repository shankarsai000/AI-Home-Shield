"""
tests/test_suite.py

End-to-End Verification Test Suite for AI Home Shield Architecture.
Validates all 15 new/enhanced modules across capture, security, storage, and agents.
Platform-independent: runs on Windows, Linux, or CI/CD pipelines.
"""

import os
import sys
import time

# Ensure project root is in path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

print("========================================================")
print("🛡️ AI Home Shield — Architecture Verification Test Suite")
print("========================================================")

# Test 1: Security - Allowlist
print("\n[1/9] Testing security/allowlist.py...")
from security.allowlist import Allowlist
al = Allowlist("data/test_allowlist.json")
al.add("192.168.1.1", label="Router Gateway", reason="Critical infrastructure")
al.add("192.168.1.2", label="DNS Server", reason="Internal resolver")
assert al.is_protected("192.168.1.1"), "Router should be protected"
assert not al.is_protected("192.168.1.100"), "Unknown IP should not be protected"
assert len(al.list_all()) >= 2, "Should list at least 2 protected devices"
print("  ✅ Allowlist PASS: Persistent storage, lookup, and protected checks verified")

# Test 2: Security - Audit Trail
print("\n[2/9] Testing security/audit.py...")
from security.audit import AuditTrail
audit = AuditTrail("logs/test_audit.jsonl")
audit.log_decision(
    action_type="BLOCK_IP",
    target="10.0.0.99",
    signals={"ml_detection": True, "deception_hit": True},
    confidence=0.95,
    policy_result="APPROVED",
    reason="Multi-signal confirmation passed",
)
audit.log_action(
    action_type="BLOCK_IP",
    target="10.0.0.99",
    command="netsh advfirewall add rule ...",
    outcome="SUCCESS",
    verified=True,
    details="Simulated test block",
)
recent = audit.query_recent(limit=10)
assert len(recent) >= 2, "Should query logged records"
print(f"  ✅ AuditTrail PASS: Append-only JSONL logging and query verified ({len(recent)} entries)")

# Test 3: Security - PolicyGate & SafetyAgent
print("\n[3/9] Testing security/policy.py & agents/safety_agent.py...")
from security.policy import PolicyGate
from agents.safety_agent import SafetyAgent

pg = PolicyGate(allowlist=al, require_multi_signal=True, min_signals=2)
safety = SafetyAgent(policy_gate=pg, audit_trail=audit)

# Test 3a: Protected IP denial
dec_protected = safety.evaluate_action("BLOCK_IP", "192.168.1.1", confidence=0.99)
assert not dec_protected.approved, "Allowlisted IP must be denied"
assert "allowlist" in dec_protected.reason.lower(), "Reason should mention allowlist"
print("  ✅ PolicyGate Rule 1: Protected allowlist enforcement verified")

# Test 3b: Single-signal denial when multi-signal required
dec_single = safety.evaluate_action(
    "BLOCK_IP", "10.0.0.5", confidence=0.95, ml_detection=True, baseline_anomaly=False, deception_hit=False
)
assert not dec_single.approved, "Single signal must be denied when 2-of-3 required"
print("  ✅ PolicyGate Rule 2: Multi-signal confirmation (2-of-3 requirement) verified")

# Test 3c: Multi-signal approval
dec_multi = safety.evaluate_action(
    "BLOCK_IP", "10.0.0.5", confidence=0.95, ml_detection=True, baseline_anomaly=True, deception_hit=False
)
assert dec_multi.approved, "Multi-signal (ML + Baseline) must be approved"
print("  ✅ PolicyGate Rule 3: Multi-signal authorization verified")

# Test 3d: Safe Mode suppression
pg.set_safe_mode(True)
dec_safe = safety.evaluate_action("BLOCK_IP", "10.0.0.6", confidence=0.95, ml_detection=True, deception_hit=True)
assert not dec_safe.approved and "safe mode" in dec_safe.reason.lower(), "Safe mode must suppress actions"
pg.set_safe_mode(False)
print("  ✅ PolicyGate Rule 4: Safe Mode automatic suppression verified")

# Test 4: Storage - SQLite ShieldDatabase
print("\n[4/9] Testing storage/database.py...")
from storage.database import ShieldDatabase
db = ShieldDatabase("data/test_shield.db")
db.upsert_device({
    "ip": "192.168.1.50",
    "device_name": "Smart Cam",
    "vendor": "TP-Link",
    "mac": "AA:BB:CC:DD:EE:FF",
    "open_ports": [554, 80],
    "risk_score": 4,
    "risk_level": "LOW",
    "risk_reasons": ["RTSP stream"],
})
db.log_action(action_type="BLOCK_IP", target="192.168.1.99", outcome="SUCCESS", verified=True)
db.log_event(event_type="ATTACK", target="192.168.1.50", label="Mirai", severity="CRITICAL")
db.log_score(88)

devs = db.get_devices()
acts = db.get_recent_actions()
stats = db.get_stats()
assert len(devs) >= 1, "Device must be stored"
assert len(acts) >= 1, "Action must be stored"
assert stats["scores"] >= 1, "Score must be recorded"
print(f"  ✅ SQLite Database PASS: Tables created, CRUD verified (Stats: {stats})")

# Test 5: Storage - EvidenceStore
print("\n[5/9] Testing storage/evidence.py...")
from storage.evidence import EvidenceStore
ev_store = EvidenceStore("data/test_events.jsonl")
ev_store.append_event(
    event_type="ATTACK_TRIGGER",
    source="perception_agent",
    target="192.168.1.80",
    evidence={"flow_label": "DDoS", "rate": 5000},
    confidence=0.98,
    action="RATE_LIMIT",
    outcome="APPLIED",
    severity="CRITICAL",
)
evts = ev_store.query_events(severity="CRITICAL")
assert len(evts) >= 1, "Event should be queryable"
print(f"  ✅ EvidenceStore PASS: Structured append-only SOC events verified ({len(evts)} critical events)")

# Test 6: Capture - FlowBuilder & FeatureExtractor
print("\n[6/9] Testing capture/flow_builder.py & feature_extractor.py...")
from capture.flow_builder import FlowBuilder
from capture.feature_extractor import FeatureExtractor

builder = FlowBuilder()
extractor = FeatureExtractor()

# Feed synthetic packets to FlowBuilder
t0 = time.time()
for p in range(10):
    builder.add_packet({
        "timestamp": t0 + (p * 0.05),
        "src_ip": "192.168.1.200",
        "dst_ip": "192.168.1.1",
        "src_port": 50000,
        "dst_port": 80,
        "protocol": "TCP",
        "length": 64 + (p * 10),
        "tcp_flags": {"SYN": 1 if p == 0 else 0, "ACK": 1 if p > 0 else 0},
    })

flows = builder.flush_all()
assert len(flows) >= 1, "Flows must be produced from packets"
flow = flows[0]
assert flow["total_packets"] == 10, "Flow packet count should be 10"

# Convert flow to 46-feature model vector
features = extractor.extract(flow)
assert len(features) == 46, f"Features vector must match 46 columns, got {len(features)}"
print(f"  ✅ Capture Pipeline PASS: Packets → Bidirectional Flows → 46 Model Features (Columns: {len(features)})")

# Test 7: Agents - NetworkStateAgent & AttackForecastingAgent
print("\n[7/9] Testing agents/network_state_agent.py & agents/attack_forecasting_agent.py...")
from agents.network_state_agent import NetworkStateAgent
from agents.attack_forecasting_agent import AttackForecastingAgent

ns = NetworkStateAgent(window_size=30, snapshot_interval=0.01)
forecaster = AttackForecastingAgent()

# Accumulate temporal state progression
for step in range(5):
    ns.update_state(
        active_flows=20 + step * 10,
        attack_flows=step * 4,
        benign_flows=20,
        avg_attack_prob=0.1 + (step * 0.15),
        session_label="PortScan" if step > 2 else "BenignTraffic",
        session_prob=0.2 + (step * 0.15),
        network_anomalies=step,
    )
    time.sleep(0.02)

forecast = forecaster.forecast(network_state_agent=ns)
assert "predicted_stage" in forecast, "Must predict stage"
assert "stage_probabilities" in forecast, "Must provide stage probabilities"
assert "confidence" in forecast, "Must calculate confidence"
assert "horizons" in forecast, "Must project multi-horizons"
print(f"  ✅ NetworkState & Forecaster PASS: Predicted Stage={forecast['predicted_stage']} (Prob: {forecast['probability']}, Confidence: {forecast['confidence']}, Posture: {forecast['recommended_posture']})")

# Test 8: Agents - OrchestratorAgent with PolicyGate
print("\n[8/9] Testing agents/orchestrator_agent.py...")
from agents.orchestrator_agent import OrchestratorAgent

orch = OrchestratorAgent(safety_agent=safety, audit_trail=audit)
decision_res = orch.evaluate_and_decide(
    session_prob=0.92,
    session_label="Mirai",
    persistence=4,
    devices=[{"ip": "192.168.1.150", "device_name": "IP Camera", "risk_score": 15}],
    honeypot_events=[{"attacker_ip": "10.10.10.10", "port": 9999}],
    honeytoken_trips=[],
    baseline_deviations=[{"type": "abnormal_fanout"}],
)
assert len(decision_res["authorized_actions"]) >= 1, "Should authorize actions"
print(f"  ✅ Orchestrator PASS: Multi-signal correlation produced {len(decision_res['authorized_actions'])} authorized actions and {len(decision_res['alerts'])} alerts")

# Test 9: Agents - FirewallAgent & ResponseAgent & VerificationAgent
print("\n[9/9] Testing agents/firewall_agent.py, response_agent.py & verification_agent.py...")
from agents.firewall_agent import FirewallAgent
from agents.verification_agent import VerificationAgent
from agents.response_agent import ResponseAgent

fw = FirewallAgent()
va = VerificationAgent(audit_trail=audit)
resp = ResponseAgent(firewall_agent=fw, safety_agent=safety, verification_agent=va, audit_trail=audit)

# Execute simulated block with verification
exec_res = resp.execute_block("DEMO_ATTACKER_99", reason="Honeypot intrusion test", confidence=0.95, bypass_policy=True)
assert exec_res["ok"], "Simulated block must succeed"
assert exec_res["verification"]["verified"], "Verification must confirm block"

fw_status = fw.status()
assert fw_status["blocked_count"] >= 1, "Firewall agent must track blocked IP"

# Cleanup test files
for fpath in ["data/test_allowlist.json", "logs/test_audit.jsonl", "data/test_shield.db", "data/test_events.jsonl"]:
    try:
        if os.path.exists(fpath):
            os.remove(fpath)
    except Exception:
        pass

print(f"  ✅ Enforcement PASS: FirewallAgent, VerificationAgent, and ResponseAgent loop verified")

print("\n========================================================")
print("🎉 ALL 9 ARCHITECTURAL MODULE TESTS PASSED WITH 100% SUCCESS!")
print("========================================================")
