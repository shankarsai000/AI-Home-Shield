import os
import time
from datetime import datetime
from typing import List, Dict, Any, Set
import statistics

class BaselineAgent:
    """Agent for maintaining baselines and detecting anomalies in devices and network."""
    
    def __init__(self, history_size: int = 20):
        self.history_size = history_size
        self.log_file = "logs/baseline.log"
        self._ensure_log_dir()
    
    def _ensure_log_dir(self):
        """Ensure logs directory exists."""
        os.makedirs("logs", exist_ok=True)
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w") as f:
                f.write("")
    
    def _log(self, message: str):
        """Log baseline events."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        try:
            with open(self.log_file, "a") as f:
                f.write(log_entry)
        except Exception:
            pass  # Silent fail to avoid crashes
    
    def _get_device_key(self, device: dict) -> str:
        """Generate a unique key for device based on available identifiers."""
        if device.get("ip") and device["ip"] != "N/A":
            return f"ip:{device['ip']}"
        elif device.get("mac") and device["mac"] != "N/A":
            return f"mac:{device['mac']}"
        elif device.get("device_id"):
            return f"id:{device['device_id']}"
        else:
            return f"name:{device.get('device_name', 'unknown')}"
    
    def _ensure_session_state_baselines(self):
        """Ensure baseline session state keys exist."""
        import streamlit as st
        if "device_baselines" not in st.session_state:
            st.session_state.device_baselines = {}
        if "network_baseline" not in st.session_state:
            st.session_state.network_baseline = {
                "flows_per_minute": [],
                "avg_flow_prob": [],
                "attack_sessions_per_minute": [],
                "last_session_prob": 0.0,
                "last_session_label": "",
                "persistence": [],
                "last_update": time.time()
            }
        if "baseline_last_check" not in st.session_state:
            st.session_state.baseline_last_check = time.time()
    
    def _capped_append(self, lst: List, item: Any, max_size: int = None) -> List:
        """Append to list with size cap."""
        if max_size is None:
            max_size = self.history_size
        lst.append(item)
        return lst[-max_size:]
    
    def update_device_baseline(self, devices: List[Dict]) -> Dict[str, int]:
        """Update device baselines with current device data."""
        import streamlit as st
        self._ensure_session_state_baselines()
        
        baselines = st.session_state.device_baselines
        updated_count = 0
        current_time = time.time()
        
        for device in devices:
            device_key = self._get_device_key(device)
            
            if device_key not in baselines:
                baselines[device_key] = {
                    "first_seen": current_time,
                    "last_seen": current_time,
                    "open_ports_history": [],
                    "firmware_history": [],
                    "risk_score_history": [],
                    "risk_label_history": [],
                    "mutation_count_seen": 0,
                    "anomaly_count": 0
                }
                self._log(f"Created baseline for device: {device_key}")
            
            baseline = baselines[device_key]
            
            # Update timestamps
            baseline["last_seen"] = current_time
            
            # Update open ports history
            if "open_ports" in device:
                current_ports = set(device["open_ports"])
                baseline["open_ports_history"] = self._capped_append(
                    baseline["open_ports_history"], 
                    list(current_ports)
                )
            
            # Update firmware history
            if "firmware" in device:
                baseline["firmware_history"] = self._capped_append(
                    baseline["firmware_history"],
                    device["firmware"]
                )
            
            # Update risk score history
            if "risk_score" in device:
                try:
                    score = float(device["risk_score"])
                    baseline["risk_score_history"] = self._capped_append(
                        baseline["risk_score_history"],
                        score
                    )
                except (ValueError, TypeError):
                    pass
            
            # Update risk label history
            if "risk_level" in device:
                baseline["risk_label_history"] = self._capped_append(
                    baseline["risk_label_history"],
                    device["risk_level"]
                )
            
            # Update mutation count
            if "mutation_count" in device:
                baseline["mutation_count_seen"] = max(
                    baseline["mutation_count_seen"],
                    int(device.get("mutation_count", 0))
                )
            
            updated_count += 1
        
        st.session_state.device_baselines = baselines
        st.session_state.baseline_last_check = current_time
        
        self._log(f"Updated baseline for {updated_count} devices")
        
        return {
            "devices_updated": updated_count,
            "baselines_total": len(baselines)
        }
    
    def detect_device_anomalies(self, devices: List[Dict]) -> List[Dict[str, Any]]:
        """Detect anomalies in devices based on baseline."""
        import streamlit as st
        self._ensure_session_state_baselines()
        
        baselines = st.session_state.device_baselines
        anomalies = []
        current_time = time.time()
        
        for device in devices:
            device_key = self._get_device_key(device)
            
            if device_key not in baselines:
                continue  # No baseline yet
            
            baseline = baselines[device_key]
            
            # Check NEW_PORT_EXPOSED
            if "open_ports" in device and baseline["open_ports_history"]:
                current_ports = set(device["open_ports"])
                historical_ports = set()
                for ports_list in baseline["open_ports_history"][:-1]:  # Exclude current
                    historical_ports.update(ports_list)
                
                new_ports = current_ports - historical_ports
                if new_ports:
                    anomalies.append({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "type": "ANOMALY",
                        "anomaly_type": "NEW_PORT_EXPOSED",
                        "severity": "MEDIUM",
                        "target": device_key,
                        "device_name": device.get("device_name", "Unknown"),
                        "ip": device.get("ip", "N/A"),
                        "details": f"New port(s) exposed: {', '.join(map(str, new_ports))}",
                        "recommended_action": ["ALERT"]
                    })
                    baseline["anomaly_count"] += 1
            
            # Check FIRMWARE_FLIP_FREQUENT
            if len(baseline["firmware_history"]) >= 3:
                recent_firmware = baseline["firmware_history"][-3:]
                unique_firmware = set(recent_firmware)
                if len(unique_firmware) >= 2:  # At least 2 different firmware versions
                    anomalies.append({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "type": "ANOMALY",
                        "anomaly_type": "FIRMWARE_FLIP_FREQUENT",
                        "severity": "HIGH",
                        "target": device_key,
                        "device_name": device.get("device_name", "Unknown"),
                        "ip": device.get("ip", "N/A"),
                        "details": f"Firmware changed {len(unique_firmware)} times in recent updates",
                        "recommended_action": ["ALERT", "AUTO_SECURE"]
                    })
                    baseline["anomaly_count"] += 1
            
            # Check RISK_SPIKE
            if len(baseline["risk_score_history"]) >= 3:
                recent_scores = baseline["risk_score_history"][-3:]
                if len(recent_scores) >= 2:
                    avg_score = statistics.mean(recent_scores[:-1])
                    current_score = recent_scores[-1]
                    
                    # Spike detection: current > avg + threshold OR jump > X
                    spike_threshold = 20
                    jump_threshold = 15
                    
                    if (current_score > avg_score + spike_threshold or 
                        current_score - recent_scores[-2] > jump_threshold):
                        anomalies.append({
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "type": "ANOMALY",
                            "anomaly_type": "RISK_SPIKE",
                            "severity": "HIGH",
                            "target": device_key,
                            "device_name": device.get("device_name", "Unknown"),
                            "ip": device.get("ip", "N/A"),
                            "details": f"Risk score spiked to {current_score:.1f} (avg: {avg_score:.1f})",
                            "recommended_action": ["ALERT", "QUARANTINE_DEVICE"]
                        })
                        baseline["anomaly_count"] += 1
            
            # Check DEVICE_CHANGED_FAST
            if "mutation_count" in device:
                current_mutations = int(device.get("mutation_count", 0))
                if current_mutations > baseline["mutation_count_seen"] + 2:
                    anomalies.append({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "type": "ANOMALY",
                        "anomaly_type": "DEVICE_CHANGED_FAST",
                        "severity": "MEDIUM",
                        "target": device_key,
                        "device_name": device.get("device_name", "Unknown"),
                        "ip": device.get("ip", "N/A"),
                        "details": f"Device mutated rapidly (count: {current_mutations})",
                        "recommended_action": ["ALERT"]
                    })
                    baseline["mutation_count_seen"] = current_mutations
                    baseline["anomaly_count"] += 1
        
        if anomalies:
            self._log(f"Detected {len(anomalies)} device anomalies")
        
        return anomalies
    
    def update_network_baseline(self, flow_info: Dict, session_info: Dict) -> Dict[str, Any]:
        """Update network baseline with current flow and session data."""
        import streamlit as st
        self._ensure_session_state_baselines()
        
        baseline = st.session_state.network_baseline
        current_time = time.time()
        
        # Update flows per minute (simplified - using flow rate if available)
        if "flow_rate" in flow_info:
            baseline["flows_per_minute"] = self._capped_append(
                baseline["flows_per_minute"],
                flow_info["flow_rate"]
            )
        
        # Update average flow probability
        if "avg_prob" in flow_info:
            baseline["avg_flow_prob"] = self._capped_append(
                baseline["avg_flow_prob"],
                flow_info["avg_prob"]
            )
        
        # Update session probability and label
        if "session_prob" in session_info:
            baseline["last_session_prob"] = float(session_info["session_prob"])
        
        if "session_label" in session_info:
            baseline["last_session_label"] = str(session_info["session_label"])
        
        # Update persistence
        if "persistence" in session_info:
            baseline["persistence"] = self._capped_append(
                baseline["persistence"],
                int(session_info["persistence"])
            )
        
        # Calculate attack sessions per minute (simplified)
        is_attack = str(session_info.get("session_label", "")).lower() not in ["benign", "benigntraffic", ""]
        if is_attack:
            baseline["attack_sessions_per_minute"] = self._capped_append(
                baseline["attack_sessions_per_minute"],
                1  # One attack session detected
            )
        else:
            baseline["attack_sessions_per_minute"] = self._capped_append(
                baseline["attack_sessions_per_minute"],
                0  # No attack session
            )
        
        baseline["last_update"] = current_time
        st.session_state.network_baseline = baseline
        
        return {
            "updated": True,
            "last_session_prob": baseline["last_session_prob"],
            "last_session_label": baseline["last_session_label"]
        }
    
    def detect_network_anomalies(self, flow_info: Dict, session_info: Dict) -> List[Dict[str, Any]]:
        """Detect network-level anomalies."""
        import streamlit as st
        self._ensure_session_state_baselines()
        
        baseline = st.session_state.network_baseline
        anomalies = []
        
        # Check ATTACK_RATE_SPIKE
        if len(baseline["attack_sessions_per_minute"]) >= 5:
            recent_attacks = baseline["attack_sessions_per_minute"][-5:]
            avg_attacks = statistics.mean(recent_attacks[:-1])
            current_attacks = recent_attacks[-1]
            
            if current_attacks > avg_attacks + 0.5:  # Spike detection
                anomalies.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "ANOMALY",
                    "anomaly_type": "ATTACK_RATE_SPIKE",
                    "severity": "HIGH",
                    "target": "NETWORK",
                    "device_name": "Network",
                    "ip": "N/A",
                    "details": f"Attack rate spike: {current_attacks:.1f} sessions/min (avg: {avg_attacks:.1f})",
                    "recommended_action": ["ALERT", "AUTO_SECURE"]
                })
        
        # Check PERSISTENCE_HIGH
        if "persistence" in session_info:
            persistence = int(session_info["persistence"])
            if persistence >= 5:  # High persistence threshold
                anomalies.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "ANOMALY",
                    "anomaly_type": "PERSISTENCE_HIGH",
                    "severity": "HIGH",
                    "target": "NETWORK",
                    "device_name": "Network",
                    "ip": "N/A",
                    "details": f"High attack persistence: {persistence} consecutive sessions",
                    "recommended_action": ["ALERT", "BLOCK_IP"]
                })
        
        # Check FLOW_PROB_SURGE
        if len(baseline["avg_flow_prob"]) >= 3:
            recent_probs = baseline["avg_flow_prob"][-3:]
            if len(recent_probs) >= 2:
                avg_prob = statistics.mean(recent_probs[:-1])
                current_prob = recent_probs[-1]
                
                if current_prob > avg_prob + 0.2:  # Probability surge
                    anomalies.append({
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "type": "ANOMALY",
                        "anomaly_type": "FLOW_PROB_SURGE",
                        "severity": "MEDIUM",
                        "target": "NETWORK",
                        "device_name": "Network",
                        "ip": "N/A",
                        "details": f"Flow probability surge: {current_prob:.3f} (avg: {avg_prob:.3f})",
                        "recommended_action": ["ALERT"]
                    })
        
        if anomalies:
            self._log(f"Detected {len(anomalies)} network anomalies")
        
        return anomalies
    
    def get_baseline_summary(self) -> Dict[str, Any]:
        """Get summary of current baselines."""
        import streamlit as st
        self._ensure_session_state_baselines()
        
        device_baselines = st.session_state.device_baselines
        network_baseline = st.session_state.network_baseline
        
        return {
            "device_count": len(device_baselines),
            "total_anomalies": sum(b.get("anomaly_count", 0) for b in device_baselines.values()),
            "network_baseline_age": time.time() - network_baseline.get("last_update", 0),
            "last_check": st.session_state.get("baseline_last_check", 0)
        }
