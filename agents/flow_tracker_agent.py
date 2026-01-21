#!/usr/bin/env python
"""
Network Flow Tracker for Real-Time Device Monitoring
Tracks network flows from discovered devices during real-time scanning
"""
import time
import subprocess
import re
from typing import List, Dict, Optional
from datetime import datetime
import json

class NetworkFlowTracker:
    """Track network flows from discovered devices in real-time."""
    
    def __init__(self, capture_duration: int = 30):
        """
        Initialize flow tracker.
        
        Args:
            capture_duration: Duration to capture flows (in seconds)
        """
        self.capture_duration = capture_duration
        self.flows = []
        self.device_flows = {}  # flows per device
        self.log_file = "logs/network_flows.log"
        self._ensure_log()
    
    def _ensure_log(self):
        """Ensure log file exists."""
        import os
        os.makedirs("logs", exist_ok=True)
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w") as f:
                f.write("")
    
    def _log(self, message: str):
        """Log flow tracking events."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(self.log_file, "a") as f:
                f.write(f"[{timestamp}] {message}\n")
        except Exception:
            pass
    
    def track_flows_from_device(self, device_ip: str, device_name: str, duration: int = None) -> Dict:
        """
        Track network flows from a specific device.
        
        Uses netstat or similar to capture flows.
        
        Args:
            device_ip: IP address of the device
            device_name: Name of the device
            duration: Capture duration (default from init)
            
        Returns:
            Dict with flow statistics
        """
        if duration is None:
            duration = self.capture_duration
        
        flow_info = {
            "device_ip": device_ip,
            "device_name": device_name,
            "timestamp": datetime.now().isoformat(),
            "capture_duration": duration,
            "outbound_flows": [],
            "inbound_flows": [],
            "protocol_stats": {},
            "port_stats": {},
            "total_flows": 0,
            "suspicious_flows": []
        }
        
        try:
            # Use netstat to get active connections
            flows = self._capture_netstat_flows(device_ip)
            flow_info["outbound_flows"] = flows.get("outbound", [])
            flow_info["inbound_flows"] = flows.get("inbound", [])
            flow_info["total_flows"] = len(flows.get("outbound", [])) + len(flows.get("inbound", []))
            
            # Analyze flows
            flow_info["protocol_stats"] = self._analyze_protocols(flows)
            flow_info["port_stats"] = self._analyze_ports(flows)
            flow_info["suspicious_flows"] = self._detect_suspicious(flows)
            
            self._log(f"Captured {flow_info['total_flows']} flows from {device_name} ({device_ip})")
            
        except Exception as e:
            self._log(f"Failed to capture flows from {device_ip}: {e}")
        
        return flow_info
    
    def _capture_netstat_flows(self, device_ip: str) -> Dict:
        """
        Capture network flows using netstat.
        
        Args:
            device_ip: Target device IP
            
        Returns:
            Dict with outbound and inbound flows
        """
        flows = {"outbound": [], "inbound": []}
        
        try:
            # Get active TCP connections
            cmd = "netstat -ano -p TCP"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            output = result.stdout
            
            # Parse netstat output
            for line in output.split('\n'):
                if not line.strip() or "ESTABLISHED" not in line:
                    continue
                
                parts = line.split()
                if len(parts) < 4:
                    continue
                
                local_addr = parts[1]
                remote_addr = parts[2]
                state = parts[3]
                
                # Check if flow involves our device
                if device_ip in local_addr:
                    flows["outbound"].append({
                        "local": local_addr,
                        "remote": remote_addr,
                        "state": state,
                        "direction": "outbound",
                        "timestamp": time.time()
                    })
                elif device_ip in remote_addr:
                    flows["inbound"].append({
                        "local": local_addr,
                        "remote": remote_addr,
                        "state": state,
                        "direction": "inbound",
                        "timestamp": time.time()
                    })
        
        except Exception as e:
            self._log(f"Netstat capture failed: {e}")
        
        return flows
    
    def _analyze_protocols(self, flows: Dict) -> Dict:
        """Analyze protocol distribution in flows."""
        stats = {}
        
        for direction in ["outbound", "inbound"]:
            for flow in flows.get(direction, []):
                remote = flow.get("remote", "")
                if ":" in remote:
                    port = remote.split(":")[-1]
                    protocol = self._classify_protocol(port)
                    stats[protocol] = stats.get(protocol, 0) + 1
        
        return stats
    
    def _analyze_ports(self, flows: Dict) -> Dict:
        """Analyze destination port distribution."""
        stats = {}
        
        for direction in ["outbound", "inbound"]:
            for flow in flows.get(direction, []):
                addr = flow.get("remote", "") if direction == "outbound" else flow.get("local", "")
                if ":" in addr:
                    port = int(addr.split(":")[-1])
                    stats[port] = stats.get(port, 0) + 1
        
        return stats
    
    def _classify_protocol(self, port: str) -> str:
        """Classify protocol from port number."""
        try:
            port_num = int(port)
        except (ValueError, TypeError):
            return "UNKNOWN"
        
        protocol_map = {
            80: "HTTP",
            443: "HTTPS",
            53: "DNS",
            22: "SSH",
            23: "TELNET",
            25: "SMTP",
            110: "POP3",
            143: "IMAP",
            445: "SMB",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
        }
        
        return protocol_map.get(port_num, f"OTHER({port_num})")
    
    def _detect_suspicious(self, flows: Dict) -> List[Dict]:
        """Detect suspicious flows."""
        suspicious = []
        risky_ports = {23, 445, 3389, 22, 21, 554, 8080, 5900, 53}
        
        for direction in ["outbound", "inbound"]:
            for flow in flows.get(direction, []):
                addr = flow.get("remote", "") if direction == "outbound" else flow.get("local", "")
                
                if ":" in addr:
                    try:
                        port = int(addr.split(":")[-1])
                        if port in risky_ports:
                            suspicious.append({
                                "flow": flow,
                                "reason": f"Risky port {port}",
                                "severity": "MEDIUM"
                            })
                    except (ValueError, TypeError):
                        pass
        
        return suspicious
    
    def track_all_devices(self, devices: List[Dict]) -> List[Dict]:
        """
        Track flows from all discovered devices.
        
        Args:
            devices: List of device dicts with 'ip' and 'device_name'
            
        Returns:
            List of flow info dicts
        """
        all_flows = []
        
        for device in devices:
            device_ip = device.get("ip")
            device_name = device.get("device_name")
            
            if not device_ip or not device_name:
                continue
            
            flow_info = self.track_flows_from_device(device_ip, device_name)
            all_flows.append(flow_info)
            self.device_flows[device_ip] = flow_info
            
            # Small delay between captures
            time.sleep(0.5)
        
        return all_flows
    
    def get_flow_summary(self, device_ip: str) -> Dict:
        """Get summary of flows for a device."""
        if device_ip not in self.device_flows:
            return {"error": "No flow data for this device"}
        
        flows = self.device_flows[device_ip]
        
        return {
            "device_ip": device_ip,
            "device_name": flows.get("device_name"),
            "total_flows": flows.get("total_flows", 0),
            "protocols": flows.get("protocol_stats", {}),
            "top_ports": sorted(
                flows.get("port_stats", {}).items(),
                key=lambda x: x[1],
                reverse=True
            )[:5],
            "suspicious_count": len(flows.get("suspicious_flows", [])),
            "outbound_count": len(flows.get("outbound_flows", [])),
            "inbound_count": len(flows.get("inbound_flows", []))
        }
    
    def export_flows_json(self, filepath: str = None) -> str:
        """Export captured flows to JSON file."""
        if filepath is None:
            filepath = f"logs/flows_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filepath, "w") as f:
                json.dump(self.device_flows, f, indent=2, default=str)
            self._log(f"Exported flows to {filepath}")
            return filepath
        except Exception as e:
            self._log(f"Failed to export flows: {e}")
            return None


if __name__ == "__main__":
    # Test the flow tracker
    print("\n" + "="*60)
    print("NETWORK FLOW TRACKER TEST")
    print("="*60)
    
    tracker = NetworkFlowTracker()
    
    print("\n[TEST] Tracking flows from localhost...")
    flow_info = tracker.track_flows_from_device("127.0.0.1", "LocalHost")
    
    print(f"\nFlow Summary:")
    print(f"  - Total flows: {flow_info['total_flows']}")
    print(f"  - Protocols: {flow_info['protocol_stats']}")
    print(f"  - Top ports: {list(flow_info['port_stats'].items())[:5]}")
    print(f"  - Suspicious: {len(flow_info['suspicious_flows'])}")
    
    print("\n✓ Flow tracker is ready to use!")
