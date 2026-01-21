# 📊 Network Flow Tracking Feature - Implementation Guide

## Overview
Yes! **You can now track network flows from discovered devices during real-time scanning.**

A new `NetworkFlowTracker` agent has been integrated into AI Home Shield to monitor network flows from all discovered devices in real-time.

---

## Features

### 1. **Real-Time Flow Capture**
- Captures active network connections from Windows `netstat` command
- Tracks both outbound and inbound flows from specified devices
- Configurable capture duration (5-60 seconds)

### 2. **Flow Analysis**
- **Protocol Distribution**: Classifies flows by protocol (HTTP, HTTPS, DNS, SSH, SMB, etc.)
- **Port Analysis**: Identifies which ports are being used
- **Suspicious Detection**: Flags risky ports (23, 445, 3389, 22, 21, 554, 8080, 5900, 53)

### 3. **Flow Statistics**
For each device, tracks:
- Total number of flows
- Outbound flows count
- Inbound flows count  
- Suspicious flows count
- Protocol distribution
- Port distribution
- Flow state (ESTABLISHED, LISTENING, etc.)

### 4. **Integration with Device Scanning**
- Works seamlessly with real-time device discovery
- Links flows to discovered devices via IP address
- Maintains flow logs in `logs/network_flows.log`

---

## How to Use

### Via Streamlit UI

1. **Go to "⚡ Threat Monitor" page**
2. **Expand "📊 Device Flow Tracking"** section
3. **Select a device** from the dropdown (discovered on Devices & Risk page)
4. **Set capture duration** (5-60 seconds)
5. **Click "🔍 Capture Device Flows"**

You'll see:
- ✓ Total flows captured
- ✓ Outbound/Inbound flow counts
- ✓ Suspicious flow alerts
- ✓ Protocol distribution chart
- ✓ Top ports chart
- ✓ Detailed flow tables

### Programmatic Usage

```python
from agents.flow_tracker_agent import NetworkFlowTracker

# Initialize tracker
tracker = NetworkFlowTracker(capture_duration=30)

# Track single device
flow_info = tracker.track_flows_from_device(
    device_ip="192.168.1.10",
    device_name="Smart TV",
    duration=30
)

# Track all devices
devices = [
    {"ip": "192.168.1.1", "device_name": "Router"},
    {"ip": "192.168.1.10", "device_name": "Smart TV"},
    {"ip": "192.168.1.12", "device_name": "Camera"}
]
all_flows = tracker.track_all_devices(devices)

# Get summary
summary = tracker.get_flow_summary("192.168.1.10")
print(summary)

# Export to JSON
filepath = tracker.export_flows_json()
```

---

## Flow Data Structure

### Captured Flow Info
```json
{
  "device_ip": "192.168.1.10",
  "device_name": "Smart TV",
  "timestamp": "2026-01-18T10:30:45.123456",
  "capture_duration": 30,
  "total_flows": 16,
  "outbound_flows": [
    {
      "local": "192.168.1.10:52345",
      "remote": "8.8.8.8:443",
      "state": "ESTABLISHED",
      "direction": "outbound"
    }
  ],
  "inbound_flows": [],
  "protocol_stats": {
    "HTTPS": 8,
    "DNS": 4,
    "OTHER": 4
  },
  "port_stats": {
    "443": 8,
    "53": 4
  },
  "suspicious_flows": [
    {
      "flow": {...},
      "reason": "Risky port 445",
      "severity": "MEDIUM"
    }
  ]
}
```

---

## Key Metrics Tracked

| Metric | Description | Example |
|--------|-------------|---------|
| **Total Flows** | Sum of all active connections | 16 flows |
| **Outbound Flows** | Connections initiated by device | 12 flows |
| **Inbound Flows** | Connections received by device | 4 flows |
| **Suspicious Flows** | Flows to/from risky ports | 2 flows |
| **Protocol Distribution** | Flow breakdown by protocol | HTTP:5, HTTPS:8, DNS:3 |
| **Top Ports** | Most frequently used ports | 443:8, 53:4 |

---

## Risky Ports Detected

The tracker automatically flags connections to these ports:
- **23** - Telnet
- **445** - SMB (Windows file sharing)
- **3389** - RDP (Remote Desktop)
- **22** - SSH
- **21** - FTP
- **554** - RTSP
- **8080** - HTTP Alternate
- **5900** - VNC
- **53** - DNS (sometimes suspicious)

---

## Log Files

### Network Flows Log
**Location**: `logs/network_flows.log`

Contains entries like:
```
[2026-01-18 10:30:45] Captured 16 flows from Smart TV (192.168.1.10)
[2026-01-18 10:31:00] Captured 12 flows from Router (192.168.1.1)
```

---

## Workflow: Device Scanning + Flow Tracking

### Recommended Workflow

1. **📡 Devices & Risk Page**
   - Click "🔍 Scan Devices Now" (Real Scan mode) or use demo mode
   - Devices are discovered and profiled
   - Risk scores calculated

2. **⚡ Threat Monitor Page**
   - Expand "📊 Device Flow Tracking" section
   - Select a discovered device
   - Click "🔍 Capture Device Flows"
   - Analyze network behavior
   - Identify suspicious connections
   - Correlate with threat detection

3. **🧠 Response + Deception Page**
   - Based on flow analysis, take response actions
   - Block suspicious IPs
   - Quarantine high-risk devices
   - Enable honeypots

---

## Integration with Other Agents

### Device Risk Agent
```
Device Discovery → Risk Profiling → Flow Tracking → Response
```

### Threat Detection Pipeline
```
Flow Capture → Flow Analysis → Suspicious Detection → Alert/Block
```

### Baseline Agent
```
Establish baseline flows → Detect anomalies in flow patterns
```

---

## Limitations & Notes

⚠️ **Windows netstat-based**: Captures flows visible to the Windows system
- Limited to local machine's routing table
- Doesn't capture packets on other interfaces
- Admin privileges recommended for full accuracy

✓ **Real-time**: Provides snapshot of active flows
- Not continuous packet capture (use tcpdump/Wireshark for that)
- Configurable capture window (5-60 seconds)

✓ **Integrated**: Works with all discovered devices
- Demo devices: Uses IP-based flow matching
- Real scanned devices: Uses actual network flows

---

## Advanced Usage

### Bulk Device Flow Analysis
```python
from agents.flow_tracker_agent import NetworkFlowTracker
import pandas as pd

tracker = NetworkFlowTracker()

# Get flows from all critical devices
critical_devices = [d for d in devices if d.get('risk_level') == 'CRITICAL']
flows = tracker.track_all_devices(critical_devices)

# Export to CSV
flows_data = []
for flow_info in flows:
    flows_data.append({
        'device': flow_info['device_name'],
        'ip': flow_info['device_ip'],
        'total_flows': flow_info['total_flows'],
        'suspicious': len(flow_info['suspicious_flows']),
        'protocols': str(flow_info['protocol_stats'])
    })

df = pd.DataFrame(flows_data)
df.to_csv('logs/device_flows_analysis.csv', index=False)
```

### Automated Flow Monitoring
```python
import time
from agents.flow_tracker_agent import NetworkFlowTracker

tracker = NetworkFlowTracker()

# Monitor device every 5 minutes
for i in range(12):  # Monitor for 1 hour
    flows = tracker.track_flows_from_device("192.168.1.10", "Smart TV")
    
    if len(flows['suspicious_flows']) > 5:
        print(f"⚠️ ALERT: Device showing suspicious activity!")
        # Trigger response actions
    
    time.sleep(300)  # 5 minutes
```

---

## Summary

✅ **Real-time flow tracking from discovered devices**  
✅ **Protocol and port analysis**  
✅ **Suspicious activity detection**  
✅ **Seamless integration with device scanning**  
✅ **Full logging and export capabilities**  

**You can now monitor both device health AND network behavior in real-time!**
