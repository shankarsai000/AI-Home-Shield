# Attack Demo Feature - Code Reference & Usage Guide

## 📦 Implementation Overview

```
ai_home_shield/
├── utils/
│   ├── attack_demo.py          ✅ NEW (250 lines)
│   ├── device_scanner_win.py
│   └── __init__.py
├── app.py                       ✅ MODIFIED (+130 lines)
├── ATTACK_DEMO_IMPLEMENTATION.md    ✅ NEW
├── ATTACK_DEMO_TEST_CHECKLIST.md    ✅ NEW
└── ...
```

---

## 🔧 API Reference

### `utils/attack_demo.py`

#### 1. `get_local_ip() → str`
**Purpose**: Auto-detect local IP address for attack demo target

**Returns**: 
- Local IP (e.g., "192.168.1.100") if available
- "127.0.0.1" as fallback

**Example**:
```python
from utils.attack_demo import get_local_ip

ip = get_local_ip()
print(ip)  # Output: 192.168.1.100 or 127.0.0.1
```

---

#### 2. `demo_honeypot_burst(host: str, port: int, count: int = 30, delay_ms: int = 20) → dict`
**Purpose**: Generate rapid socket connections to honeypot (simulates honeypot hits)

**Parameters**:
| Param | Type | Default | Range | Description |
|-------|------|---------|-------|-------------|
| `host` | str | - | any | Target IP/hostname |
| `port` | int | - | 1-65535 | Target port |
| `count` | int | 30 | 1-200 | Number of connections |
| `delay_ms` | int | 20 | 1-500 | Delay between attempts (ms) |

**Returns**:
```python
{
    "ok": True,                      # Success flag
    "message": "✓ Honeypot burst completed: 30 hits",
    "error": "",
    "stats": {
        "total_attempts": 30,
        "successful": 30,
        "failed": 0,
        "duration_seconds": 0.85,
        "avg_latency_ms": 28.3
    }
}
```

**Example Usage**:
```python
from utils.attack_demo import demo_honeypot_burst

result = demo_honeypot_burst(
    host="127.0.0.1",
    port=9999,
    count=50,
    delay_ms=15
)

if result["ok"]:
    print(f"Hits: {result['stats']['successful']}")
    print(f"Avg latency: {result['stats']['avg_latency_ms']} ms")
else:
    print(f"Failed: {result['error']}")
```

**Expected Failures**:
- Connection refused → "honeypot may not be running"
- Timeout → "Network unreachable"

---

#### 3. `demo_port_scan_burst(host: str, ports: List[int] = None, delay_ms: int = 20) → dict`
**Purpose**: Simulate port scan by attempting connections to multiple ports

**Parameters**:
| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | str | - | Target IP/hostname |
| `ports` | list | [21,22,23,80,443,9999,3389,5900] | Ports to scan |
| `delay_ms` | int | 20 | Delay between attempts (ms) |

**Returns**:
```python
{
    "ok": True,
    "message": "✓ Port scan burst completed: 2 open, 6 closed",
    "error": "",
    "stats": {
        "total_attempts": 8,
        "open_ports": [80, 443],
        "closed_ports": [21, 22, 23, 9999, 3389, 5900],
        "duration_seconds": 4.2
    }
}
```

**Example**:
```python
from utils.attack_demo import demo_port_scan_burst

# Scan custom ports
result = demo_port_scan_burst(
    host="192.168.1.100",
    ports=[22, 80, 443, 3306, 5432],
    delay_ms=100
)

print(f"Open: {result['stats']['open_ports']}")
```

---

#### 4. `demo_http_burst(url: str = "http://example.com", count: int = 30, delay_ms: int = 20) → dict`
**Purpose**: Generate HTTP request burst traffic

**Parameters**:
| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | str | http://example.com | Target URL |
| `count` | int | 30 | Number of requests |
| `delay_ms` | int | 20 | Delay between requests (ms) |

**Returns**:
```python
{
    "ok": True,
    "message": "✓ HTTP burst completed: 30 requests",
    "error": "",
    "stats": {
        "total_requests": 30,
        "successful": 29,
        "failed": 1,
        "duration_seconds": 8.5
    }
}
```

**Example**:
```python
from utils.attack_demo import demo_http_burst

result = demo_http_burst(
    url="http://192.168.1.50:8080",
    count=100,
    delay_ms=50
)

print(f"Success rate: {result['stats']['successful'] / result['stats']['total_requests'] * 100:.0f}%")
```

---

## 🎨 Streamlit Integration

### UI Location
**Page**: ⚡ Threat Monitor  
**Section**: "⚡ Attack Demo (Real-Time - Same PC)" (expandable)

### Input Controls
```
┌─────────────────────────────────────────────────┐
│ ⚡ Attack Demo (Real-Time - Same PC)             │ ◄─ Expander
│                                                  │
│ Target Host:        [192.168.1.100           ]  │
│ Honeypot Port:      [9999                    ]  │
│ Connection Count:   [████████░░░░░░░░░░░░░] 30  │
│ Delay (ms):         [████░░░░░░░░░░░░░░░░░░] 20  │
│                                                  │
│ [🎯 Trigger Honeypot Burst] [🔍 Port Scan] ... │
└─────────────────────────────────────────────────┘
```

### Button Functions

#### Button 1: "🎯 Trigger Honeypot Burst"
```
On Click:
├─ Show spinner: "🔄 Honeypot burst in progress..."
├─ Call: demo_honeypot_burst(target_host, honeypot_port, count, delay_ms)
├─ If success:
│  ├─ Show: "✅ Honeypot burst completed: X hits"
│  ├─ Display metrics: Successful Hits | Failed | Avg Latency
│  └─ Log timeline: ATTACK_DEMO_TRIGGERED / HONEYPOT_BURST
└─ If failed:
   └─ Show: "⚠️ No successful connections..."
```

#### Button 2: "🔍 Trigger Port Scan Burst"
```
On Click:
├─ Scan ports: [21, 22, 23, 80, 443, 9999, 3389, 5900]
├─ Call: demo_port_scan_burst(target_host, ports, delay_ms)
├─ If success:
│  ├─ Show: "✅ Port scan burst completed: X open, Y closed"
│  ├─ Display metrics: Open Ports | Closed Ports
│  └─ Log timeline: ATTACK_DEMO_TRIGGERED / PORT_SCAN_BURST
└─ If failed: Show warning
```

#### Button 3: "🌐 Trigger HTTP Burst"
```
On Click:
├─ Target: http://example.com
├─ Call: demo_http_burst(url, count, delay_ms)
├─ If success:
│  ├─ Show: "✅ HTTP burst completed: X requests"
│  ├─ Display metrics: Successful Requests | Failed
│  └─ Log timeline: ATTACK_DEMO_TRIGGERED / HTTP_BURST
└─ If failed: Show warning
```

### Timeline Integration
Each trigger logs to "🧭 SOC Timeline" (visible in Timeline expander):

**Example Timeline Entry**:
```
Time        Type                  Label           Target              Details
22:45:13    ATTACK_DEMO_TRIGGERED HONEYPOT_BURST 127.0.0.1:9999     Hits: 30, Duration: 0.85s
22:45:25    ATTACK_DEMO_TRIGGERED PORT_SCAN_BURST 127.0.0.1          Open: [80, 443], Duration: 4.2s
22:45:35    ATTACK_DEMO_TRIGGERED HTTP_BURST      http://example.com Requests: 25, Duration: 8.5s
```

---

## 🧪 Quick Start - Testing

### Test 1: Basic Import
```bash
cd e:\ai_home_shield\ai_home_shield
python -c "from utils.attack_demo import get_local_ip; print(get_local_ip())"
```
✅ Expected: Valid IP (e.g., 192.168.1.100 or 127.0.0.1)

### Test 2: Run App
```bash
streamlit run app.py
```
✅ Expected: App starts, no red error boxes

### Test 3: Navigate to Feature
1. Open browser at `http://localhost:8501`
2. Click "⚡ Threat Monitor" page
3. Scroll down to "⚡ Attack Demo (Real-Time - Same PC)"
4. Click expander to expand section

### Test 4: Try Port Scan (No Dependencies)
1. Set Target Host: `127.0.0.1`
2. Click "🔍 Trigger Port Scan Burst"
3. Wait 5-10 seconds
4. Should show: "Open Ports: 0, Closed Ports: 8" (typical for local Windows)

### Test 5: Check Timeline
1. Scroll to "🧭 SOC Timeline" expander at top
2. Expand it
3. Should see new entry with `ATTACK_DEMO_TRIGGERED` type

---

## 🔐 Safety Features

| Feature | Implementation | Benefit |
|---------|-----------------|---------|
| Max count cap | `count = min(count, 200)` | Prevents abuse |
| Min delay | `delay = max(delay, 1ms)` | Prevents CPU spike |
| Timeouts | 1-2 sec per connection | No hanging |
| Try/except | All I/O wrapped | No crashes |
| Graceful errors | Connection refused handled | Honeypot-optional |
| No threads | Sequential execution | UI responsive |
| Small delays | 5-500ms configurable | No blocking |

---

## 🚀 Example: Full Attack Demo Flow

**Scenario**: Demonstrating honeypot + port scan detection

```python
# In Streamlit app:
import streamlit as st
from utils.attack_demo import get_local_ip, demo_honeypot_burst, demo_port_scan_burst

# Get target
local_ip = get_local_ip()
st.text_input("Target", value=local_ip)

# Trigger honeypot burst
if st.button("Start Demo"):
    # Phase 1: Honeypot burst
    result1 = demo_honeypot_burst(local_ip, 9999, count=50, delay_ms=10)
    st.write(f"Phase 1 - Honeypot: {result1['message']}")
    
    # Phase 2: Port scan
    result2 = demo_port_scan_burst(local_ip, [22, 80, 443], delay_ms=100)
    st.write(f"Phase 2 - Port Scan: {result2['message']}")
    
    # Both logged to timeline automatically
    st.success("Demo complete! Check timeline for events.")
```

---

## 🔧 Extending the Feature

### Add a New Attack Demo Type

1. **Create function in `utils/attack_demo.py`**:
```python
def demo_custom_burst(target: str, **kwargs) -> dict:
    """Your attack simulation"""
    try:
        # Your logic here
        return {
            "ok": True,
            "message": "Custom burst complete",
            "error": "",
            "stats": {"custom_metric": 42}
        }
    except Exception as e:
        return {
            "ok": False,
            "message": "Custom burst failed",
            "error": str(e),
            "stats": {}
        }
```

2. **Add import in `app.py`**:
```python
from utils.attack_demo import ..., demo_custom_burst
```

3. **Add button in Attack Demo section**:
```python
if st.button("🔥 Trigger Custom Burst"):
    result = demo_custom_burst(attack_target_host)
    # ... handle result, log timeline
```

---

## 📋 Checklist: Running Attack Demo

- [ ] Open Streamlit app
- [ ] Navigate to "⚡ Threat Monitor"
- [ ] Find "⚡ Attack Demo (Real-Time - Same PC)" section
- [ ] Set target host (auto-filled)
- [ ] Adjust sliders (optional)
- [ ] Click desired trigger button
- [ ] Watch spinner while executing
- [ ] See results + metrics
- [ ] Check "🧭 SOC Timeline" for ATTACK_DEMO_TRIGGERED event

---

**Last Updated**: January 18, 2026  
**Status**: ✅ Production Ready
