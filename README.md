# 🛡️ AI Home Shield — Agentic AI IoT Security Appliance

🏆 **3rd Prize Winner — IIT Delhi**  
Selected as **Top 3** from **1100+ teams** at IIT Delhi for building a complete working security product.

AI Home Shield is a **consumer-friendly, plug-and-play Home SOC (Security Operations Center)** that continuously monitors the home network, detects cyber threats using AI, deploys deception (honeypots + honeytokens), and responds autonomously with real firewall-level mitigation.

---

## 🚀 What Problem We Solve

Modern homes have many IoT devices like:
- Smart TVs, Cameras, Bulbs, Speakers
- Routers, Wearables, Appliances

These devices often have:
✅ outdated firmware  
✅ weak configurations  
✅ open ports & insecure services  
✅ no visibility for home users  

**AI Home Shield brings enterprise-style security into home networks.**

---

## ✅ Key Features (Full Working Product)

### 1️⃣ IoT Device Discovery & Risk Profiling
✅ **Device Source Modes**
- 🔵 **Demo Devices (Simulated)**: auto-mutation + realistic risk changes  
- 🟢 **Real Scan Devices (Nmap)**: ARP discovery + MAC/vendor + top-50 port scan

✅ **Device Risk Profiling**
- Risk score + severity: **LOW / MEDIUM / HIGH / CRITICAL**
- Risk tags: open ports, outdated firmware, weak configs

✅ **Auto-Secure Highest Risk Device**
- One-click hardening
- Timeline + score update

---

### 2️⃣ Baseline Modelling + Anomaly Detection (Real Security Intelligence)
✅ Learns “normal behavior” and detects anomalies:

**Device anomalies**
- `NEW_PORT_EXPOSED`
- `FIRMWARE_FLIP_FREQUENT`
- `RISK_SPIKE`
- `DEVICE_CHANGED_FAST`

**Network anomalies**
- `ATTACK_RATE_SPIKE`
- `FLOW_PROB_SURGE`
- `PERSISTENCE_HIGH`

All anomalies are logged into SOC Timeline for evidence.

---

### 3️⃣ Live Threat Monitor (Flow → Session Stability)
✅ Replays network flows (CICIoT sample data) for consistent evaluation  
✅ **PerceptionAgent** predicts per-flow threat probability + label  
✅ **SessionAggregationAgent** stabilizes decisions using sliding window + persistence  
✅ Start/Stop monitoring controls  
✅ Force attack demo mode supported

---

### 4️⃣ SOC-Style Experience (WOW Features)
✅ Real-time red alert banner for attacks  
✅ Alert sound support  
✅ SOC Timeline (last 30 events)
- ATTACK, AUTO_SECURE, BLOCK_IP, QUARANTINE, ANOMALY  
- HONEYPOT_HIT, HONEYTOKEN_TRIP, ORCHESTRATOR_DECISION  
✅ Explainable AI (XAI) panel for “Why attack detected?”  
✅ **Home Shield Score (0–100)** updating live

---

### 5️⃣ Deception Layer (Enterprise Grade)
✅ **Honeypot Server (port 9999)**
- Detects attacker interactions
- Auto-blocks attacker IP on hits

✅ **Honeytokens**
- 4 bait files created with unique IDs
- Supports:
  - real trip detection (file access/change)
  - manual trip option for reliable demos
- Auto-block triggered in Autonomous Mode

Logs stored in:
- `logs/honeytokens.log`

---

### 6️⃣ Response Layer + Real Firewall Blocking (Windows)
✅ Manual response actions:
- ⛔ Block IP
- 🔒 Quarantine Device

✅ Autonomous response:
- Orchestrator can trigger blocking automatically

✅ **FirewallAgent (Windows netsh)**
- Real IP blocking enforced via Windows Firewall rules
- Logged in:
  - `logs/firewall.log`

---

### 7️⃣ Agent Safety + Resilience
✅ **Autonomous Mode Toggle**
✅ **Safe Mode (AUTO / ON / OFF)** to prevent unsafe automation  
✅ Rate-limited alerts to avoid spam  
✅ Graceful fallbacks (demo continuity even if tools/models missing)  
✅ Debug panel: script path, CWD, Nmap status, scanner status

---

## 🎬 Demo Highlights (30-second judge-ready flow)
1. Start One-Click Demo  
2. Trigger real-time “Attack Burst”  
3. Alert banner appears  
4. Orchestrator decides action  
5. Firewall blocks attacker  
6. Timeline + logs update instantly  

---

## 🧠 Tech Stack
- **Python**
- **Streamlit**
- **Nmap** (real device discovery + port scan)
- **Wireshark / tshark** (live traffic capability)
- **Windows Firewall (netsh)** for real blocking
- ML-based IDS agents (Perception + Session Aggregation)
- Agentic orchestrator + baseline anomaly engine

---

## 🏗️ Project Structure
AI_Home_Shield/
├── app.py
├── agents/
├── utils/
├── data/
├── logs/
├── honeytokens/
├── models/
├── requirements.txt


---

## ⚙️ Installation & Run

### ✅ Setup
```bash
pip install -r requirements.txt

streamlit run app.py
⚠️ Run as Administrator (Windows recommended) for firewall blocking to work properly.

🏆 Achievement

🥉 Won 3rd Prize at IIT Delhi
✅ Selected from 1100+ teams
✅ Built and demonstrated as a complete working prototype with real-time response + deception + edge mitigation.

📌 Future Scope

Deploy as router/gateway for whole-home visibility

Mobile notifications + cloud threat intelligence

Device fingerprinting + automated firmware validation

Multi-home fleet dashboard (privacy-safe)

🙌 Acknowledgements

Special thanks to our college management and mentors for supporting us and sponsoring travel from Davangere to Delhi, making this achievement possible.
