# Baseline Modelling + Anomaly Detection Test Checklist

## Prerequisites
- Streamlit running
- Demo mode enabled for device mutations
- Threat Monitor can be started

## Test 1: Device Baseline Creation
1. Go to **Devices & Risk** page
2. Enable **Real-time Device Simulation** in sidebar
3. Wait for 2-3 device mutations
4. Expected:
   - Baselines created for each device
   - `logs/baseline.log` shows "Created baseline for device"
   - No anomalies initially (first run)

## Test 2: NEW_PORT_EXPOSED Anomaly
1. In **Devices & Risk**, manually scan a device's ports
2. Add a new port (e.g., 8080) to the device
3. Wait for next auto-refresh or trigger manual refresh
4. Expected:
   - 🟡 **NEW_PORT_EXPOSED** anomaly in "📌 Baseline Anomalies"
   - Timeline entry with ANOMALY type
   - Details show new port number

## Test 3: RISK_SPIKE Anomaly
1. Force a device's risk score to increase rapidly
2. Can use **Auto Secure Highest Risk Device** to trigger changes
3. Expected:
   - 🔴 **RISK_SPIKE** anomaly
   - Score decrease in Home Shield Score (-3 points)
   - Recommended action includes QUARANTINE_DEVICE

## Test 4: DEVICE_CHANGED_FAST Anomaly
1. Enable rapid device mutations (set refresh to 1 second)
2. Let devices mutate multiple times quickly
3. Expected:
   - 🟡 **DEVICE_CHANGED_FAST** anomalies
   - Details show mutation count

## Test 5: Network Baseline - ATTACK_RATE_SPIKE
1. Go to **Threat Monitor** page
2. Click **▶ Start Monitoring**
3. Enable **🎭 Force attack demo**
4. Expected:
   - 🔴 **ATTACK_RATE_SPIKE** in "🌐 Network Anomalies"
   - Timeline entry for network anomaly
   - Score decrease (-3 points)

## Test 6: Network Baseline - PERSISTENCE_HIGH
1. In Threat Monitor, let attacks run for multiple cycles
2. Persistence will accumulate in session window
3. Expected:
   - 🔴 **PERSISTENCE_HIGH** when persistence >= 5
   - Details show persistence count

## Test 7: Network Baseline - FLOW_PROB_SURGE
1. Monitor normal traffic, then inject high-probability flows
2. Expected:
   - 🟡 **FLOW_PROB_SURGE** anomaly
   - Details show probability values

## Test 8: Timeline Integration
1. Trigger any anomaly
2. Go to **Evidence** page or check timeline in Threat Monitor
3. Expected:
   - ANOMALY events in timeline
   - Label shows anomaly type
   - Details include severity and recommendations

## Test 9: Score Impact
1. Trigger HIGH severity anomalies
2. Watch Home Shield Score in top banner
3. Expected:
   - Score decreases by 3 points per HIGH anomaly
   - MEDIUM anomalies don't affect score

## Test 10: Baseline Persistence
1. Stop/start Streamlit
2. Expected:
   - Baselines reset (session_state only)
   - New baselines created on first run

## Expected Log Entries
- `logs/baseline.log`:
  - "Created baseline for device: ..."
  - "Updated baseline for X devices"
  - "Detected X device/network anomalies"

## UI Elements to Verify
- **Devices & Risk** page: "📌 Baseline Anomalies" section
- **Threat Monitor** page: "🌐 Network Anomalies" section
- Timeline: ANOMALY type events
- Home Shield Score: Decreases on HIGH anomalies

## Cleanup
No cleanup needed - baselines are in memory only and reset on restart
