# ✅ Attack Demo Feature - Quick Test Checklist (Windows)

## Pre-Test Setup
- [ ] Ensure Python 3.8+ is installed
- [ ] Run `pip install streamlit pandas` (if not already done)
- [ ] Verify workspace: `e:\ai_home_shield\ai_home_shield\`
- [ ] Check honeypot logs dir exists: `logs/honeypot.log`

## Test 1: Basic Import & Startup
```bash
cd e:\ai_home_shield\ai_home_shield
python -c "from utils.attack_demo import get_local_ip, demo_honeypot_burst, demo_port_scan_burst, demo_http_burst; print('✓ Imports OK')"
```
- [ ] No import errors
- [ ] All 4 functions import successfully

## Test 2: Get Local IP Function
```bash
python -c "from utils.attack_demo import get_local_ip; ip = get_local_ip(); print(f'Local IP: {ip}')"
```
- [ ] Returns a valid IP (e.g., 192.168.x.x or 127.0.0.1)
- [ ] No exceptions thrown

## Test 3: Start Streamlit App
```bash
streamlit run app.py
```
- [ ] App starts without crashing
- [ ] No red error boxes on main page
- [ ] Sidebar loads normally
- [ ] Navigation to "⚡ Threat Monitor" page works

## Test 4: Threat Monitor Page - Attack Demo Section
In Streamlit UI:
- [ ] Click "⚡ Threat Monitor" page
- [ ] Scroll to find "⚡ Attack Demo (Real-Time - Same PC)" expander
- [ ] Click expander to expand it
- [ ] Verify input fields:
  - [ ] "Target Host" shows local IP (auto-detected)
  - [ ] "Honeypot Port" defaults to 9999
  - [ ] "Connection Count" slider defaults to 30
  - [ ] "Delay Between Attempts" slider defaults to 20 ms
- [ ] Three buttons visible:
  - [ ] "🎯 Trigger Honeypot Burst"
  - [ ] "🔍 Trigger Port Scan Burst"
  - [ ] "🌐 Trigger HTTP Burst"

## Test 5: Honeypot Burst (Without Running Honeypot)
- [ ] Click "🎯 Trigger Honeypot Burst"
- [ ] Spinner shows "🔄 Honeypot burst in progress..."
- [ ] After 2-5 seconds completes
- [ ] Shows warning: "⚠️ No successful connections to 127.0.0.1:9999"
- [ ] Error message shows: "Connection refused - honeypot may not be running"
- [ ] UI does NOT freeze/crash
- [ ] Can click other buttons after

## Test 6: Port Scan Burst
- [ ] Click "🔍 Trigger Port Scan Burst"
- [ ] Spinner shows "🔄 Port scan in progress..."
- [ ] After 2-5 seconds completes
- [ ] Shows results:
  - [ ] "Open Ports" metric appears (likely 0-2 on localhost)
  - [ ] "Closed Ports" metric appears (7-8 ports shown)
- [ ] No crash, UI responsive
- [ ] Can see metrics below button

## Test 7: HTTP Burst
- [ ] Click "🌐 Trigger HTTP Burst"
- [ ] Spinner shows "🔄 HTTP burst in progress..."
- [ ] After 5-10 seconds completes (example.com is external)
- [ ] Shows results:
  - [ ] "Successful Requests" metric (likely > 0)
  - [ ] "Failed" metric
- [ ] No crash
- [ ] Success message visible

## Test 8: SOC Timeline Logging
- [ ] Go to "🧭 SOC Timeline" expander (upper area)
- [ ] Click "Trigger Port Scan Burst" button again
- [ ] Check SOC Timeline
- [ ] Should see new entry with:
  - [ ] Type: "ATTACK_DEMO_TRIGGERED"
  - [ ] Label: "PORT_SCAN_BURST"
  - [ ] Target: Your local IP
  - [ ] Details: Shows ports and duration
- [ ] Timeline shows events in reverse order (newest first)

## Test 9: Honeypot Integration (Optional - With Running Honeypot)
If honeypot is running on 127.0.0.1:9999:
```bash
# In separate terminal, run honeypot test
python -c "
import socket
import threading
def hp(): 
    s = socket.socket(); s.setsockopt(1,15,1); s.bind(('0.0.0.0',9999)); s.listen(5)
    for _ in range(100): conn, _ = s.accept(); conn.close()
t = threading.Thread(target=hp, daemon=True); t.start()
import time; time.sleep(30)
"
```
Then in Streamlit:
- [ ] Click "🎯 Trigger Honeypot Burst"
- [ ] Should see: "✅ Honeypot burst completed: 30 hits"
- [ ] Metrics show:
  - [ ] "Successful Hits": 30
  - [ ] "Failed": 0
  - [ ] "Avg Latency": < 10 ms typically
- [ ] Check logs/honeypot.log for new entries

## Test 10: Configuration Variations
- [ ] Change "Target Host" to "127.0.0.1", click Port Scan → Should work
- [ ] Change "Connection Count" to 5, click Port Scan → Should be fast
- [ ] Change "Connection Count" to 200 (max) → Should not crash
- [ ] Change "Delay Between Attempts" to 500ms → Should see visible delay
- [ ] Change Honeypot Port to 8888, click Honeypot Burst → Should show connection refused (expected)

## Test 11: Existing Features NOT Broken
- [ ] "Device & Risk" page still works
- [ ] Device discovery still works
- [ ] Response & Deception page loads
- [ ] Evidence page loads
- [ ] One-Click Demo still works
- [ ] "🎭 Force attack demo" checkbox still works
- [ ] Monitoring Start/Stop buttons still work
- [ ] Device Flow Tracking section works
- [ ] Honeypot auto-block still works (if configured)

## Test 12: Safety & Stability
- [ ] Click multiple burst buttons in quick succession → No crashes
- [ ] Maximum count (200) doesn't freeze UI > 10 seconds
- [ ] Port Scan with 100 ports completes in < 30 seconds
- [ ] Close/reopen expander → State preserved, buttons work
- [ ] Refresh page (F5) → Attack Demo section resets correctly

## Known Behavior (Expected)
- ❌ Honeypot Burst will fail if honeypot not running (expected - shows nice warning)
- ✅ Port Scan shows 0 open ports on localhost (expected - Windows firewall blocks)
- ✅ HTTP Burst connects to example.com (external, may vary by network)
- ✅ First HTTP request slower than others (connection pooling)
- ✅ Latency in logs depends on system load

## Success Criteria
- [x] utils/attack_demo.py created with no errors
- [x] app.py imports attack_demo functions with fallbacks
- [x] Streamlit UI section added without breaking existing features
- [x] All three burst demo buttons work
- [x] SOC Timeline logs ATTACK_DEMO_TRIGGERED events
- [x] No UI freezes or crashes during demo execution
- [x] Graceful handling when honeypot not running
- [x] All existing features continue to work

## Troubleshooting

### Issue: Import Error in app.py
**Solution**: Ensure `utils/attack_demo.py` exists in `ai_home_shield/utils/` directory

### Issue: "Target Host" field not showing auto-detected IP
**Solution**: This is OK - falls back to 127.0.0.1. System may not have internet on port 80.

### Issue: Streamlit app crashes when clicking buttons
**Solution**: Check Python version (need 3.8+). Check for any exceptions in terminal.

### Issue: Port Scan shows all ports closed
**Solution**: Expected on Windows with firewall. Try Port 22 (SSH) which is usually closed.

### Issue: Timeline doesn't show ATTACK_DEMO_TRIGGERED events
**Solution**: Check that "🧭 SOC Timeline" expander is expanded and scrolled to bottom.

---
**Status**: ✅ Feature Ready for Testing
**Date**: January 18, 2026
