# Honeytoken System Test Checklist

## Prerequisites
- Streamlit running as Administrator (for firewall auto-block)
- Autonomous Mode enabled in sidebar

## Test 1: Create Honeytokens
1. In sidebar, click **Create Honeytokens**
2. Expected: Success message with number of tokens created
3. Verify: `honeytokens/` folder created with 4 files:
   - wifi_passwords.txt
   - router_backup.cfg
   - admin_creds.txt
   - smart_camera_config.ini
4. Check `logs/honeytokens.log` for creation entries

## Test 2: Manual Trip (Demo)
1. Select any token from dropdown (e.g., "wifi_passwords.txt (ABC12345)")
2. Click **Manual Trip (Demo)**
3. Expected:
   - Red banner: "🚨 HONEYTOKEN TRIP: wifi_passwords.txt (DEMO)"
   - Timeline entry with type "HONEYTOKEN_TRIP"
   - Home Shield Score decreases by 2 points
   - If Autonomous Mode ON: Auto-block message for DEMO_ATTACKER
4. Check `logs/honeytokens.log` for manual trip entry

## Test 3: Check Trips (Real Access)
1. Open one of the honeytoken files in a text editor
2. Save or modify the file slightly
3. In sidebar, click **Check Trips**
4. Expected:
   - Detection of trip with filename
   - Timeline entry
   - Score decrease
   - Auto-block if Autonomous Mode ON

## Test 4: Honeytoken Agent Status
1. Add this to app temporarily to test status:
   ```python
   agent = st.session_state.get("honeytoken_agent")
   if agent:
       st.json(agent.status())
   ```
2. Verify status shows:
   - num_tokens: 4
   - base_dir: "honeytokens"
   - last_check_time: timestamp

## Test 5: Timeline Integration
1. After any trip, check SOC timeline page
2. Verify entry shows:
   - Type: HONEYTOKEN_TRIP
   - Target: filename
   - Details: Token ID and reason

## Test 6: Firewall Auto-Block
1. Ensure Autonomous Mode is ON
2. Trigger any trip (manual or real)
3. Verify firewall block attempt in UI
4. Check `logs/firewall.log` for block entry

## Cleanup
```powershell
# Remove honeytokens directory
Remove-Item -Recurse -Force honeytokens

# Remove demo firewall rule if created
netsh advfirewall firewall delete rule name="AIHomeShield Block DEMO_ATTACKER"
```

## Expected Log Entries
- `logs/honeytokens.log`: Creation, trips, manual trips
- `logs/firewall.log`: Auto-block entries (if autonomous mode)
- Timeline: HONEYTOKEN_TRIP events
- Score: -2 points per trip
