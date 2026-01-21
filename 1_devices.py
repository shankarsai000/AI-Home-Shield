import streamlit as st
import pandas as pd
import time

from utils.device_scanner_win import discover_devices, scan_ports

st.set_page_config(page_title="Devices", layout="wide")
st.title("📡 AI Home Shield — Devices")

st.subheader("📡 Real-time Device Discovery (Windows + Nmap Safe Mode)")

subnet = st.text_input("Subnet to scan", value="172.24.118.0/24")

col1, col2 = st.columns([1, 1])
scan_now = col1.button("🔍 Scan Devices Now")
auto_refresh = col2.toggle("🔁 Auto refresh (10s)", value=False)

if "rt_devices" not in st.session_state:
    st.session_state["rt_devices"] = []

if scan_now or auto_refresh:
    st.session_state["rt_devices"] = discover_devices(subnet=subnet)

devices = st.session_state["rt_devices"]

if devices:
    df = pd.DataFrame(devices)
    st.dataframe(df, use_container_width=True)

    st.markdown("### ⚡ Port Scan (Safe Top-50)")

    selected_ip = st.selectbox("Select device IP", df["ip"].tolist())

    if "ports_by_ip" not in st.session_state:
        st.session_state["ports_by_ip"] = {}

    if st.button("🧪 Scan Ports"):
        st.session_state["ports_by_ip"][selected_ip] = scan_ports(selected_ip)

    ports = st.session_state["ports_by_ip"].get(selected_ip, [])

    if ports:
        st.success(f"Open ports for {selected_ip}")
        st.dataframe(pd.DataFrame(ports), use_container_width=True)
    else:
        st.info("No open ports found (phones are usually closed by default ✅).")

else:
    st.warning("No devices scanned yet. Click **Scan Devices Now**.")

if auto_refresh:
    time.sleep(10)
    st.rerun()
