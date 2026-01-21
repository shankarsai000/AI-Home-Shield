import time
import streamlit as st

from agents.discovery_agent import discover_devices_demo, mutate_devices

st.set_page_config(page_title="Device Sim Test", layout="wide")
st.title("✅ Real-time Device Simulation TEST")

# init
if "devices" not in st.session_state:
    st.session_state.devices = discover_devices_demo()

if "tick" not in st.session_state:
    st.session_state.tick = 0

auto = st.checkbox("Enable Auto Simulation", value=False)
refresh = st.slider("Refresh seconds", 1, 5, 2)

st.write("Tick:", st.session_state.tick)

# show first device BEFORE
st.subheader("Before Mutation (Device 0)")
st.json(st.session_state.devices[0])

if auto:
    time.sleep(refresh)
    st.session_state.tick += 1
    st.session_state.devices = mutate_devices(st.session_state.devices)
    st.rerun()

# show first device AFTER
st.subheader("After Mutation (Device 0)")
st.json(st.session_state.devices[0])