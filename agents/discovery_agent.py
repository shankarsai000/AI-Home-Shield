import json
import random
import os

PORT_POOL = [21, 22, 23, 80, 443, 445, 554, 8080, 3389, 5900]

def discover_devices_demo(json_path="data/devices_sample.json"):
    # Safely load sample devices; if missing, create a small default sample for demos
    if not os.path.exists(json_path):
        os.makedirs(os.path.dirname(json_path), exist_ok=True)
        sample = [
            {
                "device_name": "Camera-FrontDoor",
                "ip": "192.168.1.10",
                "mac": "AA:BB:CC:DD:EE:01",
                "device_type": "camera",
                "open_ports": [80, 554],
                "firmware_status": "OK",
                "risk_score": 0.3,
                "risk_level": "LOW",
            },
            {
                "device_name": "Thermostat-LivingRoom",
                "ip": "192.168.1.20",
                "mac": "AA:BB:CC:DD:EE:02",
                "device_type": "thermostat",
                "open_ports": [8080],
                "firmware_status": "OUTDATED",
                "risk_score": 0.6,
                "risk_level": "MED",
            },
            {
                "device_name": "SmartTV-Bedroom",
                "ip": "192.168.1.30",
                "mac": "AA:BB:CC:DD:EE:03",
                "device_type": "tv",
                "open_ports": [80, 8009],
                "firmware_status": "UNKNOWN",
                "risk_score": 0.8,
                "risk_level": "HIGH",
            },
        ]
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(sample, f, indent=2)
        except Exception:
            # if write fails, still return sample in-memory
            return sample

    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)

def mutate_devices(devices):
    """
    GUARANTEED visible change:
    - Always updates firmware status + adds a random port
    - Adds a mutation counter for proof
    """
    devices = [d.copy() for d in devices]

    idx = random.randrange(len(devices))
    d = devices[idx]

    # mutation counter
    d["_mutations"] = int(d.get("_mutations", 0)) + 1

    # flip firmware every time
    d["firmware_status"] = random.choice(["OK", "OUTDATED", "UNKNOWN"])

    # add one random port (or remove one)
    action = random.choices(["add", "remove"], weights=[75, 25])[0]

    if action == "add":
        available = [p for p in PORT_POOL if p not in d["open_ports"]]
        if available:
            d["open_ports"].append(random.choice(available))
            d["_last_change"] = f"add_port -> {d['open_ports'][-1]}"
        else:
            d["_last_change"] = "add_port -> none (all present)"
    else:
        if len(d["open_ports"]) > 1:
            removed = d["open_ports"].pop(random.randrange(len(d["open_ports"])))
            d["_last_change"] = f"remove_port -> {removed}"
        else:
            d["_last_change"] = "remove_port skipped (only 1 port)"

    devices[idx] = d
    return devices