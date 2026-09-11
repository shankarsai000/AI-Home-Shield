"""
capture/flow_builder.py

Converts raw packets into bidirectional, time-windowed network flows.

Architecture ref: Section 4 — "Flow Builder - converts packets into
bidirectional/time-windowed flows."

A flow is identified by a 5-tuple (src_ip, dst_ip, src_port, dst_port,
protocol).  Flows are emitted when they time out (idle or active timeout).
"""

import time
import threading
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict


def _flow_key(pkt: dict) -> Tuple[str, str, int, int, str]:
    """Create a canonical bidirectional flow key (smaller IP first)."""
    src = pkt.get("src_ip", "")
    dst = pkt.get("dst_ip", "")
    sport = pkt.get("src_port", 0)
    dport = pkt.get("dst_port", 0)
    proto = pkt.get("proto_name", "OTHER")

    # Canonical ordering: smaller IP first for bidirectional matching
    if (src, sport) <= (dst, dport):
        return (src, dst, sport, dport, proto)
    else:
        return (dst, src, dport, sport, proto)


class FlowBuilder:
    """
    Aggregates individual packets into bidirectional network flows.

    Flows are identified by 5-tuple and expire after idle_timeout or
    active_timeout seconds.
    """

    def __init__(
        self,
        idle_timeout: float = 120.0,
        active_timeout: float = 30.0,
    ):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout

        # Active flows: key -> flow record
        self._flows: Dict[Tuple, Dict[str, Any]] = {}
        self._completed_flows: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._total_flows_emitted = 0

    def add_packet(self, pkt: dict):
        """Add a packet to the flow table.  May emit completed flows."""
        key = _flow_key(pkt)
        now = pkt.get("timestamp", time.time())

        with self._lock:
            if key in self._flows:
                flow = self._flows[key]
                self._update_flow(flow, pkt, now)

                # Check active timeout
                if now - flow["start_time"] > self.active_timeout:
                    self._emit_flow(key)
            else:
                # Create new flow
                self._flows[key] = self._new_flow(key, pkt, now)

    def add_packets(self, packets: List[dict]):
        """Add multiple packets."""
        for pkt in packets:
            self.add_packet(pkt)

    def flush_expired(self) -> List[Dict[str, Any]]:
        """Check for and emit idle-timed-out flows. Returns emitted flows."""
        now = time.time()
        emitted = []
        with self._lock:
            expired_keys = [
                k for k, f in self._flows.items()
                if now - f["last_time"] > self.idle_timeout
            ]
            for key in expired_keys:
                flow = self._finalize_flow(self._flows.pop(key))
                self._completed_flows.append(flow)
                self._total_flows_emitted += 1
                emitted.append(flow)
        return emitted

    def flush_all(self) -> List[Dict[str, Any]]:
        """Force finalize and emit all active and buffered flows."""
        with self._lock:
            for key in list(self._flows.keys()):
                flow = self._finalize_flow(self._flows.pop(key))
                self._completed_flows.append(flow)
                self._total_flows_emitted += 1
            result = list(self._completed_flows)
            self._completed_flows = []
            return result

    def get_completed_flows(self, max_count: int = 500) -> List[Dict[str, Any]]:
        """Drain completed flows from the buffer."""
        with self._lock:
            result = self._completed_flows[:max_count]
            self._completed_flows = self._completed_flows[max_count:]
            return result

    def get_active_flow_count(self) -> int:
        return len(self._flows)

    def get_stats(self) -> Dict[str, Any]:
        return {
            "active_flows": len(self._flows),
            "completed_buffered": len(self._completed_flows),
            "total_emitted": self._total_flows_emitted,
            "idle_timeout": self.idle_timeout,
            "active_timeout": self.active_timeout,
        }

    # ------------------------------------------------------------------
    # Internal flow management
    # ------------------------------------------------------------------
    def _new_flow(self, key: Tuple, pkt: dict, now: float) -> Dict[str, Any]:
        """Create a new flow record from the first packet."""
        flags = pkt.get("tcp_flags", "")
        return {
            "src_ip": key[0],
            "dst_ip": key[1],
            "src_port": key[2],
            "dst_port": key[3],
            "protocol": key[4],
            "start_time": now,
            "last_time": now,
            "duration": 0.0,
            # Counters
            "fwd_packets": 1 if pkt.get("src_ip") == key[0] else 0,
            "bwd_packets": 0 if pkt.get("src_ip") == key[0] else 1,
            "fwd_bytes": pkt.get("length", 0) if pkt.get("src_ip") == key[0] else 0,
            "bwd_bytes": 0 if pkt.get("src_ip") == key[0] else pkt.get("length", 0),
            "total_packets": 1,
            "total_bytes": pkt.get("length", 0),
            # TCP flags
            "syn_count": 1 if "S" in flags else 0,
            "fin_count": 1 if "F" in flags else 0,
            "rst_count": 1 if "R" in flags else 0,
            "psh_count": 1 if "P" in flags else 0,
            "ack_count": 1 if "A" in flags else 0,
            "urg_count": 1 if "U" in flags else 0,
            "ece_count": 1 if "E" in flags else 0,
            "cwr_count": 1 if "C" in flags else 0,
            # Timing
            "packet_times": [now],
            "packet_sizes": [pkt.get("length", 0)],
        }

    def _update_flow(self, flow: Dict[str, Any], pkt: dict, now: float):
        """Update an existing flow with a new packet."""
        flow["last_time"] = now
        flow["total_packets"] += 1
        flow["total_bytes"] += pkt.get("length", 0)
        flow["duration"] = now - flow["start_time"]

        # Direction
        is_fwd = pkt.get("src_ip") == flow["src_ip"]
        if is_fwd:
            flow["fwd_packets"] += 1
            flow["fwd_bytes"] += pkt.get("length", 0)
        else:
            flow["bwd_packets"] += 1
            flow["bwd_bytes"] += pkt.get("length", 0)

        # TCP flags
        flags = pkt.get("tcp_flags", "")
        if "S" in flags: flow["syn_count"] += 1
        if "F" in flags: flow["fin_count"] += 1
        if "R" in flags: flow["rst_count"] += 1
        if "P" in flags: flow["psh_count"] += 1
        if "A" in flags: flow["ack_count"] += 1
        if "U" in flags: flow["urg_count"] += 1
        if "E" in flags: flow["ece_count"] += 1
        if "C" in flags: flow["cwr_count"] += 1

        # Keep timing/size data (cap at 1000 to limit memory)
        if len(flow["packet_times"]) < 1000:
            flow["packet_times"].append(now)
            flow["packet_sizes"].append(pkt.get("length", 0))

    def _emit_flow(self, key: Tuple):
        """Finalize and emit a flow, then remove from active table."""
        if key in self._flows:
            flow = self._finalize_flow(self._flows.pop(key))
            self._completed_flows.append(flow)
            self._total_flows_emitted += 1

    def _finalize_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """Compute final statistics before emitting a flow."""
        flow["duration"] = flow["last_time"] - flow["start_time"]

        times = flow.get("packet_times", [])
        sizes = flow.get("packet_sizes", [])

        # Inter-arrival times
        iats = []
        for i in range(1, len(times)):
            iats.append(times[i] - times[i - 1])

        # Rate calculations
        dur = max(flow["duration"], 0.001)
        flow["rate"] = flow["total_packets"] / dur
        flow["srate"] = flow["fwd_packets"] / dur
        flow["drate"] = flow["bwd_packets"] / dur

        # Size statistics
        if sizes:
            flow["min_size"] = min(sizes)
            flow["max_size"] = max(sizes)
            flow["avg_size"] = sum(sizes) / len(sizes)
            flow["std_size"] = _std(sizes)
        else:
            flow["min_size"] = flow["max_size"] = flow["avg_size"] = flow["std_size"] = 0

        # IAT statistics
        if iats:
            flow["avg_iat"] = sum(iats) / len(iats)
        else:
            flow["avg_iat"] = 0

        # Clean up large lists before emitting
        del flow["packet_times"]
        del flow["packet_sizes"]

        return flow


def _std(values: List[float]) -> float:
    """Standard deviation of a list of numbers."""
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    variance = sum((x - mean) ** 2 for x in values) / len(values)
    return variance ** 0.5
