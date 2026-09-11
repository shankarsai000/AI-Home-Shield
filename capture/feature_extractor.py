"""
capture/feature_extractor.py

Converts flow records into model-ready feature vectors aligned with
the 46 features defined in models/feature_columns.json.

Architecture ref: Section 4 — "Feature Extractor - produces model-ready
features."

Feature groups (from Section 4):
  Identity:   src/dst IP, MAC, device ID
  Transport:  protocol, src/dst port, TCP flags
  Volume:     packets, bytes, duration
  Timing:     inter-arrival time, burstiness
  Behavioral: destination count, fan-out, port diversity
  Session:    persistence, flow count/window
  Context:    baseline deviation, device risk
"""

import json
import os
import math
from typing import Dict, Any, List, Optional


_FEATURE_COLS_PATH = os.path.join("models", "feature_columns.json")


class FeatureExtractor:
    """
    Transforms a flow record (from FlowBuilder) into a fixed-size
    feature vector matching the model's expected input schema.
    """

    def __init__(self, feature_cols_path: str = _FEATURE_COLS_PATH):
        self.feature_cols: List[str] = []
        try:
            with open(feature_cols_path, "r", encoding="utf-8") as f:
                self.feature_cols = json.load(f)
        except Exception:
            # Fallback: use the known CICIoT feature set
            self.feature_cols = [
                "flow_duration", "Header_Length", "Protocol Type", "Duration",
                "Rate", "Srate", "Drate",
                "fin_flag_number", "syn_flag_number", "rst_flag_number",
                "psh_flag_number", "ack_flag_number", "ece_flag_number",
                "cwr_flag_number", "ack_count", "syn_count", "fin_count",
                "urg_count", "rst_count",
                "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC",
                "TCP", "UDP", "DHCP", "ARP", "ICMP", "IPv", "LLC",
                "Tot sum", "Min", "Max", "AVG", "Std",
                "Tot size", "IAT", "Number",
                "Magnitue", "Radius", "Covariance", "Variance", "Weight",
            ]

    def extract(self, flow: Dict[str, Any]) -> Dict[str, float]:
        """
        Convert a single flow record into a feature dict.

        Returns a dict mapping feature_name -> float value,
        aligned to the model's expected feature_columns.
        """
        features: Dict[str, float] = {}

        dur = float(flow.get("duration", 0) or 0)
        total_pkts = int(flow.get("total_packets", 1) or 1)
        total_bytes = int(flow.get("total_bytes", 0) or 0)
        fwd_pkts = int(flow.get("fwd_packets", 0) or 0)
        bwd_pkts = int(flow.get("bwd_packets", 0) or 0)

        # Duration / timing
        features["flow_duration"] = dur
        features["Duration"] = dur
        features["Header_Length"] = float(flow.get("total_bytes", 0) or 0)

        # Protocol type (numeric)
        proto = str(flow.get("protocol", "TCP")).upper()
        proto_map = {"TCP": 6, "UDP": 17, "ICMP": 1, "OTHER": 0}
        features["Protocol Type"] = float(proto_map.get(proto, 0))

        # Rate features
        safe_dur = max(dur, 0.001)
        features["Rate"] = float(flow.get("rate", total_pkts / safe_dur))
        features["Srate"] = float(flow.get("srate", fwd_pkts / safe_dur))
        features["Drate"] = float(flow.get("drate", bwd_pkts / safe_dur))

        # TCP flag counts
        features["fin_flag_number"] = float(flow.get("fin_count", 0) or 0)
        features["syn_flag_number"] = float(flow.get("syn_count", 0) or 0)
        features["rst_flag_number"] = float(flow.get("rst_count", 0) or 0)
        features["psh_flag_number"] = float(flow.get("psh_count", 0) or 0)
        features["ack_flag_number"] = float(flow.get("ack_count", 0) or 0)
        features["ece_flag_number"] = float(flow.get("ece_count", 0) or 0)
        features["cwr_flag_number"] = float(flow.get("cwr_count", 0) or 0)

        # Duplicate names used in some models
        features["ack_count"] = features["ack_flag_number"]
        features["syn_count"] = features["syn_flag_number"]
        features["fin_count"] = features["fin_flag_number"]
        features["urg_count"] = float(flow.get("urg_count", 0) or 0)
        features["rst_count"] = features["rst_flag_number"]

        # Protocol indicators (binary)
        src_port = int(flow.get("src_port", 0) or 0)
        dst_port = int(flow.get("dst_port", 0) or 0)

        features["HTTP"] = 1.0 if dst_port == 80 or src_port == 80 else 0.0
        features["HTTPS"] = 1.0 if dst_port == 443 or src_port == 443 else 0.0
        features["DNS"] = 1.0 if dst_port == 53 or src_port == 53 else 0.0
        features["Telnet"] = 1.0 if dst_port == 23 or src_port == 23 else 0.0
        features["SMTP"] = 1.0 if dst_port == 25 or src_port == 25 else 0.0
        features["SSH"] = 1.0 if dst_port == 22 or src_port == 22 else 0.0
        features["IRC"] = 1.0 if dst_port == 6667 or src_port == 6667 else 0.0

        features["TCP"] = 1.0 if proto == "TCP" else 0.0
        features["UDP"] = 1.0 if proto == "UDP" else 0.0
        features["DHCP"] = 1.0 if dst_port == 67 or dst_port == 68 else 0.0
        features["ARP"] = 0.0  # ARP doesn't appear in IP flows
        features["ICMP"] = 1.0 if proto == "ICMP" else 0.0
        features["IPv"] = 1.0  # All flows are IP
        features["LLC"] = 0.0  # LLC typically not in flow data

        # Statistical features
        features["Tot sum"] = float(total_bytes)
        features["Tot size"] = float(total_bytes)

        min_size = float(flow.get("min_size", 0) or 0)
        max_size = float(flow.get("max_size", 0) or 0)
        avg_size = float(flow.get("avg_size", 0) or 0)
        std_size = float(flow.get("std_size", 0) or 0)

        features["Min"] = min_size
        features["Max"] = max_size
        features["AVG"] = avg_size
        features["Std"] = std_size

        # IAT
        features["IAT"] = float(flow.get("avg_iat", 0) or 0)

        # Number (total packet count)
        features["Number"] = float(total_pkts)

        # Derived statistical features
        # Magnitude: sqrt(sum of squared sizes) — simplified
        features["Magnitue"] = math.sqrt(total_bytes * avg_size) if total_bytes > 0 else 0.0

        # Radius: spread metric
        features["Radius"] = max_size - min_size if max_size > 0 else 0.0

        # Covariance: simplified as correlation between size and count
        features["Covariance"] = avg_size * total_pkts / max(safe_dur, 1.0)

        # Variance
        features["Variance"] = std_size ** 2

        # Weight: throughput-like metric
        features["Weight"] = total_bytes / safe_dur

        return features

    def extract_vector(self, flow: Dict[str, Any]) -> List[float]:
        """Extract features as an ordered list matching feature_cols."""
        features = self.extract(flow)
        return [features.get(col, 0.0) for col in self.feature_cols]

    def extract_batch(self, flows: List[Dict[str, Any]]) -> List[Dict[str, float]]:
        """Extract features for multiple flows."""
        return [self.extract(f) for f in flows]
