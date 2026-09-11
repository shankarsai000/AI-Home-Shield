"""
agents/attack_forecasting_agent.py

Predictive intelligence: Future-state forecasting and attack progression.

Architecture ref: Section 5 — "PREDICTIVE PATH - TARGET EXTENSION:
  - Build a time-indexed network state representation
  - Encode state sequences with a temporal model
  - Forecast next network state(s) over K windows
  - Map predicted behavior to attack stages / ATT&CK techniques where defensible
  - Expose probability, horizon, evidence, and uncertainty
  - Feed predictions to orchestration as one signal - never as an unconditional command"
"""

import time
from typing import Dict, Any, List, Optional
import math


class AttackForecastingAgent:
    """
    Predictive intelligence agent that forecasts attack progression and future
    network threat states based on time-series telemetry from NetworkStateAgent.

    Maintains attack stage transitions (Markov / heuristic progression model):
      NORMAL -> RECONNAISSANCE -> INITIAL_ACCESS -> LATERAL_MOVEMENT -> IMPACT / EXFILTRATION
    """

    # ATT&CK-aligned stage taxonomy
    STAGES = [
        "BENIGN_NORMAL",
        "RECONNAISSANCE",
        "INITIAL_ACCESS",
        "LATERAL_MOVEMENT",
        "DENIAL_OF_SERVICE",
        "DATA_EXFILTRATION",
    ]

    STAGE_MITRE_MAP = {
        "BENIGN_NORMAL": "None (Baseline)",
        "RECONNAISSANCE": "T1595 - Active Scanning / Port Scanning",
        "INITIAL_ACCESS": "T1190 - Exploit Public-Facing Application",
        "LATERAL_MOVEMENT": "T1021 - Remote Services / Fan-out",
        "DENIAL_OF_SERVICE": "T1498 - Network Denial of Service (Flooding)",
        "DATA_EXFILTRATION": "T1041 - Exfiltration Over C2 Channel",
    }

    def __init__(self, forecast_horizons: Optional[List[int]] = None):
        """
        Args:
            forecast_horizons: List of time horizons in seconds to forecast (e.g., [15, 30, 60])
        """
        self.horizons = forecast_horizons or [15, 30, 60]
        self._last_forecast: Dict[str, Any] = {}
        self._forecast_history: List[Dict[str, Any]] = []

    def forecast(
        self,
        current_state: Optional[Dict[str, Any]] = None,
        history: Optional[List[Dict[str, Any]]] = None,
        network_state_agent=None,
    ) -> Dict[str, Any]:
        """
        Forecast the next network security state and attack progression over K windows.

        Args:
            current_state: Latest state dict from NetworkStateAgent (or extracted from agent)
            history: List of recent state snapshots
            network_state_agent: Optional NetworkStateAgent instance to pull state/history from

        Returns:
            Dict containing predicted state, probability, horizon, confidence, uncertainty,
            attack stage, MITRE mapping, and evidence indicators.
        """
        if network_state_agent is not None:
            if current_state is None:
                current_state = network_state_agent.get_current_state()
            if history is None:
                history = network_state_agent.get_state_history(limit=20)

        current_state = current_state or {}
        history = history or []

        # Extract current indicators
        attack_ratio = current_state.get("attack_ratio", 0.0)
        avg_attack_prob = current_state.get("avg_attack_prob", 0.0)
        session_prob = current_state.get("session_prob", 0.0)
        session_label = current_state.get("session_label", "BenignTraffic")
        network_anomalies = current_state.get("network_anomalies", 0)
        device_anomalies = current_state.get("device_anomalies", 0)
        honeypot_hits = current_state.get("honeypot_hits", 0)
        honeytoken_trips = current_state.get("honeytoken_trips", 0)
        deception_total = honeypot_hits + honeytoken_trips
        threat_level = current_state.get("threat_level", "LOW")

        # Analyze trajectory from history (derivatives / trends)
        num_snapshots = len(history)
        prob_trend = 0.0
        attack_ratio_trend = 0.0

        if num_snapshots >= 2:
            first_half = history[: num_snapshots // 2]
            second_half = history[num_snapshots // 2 :]

            avg_prob_first = sum(s.get("avg_attack_prob", 0.0) for s in first_half) / len(first_half)
            avg_prob_second = sum(s.get("avg_attack_prob", 0.0) for s in second_half) / len(second_half)
            prob_trend = avg_prob_second - avg_prob_first

            ratio_first = sum(s.get("attack_ratio", 0.0) for s in first_half) / len(first_half)
            ratio_second = sum(s.get("attack_ratio", 0.0) for s in second_half) / len(second_half)
            attack_ratio_trend = ratio_second - ratio_first

        # Estimate attack progression stage and probabilities
        stage_scores = {
            "BENIGN_NORMAL": 1.0,
            "RECONNAISSANCE": 0.0,
            "INITIAL_ACCESS": 0.0,
            "LATERAL_MOVEMENT": 0.0,
            "DENIAL_OF_SERVICE": 0.0,
            "DATA_EXFILTRATION": 0.0,
        }
        evidence: List[str] = []

        # 1. Reconnaissance signals
        if network_anomalies > 0 or "scan" in session_label.lower():
            score = 0.4 + (0.2 * min(network_anomalies, 3))
            stage_scores["RECONNAISSANCE"] += score
            evidence.append(f"Network anomaly count ({network_anomalies}) or scanning patterns detected")

        # 2. Deception triggers -> strong signal for Lateral Movement or Initial Access
        if deception_total > 0:
            stage_scores["LATERAL_MOVEMENT"] += 0.6 + (0.1 * min(deception_total, 4))
            stage_scores["INITIAL_ACCESS"] += 0.5
            evidence.append(f"Deception decoys touched (honeypot={honeypot_hits}, honeytokens={honeytoken_trips})")

        # 3. High attack flow volume / ratio -> Denial of Service
        if attack_ratio > 0.4 or "ddos" in session_label.lower() or "flood" in session_label.lower():
            score = 0.5 + (0.5 * min(attack_ratio, 1.0))
            stage_scores["DENIAL_OF_SERVICE"] += score
            evidence.append(f"High attack flow proportion ({attack_ratio*100:.1f}%) and volumetric pattern")

        # 4. Device anomaly with elevated ML score -> Initial Access or Exfiltration
        if device_anomalies > 0 and (avg_attack_prob > 0.4 or session_prob > 0.5):
            stage_scores["INITIAL_ACCESS"] += 0.4 + 0.3 * avg_attack_prob
            stage_scores["DATA_EXFILTRATION"] += 0.3 + 0.2 * session_prob
            evidence.append(f"Device behavioral deviation coupled with ML anomaly score ({avg_attack_prob:.2f})")

        # Incorporate trends
        if prob_trend > 0.15:
            for s in ["RECONNAISSANCE", "INITIAL_ACCESS", "LATERAL_MOVEMENT", "DENIAL_OF_SERVICE"]:
                stage_scores[s] += 0.2
            evidence.append(f"Accelerating threat trajectory: probability trend (+{prob_trend:.2f})")
        elif prob_trend < -0.15:
            stage_scores["BENIGN_NORMAL"] += 0.3

        # Normalize stage probabilities using Softmax
        max_s = max(stage_scores.values())
        exp_scores = {k: math.exp(v - max_s) for k, v in stage_scores.items()}
        sum_exp = sum(exp_scores.values())
        stage_probs = {k: round(v / sum_exp, 4) for k, v in exp_scores.items()}

        # Pick most probable threat stage (excluding BENIGN if any threat is significant)
        threat_candidates = {k: v for k, v in stage_probs.items() if k != "BENIGN_NORMAL"}
        top_threat_stage = max(threat_candidates, key=threat_candidates.get)
        top_threat_prob = threat_candidates[top_threat_stage]

        if top_threat_prob >= 0.35 or avg_attack_prob > 0.3 or threat_level in ["HIGH", "CRITICAL"]:
            predicted_stage = top_threat_stage
            predicted_prob = top_threat_prob
            future_threat_level = (
                "CRITICAL" if (top_threat_prob > 0.65 or threat_level == "CRITICAL")
                else "HIGH" if (top_threat_prob > 0.45 or threat_level == "HIGH")
                else "MEDIUM"
            )
        else:
            predicted_stage = "BENIGN_NORMAL"
            predicted_prob = stage_probs["BENIGN_NORMAL"]
            future_threat_level = "LOW"

        # Calculate confidence and uncertainty
        # Confidence increases with more observation history and multi-signal alignment
        history_factor = min(num_snapshots / 15.0, 1.0)
        signal_count = sum([
            1 if avg_attack_prob > 0.3 else 0,
            1 if session_prob > 0.5 else 0,
            1 if (device_anomalies + network_anomalies) > 0 else 0,
            1 if deception_total > 0 else 0,
        ])
        signal_factor = min(signal_count / 3.0, 1.0)

        confidence = round(0.4 * history_factor + 0.6 * signal_factor, 3)
        if predicted_stage == "BENIGN_NORMAL" and signal_count == 0:
            confidence = round(max(0.7, 0.5 + 0.5 * history_factor), 3)

        uncertainty = round(1.0 - confidence, 3)

        # Recommended preventive posture
        if future_threat_level == "CRITICAL":
            recommended_posture = "IMMEDIATE_QUARANTINE_OR_BLOCK"
        elif future_threat_level == "HIGH":
            recommended_posture = "PREEMPTIVE_RATE_LIMIT_AND_OBSERVE"
        elif future_threat_level == "MEDIUM":
            recommended_posture = "HEIGHTENED_MONITORING"
        else:
            recommended_posture = "STANDARD_BASELINE"

        # Multi-horizon trajectory forecast
        horizon_projections = {}
        for h in self.horizons:
            # Simple projected probability scaling based on trend
            growth_factor = 1.0 + (prob_trend * (h / 30.0))
            proj_prob = max(0.01, min(0.99, predicted_prob * growth_factor))
            horizon_projections[f"{h}s"] = {
                "projected_prob": round(proj_prob, 3),
                "stage": predicted_stage,
            }

        result = {
            "timestamp": time.time(),
            "horizon": "30s",
            "horizons": horizon_projections,
            "predicted_stage": predicted_stage,
            "probability": round(predicted_prob, 3),
            "confidence": confidence,
            "uncertainty": uncertainty,
            "future_threat_level": future_threat_level,
            "mitre_technique": self.STAGE_MITRE_MAP.get(predicted_stage, "Unknown"),
            "stage_probabilities": stage_probs,
            "recommended_posture": recommended_posture,
            "evidence": evidence or ["Traffic within established baseline variance"],
        }

        self._last_forecast = result
        self._forecast_history.append(result)
        if len(self._forecast_history) > 50:
            self._forecast_history.pop(0)

        return result

    def get_forecast_evidence(self) -> List[str]:
        """Return the evidence items from the most recent forecast."""
        return self._last_forecast.get("evidence", [])

    def get_last_forecast(self) -> Dict[str, Any]:
        """Return the most recent forecast result."""
        return self._last_forecast

    def get_attack_stages(self) -> List[str]:
        """Return the list of recognized attack stages."""
        return list(self.STAGES)
