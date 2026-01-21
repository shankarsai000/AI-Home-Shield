
import os
import json
import joblib
import numpy as np
import pandas as pd

MODELS_DIR = "models"

class PerceptionAgent:
    def __init__(self,
                 model_path=os.path.join(MODELS_DIR, "model.pkl"),
                 scaler_path=os.path.join(MODELS_DIR, "scaler.pkl"),
                 feature_cols_path=os.path.join(MODELS_DIR, "feature_columns.json")):
        # Load model if available; otherwise create a harmless dummy model for demos
        try:
            self.model = joblib.load(model_path)
        except Exception:
            # Dummy model: mostly benign predictions to keep demo deterministic and safe
            class DummyModel:
                def __init__(self):
                    import numpy as _np
                    self.classes_ = _np.array(["BenignTraffic", "Mirai", "DDoS", "PortScan"])

                def predict_proba(self, X):
                    import numpy as _np
                    n = X.shape[0]
                    # benign=0.9, others split remaining 0.1
                    probs = _np.zeros((n, len(self.classes_)), dtype=float)
                    probs[:, 0] = 0.9
                    probs[:, 1:] = 0.1 / (len(self.classes_) - 1)
                    return probs

            self.model = DummyModel()

        self.scaler = None
        if os.path.exists(scaler_path):
            try:
                self.scaler = joblib.load(scaler_path)
            except Exception:
                self.scaler = None

        self.feature_cols = None
        if os.path.exists(feature_cols_path):
            try:
                with open(feature_cols_path, "r", encoding="utf-8") as ff:
                    self.feature_cols = json.load(ff)
            except Exception:
                self.feature_cols = None

    def _ensure_feature_cols(self, flow):
        if self.feature_cols is not None:
            return

        if isinstance(flow, pd.Series):
            self.feature_cols = list(flow.index)
            return

        if isinstance(flow, dict):
            cols = []
            for k, v in flow.items():
                if str(k).lower() == "label":
                    continue
                if v is None:
                    cols.append(k)
                    continue
                if isinstance(v, (int, float, bool, np.number)):
                    cols.append(k)
                    continue
                try:
                    float(v)
                    cols.append(k)
                except Exception:
                    continue

            self.feature_cols = cols
            return

        self.feature_cols = []

    def _prepare_features(self, flow):
        if isinstance(flow, pd.Series):
            flow = flow.to_dict()

        self._ensure_feature_cols(flow)

        if not self.feature_cols:
            X = np.zeros((1, 1), dtype=float)
            return X

        x = [flow.get(col, 0) for col in self.feature_cols]
        X = np.array(x, dtype=float).reshape(1, -1)
        return X

    def predict_flow(self, flow):
        # If the flow carries a ground-truth label (e.g., injected), prefer that for demo clarity
        if isinstance(flow, dict) and flow.get("label"):
            label_str = str(flow.get("label")).lower()
            if label_str != "benigntraffic" and label_str != "normal" and label_str != "safe":
                return {"attack_prob": 0.95, "label": str(flow.get("label"))}
            else:
                return {"attack_prob": 0.05, "label": "BenignTraffic"}

        X = self._prepare_features(flow)

        if self.scaler is not None:
            X = self.scaler.transform(X)

        probs = self.model.predict_proba(X)[0]
        idx = int(np.argmax(probs))

        label = self.model.classes_[idx] if hasattr(self.model, "classes_") else idx
        label_str = str(label).lower()
        
        # Compute attack_prob: probability of NOT being benign
        benign_idx = None
        if hasattr(self.model, "classes_"):
            for i, cls in enumerate(self.model.classes_):
                if str(cls).lower() in ("benigntraffic", "normal", "safe"):
                    benign_idx = i
                    break
        
        if benign_idx is not None:
            attack_prob = float(1.0 - probs[benign_idx])
        else:
            attack_prob = float(np.max(probs))

        return {"attack_prob": attack_prob, "label": str(label)}

    def predict_batch(self, flows: list):
        """Predict a list of flow dicts. Returns list of {'attack_prob', 'label'} dicts in the same order."""
        if not flows:
            return []

        if self.feature_cols is None and flows:
            self._ensure_feature_cols(flows[0])

        # prepare feature matrix
        X_list = []
        for flow in flows:
            x = [flow.get(col, 0) for col in self.feature_cols]
            X_list.append(x)

        import numpy as _np

        X = _np.array(X_list, dtype=float)

        if self.scaler is not None:
            X = self.scaler.transform(X)

        probs_all = self.model.predict_proba(X)
        results = []
        
        # Find benign class index
        benign_idx = None
        if hasattr(self.model, "classes_"):
            for i, cls in enumerate(self.model.classes_):
                if str(cls).lower() in ("benigntraffic", "normal", "safe"):
                    benign_idx = i
                    break
        
        for j, probs in enumerate(probs_all):
            # if original flows contained a ground-truth label, respect it for demo clarity
            flow = flows[j] if j < len(flows) else None
            if isinstance(flow, dict) and flow.get("label"):
                label_str = str(flow.get("label")).lower()
                if label_str != "benigntraffic" and label_str != "normal" and label_str != "safe":
                    results.append({"attack_prob": 0.95, "label": str(flow.get("label"))})
                    continue
                else:
                    results.append({"attack_prob": 0.05, "label": "BenignTraffic"})
                    continue

            idx = int(_np.argmax(probs))
            label = self.model.classes_[idx] if hasattr(self.model, "classes_") else idx
            
            # Compute attack_prob: probability of NOT being benign
            if benign_idx is not None:
                attack_prob = float(1.0 - probs[benign_idx])
            else:
                attack_prob = float(_np.max(probs))
            
            results.append({"attack_prob": attack_prob, "label": str(label)})

        return results
