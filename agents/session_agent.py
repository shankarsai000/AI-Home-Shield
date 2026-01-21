
from collections import deque
from datetime import datetime

class SessionAggregationAgent:
    def __init__(self, window_seconds=5):
        self.window_seconds = window_seconds
        self.buffer = deque()  # (timestamp, prob, label)

    def update(self, attack_prob, label, timestamp=None):
        if timestamp is None:
            timestamp = datetime.now()

        self.buffer.append((timestamp, float(attack_prob), str(label)))
        self._prune(timestamp)
        return self.get_session_prediction()

    def _prune(self, now):
        while self.buffer:
            ts, _, _ = self.buffer[0]
            if (now - ts).total_seconds() > self.window_seconds:
                self.buffer.popleft()
            else:
                break

    def get_session_prediction(self):
        if len(self.buffer) == 0:
            return {"session_prob": 0.0, "session_label": "BENIGN", "persistence": 0}

        probs = [p for (_, p, _) in self.buffer]
        labels = [l for (_, _, l) in self.buffer]

        session_prob = sum(probs) / len(probs)

        counts = {}
        for l in labels:
            counts[l] = counts.get(l, 0) + 1
        session_label = max(counts, key=counts.get)

        return {
            "session_prob": round(float(session_prob), 4),
            "session_label": str(session_label),
            "persistence": len(self.buffer)
        }
