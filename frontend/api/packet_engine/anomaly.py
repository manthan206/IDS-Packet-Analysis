import numpy as np
from collections import deque
import time
from typing import Dict, Any, Optional

class AnomalyDetector:
    def __init__(self, window_size: int = 100):
        self.packet_lengths = deque(maxlen=window_size)
        self.packet_intervals = deque(maxlen=window_size)
        self.last_packet_time = time.time()

        # Machine Learning model placeholder (using IsolationForest from scikit-learn if available)
        self.clf = None
        self.is_trained = False
        try:
            from sklearn.ensemble import IsolationForest
            self.clf = IsolationForest(n_estimators=50, contamination=0.05, random_state=42)
        except ImportError:
            self.clf = None

    def inspect(self, pkt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        now = time.time()
        length = pkt.get("length", 0)
        interval = now - self.last_packet_time
        self.last_packet_time = now

        self.packet_lengths.append(length)
        self.packet_intervals.append(interval)

        if len(self.packet_lengths) < 30:
            return None # Need enough sample size for baseline

        # Calculate Z-Scores
        mean_len = np.mean(self.packet_lengths)
        std_len = np.std(self.packet_lengths) + 1e-5

        z_score_len = (length - mean_len) / std_len

        # Anomaly trigger: Z-Score > 4.5 or Isolation Forest anomaly
        if z_score_len > 4.5:
            src_ip = pkt.get("source_ip", "Unknown")
            return {
                "rule_name": "STATISTICAL_TRAFFIC_ANOMALY",
                "severity": "MEDIUM",
                "source_ip": src_ip,
                "dest_ip": pkt.get("dest_ip", "Unknown"),
                "source_port": pkt.get("source_port"),
                "dest_port": pkt.get("dest_port"),
                "protocol": pkt.get("protocol", "OTHER"),
                "description": f"Statistical anomaly: Packet length ({length} B) deviates significantly from baseline (mean: {mean_len:.1f} B, Z: {z_score_len:.2f})",
                "payload_snippet": pkt.get("payload_snippet", "")[:100],
                "country": "Unknown",
                "acknowledged": False
            }

        return None

anomaly_detector = AnomalyDetector()
