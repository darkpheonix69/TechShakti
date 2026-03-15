"""Threat detection logic.

Analyzes anomaly scores and graph state to generate alerts.
"""

import logging
import time
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)


class ThreatEngine:
    """Detect suspicious behavior from anomaly scores and network graphs."""

    def __init__(self):
        self.beacon_counts = {}  # MAC -> count in window
        self.device_dest_history = {}  # src_ip -> deque of (timestamp, dst_ip)
        # EWMA baseline per edge (src->dst) for graph anomaly scoring
        self.edge_weight_ewma = {}

    def _edge_key(self, src: str, dst: str) -> str:
        return f"{src}->{dst}"

    def _update_edge_baseline(self, src: str, dst: str, weight: int) -> float:
        """Update edge weight EWMA baseline and return anomaly ratio."""

        key = self._edge_key(src, dst)
        alpha = 0.2
        prev = self.edge_weight_ewma.get(key, float(weight))
        ewma = alpha * weight + (1 - alpha) * prev
        self.edge_weight_ewma[key] = ewma

        # Ratio of current weight to baseline (higher means more anomalous)
        # Add 1 to avoid division by zero.
        return weight / (ewma + 1)

    def _severity_from_score(self, score: float) -> str:
        if score >= 2.5:
            return "high"
        if score >= 1.2:
            return "medium"
        return "low"

    def _count_recent_unique_dests(self, src: str, window_seconds: int = 60) -> int:
        """Count unique destinations for a source in the recent time window."""
        from collections import deque

        if src not in self.device_dest_history:
            return 0
        cutoff = time.time() - window_seconds
        dq: deque = self.device_dest_history[src]
        # keep only recent entries and count unique destinations
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        return len(set(dst for _, dst in dq))

    def analyze(
        self,
        record: Dict[str, Any],
        features: Dict[str, float],
        scores: Dict[str, Optional[float]],
        graph: Any,
    ) -> List[Dict[str, Any]]:
        """Analyze current state and return a list of alerts."""
        alerts: List[Dict[str, Any]] = []

        anomaly_score = scores.get("anomaly_score")
        # Track graph edge anomaly ratio (current weight relative to EWMA baseline)
        edge_anomaly_ratio = None
        src = record.get("src_ip")
        dst = record.get("dst_ip")
        if src and dst and graph is not None and graph.has_edge(src, dst):
            edge_weight = graph[src][dst].get("weight", 0)
            edge_anomaly_ratio = self._update_edge_baseline(src, dst, edge_weight)

        # Compose a severity score combining model anomaly and graph edge anomaly.
        severity_score = 0.0
        if anomaly_score is not None:
            severity_score += max(0.0, -anomaly_score)
        if edge_anomaly_ratio is not None and edge_anomaly_ratio > 1.2:
            severity_score += (edge_anomaly_ratio - 1.0)

        computed_severity = self._severity_from_score(severity_score)
        if anomaly_score is not None and anomaly_score < -0.1:
            alerts.append(
                {
                    "type": "abnormal_traffic",
                    "timestamp": time.time(),
                    "severity": computed_severity,
                    "description": "Anomaly score indicates abnormal traffic patterns.",
                    "metadata": {
                        "anomaly_score": anomaly_score,
                        "src_ip": record.get("src_ip"),
                        "dst_ip": record.get("dst_ip"),
                        "protocol": record.get("protocol"),
                        "edge_anomaly_ratio": edge_anomaly_ratio,
                    },
                }
            )

        # Suspicious communication: new edge added with high weight
        src = record.get("src_ip")
        dst = record.get("dst_ip")
        if src and dst and src != "unknown" and dst != "unknown":
            # track destination history for lateral movement detection
            from collections import deque

            if src not in self.device_dest_history:
                self.device_dest_history[src] = deque()
            self.device_dest_history[src].append((time.time(), dst))

            unique_dests_recent = self._count_recent_unique_dests(src)
            if unique_dests_recent > 20:
                alerts.append(
                    {
                        "type": "lateral_movement",
                        "timestamp": time.time(),
                        "severity": "medium",
                        "description": "Source is connecting to many new destinations in a short period.",
                        "metadata": {
                            "src_ip": src,
                            "unique_dest_count": unique_dests_recent,
                        },
                    }
                )
        try:
            src = record.get("src_ip")
            dst = record.get("dst_ip")
            if graph.has_edge(src, dst) and graph[src][dst].get("weight", 0) > 100:
                alerts.append(
                    {
                        "type": "suspicious_communication",
                        "timestamp": time.time(),
                        "severity": computed_severity,
                        "description": "High volume communication between two hosts.",
                        "metadata": {
                            "src_ip": src,
                            "dst_ip": dst,
                            "weight": graph[src][dst].get("weight"),
                            "edge_anomaly_ratio": edge_anomaly_ratio,
                            "severity_score": severity_score,
                        },
                    }
                )
        except Exception:
            logger.exception("Failed to evaluate suspicious communication")

        # Possible data exfiltration heuristics
        if features.get("bandwidth", 0) > 1e6:
            alerts.append(
                {
                    "type": "possible_data_exfiltration",
                    "timestamp": time.time(),
                    "severity": "high",
                    "description": "Bandwidth usage is unusually high; possible data exfiltration.",
                    "metadata": {"bandwidth": features.get("bandwidth")},
                }
            )

        # Detect specific WiFi attacks
        attack_type = record.get("attack_type")
        if attack_type == "deauth":
            alerts.append(
                {
                    "type": "wifi_attack_deauth",
                    "timestamp": time.time(),
                    "severity": "high",
                    "description": "Deauthentication attack detected.",
                    "metadata": {
                        "src_mac": record.get("src_ip"),
                        "dst_mac": record.get("dst_ip"),
                    },
                }
            )
        elif attack_type == "beacon":
            # Simple beacon flood detection: if many beacons in short time (placeholder)
            # For real flood, need to count per MAC
            pass  # Can add logic later

        return alerts
