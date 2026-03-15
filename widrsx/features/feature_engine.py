"""Feature engineering.

Creates behavioral features from parsed traffic records.
"""

import logging
import time
from collections import deque
from typing import Dict, Optional

import pandas as pd


logger = logging.getLogger(__name__)


class FeatureEngine:
    """Builds behavioral features from streaming traffic records."""

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self.records = deque()
        # Baseline stats per device for anomaly detection
        self.device_baseline = {}

    def _update_baseline(self, device: str, packet_rate: float, bandwidth: float):
        """Update EWMA baseline for a given device."""
        alpha = 0.1
        if device not in self.device_baseline:
            self.device_baseline[device] = {
                "packet_rate": packet_rate,
                "bandwidth": bandwidth,
            }
            return
        base = self.device_baseline[device]
        base["packet_rate"] = alpha * packet_rate + (1 - alpha) * base["packet_rate"]
        base["bandwidth"] = alpha * bandwidth + (1 - alpha) * base["bandwidth"]

    def add_record(self, record: Dict):
        """Add a parsed traffic record into the sliding window."""
        self.records.append(record)
        self._purge_old_records()

    def _purge_old_records(self):
        cutoff = time.time() - self.window_seconds
        while self.records and self.records[0]["timestamp"] < cutoff:
            self.records.popleft()
        # Also limit total records to prevent memory bloat
        while len(self.records) > 10000:
            self.records.popleft()

    def compute(self) -> Optional[Dict[str, float]]:
        """Compute aggregated features over the window.

        Returns a dict of features or None if there is no data.
        """
        self._purge_old_records()
        if not self.records:
            return None

        df = pd.DataFrame(list(self.records))
        duration = max(df["timestamp"]) - min(df["timestamp"])
        duration = max(duration, 1.0)

        packet_rate = len(df) / duration
        bandwidth = df["packet_length"].sum() / duration

        connections = df[["src_ip", "dst_ip"]].drop_duplicates()
        connection_count = len(connections)
        unique_ips = pd.unique(df[["src_ip", "dst_ip"]].values.ravel())
        unique_ip_count = len(unique_ips)

        # Update device-level baselines for anomaly detection
        # (use src_ip as the device that initiated traffic)
        for src in df["src_ip"].unique():
            src_df = df[df["src_ip"] == src]
            self._update_baseline(src, len(src_df) / duration, src_df["packet_length"].sum() / duration)

        features = {
            "packet_rate": float(packet_rate),
            "bandwidth": float(bandwidth),
            "connection_count": float(connection_count),
            "unique_ip_count": float(unique_ip_count),
        }

        logger.debug("Computed features: %s", features)
        return features
