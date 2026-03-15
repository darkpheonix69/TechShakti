"""Anomaly detection engine.

Loads trained models and produces anomaly scores in real time.
"""

import logging
import os
from typing import Any, Dict, Optional, Union

import pandas as pd

from joblib import load


logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Wrapper around trained ML models."""

    def __init__(self, models_dir: str = "./models"):
        self.models_dir = models_dir
        self.network_model = self._load_model("network_model.pkl")
        self.behavior_model = self._load_model("behavior_model.pkl")
        self.wifi_model = self._load_model("wifi_attack_model.pkl")

    def _load_model(self, filename: str):
        path = os.path.join(self.models_dir, filename)
        if not os.path.exists(path):
            logger.warning("Model %s not found at %s", filename, path)
            return None
        try:
            return load(path)
        except Exception:
            logger.exception("Failed to load model %s", path)
            return None

    def score(self, features: Dict[str, float]) -> Dict[str, Optional[float]]:
        """Score the current feature vector.

        Returns:
            A dict with keys "anomaly_score", "behavior_cluster", "wifi_attack_score".
        """
        result: Dict[str, Optional[Union[float, int]]] = {
            "anomaly_score": None,
            "behavior_cluster": None,
            "wifi_attack_score": None,
        }

        # Use DataFrame with named columns to avoid sklearn warnings.
        df = pd.DataFrame([features])

        if self.network_model is not None:
            try:
                score = self.network_model.decision_function(df)[0]
                result["anomaly_score"] = float(score)
            except Exception:
                logger.exception("Failed to score network model")

        if self.behavior_model is not None:
            try:
                cluster = self.behavior_model.predict(df)[0]
                result["behavior_cluster"] = int(cluster)
            except Exception:
                logger.exception("Failed to score behavior model")

        if self.wifi_model is not None:
            try:
                # Use classifier output as a simple score (class label)
                wifi_score = self.wifi_model.predict(df)[0]
                result["wifi_attack_score"] = float(wifi_score)
            except Exception:
                logger.exception("Failed to score wifi model")

        return result
