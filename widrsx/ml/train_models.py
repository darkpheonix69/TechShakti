"""Model training utilities.

Train machine learning models for network anomaly detection and behavior modeling.
"""

import logging
import os

import numpy as np
import pandas as pd
from joblib import dump
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import KMeans


logger = logging.getLogger(__name__)


def _load_or_generate(path: str, expected_columns: list, n: int = 1000):
    """Load a CSV dataset or generate synthetic data."""
    if os.path.exists(path):
        df = pd.read_csv(path)
        logger.info("Loaded dataset %s (%d rows)", path, len(df))
        if len(df) < n:
            logger.warning("Dataset too small, generating additional data")
            additional_data = {}
            for c in expected_columns:
                if c == "attack_type":
                    additional_data[c] = np.random.randint(0, 3, n - len(df))  # 0,1,2 for classes
                else:
                    additional_data[c] = np.random.randn(n - len(df))
            additional = pd.DataFrame(additional_data)
            df = pd.concat([df, additional], ignore_index=True)
            df.to_csv(path, index=False)
        return df

    logger.warning("Dataset %s not found, generating synthetic data", path)
    data = {}
    for c in expected_columns:
        if c == "attack_type":
            data[c] = np.random.randint(0, 3, n)
        else:
            data[c] = np.random.randn(n)
    df = pd.DataFrame(data)
    df.to_csv(path, index=False)
    return df


def train_models(models_dir: str = "./models", datasets_dir: str = "./datasets"):
    """Train and persist all required models."""
    logger.info("Starting model training...")
    os.makedirs(models_dir, exist_ok=True)

    # Network anomaly detection (Isolation Forest)
    net_cols = ["packet_rate", "bandwidth", "connection_count", "unique_ip_count"]
    net_path = os.path.join(datasets_dir, "network_logs.csv")
    net_df = _load_or_generate(net_path, net_cols)

    logger.info("Training Isolation Forest for network anomalies...")
    iso = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    iso.fit(net_df[net_cols])
    dump(iso, os.path.join(models_dir, "network_model.pkl"))
    logger.info("Saved network anomaly model")

    # Device behavior clustering (K-Means)
    beh_path = os.path.join(datasets_dir, "behavior_logs.csv")
    beh_df = _load_or_generate(beh_path, net_cols)

    logger.info("Training K-Means for device behavior clustering...")
    kmeans = KMeans(n_clusters=4, random_state=42)
    kmeans.fit(beh_df[net_cols])
    dump(kmeans, os.path.join(models_dir, "behavior_model.pkl"))
    logger.info("Saved behavior clustering model")

    # WiFi attack classification (Random Forest)
    wifi_cols = ["packet_rate", "bandwidth", "connection_count", "unique_ip_count", "attack_type"]
    wifi_path = os.path.join(datasets_dir, "wifi_events.csv")
    wifi_df = _load_or_generate(wifi_path, wifi_cols)

    if "attack_type" not in wifi_df.columns:
        wifi_df["attack_type"] = 0

    logger.info("Training Random Forest for WiFi attack classification...")
    clf = RandomForestClassifier(n_estimators=50, random_state=42)
    clf.fit(wifi_df[net_cols], wifi_df["attack_type"])
    dump(clf, os.path.join(models_dir, "wifi_attack_model.pkl"))
    logger.info("Saved WiFi attack classification model")

    logger.info("Model training completed.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train_models()
