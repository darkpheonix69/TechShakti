"""WIDRS-X main controller.

This module wires together packet capture, parsing, feature engineering,
graph building, model inference, threat detection, and API exposure.
"""

import argparse
import logging
import signal
import threading
import time
from typing import Optional

from api.api_server import create_app
from database.database import Database
from detection.threat_engine import ThreatEngine
from features.feature_engine import FeatureEngine
from graph.graph_builder import GraphBuilder
from ml.anomaly_detector import AnomalyDetector
from ml.train_models import train_models
from parser.traffic_parser import TrafficParser
from sensor.packet_capture import PacketCapture


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


def main(interface: str, db_path: Optional[str] = None, api_port: int = 5000):
    """Start the WIDRS-X pipeline."""

    logging.info("Starting WIDRS-X on interface %s", interface)

    database = Database(db_path=db_path)
    database.initialize()

    # Ensure models exist before starting live inference.
    logging.info("Training/loading ML models (this may take a few seconds)...")
    try:
        train_models()
    except Exception:
        logging.exception("Model training/loading failed")

    packet_queue = []
    packet_lock = threading.Lock()

    parser = TrafficParser()
    feature_engine = FeatureEngine()
    graph_builder = GraphBuilder()
    anomaly_detector = AnomalyDetector()
    threat_engine = ThreatEngine()

    def on_packet(pkt):
        try:
            parsed = parser.parse(pkt)
            if not parsed:
                return

            logging.info("Parsed packet: %s", parsed)
            database.insert_traffic(parsed)

            with packet_lock:
                packet_queue.append(parsed)

            feature_engine.add_record(parsed)
            graph_builder.add_record(parsed)

            features = feature_engine.compute()  # current aggregated features
            if features is not None:
                scores = anomaly_detector.score(features)
                alerts = threat_engine.analyze(parsed, features, scores, graph_builder.graph)
                for alert in alerts:
                    database.insert_alert(alert)

        except Exception as exc:
            logging.exception("Error processing packet: %s", exc)

    capture = PacketCapture(interface=interface, callback=on_packet)

    stop_event = threading.Event()

    def _signal_handler(signum, frame):
        logging.info("Received stop signal (%s), shutting down", signum)
        stop_event.set()
        capture.stop()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # Start API server in a separate thread.
    app = create_app(database, graph_builder)

    api_thread = threading.Thread(target=lambda: app.run(host="0.0.0.0", port=api_port, threaded=True), daemon=True)
    api_thread.start()

    capture.start()

    logging.info("WIDRS-X is running. Press CTRL+C to stop.")
    while not stop_event.is_set():
        time.sleep(1)

    logging.info("WIDRS-X stopped")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WIDRS-X backend controller")
    parser.add_argument("--interface", default="wlan1mon", help="Network interface to capture packets from")
    parser.add_argument("--db", default="./database/logs.db", help="SQLite database path")
    parser.add_argument("--port", type=int, default=5000, help="API server port")
    args = parser.parse_args()
    main(interface=args.interface, db_path=args.db, api_port=args.port)
