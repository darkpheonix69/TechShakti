"""SQLite-based database layer."""

import json
import logging
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)


class Database:
    """SQLite database access.

    Handles traffic logs, device behavior, wifi events and alerts.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or "./database/logs.db"
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

    def initialize(self):
        """Create required tables."""
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                packet_length INTEGER,
                attack_type TEXT,
                metadata TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS device_behavior (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                packet_rate REAL,
                bandwidth REAL,
                connection_count REAL,
                unique_ip_count REAL,
                metadata TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS wifi_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                packet_rate REAL,
                bandwidth REAL,
                connection_count REAL,
                unique_ip_count REAL,
                attack_type TEXT,
                metadata TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                type TEXT,
                severity TEXT,
                description TEXT,
                metadata TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS communication_graph (
                src_ip TEXT,
                dst_ip TEXT,
                weight INTEGER,
                last_seen REAL,
                PRIMARY KEY (src_ip, dst_ip)
            )
            """
        )
        # Backwards-compatible column addition
        try:
            cur.execute("ALTER TABLE traffic_logs ADD COLUMN attack_type TEXT")
        except Exception:
            pass
        try:
            cur.execute("ALTER TABLE alerts ADD COLUMN attack_type TEXT")
        except Exception:
            pass
        self.conn.commit()
        logger.info("Database initialized: %s", self.db_path)

    def upsert_graph_edge(self, src_ip: str, dst_ip: str, weight: int = 1) -> None:
        """Update or insert a graph edge with weight and last seen timestamp."""
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO communication_graph (src_ip, dst_ip, weight, last_seen)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(src_ip, dst_ip) DO UPDATE SET
                weight = communication_graph.weight + ?,
                last_seen = ?
            """,
            (src_ip, dst_ip, weight, time.time(), weight, time.time()),
        )
        self.conn.commit()

    def insert_traffic(self, record: Dict[str, Any]) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO traffic_logs (timestamp, src_ip, dst_ip, protocol, packet_length, attack_type, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.get("timestamp"),
                record.get("src_ip"),
                record.get("dst_ip"),
                record.get("protocol"),
                record.get("packet_length"),
                record.get("attack_type"),
                json.dumps({k: v for k, v in record.items() if k not in {"timestamp", "src_ip", "dst_ip", "protocol", "packet_length", "attack_type"}}),
            ),
        )
        self.conn.commit()
        # Keep only the last 10,000 traffic logs to prevent database bloat
        cur.execute("DELETE FROM traffic_logs WHERE id NOT IN (SELECT id FROM traffic_logs ORDER BY id DESC LIMIT 10000)")
        self.conn.commit()

    def insert_alert(self, alert: Dict[str, Any]) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT INTO alerts (timestamp, type, severity, description, metadata)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                alert.get("timestamp"),
                alert.get("type"),
                alert.get("severity"),
                alert.get("description"),
                json.dumps(alert.get("metadata", {})),
            ),
        )
        self.conn.commit()
        # Keep only the last 1,000 alerts
        cur.execute("DELETE FROM alerts WHERE id NOT IN (SELECT id FROM alerts ORDER BY id DESC LIMIT 1000)")
        self.conn.commit()

    def query_traffic(self, limit: int = 100) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM traffic_logs ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]

    def query_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]

    def query_devices(self, limit: int = 100) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT src_ip AS ip FROM traffic_logs
            UNION
            SELECT dst_ip AS ip FROM traffic_logs
            ORDER BY ip
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cur.fetchall()]
