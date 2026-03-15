"""Flask API server exposing WIDRS-X data."""

import logging

from flask import Flask, jsonify, request
from flask_cors import CORS


logger = logging.getLogger(__name__)


# Minimal OUI/vendor lookup (expand as needed)
OUI_VENDOR = {
    "00:11:22": "ExampleVendor",
    "00:1a:2b": "ExampleVendor2",
}


def _mac_type(mac: str) -> str:
    """Classify MAC addresses into unicast/multicast/broadcast."""

    mac = mac.lower().strip()
    if mac == "ff:ff:ff:ff:ff:ff":
        return "broadcast"
    try:
        first_octet = int(mac.split(":")[0], 16)
    except Exception:
        return "unknown"
    # Least significant bit of first octet indicates multicast
    return "multicast" if (first_octet & 1) else "unicast"


def _lookup_vendor(mac: str) -> str:
    mac = mac.lower().strip()
    parts = mac.split(":")
    if len(parts) < 3:
        return "unknown"
    oui = ":".join(parts[:3])
    return OUI_VENDOR.get(oui, "unknown")


def create_app(database, graph_builder):
    """Create and configure the Flask application."""

    app = Flask(__name__)
    CORS(app, origins="*")  # Allow all origins for CORS

    @app.route("/traffic", methods=["GET"])
    def get_traffic():
        limit = int(request.args.get("limit", 100))
        rows = database.query_traffic(limit=limit)
        return jsonify(rows)

    @app.route("/logs", methods=["GET"])
    def get_logs():
        # Alias for /traffic
        limit = int(request.args.get("limit", 100))
        rows = database.query_traffic(limit=limit)
        return jsonify(rows)

    @app.route("/alerts", methods=["GET"])
    def get_alerts():
        limit = int(request.args.get("limit", 100))
        rows = database.query_alerts(limit=limit)
        return jsonify(rows)

    @app.route("/devices", methods=["GET"])
    def get_devices():
        limit = int(request.args.get("limit", 100))
        rows = database.query_devices(limit=limit)
        return jsonify(rows)

    @app.route("/graph", methods=["GET"])
    @app.route("/graphs", methods=["GET"])  # Alias for frontend compatibility
    def get_graph():
        # Return a filtered/annotated view of the in-memory communication graph.
        graph = graph_builder.graph

        min_weight = int(request.args.get("min_weight", 1))
        top_n = request.args.get("top_n")
        if top_n is not None:
            try:
                top_n = int(top_n)
            except ValueError:
                top_n = None

        include_nodes = request.args.get("include_nodes", "true").lower() in (
            "1",
            "true",
            "yes",
        )
        include_metadata = request.args.get("include_metadata", "false").lower() in (
            "1",
            "true",
            "yes",
        )

        edges = [
            {"src": u, "dst": v, "weight": graph[u][v].get("weight", 1)}
            for u, v in graph.edges()
            if graph[u][v].get("weight", 1) >= min_weight
        ]

        # Sort by weight descending to highlight the most active flows.
        edges.sort(key=lambda e: (e["weight"], e["src"], e["dst"]), reverse=True)
        if top_n is not None:
            edges = edges[:top_n]

        response = {"edges": edges}

        if include_nodes:
            if include_metadata:
                response["nodes"] = [
                    {
                        "id": n,
                        "type": _mac_type(n),
                        "vendor": _lookup_vendor(n),
                        "degree": graph.degree(n),
                        "in_degree": graph.in_degree(n),
                        "out_degree": graph.out_degree(n),
                    }
                    for n in sorted(graph.nodes())
                ]
            else:
                response["nodes"] = sorted(list(graph.nodes))

        return jsonify(response)

    @app.route("/attacks", methods=["GET"])
    def get_attacks():
        limit = int(request.args.get("limit", 100))
        rows = database.query_alerts(limit=limit)
        # Filter for attack-related alerts
        attack_alerts = [row for row in rows if "attack" in row.get("type", "").lower()]
        return jsonify(attack_alerts)

    @app.route("/health", methods=["GET"])
    def health():
        cur = database.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM traffic_logs")
        traffic_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM alerts")
        alert_count = cur.fetchone()[0]
        return jsonify({
            "status": "ok",
            "traffic_logs_count": traffic_count,
            "alerts_count": alert_count
        })

    return app
