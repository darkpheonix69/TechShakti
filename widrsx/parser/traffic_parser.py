"""Traffic parser.

Extracts structured fields from raw scapy packets.
"""

import logging
import time
from typing import Any, Dict, Optional

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.dot11 import Dot11, Dot11Deauth, Dot11Beacon
from scapy.packet import Packet


logger = logging.getLogger(__name__)


class TrafficParser:
    """Parses raw packets into structured records."""

    def parse(self, pkt: Packet) -> Optional[Dict[str, Any]]:
        """Parse a scapy packet into a structured dict."""

        record = {
            "timestamp": time.time(),
            "packet_length": len(pkt),
            "attack_type": "normal",
        }

        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            record.update({
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "protocol": self._get_protocol(pkt),
                "attack_type": "normal",
            })
        elif pkt.haslayer(Dot11):
            dot11 = pkt[Dot11]
            record.update({
                "src_ip": dot11.addr2 or "unknown",  # Transmitter address
                "dst_ip": dot11.addr1 or "unknown",  # Receiver address
                "protocol": "WiFi",
            })
            # Detect specific attacks
            if pkt.haslayer(Dot11Deauth):
                record["attack_type"] = "deauth"
            elif pkt.haslayer(Dot11Beacon):
                record["attack_type"] = "beacon"
            else:
                record["attack_type"] = "normal"
        elif pkt.haslayer(Ether):
            ether = pkt[Ether]
            record.update({
                "src_ip": ether.src,
                "dst_ip": ether.dst,
                "protocol": "Ethernet",
                "attack_type": "normal",
            })
        else:
            # Unknown packet type, still log it
            record.update({
                "src_ip": "unknown",
                "dst_ip": "unknown",
                "protocol": "Unknown",
                "attack_type": "normal",
            })

        logger.debug("Parsed packet: %s", record)
        return record

    def _get_protocol(self, pkt: Packet) -> str:
        """Get protocol string from packet."""
        if pkt.haslayer(TCP):
            return "TCP"
        elif pkt.haslayer(UDP):
            return "UDP"
        else:
            ip_layer = pkt[IP]
            return str(ip_layer.proto)
