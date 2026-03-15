"""Packet capture module.

Uses scapy to capture live traffic from a given interface and dispatch packets to a callback.
"""

import logging
import threading
from typing import Callable, Optional


from scapy.all import conf, sniff


logger = logging.getLogger(__name__)


class PacketCapture:
    """Live packet capture component."""

    def __init__(self, interface: str, callback: Callable[[object], None]):
        self.interface = interface
        self.callback = callback
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def _capture_loop(self):
        logger.info("Starting packet capture on %s", self.interface)
        conf.sniff_promisc = True

        def _packet_handler(pkt):
            if self._stop_event.is_set():
                return False
            try:
                self.callback(pkt)
            except Exception:
                logger.exception("Exception in packet callback")

        sniff(iface=self.interface, prn=_packet_handler, store=False, stop_filter=lambda x: self._stop_event.is_set())
        logger.info("Packet capture stopped")

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def stop(self):
        logger.info("Stopping packet capture")
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
