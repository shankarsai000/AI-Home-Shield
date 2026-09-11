"""
capture/packet_capture.py

Packet capture adapter using scapy.

Architecture ref: Section 4 — "Capture Adapter - tshark/libpcap or
equivalent packet source."

Provides a PacketCaptureAdapter that can sniff packets from a network
interface and deliver them to the FlowBuilder.
"""

import threading
import time
from typing import List, Optional, Callable, Any
from collections import deque
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, conf
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


class PacketCaptureAdapter:
    """
    Network packet capture using scapy.

    Captures packets on a specified interface and buffers them for
    consumption by the FlowBuilder.  Runs in a background daemon thread.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "ip",
        buffer_size: int = 10000,
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.buffer_size = buffer_size

        self._buffer: deque = deque(maxlen=buffer_size)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._packet_count = 0
        self._start_time: Optional[float] = None
        self._callbacks: List[Callable] = []

    @property
    def is_available(self) -> bool:
        return _SCAPY_AVAILABLE

    @property
    def is_running(self) -> bool:
        return self._running

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self):
        """Start capturing packets in a background thread."""
        if not _SCAPY_AVAILABLE:
            raise RuntimeError("scapy is not installed")
        if self._running:
            return

        self._running = True
        self._start_time = time.time()
        self._thread = threading.Thread(
            target=self._capture_loop, daemon=True, name="PacketCapture"
        )
        self._thread.start()

    def stop(self):
        """Stop capturing."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None

    def _capture_loop(self):
        """Internal capture loop running in daemon thread."""
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: not self._running,
                timeout=1,  # Check stop condition every second
            )
        except Exception:
            pass

        # If still running, re-enter loop (scapy timeout exited)
        while self._running:
            try:
                sniff(
                    iface=self.interface,
                    filter=self.bpf_filter,
                    prn=self._handle_packet,
                    store=False,
                    stop_filter=lambda _: not self._running,
                    timeout=1,
                )
            except Exception:
                time.sleep(0.5)

    def _handle_packet(self, pkt):
        """Process one captured packet."""
        if not _SCAPY_AVAILABLE:
            return

        try:
            if not pkt.haslayer(IP):
                return

            ip_layer = pkt[IP]
            record = {
                "timestamp": time.time(),
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "protocol": ip_layer.proto,
                "length": len(pkt),
                "ttl": ip_layer.ttl,
            }

            # TCP details
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                record["src_port"] = tcp.sport
                record["dst_port"] = tcp.dport
                record["tcp_flags"] = str(tcp.flags)
                record["proto_name"] = "TCP"
            # UDP details
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                record["src_port"] = udp.sport
                record["dst_port"] = udp.dport
                record["proto_name"] = "UDP"
            # ICMP
            elif pkt.haslayer(ICMP):
                record["src_port"] = 0
                record["dst_port"] = 0
                record["proto_name"] = "ICMP"
            else:
                record["src_port"] = 0
                record["dst_port"] = 0
                record["proto_name"] = "OTHER"

            with self._lock:
                self._buffer.append(record)
                self._packet_count += 1

            # Notify callbacks
            for cb in self._callbacks:
                try:
                    cb(record)
                except Exception:
                    pass

        except Exception:
            pass

    # ------------------------------------------------------------------
    # Packet retrieval
    # ------------------------------------------------------------------
    def get_packets(self, max_count: int = 1000) -> List[dict]:
        """Drain up to max_count packets from the buffer."""
        packets = []
        with self._lock:
            while self._buffer and len(packets) < max_count:
                packets.append(self._buffer.popleft())
        return packets

    def on_packet(self, callback: Callable):
        """Register a callback for each captured packet."""
        self._callbacks.append(callback)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def get_status(self) -> dict:
        uptime = time.time() - self._start_time if self._start_time else 0
        return {
            "available": _SCAPY_AVAILABLE,
            "running": self._running,
            "interface": self.interface or "default",
            "filter": self.bpf_filter,
            "packets_captured": self._packet_count,
            "buffer_size": len(self._buffer),
            "buffer_max": self.buffer_size,
            "uptime_seconds": round(uptime, 1),
            "pps": round(self._packet_count / max(uptime, 0.1), 1),
        }
