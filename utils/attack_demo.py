"""
Attack Demo Module for AI Home Shield
Provides safe, same-machine attack simulation for Threat Monitor demo.

Features:
- Honeypot burst connections
- Port scan-style burst traffic
- HTTP request burst
"""

import socket
import threading
import time
import urllib.request
import urllib.error
from typing import Dict, List, Any


def get_local_ip() -> str:
    """
    Best-effort method to get local IP address.
    Returns local IP if available, otherwise falls back to 127.0.0.1.
    """
    try:
        # Create a socket to determine the local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            # Fallback: try hostname resolution
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if ip and not ip.startswith("127."):
                return ip
        except Exception:
            pass
    return "127.0.0.1"


def demo_honeypot_burst(
    host: str, port: int, count: int = 30, delay_ms: int = 20
) -> Dict[str, Any]:
    """
    Generate honeypot hit burst by making rapid connections to target host:port.

    Args:
        host: Target host (e.g., local IP or 127.0.0.1)
        port: Target port (e.g., 9999)
        count: Number of connection attempts (max 200)
        delay_ms: Delay between attempts in milliseconds

    Returns:
        {
            "ok": bool,
            "message": str,
            "error": str,
            "stats": {
                "total_attempts": int,
                "successful": int,
                "failed": int,
                "duration_seconds": float,
                "avg_latency_ms": float
            }
        }
    """
    count = min(count, 200)  # Cap at 200
    delay_sec = max(delay_ms / 1000.0, 0.001)  # Minimum 1ms

    start_time = time.time()
    successful = 0
    failed = 0
    latencies = []

    try:
        for i in range(count):
            conn_start = time.time()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)  # 1 second timeout
                sock.connect((host, port))
                latency = (time.time() - conn_start) * 1000  # ms
                latencies.append(latency)
                successful += 1
                try:
                    sock.sendall(b"DEMO_ATTACK_BURST\n")
                except Exception:
                    pass
                sock.close()
            except (socket.timeout, ConnectionRefusedError, OSError) as e:
                failed += 1
                # Honeypot likely not running
            except Exception as e:
                failed += 1

            # Avoid blocking UI with small delays
            if i < count - 1:
                time.sleep(delay_sec)

        duration = time.time() - start_time
        avg_latency = sum(latencies) / len(latencies) if latencies else 0

        if successful > 0:
            return {
                "ok": True,
                "message": f"✓ Honeypot burst completed: {successful} hits",
                "error": "",
                "stats": {
                    "total_attempts": count,
                    "successful": successful,
                    "failed": failed,
                    "duration_seconds": round(duration, 2),
                    "avg_latency_ms": round(avg_latency, 1),
                },
            }
        else:
            return {
                "ok": False,
                "message": f"⚠️ No successful connections to {host}:{port}",
                "error": "Connection refused - honeypot may not be running",
                "stats": {
                    "total_attempts": count,
                    "successful": 0,
                    "failed": count,
                    "duration_seconds": round(duration, 2),
                    "avg_latency_ms": 0,
                },
            }

    except Exception as e:
        return {
            "ok": False,
            "message": "❌ Honeypot burst failed",
            "error": str(e),
            "stats": {
                "total_attempts": count,
                "successful": successful,
                "failed": failed,
                "duration_seconds": round(time.time() - start_time, 2),
                "avg_latency_ms": 0,
            },
        }


def demo_port_scan_burst(
    host: str, ports: List[int] = None, delay_ms: int = 20
) -> Dict[str, Any]:
    """
    Generate port scan-style burst by connecting to multiple ports on target host.

    Args:
        host: Target host
        ports: List of ports to scan (default: [21, 22, 23, 80, 443, 9999])
        delay_ms: Delay between connection attempts

    Returns:
        {
            "ok": bool,
            "message": str,
            "error": str,
            "stats": {
                "total_attempts": int,
                "open_ports": list,
                "closed_ports": list,
                "duration_seconds": float
            }
        }
    """
    if ports is None:
        ports = [21, 22, 23, 80, 443, 9999]

    ports = ports[:50]  # Cap at 50 ports
    delay_sec = max(delay_ms / 1000.0, 0.001)

    start_time = time.time()
    open_ports = []
    closed_ports = []

    try:
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                else:
                    closed_ports.append(port)
                sock.close()
            except Exception:
                closed_ports.append(port)

            time.sleep(delay_sec)

        duration = time.time() - start_time

        return {
            "ok": True,
            "message": f"✓ Port scan burst completed: {len(open_ports)} open, {len(closed_ports)} closed",
            "error": "",
            "stats": {
                "total_attempts": len(ports),
                "open_ports": open_ports,
                "closed_ports": closed_ports,
                "duration_seconds": round(duration, 2),
            },
        }

    except Exception as e:
        return {
            "ok": False,
            "message": "❌ Port scan burst failed",
            "error": str(e),
            "stats": {
                "total_attempts": len(ports),
                "open_ports": open_ports,
                "closed_ports": closed_ports,
                "duration_seconds": round(time.time() - start_time, 2),
            },
        }


def demo_http_burst(
    url: str = "http://example.com", count: int = 30, delay_ms: int = 20
) -> Dict[str, Any]:
    """
    Generate HTTP request burst.

    Args:
        url: Target URL (default: http://example.com)
        count: Number of requests
        delay_ms: Delay between requests

    Returns:
        {
            "ok": bool,
            "message": str,
            "error": str,
            "stats": {
                "total_requests": int,
                "successful": int,
                "failed": int,
                "duration_seconds": float
            }
        }
    """
    count = min(count, 200)  # Cap at 200
    delay_sec = max(delay_ms / 1000.0, 0.001)

    start_time = time.time()
    successful = 0
    failed = 0

    try:
        for i in range(count):
            try:
                req = urllib.request.Request(
                    url,
                    data=None,
                    headers={"User-Agent": "AI-HomeShield-Demo/1.0"},
                    timeout=2,
                )
                with urllib.request.urlopen(req, timeout=2) as response:
                    _ = response.read()
                    successful += 1
            except urllib.error.URLError as e:
                failed += 1
            except Exception as e:
                failed += 1

            if i < count - 1:
                time.sleep(delay_sec)

        duration = time.time() - start_time

        return {
            "ok": True,
            "message": f"✓ HTTP burst completed: {successful} requests",
            "error": "",
            "stats": {
                "total_requests": count,
                "successful": successful,
                "failed": failed,
                "duration_seconds": round(duration, 2),
            },
        }

    except Exception as e:
        return {
            "ok": False,
            "message": "❌ HTTP burst failed",
            "error": str(e),
            "stats": {
                "total_requests": count,
                "successful": successful,
                "failed": failed,
                "duration_seconds": round(time.time() - start_time, 2),
            },
        }
