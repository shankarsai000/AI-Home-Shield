import socket
import threading
from datetime import datetime
import os


HONEYPOT_LOG = "logs/honeypot.log"


def _log_honeypot_event(attacker_ip, attacker_port, message="Connection Attempt"):
    os.makedirs("logs", exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] attacker_ip={attacker_ip} port={attacker_port} event={message}\n"
    with open(HONEYPOT_LOG, "a") as f:
        f.write(line)


def _honeypot_server(host="0.0.0.0", port=9999):
    """
    Simple honeypot: listens for incoming connections.
    Logs attacker IP and closes connection immediately.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(5)

    while True:
        conn, addr = s.accept()
        attacker_ip, attacker_port = addr[0], addr[1]
        _log_honeypot_event(attacker_ip, attacker_port, message="HONEYPOT_TRIGGERED")
        try:
            conn.sendall(b"Fake IoT Service: Access Denied.\n")
        except Exception:
            pass
        conn.close()


def start_honeypot_in_background(host="0.0.0.0", port=9999):
    """
    Starts honeypot in daemon thread so Streamlit doesn't freeze.
    """
    thread = threading.Thread(target=_honeypot_server, args=(host, port), daemon=True)
    thread.start()
    return thread
