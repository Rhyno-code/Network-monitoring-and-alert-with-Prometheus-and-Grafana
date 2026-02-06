from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from collections import defaultdict
import time
import sys
import socket
from prometheus_client import start_http_server, Counter, Gauge


class Logger(object):
    def __init__(self, filename="pscn_loggs"):
        self.terminal = sys.stdout
        self.log = open(filename, "a")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()

def setup_logging():
    sys.stdout = Logger()


# Prometheus Metrics
PACKETS_MONITORED = Counter("packets_monitored", "Total TCP packets monitored")
PORT_SCANS_DETECTED = Counter("port_scans_detected", "Total port scan attempts detected")
PORT_SCANS_PER_IP = Gauge("port_scans_per_ip", "Number of ports accessed per suspected scanner", ["ip_address"])

# Port Scan Detection Parameters
PORT_SCAN_THRESHOLD = 5  # Number of unique ports per time window
TIME_WINDOW = 10  # Seconds

# Dictionary to track scanning attempts (IP -> {port: timestamp})
scan_attempts = defaultdict(dict)

def detect_port_scan(packet):
    """Callback function for sniffing TCP packets."""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        PACKETS_MONITORED.inc()  # Increment monitored packets counter
        
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        current_time = time.time()

        # Remove old scan attempts beyond TIME_WINDOW
        for port in list(scan_attempts[src_ip].keys()):
            if current_time - scan_attempts[src_ip][port] > TIME_WINDOW:
                del scan_attempts[src_ip][port]

        # Log port access attempt
        scan_attempts[src_ip][dst_port] = current_time

        # Check for scan detection
        if len(scan_attempts[src_ip]) >= PORT_SCAN_THRESHOLD:
            PORT_SCANS_DETECTED.inc()  # Increment port scan detection counter
            PORT_SCANS_PER_IP.labels(ip_address=src_ip).set(len(scan_attempts[src_ip]))  # Update gauge
            print(f" ---{time.strftime('%Y-%m-%d %H:%M:%S')}--- [ALERT] Possible port scan detected from {src_ip} (Accessed {len(scan_attempts[src_ip])} ports)")

if __name__ == "__main__":
    setup_logging()
    # Start Prometheus metrics server on port 8000
    start_http_server(8003)
    print("Listening for port scans...")
    
    # Sniff incoming TCP packets (requires sudo/admin)
    sniff(filter="tcp", prn=detect_port_scan, store=False)
