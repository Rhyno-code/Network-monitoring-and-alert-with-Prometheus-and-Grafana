import scapy.all as scape
from scapy.layers.inet import IP, ICMP
from prometheus_client import start_http_server, Gauge
import time
import sys
import statistics
import threading
import socket


class Logger(object):
    def __init__(self, filename="ipv4_loggs"):
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

# Targets Configuration (Replace with actual addresses)
IPV4_TARGET = socket.gethostname()  # Google's public IPv4 DNS

# Monitoring Configuration
NUMBER_OF_PACKETS = 10
INTERVAL = 1 # Time interval between packets (seconds)

# Prometheus Metrics
latency_ipv4 = Gauge("ipv4_latency_ms", "Average IPv4 Latency in milliseconds")
jitter_ipv4 = Gauge("ipv4_jitter_ms", "IPv4 Network Jitter in milliseconds")
throughput_ipv4 = Gauge("ipv4_throughput_bps", "IPv4 Network Throughput in bps")
packet_loss_ipv4 = Gauge("ipv4_packet_loss_pct", "IPv4 Packet Loss Percentage")
# new metrics
connection_time_gauge = Gauge("connection_establishment_time_ms", "Time taken to establish connection")
uptime_gauge = Gauge("uptime_ms", "Uptime status(1=up, 0=down)")
mttr_gauge = Gauge("MTTR", "Mean Time To Repair")


# Storage for Metrics
ipv4_latencies = []
ipv4_sent = ipv4_received = 0
start_time = time.time()
downtime_start = None

def measure_connection_time():
    start = time.time()
    reply = scape.sr1(IP(dst=IPV4_TARGET)/ICMP(), timeout=2, verbose=0)
    end = time.time()
    if reply:
        connection_time_gauge.set(end - start)
        return True
    return False

def monitor_infrastructure():
    global downtime_start

    while True:
        is_up = measure_connection_time()
        if is_up:
            uptime_gauge.set(1)
            if downtime_start is not None:
                mttr = time.time() - downtime_start
                mttr_gauge.set(mttr)
                print(f"[RECOVERY] MTTR: {mttr:.2f} seconds")
                downtime_start = None
        else:
            uptime_gauge.set(0)
            if downtime_start is None:
                downtime_start = time.time()
                print(f"[ALERT] Target is down")
        time.sleep(3)

def measure_latency(protocol):
    """Measure latency for IPv4 or IPv6 using ICMP."""
    global ipv4_sent, ipv4_received
    packet = None
    if protocol == "ipv4":
        packet = IP(dst=IPV4_TARGET) / ICMP()
        ipv4_sent += 1

    if packet:
        send_time = time.time()
        reply = scape.sr1(packet, timeout=1, verbose=0)
        receive_time = time.time()

        if reply:
            latency = (receive_time - send_time) * 1000  # Convert to milliseconds
            if protocol == "ipv4":
                ipv4_latencies.append(latency)
                ipv4_received += 1

def calculate_metrics():
    """Calculate average latency, jitter, packet loss, and throughput."""
    end_time = time.time()
    duration = end_time - start_time

    # IPv4 Metrics
    avg_latency_ipv4 = sum(ipv4_latencies) / len(ipv4_latencies) if ipv4_latencies else 0
    jitter_ipv4_value = statistics.stdev(ipv4_latencies) if len(ipv4_latencies) > 1 else 0
    ipv4_loss = ((ipv4_sent - ipv4_received) / ipv4_sent * 100) if ipv4_sent else 0
    ipv4_throughput = (ipv4_received * 64 * 8) / duration if duration > 0 else 0

    # Print Metrics
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} ~  IPv4: Latency={avg_latency_ipv4:.2f}ms, Jitter={jitter_ipv4_value:.2f}ms, "
          f"Loss={ipv4_loss:.2f}%, Throughput={ipv4_throughput:.2f}bps")

    # Update Prometheus Metrics
    latency_ipv4.set(avg_latency_ipv4)
    jitter_ipv4.set(jitter_ipv4_value)
    packet_loss_ipv4.set(ipv4_loss)
    throughput_ipv4.set(ipv4_throughput)


def main():
    """Main function to run dual-stack monitoring."""
    start_http_server(8000)  # Start Prometheus metrics server
    print("Starting Monitoring (IPv4)...")
    
    # Start infrastructure monitoring in a separate thread
    threading.Thread(target=monitor_infrastructure, daemon=True).start()

    while True:        # Main monitoring loop to collect and calculate network metrics periodically

        global ipv4_latencies,ipv4_sent,ipv4_received,start_time

        ipv4_latencies = []
        ipv4_sent = ipv4_received = 0
        start_time = time.time()


        for _ in range(NUMBER_OF_PACKETS):
            measure_latency("ipv4")
            time.sleep(INTERVAL)

        calculate_metrics()
        time.sleep(1)

if __name__ == "__main__":
    setup_logging()
    main()
