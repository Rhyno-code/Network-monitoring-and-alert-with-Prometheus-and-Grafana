import scapy.all as scape
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from prometheus_client import start_http_server, Gauge
import time
import sys
import socket
import statistics


class Logger(object):
    def __init__(self, filename="dual-stack-loggs"):
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
IPV4_TARGET = socket.gethostname()     # Google's public IPv4 DNS
IPV6_TARGET = socket.gethostname()   # Google's public IPv6 DNS

# Monitoring Configuration
NUMBER_OF_PACKETS = 10
INTERVAL = 3 # Time interval between packets (seconds)

# Prometheus Metrics
latency_ipv4 = Gauge("ipv4_latency_ms", "Average IPv4 Latency in milliseconds")
latency_ipv6 = Gauge("ipv6_latency_ms", "Average IPv6 Latency in milliseconds")
jitter_ipv4 = Gauge("ipv4_jitter_ms", "IPv4 Network Jitter in milliseconds")
jitter_ipv6 = Gauge("ipv6_jitter_ms", "IPv6 Network Jitter in milliseconds")
throughput_ipv4 = Gauge("ipv4_throughput_bps", "IPv4 Network Throughput in bps")
throughput_ipv6 = Gauge("ipv6_throughput_bps", "IPv6 Network Throughput in bps")
packet_loss_ipv4 = Gauge("ipv4_packet_loss_pct", "IPv4 Packet Loss Percentage")
packet_loss_ipv6 = Gauge("ipv6_packet_loss_pct", "IPv6 Packet Loss Percentage")

# Storage for Metrics
ipv4_latencies = []
ipv6_latencies = []
ipv4_sent = ipv4_received = 0
ipv6_sent = ipv6_received = 0
start_time = time.time()

def measure_latency(protocol):
    """Measure latency for IPv4 or IPv6 using ICMP."""
    global ipv4_sent, ipv4_received, ipv6_sent, ipv6_received
    if protocol == "ipv4":
        packet = IP(dst=IPV4_TARGET) / ICMP()
        ipv4_sent += 1
    else:
        packet = IPv6(dst=IPV6_TARGET) / ICMPv6EchoRequest()
        ipv6_sent += 1

    send_time = time.time()
    reply = scape.sr1(packet, timeout=1, verbose=0)
    receive_time = time.time()

    if reply:
        latency = (receive_time - send_time) * 1000  # Convert to milliseconds
        if protocol == "ipv4":
            ipv4_latencies.append(latency)
            ipv4_received += 1
        else:
            ipv6_latencies.append(latency)
            ipv6_received += 1

def calculate_metrics():
    """Calculate average latency, jitter, packet loss, and throughput."""
    end_time = time.time()
    duration = end_time - start_time

    # IPv4 Metrics
    avg_latency_ipv4 = sum(ipv4_latencies) / len(ipv4_latencies) if ipv4_latencies else 0
    jitter_ipv4_value = statistics.stdev(ipv4_latencies) if len(ipv4_latencies) > 1 else 0
    ipv4_loss = ((ipv4_sent - ipv4_received) / ipv4_sent * 100) if ipv4_sent else 0
    ipv4_throughput = (ipv4_received * 64 * 8) / duration if duration > 0 else 0

    # IPv6 Metrics
    avg_latency_ipv6 = sum(ipv6_latencies) / len(ipv6_latencies) if ipv6_latencies else 0
    jitter_ipv6_value = statistics.stdev(ipv6_latencies) if len(ipv6_latencies) > 1 else 0
    ipv6_loss = ((ipv6_sent - ipv6_received) / ipv6_sent * 100) if ipv6_sent else 0
    ipv6_throughput = (ipv6_received * 64 * 8) / duration if duration > 0 else 0

    # Print Metrics
    print(f" {time.strftime('%Y-%m-%d %H:%M:%S')} ~ IPv4: Latency={avg_latency_ipv4:.2f}ms, Jitter={jitter_ipv4_value:.2f}ms, "
          f"Loss={ipv4_loss:.2f}%, Throughput={ipv4_throughput:.2f}bps")
    print(f"  {time.strftime('%Y-%m-%d %H:%M:%S')} ~ IPv6: Latency={avg_latency_ipv6:.2f}ms, Jitter={jitter_ipv6_value:.2f}ms, "
          f"Loss={ipv6_loss:.2f}%, Throughput={ipv6_throughput:.2f}bps")

    # Update Prometheus Metrics
    latency_ipv4.set(avg_latency_ipv4)
    jitter_ipv4.set(jitter_ipv4_value)
    packet_loss_ipv4.set(ipv4_loss)
    throughput_ipv4.set(ipv4_throughput)

    latency_ipv6.set(avg_latency_ipv6)
    jitter_ipv6.set(jitter_ipv6_value)
    packet_loss_ipv6.set(ipv6_loss)
    throughput_ipv6.set(ipv6_throughput)

def main():
    """Main function to run dual-stack monitoring."""
    start_http_server(8000)  # Start Prometheus metrics server
    print("Starting Dual-Stack Monitoring (IPv4 and IPv6)...")
    while True:
        global ipv4_latencies,ipv6_latencies,ipv4_sent,ipv4_received,ipv6_received,ipv6_sent,start_time

        ipv4_latencies = []
        ipv6_latencies = []
        ipv4_sent = ipv4_received = 0
        ipv6_sent = ipv6_received = 0
        start_time = time.time()


        for _ in range(NUMBER_OF_PACKETS):
            measure_latency("ipv4")
            measure_latency("ipv6")
            time.sleep(INTERVAL)

        calculate_metrics()
        time.sleep(5)

if __name__ == "__main__":
    setup_logging()
    main()
