import time
import sys
from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, ICMP
import psutil
from prometheus_client import start_http_server, Gauge
import threading

# Configuration
interface = conf.iface  # Automatically detect the default network interface
syn_threshold = 100  # SYN packets per second threshold
icmp_threshold = 100  # ICMP packets per second threshold
monitoring_interval = 10  # Seconds per monitoring cycle

# Prometheus metrics for SYN flood
SYN_COUNT = Gauge('syn_packets_total', 'Total SYN packets received')
SYN_RATE = Gauge('syn_packets_per_second', 'Rate of SYN packets per second')
HALF_OPEN = Gauge('half_open_connections', 'Number of half-open connections')
# Prometheus metrics for ICMP flood
ICMP_COUNT = Gauge('icmp_packets_total', 'Total ICMP Echo Request packets received')
ICMP_RATE = Gauge('icmp_packets_per_second', 'Rate of ICMP Echo Request packets per second')
# Common metrics
CPU_USAGE = Gauge('cpu_usage_percent', 'CPU usage percentage')
MEMORY_USAGE = Gauge('memory_usage_percent', 'Memory usage percentage')
SOURCE_IP_DIVERSITY = Gauge('source_ip_diversity', 'Number of unique source IPs sending SYN or ICMP packets')

# Global counters
syn_count = 0
icmp_count = 0
half_open_connections = {}
unique_source_ips = set()
data_lock = threading.Lock()

class Logger(object):
    def __init__(self, filename="loggs"):
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

def packet_callback(packet):
    """Analyze each packet for SYN flags and ICMP Echo Requests."""
    global syn_count, icmp_count
    with data_lock:
        if IP in packet:
            src_ip = packet[IP].src
            unique_source_ips.add(src_ip)  # Track unique source IPs for both SYN and ICMP
            
            # Check for SYN packets
            if TCP in packet:
                if packet[TCP].flags == "S":  # SYN flag only
                    syn_count += 1
                    src_port = packet[TCP].sport
                    conn_key = f"{src_ip}:{src_port}"
                    half_open_connections[conn_key] = time.time()
                elif packet[TCP].flags == "SA":  # SYN-ACK response
                    dst_ip = packet[IP].dst
                    dst_port = packet[TCP].dport
                    conn_key = f"{dst_ip}:{dst_port}"
                    half_open_connections.pop(conn_key, None)  # Remove if handshake progresses
            
            # Check for ICMP Echo Requests
            if ICMP in packet:
                if packet[ICMP].type == 8:  # ICMP Echo Request (type 8)
                    icmp_count += 1

def monitor_resources():
    """Monitor CPU and memory usage."""
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_usage = psutil.virtual_memory().percent
    return cpu_usage, memory_usage

def sniff_packets():
    """Run packet sniffing in a separate thread."""
    while True:
        sniff(iface=interface, prn=packet_callback, store=0, timeout=monitoring_interval)

def monitor_loop():
    """Main monitoring loop running infinitely."""
    global syn_count, icmp_count
    print(f"Monitoring interface: {interface} ")
    print("Ensure this matches your VirtualBox Host-Only Adapter name (check 'ipconfig').")
    print(f"Starting SYN and ICMP flood monitoring... (updates every {monitoring_interval} seconds)")

    # Start packet sniffing in a background thread
    sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
    sniff_thread.start()

    while True:
        try:
            start_time = time.time()
            time.sleep(monitoring_interval)  # Monitor for the interval

            # Snapshot and reset counts atomically
            with data_lock:
                current_syn_count = syn_count
                current_icmp_count = icmp_count
                current_half_open = len(half_open_connections)
                current_unique_ips = len(unique_source_ips)
                syn_count = 0
                icmp_count = 0

            # Calculate elapsed time and rates
            elapsed_time = time.time() - start_time
            syn_rate = current_syn_count / elapsed_time if elapsed_time > 0 else 0
            icmp_rate = current_icmp_count / elapsed_time if elapsed_time > 0 else 0

            # Get resource usage
            cpu_usage, memory_usage = monitor_resources()

            # Update Prometheus metrics
            SYN_COUNT.set(current_syn_count)
            SYN_RATE.set(syn_rate)
            HALF_OPEN.set(current_half_open)
            ICMP_COUNT.set(current_icmp_count)
            ICMP_RATE.set(icmp_rate)
            CPU_USAGE.set(cpu_usage)
            MEMORY_USAGE.set(memory_usage)
            SOURCE_IP_DIVERSITY.set(current_unique_ips)

            # Report findings
            print(f"\n   {time.strftime('%Y-%m-%d %H:%M:%S')} --- Monitoring Results ---")
            print(f"Total SYN packets received: {current_syn_count}")
            print(f"SYN packets per second: {syn_rate:.2f}")
            print(f"Half-open connections: {current_half_open}")
            print(f"Total ICMP Echo Request packets received: {current_icmp_count}")
            print(f"ICMP packets per second: {icmp_rate:.2f}")
            print(f"Unique source IPs: {current_unique_ips}")
            print(f"CPU Usage: {cpu_usage}%")
            print(f"Memory Usage: {memory_usage}%")

            # Detect potential floods
            if syn_rate > syn_threshold or current_half_open > 50:
                print("WARNING: Possible SYN flood attack detected!")
            else:
                print("No significant SYN flood activity detected.")
            
            if icmp_rate > icmp_threshold:
                print("WARNING: Possible ICMP flood attack detected!")
            else:
                print("No significant ICMP flood activity detected.")

        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    setup_logging()
    # Start Prometheus HTTP server on port 8000
    start_http_server(8001)
    print("Prometheus metrics available at http://localhost:8001")
    
    # Run the monitoring loop
    monitor_loop()