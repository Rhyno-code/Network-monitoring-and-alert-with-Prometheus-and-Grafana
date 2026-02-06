# Dual-Stack Network Monitoring Agent

This project is a Python-based network monitoring tool designed to measure and analyze network performance for both IPv4 and IPv6 protocols simultaneously. It utilizes `scapy` for packet generation and `prometheus_client` to expose metrics for scraping.

## Project Structure

- **`vers0.py`**: The main Python script containing the monitoring logic, Prometheus exporter, and custom logging class.
- **`dual-stack-loggs`**: A text file where the script appends its standard output, providing a persistent history of network performance.

## Features

- **Dual-Stack Monitoring**: Monitors IPv4 and IPv6 connectivity concurrently.
- **Key Metrics**:
  - **Latency**: Round-trip time (RTT) in milliseconds.
  - **Jitter**: Variation in latency (standard deviation).
  - **Packet Loss**: Percentage of lost packets.
  - **Throughput**: Estimated throughput in bits per second (bps).
- **Prometheus Integration**: Exposes metrics via an HTTP server on port `8000`.
- **Logging**: Logs output to both the console and a file named `dual-stack-loggs`.

## How it Works

The script `vers0.py` operates in a continuous loop:
1.  **Packet Generation**: It sends a burst of ICMP (IPv4) and ICMPv6 (IPv6) Echo Requests using `scapy`.
2.  **Measurement**: It records the send and receive times to calculate Round-Trip Time (RTT).
3.  **Metric Calculation**: After sending `NUMBER_OF_PACKETS`, it calculates:
    - **Average Latency**: Mean of RTTs.
    - **Jitter**: Standard deviation of RTTs (using `statistics.stdev`).
    - **Packet Loss**: Ratio of unreturned packets.
    - **Throughput**: Estimated based on received bytes over the duration.
4.  **Exposition**: Metrics are updated in the Prometheus registry.
5.  **Logging**: Results are printed to the console and appended to `dual-stack-loggs`.

## Prerequisites

- Python 3.x
- Administrator/Root privileges (required for creating raw sockets with Scapy).

## Installation

1. **Ensure Python is installed**.

2. **Install Dependencies**:
   Use `pip` to install the required Python libraries:
   ```bash
   pip install scapy prometheus-client
   ```

## Configuration

Before running the script, you should edit `vers0.py` to configure the monitoring targets. By default, it targets the local hostname, which may not be useful for network testing.

Open `vers0.py` and modify the following lines:

```python
# Targets Configuration (Replace with actual addresses)
IPV4_TARGET = "8.8.8.8"              # Example: Google Public DNS (IPv4)
IPV6_TARGET = "2001:4860:4860::8888" # Example: Google Public DNS (IPv6)

# Monitoring Configuration
NUMBER_OF_PACKETS = 10               # Number of packets per measurement cycle
INTERVAL = 3                         # Time interval between packets (seconds)
```

## Usage

Run the script with elevated privileges (sudo on Linux, Administrator on Windows) because Scapy requires raw socket access to send ICMP packets.

```bash
# Linux / macOS
sudo python3 vers0.py

# Windows (Run Command Prompt as Administrator)
python vers0.py
```

The script will start the Prometheus metrics server on port `8000` and begin the monitoring loop.

## Logging

The script employs a custom `Logger` class in `vers0.py` that intercepts `sys.stdout`. This ensures that all console output is simultaneously written to the `dual-stack-loggs` file in the same directory.

**Example Output (`dual-stack-loggs`):**
```text
Starting Dual-Stack Monitoring (IPv4 and IPv6)...
 2026-01-29 10:19:35 ~ IPv4: Latency=7.57ms, Jitter=1.56ms, Loss=0.00%, Throughput=101.17bps
  2026-01-29 10:19:35 ~ IPv6: Latency=0.00ms, Jitter=0.00ms, Loss=100.00%, Throughput=0.00bps
```

## Metrics

The following metrics are exposed at `http://localhost:8000`:

| Metric Name | Description |
| :--- | :--- |
| `ipv4_latency_ms` | Average IPv4 Latency (ms) |
| `ipv6_latency_ms` | Average IPv6 Latency (ms) |
| `ipv4_jitter_ms` | IPv4 Network Jitter (ms) |
| `ipv6_jitter_ms` | IPv6 Network Jitter (ms) |
| `ipv4_packet_loss_pct` | IPv4 Packet Loss Percentage |
| `ipv6_packet_loss_pct` | IPv6 Packet Loss Percentage |
| `ipv4_throughput_bps` | IPv4 Network Throughput (bps) |
| `ipv6_throughput_bps` | IPv6 Network Throughput (bps) |
