import subprocess
import re
import time
import sys
from prometheus_client import start_http_server, Gauge, Counter



class Logger(object):
    def __init__(self, filename="arp_loggs"):
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



#prometheus metrics
arp_spoofing_alerts = Counter("arp_spoofing_alerts", "total number of arp spoofing attemps detected")
arp_spoofing_status = Gauge("arp_spoofing_status", "surrent arp spoofing detection status (1 = attack detected and 0 = no attack)")

def get_arp_table():
    arp_output = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout
    arp_table = {}

    for line in arp_output.splitlines():
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([\w-]+)\s+dynamic", line)
        if match:
            ip, mac = match.groups()
            if mac in arp_table and arp_table[mac] != ip:
                return True  # Attack detected
            arp_table[mac] = ip  # Store IP for each MAC

    return False  # No attack

def monitor_arp():
    while True:
        if get_arp_table():
            print("[ALERT] ARP Spoofing detected!")
            arp_spoofing_alerts.inc()
            arp_spoofing_status.set(1)
        else:
            print("[SAFE] No ARP spoofing detected.")
            arp_spoofing_status.set(0)
        time.sleep(30)

if __name__ == "__main__":
    setup_logging()
    print("Starting prometheus at port 8002")
    start_http_server(8002)
    print("Starting ARP monitoring...")
    monitor_arp()