import pyshark
from collections import Counter, defaultdict, deque
import time
import subprocess
import threading
import signal
import sys

# Configuration
TIME_WINDOW = 60  # Time window in seconds to analyze traffic
REQUEST_THRESHOLD = 3000  # Number of requests that indicates a potential DDoS attack
PORT_FLOOD_THRESHOLD = 200  # Number of requests to the same port indicating a flood
OWN_IP = '192.168.137.229'  # Replace with your own IP address

# Shared counters and locks
ip_counter = Counter()
port_counter = defaultdict(Counter)
packet_times = deque()  # Stores packets with their timestamps
lock = threading.Lock()
blocked_ips = set()  # Set to store blocked IPs

def block_ip(ip):
    """Block the IP address using iptables."""
    if ip == OWN_IP:
       #print(f"Skipping blocking own IP address: {ip}")
        return

    try:
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
        blocked_ips.add(ip)
        print(f"Blocked IP address: {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to block IP address {ip}: {e}")

def unblock_ip(ip):
    """Unblock the IP address using iptables."""
    try:
        subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
        print(f"Unblocked IP address: {ip}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to unblock IP address {ip}: {e}")

def analyze_packet(packet):
    current_time = time.time()  # Current timestamp

    with lock:
        # Remove outdated packets from the deque
        while packet_times and current_time - packet_times[0]['time'] > TIME_WINDOW:
            old_packet = packet_times.popleft()
            ip_counter[old_packet['ip_src']] -= 1
            if 'src_port' in old_packet:
                port_counter[old_packet['ip_src']][old_packet['src_port']] -= 1

        if 'ip' in packet:
            ip_src = packet.ip.src
            packet_entry = {'ip_src': ip_src, 'time': current_time}
            packet_times.append(packet_entry)

            ip_counter[ip_src] += 1

            if 'tcp' in packet or 'udp' in packet:
                src_port = packet[packet.transport_layer].srcport
                packet_entry['src_port'] = src_port

                port_counter[ip_src][src_port] += 1

                # Check for port flooding
                if port_counter[ip_src][src_port] > PORT_FLOOD_THRESHOLD:
                    print(f"Potential port flood detected from IP: {ip_src} on port: {src_port}")
                    block_ip(ip_src)
                    return True

            # Check if the number of requests exceeds the threshold
            if ip_counter[ip_src] > REQUEST_THRESHOLD:
                print(f"Potential DDoS attack detected from IP: {ip_src}")
                block_ip(ip_src)
                return True

    return False

def monitor_network(interface):
    try:
        capture = pyshark.LiveCapture(interface=interface)
        print(f"Monitoring network on interface: {interface}")
        for packet in capture.sniff_continuously():
            analyze_packet(packet)
    except Exception as e:
        print(f"An error occurred: {e}")

def signal_handler(sig, frame):
    print("Ctrl+C pressed, unblocking all IPs...")
    with lock:
        for ip in blocked_ips:
            unblock_ip(ip)
    sys.exit(0)

# Example of usage; specify your network interface here
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    network_interface = 'eth0'  # Replace 'eth0' with your network interface
    monitor_network(network_interface)
