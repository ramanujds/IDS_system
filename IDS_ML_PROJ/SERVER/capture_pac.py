import pyshark
import netifaces
import asyncio
import time

class APIServer:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def print_packet_details(self, packet):
        try:
            print(f"Timestamp: {packet.sniff_time}")
            print(f"Layer: {packet.highest_layer}")
            if 'IP' in packet:
                print(f"Source IP: {packet.ip.src}")
                print(f"Destination IP: {packet.ip.dst}")
            if 'TCP' in packet or 'UDP' in packet:
                print(f"Source Port: {packet[packet.transport_layer].srcport}")
                print(f"Destination Port: {packet[packet.transport_layer].dstport}")
            print("-" * 50)  # Separator for readability
        except AttributeError as e:
            print(f"Error printing packet details: {e}")

    def start_capture(self, interface, output_file='captured_packets.pcap'):
        print(f"Starting continuous capture on interface {interface}...")
        
        # Set up a live capture with an ongoing output file
        capture = pyshark.LiveCapture(interface=interface, output_file=output_file)
        
        def packet_callback(packet):
            self.print_packet_details(packet)
        
        try:
            while True:
                capture.apply_on_packets(packet_callback)
                print(f"Capture session ongoing. Packets saved to {output_file}")
                time.sleep(10)  # Sleep to avoid tight loop; adjust as needed
        except KeyboardInterrupt:
            print("Capture stopped by user.")
        except asyncio.TimeoutError:
            print("Capture timed out.")
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Define server and network interface
    server = APIServer('192.168.137.229', '8080')
    
    # Get default network interface
    intF = netifaces.gateways()['default'][netifaces.AF_INET][1]
    
    # Start continuous packet capture and save to PCAP file
    server.start_capture(interface=intF, output_file='captured_packets.pcap')
