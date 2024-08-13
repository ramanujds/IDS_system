import pandas as pd
from scapy.all import rdpcap
from scapy.layers.inet import IP, UDP, TCP, ICMP

def extract_features(pcap_file):
    packets = rdpcap(pcap_file)
    flow_stats = {}
    timestamps = {}
    
    # Initialize a DataFrame to collect all rows
    data = []

    for packet in packets:
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            
            if UDP in packet:
                protocol = 17  # UDP
                port_no = packet[UDP].dport
            elif TCP in packet:
                protocol = 6   # TCP
                port_no = packet[TCP].dport
                # Check for TCP RST flag
                is_rst = packet[TCP].flags & 0x4  # Check if RST flag is set
                label = 1 if is_rst else 0
            elif ICMP in packet:
                protocol = 1   # ICMP
                port_no = 0     # ICMP doesn't use ports
                label = 0
            else:
                continue  # Skip non-UDP/TCP/ICMP packets
            
            key = (src, dst, protocol, port_no)
            if key not in flow_stats:
                flow_stats[key] = {
                    'pktcount': 0,
                    'bytecount': 0,
                    'tx_bytes': 0,
                    'rx_bytes': 0,
                    'Protocol': protocol,
                    'port_no': port_no,
                    'first_time': packet.time,
                    'last_time': packet.time
                }
                timestamps[key] = [packet.time, packet.time]

            # Update flow statistics
            flow_stats[key]['pktcount'] += 1
            flow_stats[key]['bytecount'] += len(packet)
            if src == '192.168.29.12':  # Example logic to distinguish tx and rx
                flow_stats[key]['tx_bytes'] += len(packet)
            else:
                flow_stats[key]['rx_bytes'] += len(packet)
            
            # Update timestamps
            flow_stats[key]['last_time'] = packet.time
            timestamps[key][1] = packet.time

            # Add data for current packet
            start_time, end_time = timestamps[key]
            duration = end_time - start_time
            duration_sec = int(duration)
            duration_nsec = int((duration - duration_sec) * 1e9)
            tot_dur = duration_sec
            flows = 1
            packetins = flow_stats[key]['pktcount']
            tx_kbps = (flow_stats[key]['tx_bytes'] * 8) / (1000 * 1)  # assuming 1 second for simplicity
            rx_kbps = (flow_stats[key]['rx_bytes'] * 8) / (1000 * 1)
            tot_kbps = tx_kbps + rx_kbps

            data.append([
                1,  # switch
                src,
                dst,
                flow_stats[key]['pktcount'],
                flow_stats[key]['bytecount'],
                duration_sec,
                duration_nsec,
                tot_dur,
                flows,
                packetins,
                flow_stats[key]['pktcount'],  # pktperflow
                flow_stats[key]['bytecount'],  # byteperflow
                flow_stats[key]['pktcount'] / duration if duration > 0 else 0,  # pktrate
                flow_stats[key]['pktcount'],  # Pairflow
                protocol,  # Protocol number
                port_no,
                flow_stats[key]['tx_bytes'],
                flow_stats[key]['rx_bytes'],
                tx_kbps,
                rx_kbps,
                tot_kbps,
                label   # label
            ])

    df = pd.DataFrame(data, columns=[
        'switch', 'src', 'dst', 'pktcount', 'bytecount', 'dur', 'dur_nsec', 'tot_dur', 'flows',
        'packetins', 'pktperflow', 'byteperflow', 'pktrate', 'Pairflow', 'Protocol', 'port_no',
        'tx_bytes', 'rx_bytes', 'tx_kbps', 'rx_kbps', 'tot_kbps', 'label'
    ])

    # Define protocol mapping
    protocol_mapping = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP'
    }

    # Convert Protocol numbers to names
    df['Protocol'] = df['Protocol'].map(protocol_mapping).fillna('Unknown')

    df.to_csv("pck_data.csv", index=False)
    print("Feature extraction complete. Data saved to pck_data.csv.") 

if __name__ == "__main__":
    pcap_file = "captured_packets.pcap"
    extract_features(pcap_file)
