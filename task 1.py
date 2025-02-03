from scapy.all import sniff, IP, TCP, UDP

# Function to process each captured packet
def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"Source IP: {ip_src} --> Destination IP: {ip_dst}")

        # Check for TCP or UDP layer and display ports
        if packet.haslayer(TCP):
            print(f"TCP - Source Port: {packet[TCP].sport} --> Destination Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"UDP - Source Port: {packet[UDP].sport} --> Destination Port: {packet[UDP].dport}")

# Start sniffing network traffic
print("Starting packet sniffing...")
sniff(prn=packet_callback, store=0)  # prn=callback function, store=0 (don’t store packets)
