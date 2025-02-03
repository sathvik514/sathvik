import sys
from scapy.all import IP, TCP, sniff, get_if_list

# Function to handle each captured packetAEFW$GSD
def handle_packet(packet, log):
    try:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            # Extract source and destination IP addresses
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # Extract source and destination ports
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            # Write packet information to log file
            log.write(f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")
            log.flush()  # Ensure the log is written immediately
    except Exception as e:
        print(f"Error processing packet: {e}")

# Main function to start packet sniffing
def main(interface):
    logfile_name = f"sniffer_{interface}_log.txt"  # Log file name based on interface
    with open(logfile_name, 'a') as logfile:  # Open log file in append mode
        print(f"Starting packet sniffer on interface: {interface}")
        try:
            # Start sniffing packets on the specified interface
            sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, logfile), store=0)
        except KeyboardInterrupt:
            print("Sniffer stopped by user.")
            sys.exit(0)
        except Exception as e:
            print(f"An error occurred: {e}")
            sys.exit(1)

# Check if the script is being run directly
if __name__ == "_main_":
    if len(sys.argv) != 2:
        print("Usage: python sniffer.py <interface>")
        sys.exit(1)
    main(sys.argv[1]);