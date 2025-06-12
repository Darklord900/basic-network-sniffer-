import pyfiglet 
# Print ASCII art banner
ascii_banner = pyfiglet.figlet_format("Build by sk")
print(ascii_banner)

from scapy.all import sniff, IP, TCP, UDP, Ether

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Determine the protocol
        if proto == 6 and TCP in packet:
            protocol = "TCP"
            payload = str(packet[TCP].payload) if packet[TCP].payload else "No payload"
        elif proto == 17 and UDP in packet:
            protocol = "UDP"
            payload = str(packet[UDP].payload) if packet[UDP].payload else "No payload"
        else:
            protocol = "Other"
            payload = "No payload"

        # Print packet information
        print(f"Source IP: {ip_src} | Destination IP: {ip_dst} | Protocol: {protocol}")
        print(f"Payload: {payload}\n")


# Start sniffing packets
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0)
