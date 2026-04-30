from scapy.all import sniff

# Function to process each packet
def packet_callback(packet):
    print("\n--- Packet Captured ---")
    
    # Check if packet has IP layer
    if packet.haslayer("IP"):
        ip_layer = packet["IP"]
        print("Source IP:", ip_layer.src)
        print("Destination IP:", ip_layer.dst)
        print("Protocol:", ip_layer.proto)
    
    # Check for TCP
    if packet.haslayer("TCP"):
        print("Protocol Type: TCP")
    
    # Check for UDP
    elif packet.haslayer("UDP"):
        print("Protocol Type: UDP")
    
    # Check for ICMP
    elif packet.haslayer("ICMP"):
        print("Protocol Type: ICMP")
    
    # Show payload (data inside packet)
    if packet.haslayer("Raw"):
        print("Payload:", packet["Raw"].load)

# Start sniffing
print("Starting packet capture... Press Ctrl+C to stop.")
sniff(prn=packet_callback, count=10)
