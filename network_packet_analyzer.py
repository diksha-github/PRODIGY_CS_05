from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def analyze_packet(packet):
    print("\n[+] Packet Captured")

    if IP in packet:
        ip_layer = packet[IP]
        print(f"    Source IP      : {ip_layer.src}")
        print(f"    Destination IP : {ip_layer.dst}")
        print(f"    Protocol       : {ip_layer.proto}")

    if TCP in packet:
        tcp_layer = packet[TCP]
        print("    Protocol Type  : TCP")
        print(f"    Source Port    : {tcp_layer.sport}")
        print(f"    Destination Port: {tcp_layer.dport}")

    elif UDP in packet:
        udp_layer = packet[UDP]
        print("    Protocol Type  : UDP")
        print(f"    Source Port    : {udp_layer.sport}")
        print(f"    Destination Port: {udp_layer.dport}")

    elif ICMP in packet:
        print("    Protocol Type  : ICMP")

    if Raw in packet:
        payload = packet[Raw].load
        print(f"    Payload Data   : {payload[:50]}...")  # Truncate long data

# Print ethical warning
print("Note: This tool is for EDUCATIONAL PURPOSES ONLY.")
print("Do not use it on networks without permission.")
print("Sniffing started... Press Ctrl+C to stop.")

# Start sniffing
sniff(prn=analyze_packet, store=False)
