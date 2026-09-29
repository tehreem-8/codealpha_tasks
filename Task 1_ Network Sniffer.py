from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


def analyze_packet(packet):

    # Check if packet contains an IP layer
    if IP in packet:

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        # Identify the protocol
        if TCP in packet:
            protocol = "TCP"

        elif UDP in packet:
            protocol = "UDP"

        elif ICMP in packet:
            protocol = "ICMP"

        else:
            protocol = "Other IP"

        packet_length = len(packet)

        print("\n" + "=" * 50)
        print("PACKET CAPTURED")
        print("=" * 50)

        print(f"Source IP      : {source_ip}")
        print(f"Destination IP : {destination_ip}")
        print(f"Protocol       : {protocol}")
        print(f"Packet Length  : {packet_length} bytes")

        # Check whether the packet contains a payload
        if Raw in packet:

            payload = bytes(packet[Raw].load)

            print(f"Payload Length : {len(payload)} bytes")

            # Display only a small payload preview
            preview = payload[:32]

            print(f"Payload Preview: {preview.hex()}")

        else:
            print("Payload        : No application payload detected")


print("=" * 50)
print("BASIC NETWORK SNIFFER")
print("=" * 50)

print("Starting packet capture...")
print("Capture duration: 30 seconds")
print("Monitoring local network traffic...")
print()

# Capture packets for 30 seconds
sniff(prn=analyze_packet, timeout=30)

print("\n" + "=" * 50)
print("PACKET CAPTURE COMPLETED")
print("=" * 50)
