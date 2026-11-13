from scapy.all import IP, TCP, UDP, ICMP, wrpcap

# ==========================================
# NETWATCH - CLEAN SAMPLE PCAP GENERATOR
# ==========================================

packets = []

# 1. Normal web traffic
for port in [80, 443, 443, 80, 443]:

    packet = (
        IP(src="192.0.2.10", dst="198.51.100.20") /
        TCP(sport=50000 + port, dport=port, flags="S")
    )

    packets.append(packet)


# 2. Normal DNS traffic
for i in range(3):

    packet = (
        IP(src="192.0.2.10", dst="198.51.100.53") /
        UDP(sport=53000 + i, dport=53)
    )

    packets.append(packet)


# 3. Normal ICMP traffic
packet = (
    IP(src="192.0.2.10", dst="198.51.100.30") /
    ICMP(type=8)
)

packets.append(packet)


# 4. Simulated port scanning activity
for port in [21, 22, 23, 25, 80, 110, 443, 445, 8080]:

    packet = (
        IP(src="203.0.113.50", dst="198.51.100.20") /
        TCP(sport=40000 + port, dport=port, flags="S")
    )

    packets.append(packet)


# 5. Save PCAP file
output_file = "netwatch/samples/sample_traffic.pcap"

wrpcap(output_file, packets)

print("Sample PCAP generated successfully!")
print("Total packets:", len(packets))
print("Saved to:", output_file)