from scapy.all import rdpcap, IP, TCP, UDP, ICMP
from collections import Counter, defaultdict
from pathlib import Path

# ==========================================
# NETWATCH - NETWORK TRAFFIC ANALYZER
# ==========================================

PCAP_FILE = Path("netwatch/samples/sample_traffic.pcap")
REPORT_FILE = Path("netwatch/reports/network_report.txt")

# Detection configuration
PORT_SCAN_THRESHOLD = 9

# Common destination ports

COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL"
}


# ==========================================
# ANALYZE PACKETS
# ==========================================

def analyze_packets():

    if not PCAP_FILE.exists():
        print("ERROR: PCAP file not found:", PCAP_FILE)
        print("Run generate_sample.py first.")
        return

    print("=" * 55)
    print("       NETWATCH - NETWORK TRAFFIC ANALYZER")
    print("=" * 55)

    try:
        packets = rdpcap(str(PCAP_FILE))
    except Exception as error:
        print("ERROR: Could not read PCAP file:", error)
        return

    if len(packets) == 0:
        print("No packets found in the capture.")
        return

    # Statistics

    protocol_counts = Counter()
    source_counts = Counter()
    destination_counts = Counter()

    connection_counts = Counter()

    destination_ports = defaultdict(set)
    syn_counts = Counter()

    packet_details = []

    # ======================================
    # INSPECT EACH PACKET
    # ======================================

    for packet in packets:

        if IP not in packet:
            continue

        ip_layer = packet[IP]

        source_ip = ip_layer.src
        destination_ip = ip_layer.dst

        protocol = "OTHER"
        source_port = None
        destination_port = None

        source_counts[source_ip] += 1
        destination_counts[destination_ip] += 1

        # TCP analysis

        if TCP in packet:

            protocol = "TCP"

            tcp_layer = packet[TCP]

            source_port = tcp_layer.sport
            destination_port = tcp_layer.dport

            connection_counts[
                (source_ip, destination_ip, "TCP")
            ] += 1

            destination_ports[
                (source_ip, destination_ip)
            ].add(destination_port)

            # SYN without ACK: connection initiation indicator

            if (
                tcp_layer.flags & 0x02
                and not tcp_layer.flags & 0x10
            ):
                syn_counts[
                    (source_ip, destination_ip)
                ] += 1

        # UDP analysis

        elif UDP in packet:

            protocol = "UDP"

            udp_layer = packet[UDP]

            source_port = udp_layer.sport
            destination_port = udp_layer.dport

            connection_counts[
                (source_ip, destination_ip, "UDP")
            ] += 1

        # ICMP analysis

        elif ICMP in packet:

            protocol = "ICMP"

        protocol_counts[protocol] += 1

        packet_details.append({
            "source": source_ip,
            "destination": destination_ip,
            "protocol": protocol,
            "source_port": source_port,
            "destination_port": destination_port
        })

    # ======================================
    # DISPLAY PACKET SUMMARY
    # ======================================

    print("\n========== CAPTURE SUMMARY ==========")

    print("Total packets:", len(packets))
    print("Analyzed IPv4 packets:", len(packet_details))

    print("\n========== PROTOCOL STATISTICS ==========")

    for protocol, count in protocol_counts.items():

        print(protocol + ":", count)

    print("\n========== TOP SOURCE IP ADDRESSES ==========")

    for ip, count in source_counts.most_common():

        print(ip, ":", count, "packets")

    print("\n========== DESTINATION PORT ANALYSIS ==========")

    for detail in packet_details:

        if detail["destination_port"] is not None:

            port = detail["destination_port"]

            service = COMMON_PORTS.get(
                port,
                "Unknown service"
            )

            print(
                detail["source"],
                "->",
                detail["destination"],
                "| Port:",
                port,
                "| Service:",
                service
            )

    # ======================================
    # DETECT POSSIBLE PORT SCANNING
    # ======================================

    print("\n========== SECURITY ALERTS ==========")

    alerts = []

    for pair, ports in destination_ports.items():

        source_ip, destination_ip = pair

        unique_port_count = len(ports)

        if unique_port_count >= PORT_SCAN_THRESHOLD:

            alert = (
                "POSSIBLE PORT SCANNING: "
                + source_ip
                + " contacted "
                + destination_ip
                + " on "
                + str(unique_port_count)
                + " different destination ports."
            )

            alerts.append(alert)

            print("[HIGH]", alert)

    if not alerts:

        print("No suspicious port patterns detected.")

    # ======================================
    # GENERATE REPORT
    # ======================================

    REPORT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with REPORT_FILE.open("w", encoding="utf-8") as report:

        report.write("NETWATCH NETWORK INVESTIGATION REPORT\n")
        report.write("=" * 50 + "\n\n")

        report.write("Total packets: " + str(len(packets)) + "\n")

        report.write(
            "Analyzed IPv4 packets: "
            + str(len(packet_details))
            + "\n\n"
        )

        report.write("PROTOCOL STATISTICS\n")
        report.write("-" * 30 + "\n")

        for protocol, count in protocol_counts.items():

            report.write(
                protocol + ": " + str(count) + "\n"
            )

        report.write("\nSOURCE IP STATISTICS\n")
        report.write("-" * 30 + "\n")

        for ip, count in source_counts.most_common():

            report.write(
                ip + ": " + str(count) + " packets\n"
            )

        report.write("\nSECURITY ALERTS\n")
        report.write("-" * 30 + "\n")

        if alerts:

            for alert in alerts:

                report.write(alert + "\n")

        else:

            report.write("No suspicious patterns detected.\n")

    print("\nReport generated:", REPORT_FILE)
    print("\nAnalysis completed successfully!")


# ==========================================
# MAIN PROGRAM
# ==========================================

if __name__ == "__main__":

    analyze_packets()