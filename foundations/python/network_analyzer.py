import ipaddress

print("======================================")
print("       NETWORK INFORMATION ANALYZER")
print("======================================")

user_input = input("\nEnter IP address with prefix (e.g. 192.168.1.10/24): ")

try:
    interface = ipaddress.ip_interface(user_input)

    if not isinstance(interface, ipaddress.IPv4Interface):
        raise ValueError("Please enter an IPv4 address.")

    ip = interface.ip
    network = interface.network

    print("\n========== ANALYSIS RESULTS ==========")

    print("IP Address:", ip)
    print("IP Version:", ip.version)
    print("Subnet Mask:", network.netmask)
    print("Network Address:", network.network_address)
    print("Broadcast Address:", network.broadcast_address)
    print("Network Prefix: /" + str(network.prefixlen))
    print("Total Addresses:", network.num_addresses)

    if network.prefixlen <= 30:
        usable_hosts = network.num_addresses - 2
    elif network.prefixlen == 31:
        usable_hosts = 2
    else:
        usable_hosts = 1

    print("Usable Host Addresses:", usable_hosts)

    if ip.is_private:
        print("IP Classification: Private")
    else:
        print("IP Classification: Not classified as private")

    print("\n======================================")
    print("Analysis completed successfully!")
    print("======================================")

except ValueError as error:
    print("\nError:", error)
    print("Please enter a valid IPv4 address with CIDR prefix.")