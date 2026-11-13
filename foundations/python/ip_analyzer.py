import ipaddress
print("================================")
print("      IP ADDRESS ANALYZER")
print("================================")
ip_address = input("Enter an IP address: ")
try:
    validated_ip = ipaddress.IPv4Address(ip_address)
    print("\n--- Analysis Results ---")
    print("IP Address:", validated_ip)
    print("IP Version:", validated_ip.version)
    if validated_ip.is_private:
        print("IP Type: Private")
    else:
        print("IP Type: Public")
    print("Status: Valid IPv4 address")
except ipaddress.AddressValueError:
    print("\nStatus: Invalid IPv4 address!")
print("\nAnalysis completed.")