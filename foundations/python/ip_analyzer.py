import ipaddress
ip_address = input("Enter an IP address: ")
try:
    validated_ip = ipaddress.IPv4Address(ip_address)
    print("Valid IPv4 address!")
    print("IP Address:", validated_ip)
    print("Version:", validated_ip.version)
except ipaddress.AddressValueError:
    print("Invalid IPv4 address!")