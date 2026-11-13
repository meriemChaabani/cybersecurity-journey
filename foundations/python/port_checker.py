# Exercise 04 - Port Information Checker

print("======================================")
print("       PORT INFORMATION CHECKER")
print("======================================")

# Common network ports and their information

ports = {
    20: {
        "service": "FTP Data",
        "protocol": "TCP",
        "description": "Transfers files using FTP."
    },
    21: {
        "service": "FTP Control",
        "protocol": "TCP",
        "description": "Controls FTP file transfer sessions."
    },
    22: {
        "service": "SSH",
        "protocol": "TCP",
        "description": "Provides secure remote access."
    },
    23: {
        "service": "Telnet",
        "protocol": "TCP",
        "description": "Provides remote terminal access."
    },
    25: {
        "service": "SMTP",
        "protocol": "TCP",
        "description": "Used for sending emails."
    },
    53: {
        "service": "DNS",
        "protocol": "TCP/UDP",
        "description": "Translates domain names into IP addresses."
    },
    80: {
        "service": "HTTP",
        "protocol": "TCP",
        "description": "Used for web communication."
    },
    110: {
        "service": "POP3",
        "protocol": "TCP",
        "description": "Retrieves emails from a mail server."
    },
    143: {
        "service": "IMAP",
        "protocol": "TCP",
        "description": "Accesses emails stored on a server."
    },
    443: {
        "service": "HTTPS",
        "protocol": "TCP",
        "description": "Provides encrypted web communication."
    },
    3306: {
        "service": "MySQL",
        "protocol": "TCP",
        "description": "Used for MySQL database connections."
    },
    3389: {
        "service": "RDP",
        "protocol": "TCP",
        "description": "Provides remote desktop access."
    },
    5432: {
        "service": "PostgreSQL",
        "protocol": "TCP",
        "description": "Used for PostgreSQL database connections."
    }
,    67: {
    "service": "DHCP Server",
    "protocol": "UDP",
    "description": "Assigns network configuration to clients."
},
68: {
    "service": "DHCP Client",
    "protocol": "UDP",
    "description": "Receives network configuration from DHCP servers."
},
123: {
    "service": "NTP",
    "protocol": "UDP",
    "description": "Synchronizes system clocks."
},
161: {
    "service": "SNMP",
    "protocol": "UDP",
    "description": "Monitors and manages network devices."
},
445: {
    "service": "SMB",
    "protocol": "TCP",
    "description": "Provides network file and printer sharing."
},
8080: {
    "service": "HTTP Alternative",
    "protocol": "TCP",
    "description": "Common alternative HTTP service port."
},
8443: {
    "service": "HTTPS Alternative",
    "protocol": "TCP",
    "description": "Common alternative HTTPS service port."
}
}

# Get port number from user

user_input = input("\nEnter a port number: ")

try:
    port_number = int(user_input)

    # Validate port range

    if port_number < 1 or port_number > 65535:
        print("\nError: Port must be between 1 and 65535.")

    else:
        print("\n========== PORT ANALYSIS ==========")

        print("Port Number:", port_number)

        if port_number in ports:

            information = ports[port_number]

            print("Service:", information["service"])
            print("Protocol:", information["protocol"])
            print("Description:", information["description"])

        else:
            print("Service: Unknown in our database")
            print("Protocol: Not identified")
            print("Description: No information available.")

        print("\nAnalysis completed.")

except ValueError:
    print("\nError: Please enter a valid numeric port number.")

print("======================================")