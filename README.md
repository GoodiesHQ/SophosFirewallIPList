# SophosFirewallIPList

A simple utility to take a JSON file for IP Lists and apply it to a Sophos Firewall.

### Configuration
Before running, set the variables required to authenticate to the firewall. Ensure you are running this from a source permitted to reach the firewall management plane.

    # Set firewall variables
    FW_USER = ""        # Firewall API user username 
    FW_PASS = ""        # Firewall API user password
    FW_HOST = ""        # Firewall public IP address or hostname
    FW_PORT = 4444      # Firewall admin management port
    OBJ_PREFIX = ""     # A prefix to add to all objects during operation
    IP_FILENAME = ""    # The JSON filename containing the IP addresses

### JSON Data
The JSON file must contain a map of names to IP address lists. The data should look like:

    {
      "Some Object": [
        "1.1.1.1",
        "2.2.2.2"
      ],
      "Some Other Object": [
        "3.3.3.3",
        "4.4.4.4"
      ]
    }
