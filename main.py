from ipaddress import ip_address, IPv4Address
from pprint import pprint
import json
from typing import Dict

from sophosfirewall_python.firewallapi import (
    SophosFirewall,
    SophosFirewallAPIError,
)

# Set firewall variables
FW_USER = ""
FW_PASS = ""
FW_HOST = ""
FW_PORT = 4444
OBJ_PREFIX = ""
IP_FILENAME = ""

# JSON file format:
# {"Some Object": ["1.1.1.1", "2.2.2.2"], "Some Other Object": ["3.3.3.3", "4.4.4.4"]}

TEMPLATE_DIR = "./templates"
TEMPLATE_IPLIST = "iplist_template.xml"

def errmsg(e: SophosFirewallAPIError) -> str:
    if len(e.args) == 0 or not isinstance(e.args[0], dict):
        return "Unknown SophosFirewallAPIError"
    return e.args[0].get("Status", {}).get("#text", "")

def do_iplist(fw: SophosFirewall, operation: str, name: str, ips: list[str], description: str) -> dict:
    return fw.submit_template(
        template_dir=TEMPLATE_DIR,
        filename=TEMPLATE_IPLIST,
        template_vars={
            "name": name,
            "operation": operation,
            "description": description,
            "ip_list_csv": ",".join(map(str, ips)),
        }
    )

def add_iplist(fw: SophosFirewall, name: str, ips: list[IPv4Address], description: str = "") -> dict:
    print(f"Attempting to add firewall object '{name}'...")
    return do_iplist(fw, "add", name, ips, description)

def update_iplist(fw: SophosFirewall, name: str, ips: list[IPv4Address], description: str = "") -> bool:
    print(f"Attempting to update firewall object '{name}'...")
    return do_iplist(fw, "update", name, ips, description)

def add_or_update_iplist(fw: SophosFirewall, name: str, ips: list[IPv4Address], description: str = "") -> dict:
    try:
        return add_iplist(fw, name, ips, description)
    except SophosFirewallAPIError as e:
        if "Entity having same name already exists" in errmsg(e):
            return update_iplist(fw, name, ips, description)

def apply_iplists(fw: SophosFirewall, iplist: Dict[str, list[IPv4Address]]):
    for name, ips in iplist.items():
        try:
            result = add_or_update_iplist(fw, name, ips)
            print(result)
        except SophosFirewallAPIError as e:
            print(f"Error processing IP list '{name}': {errmsg(e)}")

def check_login(fw: SophosFirewall) -> bool:
    print("Attempting to login...")
    """
    Attempt to login and verify authentication was successful
    
    :param fw: client SophosFirewall instance
    :type fw: SophosFirewall
    :return: True if login successful, False otherwise
    :rtype: bool
    """
    try:
        login = fw.login()
        if login["Response"]["Login"]["status"] != "Authentication Successful":
            pprint(login)
            raise Exception("Login failed")
        print(f"Successfully authenticated to Sophos Firewall @ {FW_HOST}:{FW_PORT}")
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

def parseips(ips: list[str]) -> list[IPv4Address]:
    addrs = []
    for ip in ips:
        try:
            ip_obj = ip_address(ip)
            if not isinstance(ip_obj, IPv4Address):
                print(f"Warning: '{ip}' is not a valid IPv4 address, skipping...")
                continue
            addrs.append(ip_address(ip))
        except:
            pass
    return addrs


def main():
    with open(IP_FILENAME, "r") as f:
        cerberus = json.load(f)
    
    ip_lists: Dict[str, list[IPv4Address]] = {}

    for name, ips in cerberus.items():
        ip_list = parseips(ips)
        if len(ip_list) == 0:
            print(f"Warning: No valid IPs found for '{name}', skipping...")
            continue
        if len(ip_list) > 1000:
            print(f"Warning: More than 1000 IPs found for '{name}'. Cannot continue.")
            return
        ip_lists[OBJ_PREFIX + name] = ip_list

    print(len(ip_lists), "IP lists parsed successfully.")

    # Create the firewall API client
    fw = SophosFirewall(
        username=FW_USER,
        password=FW_PASS,
        hostname=FW_HOST,
        port=FW_PORT,
        verify=False,
    )

    if not check_login(fw):
        return
    
    apply_iplists(fw, ip_lists)

if __name__ == "__main__":
    main()
