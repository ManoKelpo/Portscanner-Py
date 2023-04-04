# nmap-portscanner.py
# Purpose: Python wrapper for nmap scanner
# Author: Rayan

# ###############

# Version 0.1
#       Initial build

import argparse
import nmap


def argument_parser():
    # Allow the user to specify the port of the target host
    parser = argparse.ArgumentParser(description="TCP port scanner. Accepts a hostname/IP address and list of ports to"
    "scan. Attempts to identify the service running on a port.")
    parser.add_argument("-o", "--host", nargs="?", help="Host IP address")
    parser.add_argument("-p", "--ports", nargs="?", help="Comma-separated port list, such as '25,80,8080'")

    var_args = vars(parser.parse_args())

    return var_args

def nmap_scan(host_id, port_num):
    # Use nmap utility to check host ports for status.
    nm_scan = nmap.PortScanner()
    nm_scan.scan(host_id, port_num)
    state = nm_scan[host_id]['tcp'][int(port_num)]['state'] # indicate thet type of scan and port number
    result = ("[*] {host} tcp/{port} {state}". format(host=host_id, port=port_num, state=state))

    return result


if __name__ == "__main__":
    try:
        user_arg = argument_parser()
        host = user_arg["host"]
        ports = user_arg["ports"].split(",")
        for port in ports:
            print(nmap_scan(host, port))
    except AttributeError:
        print("Error. Please provide the command-line argument before running.")
