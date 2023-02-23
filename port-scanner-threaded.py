# nmap-scanner-threaded.py
# Purpose: Python wrapper for nmap scanner
# Author: Rayan Araujo
# ##################
# Version 0.1
#   Initial build

#clear terminal
import os
os.system('clear')

import argparse
import threading
import nmap

def argument_parser():
    # Allow user to specify target host and port.
    parser = argparse.ArgumentParser(description="Nmap port scanner. Accepts hostname/IP address and list of ports to"
    "to scan. Attempts to identify the service running on a port")
    parser.add_argument("-o", "--host", nargs="?", help="Host IP address")
    parser.add_argument("-p", "--ports", nargs="?", help="Comma-separated port list, such as '25,80,8080'")
    var_args = vars(parser.parse_args())
    return var_args


def nmap_scan(host_id, port_num):
    # Use nmap to check status of host posts
    nmap_scan = nmap.PortScanner()
    nmap_scan.scan(host_id, port_num)
    state = nmap_scan[host_id]['tcp'][int(port_num)]['state'] # Indicate the type of scan and port nmber.
    result = ("[*]{host} tcp/{port} {satte}".format(host=host_id, port=port_num, state=state))

    return result


if __name__ == "__main__":
    try:
        user_args = argument_parser()
        host = user_args["host"]
        ports = user_args["ports"].split(",") # Make list from given port numbers "1,2,3,4,5"
        for port in ports:
            print(nmap_scan(host, port))
    except AttributeError:
        print("Error. Please provide the command-line arguments before running")