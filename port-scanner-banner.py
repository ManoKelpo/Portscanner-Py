import argparse
import socket
import threading

#clear terminal
import os
os.system('clear')

def connection_scan(target_ip, target_port):
    # Attempts to create a socket connection with the given IP and Port.
    # If successful, the port is open. If not, the port is closed.
    conn_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conn_socket.connect((target_ip, target_port))
        conn_socket.send(b'Banner_query\r\n')
        results = conn_socket.recv(100)

        print("     [+] {}/tcp open".format(target_port) + "- ({})".format(str(results))) # print if port is open + banner

    except OSError:
        print("     [-] {}/tcp closed".format(target_port))
    finally:
        conn_socket.close() # Ensures the connection is closed


def port_scan(target, port_num):
    # Scan the ports indicated
    # It first attempts to solve the IP, then enumerate through the ports
    try:
        target_ip = socket.gethostbyname(target)
    except OSError:
        print("[^] Cannot resolve {}: Unknown host".format(target))
        return # Exit scan if IP is not resolved

    try:
        target_name = socket.gethostbyaddr(target_ip)
    except OSError:
        return
        #print('[*] Scan Results for: {}'.format(target_ip))

    t = threading.Thread(target=connection_scan, args=(target, int(port_num)))
    t.start()






def argument_parser():
    # Allow user to specify target host and port.
    parser = argparse.ArgumentParser(description="TCP port scanner. Accepts a hostname/IP address and list of ports to scan. Attempts to identify the service running on a port.")

    parser.add_argument("-o", "--host", nargs="?", help="Host IP address")
    parser.add_argument("-p", "--ports", nargs="?", help="Comma-separated port list, such as '25,80,8080'")

    var_args = vars(parser.parse_args())

    return var_args

if __name__ == '__main__':
    try:
        user_args = argument_parser()
        host_list = user_args["host"].split(",")
        port_list = user_args["ports"].split(",") 

        #search the list of ports in each host in the list of hosts
        for host in host_list:
            #print('\nScan Results for: {}'.format(host))
            print('[*]\nScan Results for: {}'.format(host))
            #port scan in the host
            for port in port_list:
                port_scan(host, port)

    except AttributeError:
        print("Please provide the command-line arguments before running.")