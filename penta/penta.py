#!/usr/bin/env python
import sys
import socket
import argparse

try:
    from bs4 import BeautifulSoup
except Exception as e:
    print("[!] pipenv install beautifulsoup4")
    exit(1)

from utils import Colors, LogHandler
from inspector.inspector import Inspect
from inspector.nmap_scan import NmapScanner
from inspector.dns_scan import DnsScanner


def logo():
    banner = r"""{}{}
   ██████╗ ███████╗███╗   ██╗████████╗ █████╗
   ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗
   ██████╔╝█████╗  ██╔██╗ ██║   ██║   ███████║
   ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══██║
   ██║     ███████╗██║ ╚████║   ██║   ██║  ██║
   ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝
==================================================
  Author: @takuzoo3868
  Web: https://takuzoo3868.github.io
  Last Modified: 22 May 2019.
==================================================
- Penta is Pentest automation tool. It provides
advanced features such as metasploit and nexpose
to extract vuln info found on specific servers.
=================================================={}
""".format(Colors.OKGREEN, Colors.BOLD, Colors.END)
    print(banner)


def menu():
    print("[ ] === MENU LIST ===========================================")
    print("[0] EXIT")
    print("[1] Check opened port(s) \tDefault: 21,22,25,80,110,443,8080")
    print("[2] Port scanning")
    print("[3] Nmap")
    print("[4] Check HTTP option methods")
    print("[5] Grab DNS server info")
    print("[ ] =========================================================")

    num_menu = input("\n[>] Choose an option number: ")
    return num_menu


def main():
    parser = argparse.ArgumentParser(description='Penta is Pentest automation tool')

    # Main arguments
    parser.add_argument("-target", dest="target", help="Specify target IP / domain")
    parser.add_argument("-ports", dest="ports",
                        help="Please, specify the target port(s) separated by comma. Default: 21,22,25,80,110,443,8080",
                        default="21,22,25,80,110,443,8080")
    parser.add_argument("-proxy", dest="proxy", help="Proxy[IP:PORT]")

    options = parser.parse_args()

    checker = Inspect()
    nmap_scan = NmapScanner()
    dns_scan = DnsScanner()
    log_handler = LogHandler()

    # default port list
    ip = ""
    hostname = ""
    num_menu = ""

    if options.target is None:
        while hostname == "":
            hostname = input("[*] Introduce IP or name domain:")
    else:
        hostname = options.target

    print("[*] Obtain IP address from host name")
    print("-----------------------------------")
    ip = socket.gethostbyname(hostname)
    print('[+] The IP address of {} is {}\n'.format(hostname, ip))

    while num_menu != 0:
        num_menu = menu()

        if num_menu == "0":
            sys.exit(1)

        elif num_menu == "1":
            print("\n[*] === CHECK PORTS")
            ports = options.ports.split(',')
            checker.check_open_ports(ip, hostname, ports)
            print("[*] === DONE ================================================\n")

        elif num_menu == "2":
            print("\n[*] === PORT SCAN")
            port_list = options.ports.split(',')
            for port in port_list:
                nmap_scan.nmap_scan(ip, port)

            results = nmap_scan.nmap_json_export(ip, options.ports)
            log_filename = "scan_{}.json".format(hostname)

            log_handler.save_logfile(log_filename, results)
            print("[+] {} was generated".format(log_filename))
            print("[*] === DONE ================================================\n")

        elif num_menu == "3":
            print("\n[*] === NMAP SCAN")
            nmap_scan.check_nmap(ip)
            print("[*] === DONE ================================================\n")

        elif num_menu == "4":
            print("\n[*] === CHECK OPTION METHODS")
            checker.check_option_methods(hostname)
            print("[*] === DONE ================================================\n")

        elif num_menu == "5":
            print("\n[*] === DNS INFO")
            dns_scan.check_dns_info(ip, hostname)
            print("[*] === DONE ================================================\n")

        else:
            print("[-] Incorrect option")


if __name__ == "__main__":
    logo()
    main()
