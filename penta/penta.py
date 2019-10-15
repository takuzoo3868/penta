#!/usr/bin/env python
import argparse
import socket
import sys

from inspector.dns_scan import DnsScanner
from inspector.ftp_access import FtpConnector
from inspector.inspector import Inspect
from inspector.nmap_scan import NmapScanner
from inspector.shodan_scan import ShodanSearch
from inspector.ssh_access import SshConnector
from msfscan.metasploit import MetaSploitRPC
from utils import Colors, LogHandler

try:
    from bs4 import BeautifulSoup
except Exception:
    print("[!] pipenv install beautifulsoup4")
    exit(1)


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
""".format(Colors.GREEN, Colors.BOLD, Colors.END)
    print(banner)


def menu():
    print("[ ] === MENU LIST ===========================================")
    print("[0] EXIT")
    print("[1] Port scanning Default: 21,22,25,80,110,443,8080")
    print("[2] Nmap & vuln scanning")
    print("[3] Check HTTP option methods")
    print("[4] Grab DNS server info")
    print("[5] Shodan host search")
    print("[6] FTP connect with anonymous")
    print("[7] SSH connect with Brute Force")
    print("[8] Metasploit Frame Work")
    print("[99] Change target host")

    num_menu = input("\n[>] Choose an option number: ")
    return num_menu


def main():
    parser = argparse.ArgumentParser(description='Penta is Pentest automation tool')

    parser.add_argument("-target", dest="target", help="Specify target IP / domain")
    parser.add_argument("-ports", dest="ports",
                        help="Specify the target port(s) separated by comma. Default: 21,22,25,80,110,443,8080",
                        default="21,22,25,80,110,443,8080")
    parser.add_argument("-proxy", dest="proxy", help="Proxy[IP:PORT]")

    options = parser.parse_args()

    checker = Inspect()
    nmap_scan = NmapScanner()
    dns_scan = DnsScanner()
    shodan_search = ShodanSearch()
    ftp_access = FtpConnector()
    ssh_access = SshConnector()
    msf_scan = MetaSploitRPC()
    log_handler = LogHandler()

    hostname = ""
    num_menu = ""

    if options.target is None:
        while hostname == "":
            hostname = input("[*] Specify IP or name domain:")
    else:
        hostname = options.target

    print("[*] Get IP address from host name...")
    ip = socket.gethostbyname(hostname)
    print('[+] The IP address of {} is {}{}{}\n'.format(hostname, Colors.GREEN, ip, Colors.END))

    while num_menu != 0:
        num_menu = menu()

        if num_menu == "0":
            sys.exit(1)

        elif num_menu == "1":
            port_list = options.ports.split(',')
            for port in port_list:
                nmap_scan.nmap_scan(ip, port)

            results = nmap_scan.nmap_json_export(ip, options.ports)
            log_filename = "scan_{}.json".format(hostname)

            log_handler.save_logfile(log_filename, results)
            print("[+] {}{}{} was generated".format(Colors.GREEN, log_filename, Colors.END))
            print("\n")

        elif num_menu == "2":
            nmap_scan.nmap_menu(ip)
            print("\n")

        elif num_menu == "3":
            print("\n")
            checker.check_option_methods(hostname)
            print("\n")

        elif num_menu == "4":
            print("\n")
            dns_scan.check_dns_info(ip, hostname)
            print("\n")

        elif num_menu == "5":
            shodan_search.shodan_host_info(ip)
            print("\n")

        elif num_menu == "6":
            ftp_access.ftp_connect_anonymous(ip)
            print("\n")

        elif num_menu == "7":
            ssh_access.ssh_connect(ip)
            print("\n")

        elif num_menu == "8":
            msf_scan.msf_scan(ip)
            print("\n")

        elif num_menu == "9":
            # TODO: hydra brute force login --> smb ssh ftp http
            # TODO: malware detect functions e.g avast socks
            pass

        elif num_menu == "99":
            hostname = input("[*] Specify IP or name domain:")
            print("[*] Get IP address from host name...")
            ip = socket.gethostbyname(hostname)
            print('[+] The IP address of {} is {}{}{}\n'.format(hostname, Colors.GREEN, ip, Colors.END))

        else:
            print("[-] Incorrect option")


if __name__ == "__main__":
    if sys.version_info[0] < 3:
        raise Exception("[!] Must be using Python 3")

    logo()
    main()
