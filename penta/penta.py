#!/usr/bin/env python
import argparse
import logging
import socket
import sys

from fetch.fetch_edb import EdbCollector
from fetch.fetch_msf import MsfCollector, MsfLocalCollector
from fetch.fetch_nvd import NvdCveCollector
from modules.inspector import Inspect
from modules.report_vuln import DailyReportor
from modules.scan_dns import DnsScanner
from modules.scan_ftp import FtpConnector
from modules.scan_msf import MetaSploitRPC
from modules.scan_nmap import NmapScanner
from modules.scan_shodan import ShodanSearch
from modules.scan_ssh import SshConnector
from utils import Colors, LogHandler


logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S %Z")


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
  Last Modified: 28 April 2020.
==================================================
- Penta is Pentest semi-automation tool. It
provides advanced features such as metasploit to
extract vuln info found on specific servers.
=================================================={}
""".format(Colors.LIGHTGREEN, Colors.BOLD, Colors.END)
    print(banner)


def main_menu_list():
    print("[ ] === MENU LIST ===========================================")
    print("[0] EXIT")
    print("[1] IP based scan menu")
    print("[2] VulnDB construction menu")


def ip_menu_list():
    print("[ ] === MENU LIST ===========================================")
    print("[0] Return to MAIN MENU")
    print("[1] Port scanning Default: 21,22,25,80,110,443,8080")
    print("[2] Nmap & vuln scanning")
    print("[3] Check HTTP option methods")
    print("[4] Grab DNS server info")
    print("[5] Shodan host search")
    print("[6] FTP connect with anonymous")
    print("[7] SSH connect with Brute Force")
    print("[8] Metasploit Frame Work")
    print("[99] Change target host")


def report_menu_list():
    print("[ ] === MENU LIST ===========================================")
    print("[0] Return to MAIN MENU")
    print("[1] Generate a daily report: CVE,EDB,MSF...")
    print("[2] View a report")
    print("[3] Fetch CVEs from nvd.nist")
    print("[4] Fetch EDB records from exploit-db")
    print("[5] Fetch MSF modules from rapid7")
    print("[6] Fetch MSF modules from local")


def choice_num():
    number = int(input("\n[>] Choose an option number: "))
    return number


def main_menu(options):
    num_menu = ""
    main_menu_list()

    while num_menu != 0:
        num_menu = choice_num()
        if num_menu == 0:
            sys.exit(0)

        elif num_menu == 1:
            ip_menu(options)

        elif num_menu == 2:
            report_menu(options)

        else:
            logging.error("Incorrect option")


def ip_menu(options):
    hostname = ""
    num_menu = ""

    checker = Inspect()
    nmap_scan = NmapScanner()
    dns_scan = DnsScanner()
    shodan_search = ShodanSearch()
    ftp_access = FtpConnector()
    ssh_access = SshConnector()
    msf_rpc_scan = MetaSploitRPC()
    log_handler = LogHandler()

    if options.target is None:
        while hostname == "":
            hostname = input("[>] Specify IP or name domain: ")
    else:
        hostname = options.target

    print("[*] Get IP address from host name...")
    ip = socket.gethostbyname(hostname)
    print('[+] The IP address of {} is {}{}{}\n'.format(hostname, Colors.LIGHTGREEN, ip, Colors.END))

    ip_menu_list()
    while num_menu != 0:
        num_menu = choice_num()
        if num_menu == 0:
            main_menu(options)

        elif num_menu == 1:
            port_list = options.ports.split(',')
            for port in port_list:
                nmap_scan.nmap_scan(ip, port)

            results = nmap_scan.nmap_json_export(ip, options.ports)
            log_filename = "scan_{}.json".format(hostname)

            log_handler.save_logfile(log_filename, results)
            print("[+] {}{}{} was generated".format(Colors.LIGHTGREEN, log_filename, Colors.END))

        elif num_menu == 2:
            nmap_scan.nmap_menu(ip)

        elif num_menu == 3:
            checker.check_option_methods(hostname)

        elif num_menu == 4:
            dns_scan.check_dns_info(ip, hostname)

        elif num_menu == 5:
            shodan_search.shodan_host_info(ip)

        elif num_menu == 6:
            ftp_access.ftp_connect_anonymous(ip)

        elif num_menu == 7:
            ssh_access.ssh_connect(ip)

        elif num_menu == 8:
            msf_rpc_scan.scan(ip)

        elif num_menu == 9:
            # TODO: hydra brute force login --> smb ssh ftp http
            # TODO: malware detect functions e.g avast socks
            pass

        elif num_menu == 99:
            hostname = input("[*] Specify IP or name domain: ")
            print("[*] Get IP address from host name...")
            ip = socket.gethostbyname(hostname)
            print('[+] The IP address of {} is {}{}{}\n'.format(hostname, Colors.LIGHTGREEN, ip, Colors.END))

        else:
            logging.error("Incorrect option")
        ip_menu_list()


def report_menu(options):
    num_menu = ""

    fetch_nvd = NvdCveCollector()
    fetch_msf = MsfCollector()
    fetch_msf_local = MsfLocalCollector()
    fetch_edb = EdbCollector()
    report = DailyReportor()

    report_menu_list()
    while num_menu != 0:
        num_menu = choice_num()
        if num_menu == 0:
            main_menu(options)

        elif num_menu == 1:
            report.fetch_report()

        elif num_menu == 2:
            report.view_report()

        elif num_menu == 3:
            fetch_nvd.download()

        elif num_menu == 4:
            fetch_edb.major_update()

        elif num_menu == 5:
            fetch_msf.update()

        elif num_menu == 6:
            fetch_msf_local.update()

        else:
            logging.error("Incorrect option")
        report_menu_list()


def main():
    parser = argparse.ArgumentParser(description='Penta is Pentest automation tool')

    parser.add_argument("-target", dest="target", help="Specify target IP / domain")
    parser.add_argument("-ports", dest="ports",
                        help="Specify the target port(s) separated by comma. Default: 21,22,25,80,110,443,8080",
                        default="21,22,25,80,110,443,8080")
    parser.add_argument("-proxy", dest="proxy", help="Proxy[IP:PORT]")

    options = parser.parse_args()

    main_menu(options)


if __name__ == "__main__":
    if sys.version_info[0] < 3:
        raise Exception("[!] Must be using Python 3")

    logo()
    main()
