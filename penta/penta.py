#!/usr/bin/env python
import argparse
import logging
import os
import readline  # noqa: F401
import socket
import sys

import config
import fetch
import lib
from lib.menu import Menu
from lib.utils import ColorfulHandler, Colors, system_exit
import modules


hostname = None
ip = None


def logo():
    banner = r"""{}{}
                   .',:clllllllllc:,'.
              .';llllllllllllllllc;:lll..'.
           .,clllllllllllllllllll.  ''' lllc,.
         .:lllllllllllllllllllllllcllll clllllc.
       .cllllllllllllllllllllllllllc,,'.'cllllllc.
      ;lloooodddoooolllllllllllllll ;:..,..;clllc;.
    .loddddddddddddddddolllllllllll:'':llll:,..c :ll.
   .oddddddddddddddddddddollllllllllllllllllll c clll.
   ddddddddddddolodddddddddllllllllllllllllll: :'.;lll
  ldddddddddo. ..  ,dddddc;,,,,,,;;:cllllllll clll cll:
 .dddddddddd. oddd' :ddl'''''''''''''',llllll;.''.,llll.
 ;dddddddddd, 'cc;  odd:'''''''',;;::clllllllllllllllll,
 cdddddddddddl,..,cddddd;''''';clllllllllllllllllllllll:
 lddddddddddddddddddddddddoloolllllllllllllllllllllllll:
 :dddddddddddddddddddddddddddolllllllllllllllllllllllll;
 .dddddddddddddddddddddddddc;';llllllllllllllllllllllll.
  lddddddddddddddddddddl,.     .:lllllllllllllllllllll:
  .ddddddddddddddddddc.          'llllllllllllllllllll.
   .dddddddddddddddd.             .:lllllllllllllllll.
    .dddddddddddddd.                ;lllllllllllllll.
      cddddddddddd:                  ,llllllllllll:
       .oddddddddd'                   ;lllllllllc.

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
    menu = Menu(False)
    title = "======= MAIN MENU ==========================================="
    menu_list = [
        'Menu list for IP-based scan',
        'Menu list for building VulnDB',
        '[Exit]'
    ]
    menu_num = menu.show(title, menu_list)
    return menu_num


def ip_menu_list():
    menu = Menu(False)
    title = "======= PENTEST MENU LIST ==================================="
    menu_list = [
        'Port scan',
        'Nmap & vuln scan',
        'Check HTTP option methods',
        'Grab DNS server info',
        'Shodan host search',
        'FTP connect with anonymous',
        'SSH connect with Brute Force',
        'Metasploit Frame Work',
        'Change target host',
        '[Return]'
    ]
    menu_num = menu.show(title, menu_list)
    return menu_num


def report_menu_list():
    menu = Menu(False)
    title = "======= REPORT MENU LIST ===================================="
    menu_list = [
        'Daily report: CVE,EDB,MSF...',
        'View  report',
        'Fetch CVEs',
        'Fetch Exploits',
        'Fetch Msf modules',
        'Menu list for DB',
        '[Return]'
    ]
    menu_num = menu.show(title, menu_list)
    return menu_num


def main_menu(options):
    while True:
        menu_num = main_menu_list()
        if menu_num is not None:
            if menu_num == 0:
                ip_menu(options)
            if menu_num == 1:
                report_menu(options)
            if menu_num == -1 or menu_num == 2:
                logging.info("Stay out of trouble!!!")
                sys.exit(0)
        else:
            print("[!] Incorrect choice")


def initialize_variable(options):
    global hostname
    global ip

    addr_list = get_ip()
    if addr_list is not None:
        hostname, ip = addr_list
    else:
        main_menu(options)


def get_ip():
    while True:
        try:
            addr = input("[?] Specify IP or name domain: ")
            if 'http://' in addr:
                addr = addr.strip('http://')
            elif 'https://' in addr:
                addr = addr.strip('https://')
            else:
                addr = addr
        except KeyboardInterrupt:
            system_exit()
            return None

        if config.IPV4_REGEX.match(addr) or config.DOMAIN_REGEX.match(addr):
            hostname = addr
            print("[*] Get IP address from host name...")
            try:
                ip = socket.gethostbyname(hostname)
                print('[+] The IP address of {} is {}{}{}\n'.format(hostname, Colors.LIGHTGREEN, ip, Colors.END))
                break
            except Exception as e:
                logging.error(e)
                continue
        else:
            continue
    return [hostname, ip]


# TODO: hydra brute force login --> smb ssh ftp http
# TODO: malware detect functions e.g avast socks
def ip_menu(options):
    global hostname
    global ip

    if hostname is None:
        initialize_variable(options)

    checker = modules.Inspect()
    nmap_scan = modules.NmapScanner()
    dns_scan = modules.DnsScanner()
    shodan_search = modules.ShodanSearch()
    ftp_access = modules.FtpConnector()
    ssh_access = modules.SshConnector()
    msf_rpc_scan = modules.MetaSploitRPC()

    print("\n[*] Target Host: {} IP: {}".format(hostname, ip))
    num_menu = ip_menu_list()
    if num_menu == -1:
        main_menu(options)
    elif num_menu == 0:
        nmap_scan.port_scan(ip)
    elif num_menu == 1:
        nmap_scan.menu(ip)
    elif num_menu == 2:
        checker.check_option_methods(hostname)
    elif num_menu == 3:
        dns_scan.scan(ip, hostname)
    elif num_menu == 4:
        shodan_search.shodan_ip_to_service(ip)
    elif num_menu == 5:
        ftp_access.ftp_connect_anonymous(ip)
    elif num_menu == 6:
        ssh_access.ssh_connect(ip)
    elif num_menu == 7:
        msf_rpc_scan.scan(ip)

    elif num_menu == 8:
        initialize_variable(options)

    elif num_menu == 9:
        main_menu(options)
    else:
        print("[!] Incorrect choice")

    ip_menu(options)


def report_menu(options):
    nvd = fetch.NvdCveCollector()
    msf = fetch.MsfSelector()
    edb = fetch.EdbSelector()
    report = modules.DailyReportor()

    num_menu = report_menu_list()
    if num_menu is not None:
        if num_menu == -1:
            main_menu(options)
        if num_menu == 0:
            report.fetch_report()
        if num_menu == 1:
            report.view_report()
        if num_menu == 2:
            nvd.download()
        if num_menu == 3:
            edb.update()
        if num_menu == 4:
            msf.update()
        if num_menu == 5:
            lib.db_menu()
        if num_menu == 6:
            main_menu(options)
    else:
        print("[!] Incorrect choice")

    report_menu(options)


def main():
    parser = argparse.ArgumentParser(description='Penta is Pentest semi-automation tool')
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity logging level")
    parser.add_argument("--proxy", help="Proxy[IP:PORT]")
    options = parser.parse_args()

    try:
        loglevel = {
            0: logging.ERROR,
            1: logging.WARN,
            2: logging.INFO,
            3: logging.DEBUG
        }[options.verbose]
    except KeyError:
        loglevel = logging.DEBUG

    logging.basicConfig(
        handlers=[ColorfulHandler()],
        level=loglevel,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S %Z")

    if options.verbose == 3:
        logging.getLogger('sqlalchemy.engine').setLevel(loglevel)
    else:
        logging.getLogger().setLevel(loglevel)

    main_menu(options)


if __name__ == "__main__":
    if sys.version_info[0] < 3:
        raise Exception("[!] Must be using Python 3")

    os.system('clear')
    logo()
    main()
