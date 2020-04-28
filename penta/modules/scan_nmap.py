#!/usr/bin/env python
import os
import socket
from pprint import pprint
from socket import AF_INET, SOCK_STREAM, setdefaulttimeout

import nmap

from utils import Colors


class NmapScanner:

    def __init__(self):
        self.nmsc = nmap.PortScanner()

    def nmap_scan(self, ip, port):
        try:
            print("\n[*] Checking port {} ......".format(port))
            self.nmsc.scan(ip, port)

            print("[*] Executing command: {}".format(self.nmsc.command_line()))
            state = self.nmsc[ip]['tcp'][int(port)]['state']
            proto = self.nmsc[ip]['tcp'][int(port)]['name']

            if state == "open":
                print("{} {}/tcp {}OPEN{}".format(proto, port, Colors.LIGHTGREEN, Colors.END))
                cpe = self.nmsc[ip].tcp(int(port))['cpe']
                server = self.nmsc[ip].tcp(int(port))['product']
                version = self.nmsc[ip].tcp(int(port))['version']
                print("CPE: {}".format(cpe))
                print("Product: {} {}".format(server, version))
                if port == "80":
                    print("\n[ ] Checking connection from port 80")
                    self.check_open_port_80(ip)
            else:
                print("{} {}/tcp {}CLOSED{}".format(proto, port, Colors.RED, Colors.END))

        except Exception as err:
            print("[-] Failed to connect with {} for port scanning".format(ip))
            print("{}[!]{} ERROR: {}".format(Colors.RED, Colors.END, err))
            pass

    def check_open_port_80(self, ip):
        setdefaulttimeout(5)

        # AF_INET:     Set(host, port)
        # SOCK_STREAM: Connection TCP Protocol
        con = socket.socket(AF_INET, SOCK_STREAM)
        try:
            con.connect((ip, 80))
            con.send(b"HEAD / HTTP/1.0\r\n\r\n")

            banner_sum = ''
            while True:
                banner = con.recv(1024).decode("utf-8")
                if not banner:
                    break
                banner_sum += banner_sum + banner
            con.close()
            print("{}{}{}".format(Colors.LIGHTGREEN, banner_sum, Colors.END))

        except Exception as err:
            print("{}[!]{} ERROR {}".format(Colors.RED, Colors.END, err))
            return False

    def nmap_json_export(self, ip, ports):
        try:
            self.nmsc.scan(ip, ports)
            print("\n[*] Logging results...")
            results = {}

            for x in self.nmsc.csv().split("\n")[1:-1]:
                salted_line = x.split(";")
                ip = salted_line[0]
                proto = salted_line[3]
                port = salted_line[4]
                state = salted_line[6]

                try:
                    if state == "open":
                        results[ip].append({proto: port})
                except KeyError:
                    results[ip] = []
                    results[ip].append({proto: port})

            return results

        except Exception as err:
            print("[-] Error to connect with {} for port scanning".format(ip))
            print("[-] ERROR: {}".format(err))
            pass

    @staticmethod
    def nmap_menu_list():
        print("\nNmap scan options")
        print("[0] Return main menu")
        print("[1] Intense scan")
        print("[2] Intense scan, plus UDP")
        print("[3] Intense scan, all TCP ports")
        print("[4] Intense scan, no ping")
        print("[5] Ping scan")
        print("[6] Quick scan")
        print("[7] Quick scan plus")
        print("[8] Quick Trace Route")
        print("[9] Regular scan")
        print("[10] Send Bad Checksums")
        print("[11] Generate Random Mac Address Spoofing")
        print("[12] Fragment Packets")
        print("[13] Slow comprehensive scan")
        print("[14] NSE Script scan")

        option = input("\n[>] Choose an option number: ")
        return option

    def nmap_menu(self, ip):
        while True:
            option = self.nmap_menu_list()

            if option == "1":
                self.nmsc.scan(hosts=ip, arguments="-T4 -A -v")
                print("[*] Executing command: {}".format(self.nmsc.command_line()))
                pprint(self.nmsc[ip])

            elif option == "2":
                euid = os.geteuid()
                if euid != 0:
                    print("[-] Error: SYN scan requires root permission")
                else:
                    self.nmsc.scan(hosts=ip, arguments="-sS -sU -T4 -A")
                    print("[*] Executing command: {}".format(self.nmsc.command_line()))
                    pprint(self.nmsc[ip])

            elif option == "3":
                self.nmsc.scan(hosts=ip, arguments="-p 1-65535 -T4 -A")
                print("[*] Executing command: {}".format(self.nmsc.command_line()))
                pprint(self.nmsc[ip])

            elif option == "4":
                self.nmsc.scan(hosts=ip, arguments="-T4 -A -v -Pn")
                print("[*] Executing command: {}".format(self.nmsc.command_line()))
                pprint(self.nmsc[ip])

            elif option == "5":
                self.nmsc.scan(hosts=ip, arguments="-sn")
                print("[*] Executing command: {}".format(self.nmsc.command_line()))
                pprint(self.nmsc[ip])

            elif option == "6":
                self.nmsc.scan(hosts=ip, arguments="-T4 -F")
                print("[*] Executing command: {}".format(self.nmsc.command_line()))
                pprint(self.nmsc[ip])

            elif option == "7":
                self.nmsc.scan(hosts=ip, arguments="-sV -T4 -O -F --version-light")
                print("[*] Executing command: {}".format(self.nmsc.command_line()))
                pprint(self.nmsc[ip])

            elif option == "8":
                self.nmsc.scan(hosts=ip, arguments="-sn --traceroute")
                print("[*] Executing command: {}".format(self.nmsc.command_line()))
                pprint(self.nmsc[ip])

            elif option == "9":
                self.nmsc.scan(hosts=ip)
                print("[*] Executing command: {}".format(self.nmsc.command_line()))
                pprint(self.nmsc[ip])

            elif option == "10":
                self.nmsc.scan(hosts=ip, arguments="--badsum")
                print("[*] Executing command: {}".format(self.nmsc.command_line()))
                pprint(self.nmsc[ip])

            elif option == "11":
                self.nmsc.scan(hosts=ip, arguments="-sT -Pn --spoof-mac 0")
                print("[*] Executing command: {}".format(self.nmsc.command_line()))
                pprint(self.nmsc[ip])

            elif option == "12":
                euid = os.geteuid()
                if euid != 0:
                    print("[-] Error: Flag scan requires root permission")
                else:
                    self.nmsc.scan(hosts=ip, arguments="-f")
                    print("[*] Executing command: {}".format(self.nmsc.command_line()))
                    pprint(self.nmsc[ip])

            elif option == "13":
                euid = os.geteuid()
                if euid != 0:
                    print("[-] Error: Flag scan requires root permission")
                else:
                    self.nmsc.scan(hosts=ip,
                                   arguments="-sS -sU -T4 -A -PE -PP -PS80 -PA3389 -PU40125 -PY -g 53 "
                                             "--script=safe")
                    print("[*] Executing command: {}".format(self.nmsc.command_line()))
                    pprint(self.nmsc[ip])

            elif option == "14":
                self.nmap_scan_script(ip)

            elif option == "0":
                break

            else:
                print("[-] Incorrect option\n")

    def nmap_scan_script(self, ip):
        self.nmsc.scan(ip, arguments="-T4 -F")
        print("[*] Executing command: {}".format(self.nmsc.command_line()))

        host = self.nmsc.all_hosts()[0]
        print("Host: {}".format(host))

        for port in self.nmsc[host]['tcp']:
            print("\tPort: {}:\t{} {}".format(port, self.nmsc[host]['tcp'][port]['state'],
                                              self.nmsc[host]['tcp'][port]['name']))

        for port in self.nmsc[host]['tcp']:

            if (port == 21) and self.nmsc[host]['tcp'][port]['state'] == "open":
                print("[*] Checking FTP {} port with NSE".format(port))
                self.nmap_scan_script_result(ip, port)

            elif (port == 22) and self.nmsc[host]['tcp'][port]['state'] == "open":
                print("[*] Checking SSH {} port with NSE".format(port))
                self.nmap_scan_script_result(ip, port)

            elif (port == 80 or port == 8080) and self.nmsc[host]['tcp'][port]['state'] == "open":
                print("[*] Checking HTTP {} port with NSE".format(port))
                self.nmap_scan_script_result(ip, port)

            elif (port == 443) and self.nmsc[host]['tcp'][port]['state'] == "open":
                print("[*] Checking SSL {} port with NSE".format(port))
                self.nmap_scan_script_result(ip, port)

            elif (port == 3306) and self.nmsc[host]['tcp'][port]['state'] == "open":
                print("[*] Checking MySQL {} port with NSE".format(port))
                self.nmap_scan_script_result(ip, port)

            elif (port == 5432) and self.nmsc[host]['tcp'][port]['state'] == "open":
                print("[*] Checking POSTGRES {} port with NSE".format(port))
                self.nmap_scan_script_result(ip, port)

            elif (port == 5900) and self.nmsc[host]['tcp'][port]['state'] == "open":
                print("[*] Checking VNC {} port with NSE".format(port))
                self.nmap_scan_script_result(ip, port)

            elif (port == 27017) and self.nmsc[host]['tcp'][port]['state'] == "open":
                print("[*] Checking MONGODB {} port with NSE".format(port))
                self.nmap_scan_script_result(ip, port)

            elif (port == 55553) and self.nmsc[host]['tcp'][port]['state'] == "open":
                print("[*] Checking METAEXPLOIT {} port with NSE".format(port))
                self.nmap_scan_script_result(ip, port)

    @staticmethod
    def nmap_scan_script_result(ip, port):
        nm = nmap.PortScanner()

        try:
            nm.scan(hosts=ip, arguments="-sC -sV -p{} --script=safe".format(port))

            script_results = nm[ip]['tcp'][port]['script']
            for key, value in script_results.items():
                print("Script: {}{}{}".format(Colors.LIGHTGREEN, key, Colors.END))
                print("{}\n".format(value))

        except Exception:
            pass
