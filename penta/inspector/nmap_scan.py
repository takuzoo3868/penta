#!/usr/bin/env python
import nmap
import os


class NmapScanner:

    def __init__(self):
        self.nmsc = nmap.PortScanner()

    def nmap_scan(self, host, port):
        try:
            print("\n[*] Checking port {} ......".format(port))
            self.nmsc.scan(host, port)

            # Command info
            print("[*] Executing command: %s" % self.nmsc.command_line())

            self.state = self.nmsc[host]['tcp'][int(port)]['state']
            print("[+] {} tcp/{} {}".format(host, port, self.state))
            print("[+] {}".format(self.nmsc[host].tcp(int(port))))

            if self.state == "open":
                self.server = self.nmsc[host].tcp(int(port))['product']
                self.version = self.nmsc[host].tcp(int(port))['version']
                print("[+] {} {} tcp/{}".format(self.server, self.version, port))

        except Exception as err:
            print("[-] Failed to connect with {} for port scanning".format(host))
            print("[-] ERROR: {}".format(err))
            pass

    def nmap_json_export(self, host, ports):
        try:
            print("\n[*] Checking ports: {}".format(str(ports)))
            self.nmsc.scan(host, ports)

            print("[*] Executing command: %s" % self.nmsc.command_line())

            print(self.nmsc.csv())
            results = {}

            for x in self.nmsc.csv().split("\n")[1:-1]:
                salted_line = x.split(";")
                host = salted_line[0]
                proto = salted_line[3]
                port = salted_line[4]
                state = salted_line[6]

                try:
                    if state == "open":
                        results[host].append({proto: port})
                except KeyError:
                    results[host] = []
                    results[host].append({proto: port})

            return results

        except Exception as err:
            print("[-] Error to connect with {} for port scanning".format(host))
            print("[-] ERROR: {}".format(err))
            pass

    def check_nmap(self, ip):
        print("[ ] === MENU LIST nmap=======================================")
        print("[1] Intense Scan")
        print("[2] Intense Scan [UDP]")
        print("[3] Intense Scan [all TCP ports]")
        print("[4] Intense Scan without ping")
        print("[5] Ping Scan")
        print("[6] Quickie Scan")
        print("[7] Quick trace route")
        print("[8] Normal Scan")
        print("[9] Send Bad Checksums")
        print("[10] Generate Random Mac Address Spoofing for Evasion")
        print("[11] Fragment Packets")

        option = input("\n[>] Choose an option number: ")

        print("\n[*] Scanning......")
        if option == '1':
            os.system("nmap -T4 -A -v {}".format(ip))

        elif option == '2':
            euid = os.geteuid()
            if euid != 0:
                print("[-] Error: SYN scan requires root permission")
            else:
                os.system("nmap -sS -sU -T4 -A -v {}".format(ip))

        elif option == '3':
            os.system("nmap -p 1-65535 -T4 -A -v {}".format(ip))

        elif option == '4':
            os.system("nmap -T4 -A -v -Pn {}".format(ip))

        elif option == '5':
            os.system("nmap -sn {}".format(ip))

        elif option == '6':
            os.system("nmap -T4 -F {}".format(ip))

        elif option == '7':
            os.system("nmap -sn --traceroute {}".format(ip))

        elif option == '8':
            os.system("nmap {}".format(ip))

        elif option == '9':
            os.system("nmap --badsum {}".format(ip))

        elif option == '10':
            os.system("nmap -sT -Pn --spoof-mac 0 {}".format(ip))

        elif option == '11':
            euid = os.geteuid()
            if euid != 0:
                print("[-] Error: Flag scan requires root permission")
            else:
                os.system("nmap -f {}".format(ip))

        else:
            print("[-] Incorrect option")
