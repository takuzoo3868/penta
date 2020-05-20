import logging
import os
from pprint import pprint
import readline  # noqa: F401

from lib.loading import Loading
from lib.menu import Menu
from lib.utils import Colors, system_exit
import nmap
from tabulate import tabulate


# ref: https://nmap.org/book/reduce-scantime.html
class NmapScanner(object):
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.default_ports = "20-1024,8080"

    def input_target_ports(self):
        while True:
            try:
                input_val = input("[?] Specify the target ports (default: 20-1024,8080): ")
                split_val = input_val.split(",")
            except KeyboardInterrupt:
                system_exit()
                break

            if len(input_val) == 0:
                defalut_ports = self.default_ports.split(",")
                return self.output_target_ports(defalut_ports)
            else:
                target_ports = self.output_target_ports(split_val)
                if target_ports is not None:
                    return target_ports
                else:
                    print("[-] Please input port like '22,53,110,143-4564'")
                    continue

        return None

    def output_target_ports(self, port_list: list):
        checked_list = []
        try:
            for port in port_list:
                if "-" in port:
                    high_range = int(port.split('-')[1])
                    low_range = int(port.split('-')[0])
                    if high_range < low_range:
                        high_range, low_range = low_range, high_range

                    ports_range = [i for i in range(low_range, (high_range + 1))]

                    for p in ports_range:
                        if self.validate_port_range(p):
                            checked_list.append(p)
                        else:
                            return None
                else:
                    p = int(port)
                    if self.validate_port_range(p):
                        checked_list.append(p)
                    else:
                        return None
        except Exception:
            return None

        target_port_list = list(set(sorted(checked_list)))
        return target_port_list

    def validate_port_range(self, port: int):
        try:
            port_num = port
            if 0 <= port_num <= 65535:
                return True
        except ValueError:
            return False
        return False

    def port_scan(self, ip):
        ports = self.input_target_ports()
        if ports is None:
            return None

        self.check_ports(ip, ports)
        return None

    def check_ports(self, ip, ports):
        try:
            # Check if the target is online or offline first.
            scan_result = []
            if self.is_online(ip):
                mapped_ports = map(str, ports)
                all_ports = ",".join(mapped_ports)
                port_details = self.peep_state(ip, all_ports)

                for port, detail in port_details.items():
                    # name = detail['name']
                    state = detail['state']

                    print("[*] Prot {}: {}".format(str(port), self.get_state(state)))

                    if self.check_state(state):
                        result = self.detect_service(ip, port)
                        scan_result.append((self.get_result(result, port)))
                    else:
                        # scan_result.append((port, state, name, None, None))
                        pass

                sort_list = sorted(scan_result)
                logging.info("Opened ports information...")
                print(tabulate(sort_list, headers=["PORT", "SERVICE", "INFO", "CPE", "DETAIL"], tablefmt="grid"))

            elif not self.is_online(ip):
                logging.error("Target IP is offline, or blocking ping probe")

        except KeyboardInterrupt:
            logging.warn("Process stopped as TERMINATE Signal received")

    def get_state(self, state: str):
        if state == "open":
            return "{}{}{}".format(Colors.GREEN, state.upper(), Colors.END)
        elif state == "closed":
            return "{}{}{}".format(Colors.RED, state.upper(), Colors.END)
        elif state == "filtered":
            return "{}{}{}".format(Colors.DARKGRAY, state.upper(), Colors.END)
        elif state == "unfiltered":
            return "{}{}{}".format(Colors.LIGHTGRAY, state.upper(), Colors.END)
        elif state == "open|filtered":
            return "{}{}{}".format(Colors.DARKGRAY, state.upper(), Colors.END)
        elif state == "closed|filtered":
            return "{}{}{}".format(Colors.DARKGRAY, state.upper(), Colors.END)

    def get_result(self, result, port):
        # state = result[port]['state']
        name = result[port]['name']
        product = result[port]['product']
        version = result[port]['version']
        info = "{} {}".format(product, version)
        cpe = result[port]['cpe']
        extra = result[port]['extrainfo']

        return port, name, info, cpe, extra

    # Check target port service
    def detect_service(self, ip, port):
        try:
            with Loading(text='Detect port {} service...'.format(port), spinner='dots'):
                self.nm.scan(hosts=ip, ports=str(port), arguments='-sV -T5')
            return self.nm[ip]['tcp']
        except KeyError:
            pass

    def peep_state(self, ip, port):
        try:
            with Loading(text='Scanning...', spinner='dots'):
                self.nm.scan(hosts=ip, ports=str(port), arguments='-d2 -T4')
            return self.nm[ip]['tcp']
        except KeyError:
            pass

    def check_state(self, state):
        if state == "open":
            return True
        else:
            return False

    # Check if target is online using Ping scan
    def is_online(self, ip):
        try:
            self.nm.scan(hosts=ip, arguments='-sP')
            result = self.nm[ip].state()
        except KeyError:
            pass
        else:
            if result == 'up':
                return True
            else:
                return False

    @staticmethod
    def nmap_menu_list():
        menu = Menu(False)
        title = "======= NMAP MENU LIST ======================================"
        menu_list = [
            'Intense',
            'Intense + UDP',
            'Intense + TCP',
            'Intense + no ping',
            'Ping',
            'Quick',
            'Quick alpha',
            'Quick traceroute',
            'Regular',
            'Send Bad Checksums',
            'Generate Random Mac Address Spoofing',
            'Fragment Packets',
            'Slow comprehensive scan',
            'NSE Script',
            '[Return]'
        ]

        menu_num = menu.show(title, menu_list)
        return menu_num

    def menu(self, ip):
        arg_dict = {
            0: "-T4 -A -v",
            1: "-sS -sU -T4 -A",
            2: "-p 1-65535 -T4 -A",
            3: "-T4 -A -v -Pn",
            4: "-sn",
            5: "-T4 -F",
            6: "-sV -T4 -O -F --version-light",
            7: "-sn --traceroute",
            8: "-d2",
            9: "--badsum",
            10: "-sT -Pn --spoof-mac 0",
            11: "-f",
            12: "-sS -sU -T4 -A -PE -PP -PS80 -PA3389 -PU40125 -PY -g 53 --script=safe",
        }

        number = self.nmap_menu_list()
        if number is not None:
            if 0 <= number <= 12:
                self._run(ip, arg_str=arg_dict[number])
            elif number == 13:
                self._run_script(ip)
            elif number == 14 or number == -1:
                pass
        else:
            print("[!] Incorrect choice")

        return None

    def _run(self, ip_str, arg_str):
        if arg_str in ("-sS", "-sN", "-sF", "-sX", "-O", "-f"):
            euid = os.geteuid()
            if euid != 0:
                logging.warn("Requires root permission")
                return None
            else:
                pass

        logging.info("Executing nmap")
        try:
            with Loading(text='Scanning...', spinner='dots'):
                self.nm.scan(hosts=ip_str, arguments=arg_str)
            logging.info("Executed command: {}".format(self.nm.command_line()))
            pprint(self.nm[ip_str])
        except nmap.PortScannerError as e:
            logging.error(e)
            return None
        return None

    def _run_script(self, ip):
        logging.info("Executing nmap")
        try:
            with Loading(text='Scanning...', spinner='dots'):
                self.nm.scan(ip, arguments="-T4 -F")
            logging.info("Executed command: {}".format(self.nm.command_line()))
        except Exception:
            return None

        host = self.nm.all_hosts()[0]
        print("Host: {}".format(host))

        for port in self.nm[host]['tcp']:
            print("\tPort: {}:\t{} {}".format(port, self.nm[host]['tcp'][port]['state'],
                                              self.nm[host]['tcp'][port]['name']))

        for port in self.nm[host]['tcp']:
            if (port == 21) and self.nm[host]['tcp'][port]['state'] == "open":
                print("[*] Checking FTP {} port with NSE".format(port))
                NmapScanner._run_script_deep(ip, port)

            if (port == 22) and self.nm[host]['tcp'][port]['state'] == "open":
                print("[*] Checking SSH {} port with NSE".format(port))
                NmapScanner._run_script_deep(ip, port)

            if (port == 80 or port == 8080) and self.nm[host]['tcp'][port]['state'] == "open":
                print("[*] Checking HTTP {} port with NSE".format(port))
                NmapScanner._run_script_deep(ip, port)

            if (port == 443) and self.nm[host]['tcp'][port]['state'] == "open":
                print("[*] Checking SSL {} port with NSE".format(port))
                NmapScanner._run_script_deep(ip, port)

            if (port == 3306) and self.nm[host]['tcp'][port]['state'] == "open":
                print("[*] Checking MySQL {} port with NSE".format(port))
                NmapScanner._run_script_deep(ip, port)

            if (port == 5432) and self.nm[host]['tcp'][port]['state'] == "open":
                print("[*] Checking POSTGRES {} port with NSE".format(port))
                NmapScanner._run_script_deep(ip, port)

            if (port == 5900) and self.nm[host]['tcp'][port]['state'] == "open":
                print("[*] Checking VNC {} port with NSE".format(port))
                NmapScanner._run_script_deep(ip, port)

            if (port == 27017) and self.nm[host]['tcp'][port]['state'] == "open":
                print("[*] Checking MONGODB {} port with NSE".format(port))
                NmapScanner._run_script_deep(ip, port)

            if (port == 55553) and self.nm[host]['tcp'][port]['state'] == "open":
                print("[*] Checking MetaExploit {} port with NSE".format(port))
                NmapScanner._run_script_deep(ip, port)

        return None

    @staticmethod
    def _run_script_deep(ip, port):
        nm = nmap.PortScanner()

        try:
            with Loading(text='Scanning...', spinner='dots'):
                nm.scan(hosts=ip, arguments="-sC -sV -p {} --script=safe".format(port))

            script_results = nm[ip]['tcp'][port]['script']
            for key, value in script_results.items():
                print("Script: {}{}{}".format(Colors.LIGHTGREEN, key, Colors.END))
                print("{}\n".format(value))

        except Exception:
            pass
