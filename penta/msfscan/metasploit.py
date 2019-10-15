#!/usr/bin/env python
import csv
import datetime
import getpass
import importlib
import itertools
import multiprocessing
import os
import pathlib
import random
import sqlite3
import subprocess
import sys
import time
import xml.etree.ElementTree
from multiprocessing import reduction
from xml.etree import ElementTree

import netifaces
import nmap
import requests
import xmltodict
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from pymetasploit3.msfrpc import *
from tabulate import tabulate

# VARIABLEs
msf_ip = "127.0.0.1"
msf_port = 55553
msf_user = "msf"

num_threads = 1
chunk_size = 100

port_list = []
port_module_list = []
greater_than_ports = 0
path_list = []
path_module_list = []

os_list = []
target_list = []

host_port_list = []
unique_svc_namelist = []
unique_svc_bannerlist = []
service_bannerlist = []

exclude_portlist = []
tmp_modulelist = []

manual_explist = []

port_info_list = []

catch_dup_sessionlist = []
shell_notice_list = []
alr_tested_module_list = []
working_exploit_list = []

# PATH
penta_path = pathlib.Path(__file__).resolve().parent.parent.parent
dotenv_path = penta_path / ".env"
load_dotenv(dotenv_path)
msgrpc_pass = os.environ.get("MSGRPC_PASS")

data_path = penta_path / "data"
msf_path = data_path / "msf"
msf_db_path = msf_path / "module_list.db"
msf_port_db = msf_path / "port_db.sqlite"

log_directory = penta_path / "logs"

debug_file = log_directory / "test"

# Building timestamped filename
date_and_time = time.strftime("%m") + time.strftime("%d") + time.strftime("%y") + '_' + time.strftime(
    "%H") + time.strftime("%M") + time.strftime("%S")

# HTTP headers
headers = {"User-Agent": "Mozilla/5.0 (Windows NT 6.2; rv:30.0) Gecko/20150101 Firefox/32.0",
           "Connection": "keep-alive"}


class MetaSploitRPC:

    def __init__(self):
        self.nm = nmap.PortScanner()

    def msf_scan(self, ip):
        self.exec_msf()
        print("[*] Reading data from module_list.db")
        self.read_db()
        print("[*] Loaded {} URI paths from module_list.db".format(str(len(path_list))))

        nmap_filename = self.run_nmap(ip)
        http_list, https_list, ports_list, os_list = self.parse_nmap(str(nmap_filename) + ".xml")
        # http_list, https_list, ports_list, os_list = parse_nmap(str(DEBUG_file) + ".xml")

        tmp_list = []
        port_data_list = []
        for x in ports_list:
            if [x[1], x[2]] not in port_data_list:
                port_data_list.append([x[1], x[2]])
        if len(port_data_list) > 0:
            self.show_port_info(port_data_list)
        else:
            print("[!] No open ports found.  Please check your target IPs")

        self.run_msf(ports_list)
        self.kill_msf()
        print("[+] Exit!")

    def exec_msf(self):
        print("[*] Launching Metasploit for msfrpcd")
        msfrpcd_cmd = "msfrpcd -p " + str(msf_port) + " -U " + msf_user + " -P " + msgrpc_pass + " -u /api/ -S"
        subprocess.run(msfrpcd_cmd.split())

    def kill_msf(self):
        cmd = "pkill -f msfrpcd"
        subprocess.run(cmd.split())

    def run_msf(self, target_data_list):
        global auto_explist_exp
        global auto_explist_aux
        global tmp_modulelist
        global msf_csv_list

        try:
            vuln_urllist = []
            tmp_modulelist_01 = []
            if len(tmp_modulelist) < 1:
                tmp_modulelist = self.pull_msf()
            msf_csv_list = self.read_msf_csv()

            tmp_modulelist_02 = tmp_modulelist
            for mlist in tmp_modulelist:
                module = mlist[1]
                if self.filter_modulename(module):
                    tmp_modulelist_01.append(module)

            compare_list_01 = []
            missing_modulelist_from_db = []

            for plist in port_module_list:
                compare_list_01.append(plist[2])

            for tmp in tmp_modulelist_02:
                if tmp[1] not in compare_list_01:
                    missing_modulelist_from_db.append(tmp)

            for target in target_data_list:
                target_list.append(target)

            self.run_msf_portbased_modules()
            # TODO: run msf each modules
            # run_msf_servicebased_modules()

            print("\n[List of Matching Metasploit Modules]")
            if len(working_exploit_list) > 0:
                print(tabulate(working_exploit_list, headers=["Host", "Module"]))
            else:
                print("No results found\n")
            self.kill_msf()

        except KeyboardInterrupt:
            self.kill_msf()
            print("[-] Killed msfrpcd")

    def pull_msf(self):
        ip = msf_ip
        port = msf_port

        tmp_msf_modulelist = []

        try:
            client = MsfRpcClient(msgrpc_pass, port=55553)

            aux_list = client.modules.auxiliary
            for aux in aux_list:
                tmp_msf_modulelist.append(['auxiliary', aux])
            time.sleep(1)

            exp_list = client.modules.exploits
            for exp in exp_list:
                tmp_msf_modulelist.append(['exploit', exp])
            print("\n[*] Loaded {} modules from Metasploit".format(str(len(tmp_msf_modulelist))))
            del client

        except MsfRpcError as err:
            print("[!] {}".format(err))
            self.kill_msf()
            sys.exit()

        return tmp_msf_modulelist

    def read_msf_csv(self):
        tmp_csvlist = []
        filename = "port_list.csv"

        csvlist_path = msf_path / filename
        with open(str(csvlist_path)) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')

            for row in csv_reader:
                tmp_portno = row[0]
                if int(tmp_portno) not in exclude_portlist:
                    tmp_csvlist.append(row)
        return tmp_csvlist

    @staticmethod
    def filter_modulename(import_module_name):
        if not import_module_name.startswith('admin/') and not import_module_name.startswith(
                'post/') and 'fuzzers' not in import_module_name and 'auxiliary/server' not in import_module_name and '_dos' not in import_module_name and 'spoof/' not in import_module_name and 'auxiliary/fuzzers' not in import_module_name and 'scanner/portscan' not in import_module_name and 'server/' not in import_module_name and 'analyze/' not in import_module_name and 'scanner/discovery' not in import_module_name and 'fuzzers/' not in import_module_name and 'server/capture/' not in import_module_name and '/browser/' not in import_module_name and 'dos/' not in import_module_name and '/local/' not in import_module_name and 'bof' not in import_module_name and 'fileformat' not in import_module_name:
            return True
        else:
            return False

    def show_port_info(self, tcp_port_list):
        for x in tcp_port_list:
            try:
                port_no, port_name, port_desc = self.extract_port_info([x[0], x[1]])
                if port_name is None and port_desc is None:
                    if [x[0] + "/" + x[1], "", ""] not in port_info_list:
                        port_info_list.append([x[0] + "/" + x[1], "", ""])
                if len(port_no) > 0 and len(port_name) > 0 and len(port_desc) > 0:
                    if [port_no, port_name, port_desc[0:80]] not in port_info_list:
                        port_info_list.append([port_no, port_name, port_desc[0:80]])
            except requests.exceptions.ConnectTimeout:
                continue

        if len(port_info_list) > 0:
            print("\n**** Port Description ****")
            print(tabulate(port_info_list, headers=["Port No", "Service", "Port Description"]))

    @staticmethod
    def extract_port_info(data):
        port_no = data[0]
        protocol = data[1]
        port = ""
        port_desc = ""
        port_name = ""

        conn = sqlite3.connect(msf_port_db)
        conn.text_factory = str

        url = "http://webcache.googleusercontent.com/search?q=cache:http://www.speedguide.net/port.php?port=" + str(
            port_no)
        cur = conn.execute("SELECT portNo, portType, portDescription from db WHERE portNo=?",
                           (str(port_no) + "/" + str(protocol),))
        row = cur.fetchone()
        if row is not None:
            port = row[0]
            port_name = row[1]
            port_desc = row[2]
        else:
            r = requests.get(url, headers=headers, verify=False, timeout=15, allow_redirects=False)
            soup = BeautifulSoup(r.content, 'lxml')

            try:
                table = soup.find("table", {"class": "port"})
                rows = table.find_all('tr')
                bold = True
                found = False
                for tr in rows:
                    cols = tr.find_all('td')
                    if found is False:
                        try:
                            if protocol in cols[1].text.strip():
                                port = str(port_no) + "/" + protocol
                                port_name = cols[2].text.strip()
                                port_desc = cols[3].text.split("\n")[0]
                                conn.execute("INSERT INTO db (portNo, portType, portDescription) VALUES  (?,?,?)",
                                             (port, port_name, port_desc))
                                conn.commit()
                                found = True
                        except:
                            pass
            except:
                pass

        time.sleep(3)
        conn.close()
        return [port, port_name, port_desc]

    @staticmethod
    def read_db():
        conn = sqlite3.connect(msf_db_path)
        conn.text_factory = str
        select = conn.execute(
            "SELECT portNo, moduleType, moduleName, moduleParameters, moduleDescription from portList")
        all_rows = select.fetchall()

        for row in all_rows:
            port_num = row[0]
            module_type = row[1]
            module_name = row[2]
            module_parameters = row[3]
            module_description = row[4]

            if port_num not in port_list:
                if int(port_num) > int(greater_than_ports):
                    port_list.append(port_num)

            if [port_num, module_type, module_name, module_parameters, module_description] not in port_module_list:
                port_module_list.append([port_num, module_type, module_name, module_parameters, module_description])

        conn_url = sqlite3.connect(msf_db_path)
        conn_url.text_factory = str
        select_url = conn_url.execute(
            "SELECT uriPath, moduleType, moduleName, moduleParameters, moduleDescription from pathList")
        all_rows_url = select_url.fetchall()

        for row in all_rows_url:
            url_path = row[0]
            module_type = row[1]
            module_name = row[2]
            module_parameters = row[3]
            module_description = row[4]

            if url_path not in path_list and url_path != "/":
                path_list.append(url_path)

            if [url_path, module_type, module_name, module_parameters, module_description] not in path_module_list:
                path_module_list.append([url_path, module_type, module_name, module_parameters, module_description])

    @staticmethod
    def run_nmap(ip):
        print("[+] Running nmap for port scan: {}".format(ip))
        port_str = ''
        count = 0

        for x in port_list:
            port_str += x
            if count < len(port_list) - 1:
                port_str += ','
                count += 1

        basename = "nmap_"
        suffix = datetime.datetime.now().strftime("%y%m%d_%H%M%S")
        filename = "_".join([basename, suffix])
        nmap_filename = log_directory / "nmap" / filename

        time.sleep(5)
        passwd = (getpass.getpass() + '\n').encode()
        time.sleep(5)

        if len(port_str) < 1:
            nmap_cmd = "sudo -S nmap -O --max-retries 3 -T4 -n -Pn --open -sT -sV --top-ports 65535 " + ip + " -oA " + str(
                nmap_filename)
        else:
            nmap_cmd = "sudo -S nmap -O --max-retries 3 -T4 -n -Pn --open -sT -sV -p " + port_str + " " + ip + " -oA " + str(
                nmap_filename)
        subprocess.run(nmap_cmd.split(), input=passwd, check=True)
        return nmap_filename

    @staticmethod
    def parse_nmap(filename):
        tmp_http_list = []
        tmp_https_list = []
        tmp_ports_list = []
        tmp_os_list = []

        notrelevant = ['name', 'method', 'conf', 'cpelist', 'servicefp', 'tunnel']
        relevant = ['@product', '@version', '@extrainfo']

        with open(filename, "rt") as f:
            tree = xmltodict.parse(f.read())
        root = tree['nmaprun']

        for host_addr in root['host']['address']:
            if host_addr['@addrtype'] == "ipv4":
                ip = host_addr['@addr']

        os_data = root['host']['os']['osmatch']
        os_dist = os_data.get('@name')

        if "linux" in os_dist.lower() or "unix" in os_dist.lower():
            if [ip, "linux"] not in tmp_os_list:
                tmp_os_list.append([ip, "linux"])
            if [ip, "unix"] not in tmp_os_list:
                tmp_os_list.append([ip, "unix"])
        if "windows" in os_dist.lower():
            tmp_os_list.append([ip, "windows"])
        if "apple" in os_dist.lower() or "apple os x" in os_dist.lower():
            tmp_os_list.append([ip, "osx"])
        if "solaris" in os_dist.lower():
            tmp_os_list.append([ip, "solaris"])

        for port in root['host']['ports']['port']:
            if port['state']['@state'] == "open":
                if [ip, port['@portid']] not in host_port_list:
                    host_port_list.append([ip, port['@portid']])

                try:
                    banner = ""
                    service_keys = port['service'].keys()
                    if '@method' in port['service'] and port['service']['@method'] == "probed":
                        for rel_key in relevant:
                            if rel_key in service_keys:
                                banner += "{0}: {1} ".format(rel_key.strip("@"), port['service'][rel_key])
                        for m_key in service_keys:
                            if m_key not in notrelevant and m_key not in relevant:
                                banner += '{0}: {1} '.format(m_key.strip("@"), port['service'][m_key])

                    banner_data = banner.rstrip()

                    if len(banner_data.split(" ")[1]) > 2:
                        service_banner = (banner_data.split(" ")[1]).lower()
                        if [ip, port['@portid'], service_banner] not in unique_svc_bannerlist:
                            unique_svc_bannerlist.append([ip, port['@portid'], service_banner])
                        tmp_banner = banner_data.replace("product: ", "")
                        if [str(port['@portid']) + "/" + port['@protocol'], tmp_banner] not in service_bannerlist:
                            service_bannerlist.append([str(port['@portid']) + "/" + port['@protocol'], tmp_banner])

                except IndexError:
                    pass

                tmp_ports_list.append([str(ip), str(port['@portid']), port['@protocol'], port['service']['@name']])

                if port['service']['@name'] != "http":
                    if port['service']['@name'] not in unique_svc_namelist and "?" not in str(port['service']['@name']):
                        unique_svc_namelist.append([ip, port['@portid'], port['service']['@name']])
                else:
                    if '@tunnel' in port['service']:
                        if port['service']['@tunnel'] == "ssl":
                            tmp_https_list.append(
                                [str(ip), str(port['@portid']), port['@protocol'], port['service']['@name']])
                    else:
                        tmp_http_list.append(
                            [str(ip), str(port['@portid']), port['@protocol'], port['service']['@name']])

        return tmp_http_list, tmp_https_list, tmp_ports_list, tmp_os_list

    def run_msf_portbased_modules(self):
        global exclude_portlist
        # print("\n**** Finding MSF Modules based on Service Name ****")

        auto_explist_aux = []
        tmp_auto_explist_aux = []
        auto_explist_exp = []
        tmp_auto_explist_exp = []
        tmp_manual_explist = []

        for target in target_list:
            host_no = target[0]
            port_no = target[1]
            port_protocol = target[2]

            tmp_result_list = self.lookup_port_db(port_no, port_protocol)
            found_flag = False
            for data in tmp_result_list:
                port_no = data[0]
                module_type = data[1]
                module_name = data[2]
                module_param = data[3]
                module_description = data[4]

                for banner in unique_svc_bannerlist:
                    tmp_ip = banner[0]
                    tmp_port = banner[1]
                    tmp_svc_banner = banner[2]

                    if host_no == tmp_ip and str(port_no) == str(tmp_port):
                        if tmp_svc_banner.lower() in module_description.lower():
                            if module_param == "":
                                if module_type == "auxiliary":
                                    if [host_no, port_no, module_type, module_name, module_param,
                                        module_description] not in auto_explist_aux:
                                        found_flag = True
                                        auto_explist_aux.append(
                                            [host_no, port_no, module_type, module_name, module_param,
                                             module_description])
                                if module_type == "exploit":
                                    if [host_no, port_no, module_type, module_name, module_param,
                                        module_description] not in auto_explist_exp:
                                        found_flag = True
                                        auto_explist_exp.append(
                                            [host_no, port_no, module_type, module_name, module_param,
                                             module_description])
                            else:
                                if [host_no, port_no, module_type, module_name, module_param,
                                    module_description] not in manual_explist:
                                    found_flag = True
                                    manual_explist.append(
                                        [host_no, port_no, module_type, module_name, module_param, module_description])
                        else:
                            if tmp_svc_banner in module_description:
                                if module_param == "":
                                    if module_type == "auxiliary":
                                        if [host_no, port_no, module_type, module_name, module_param,
                                            module_description] not in tmp_auto_explist_aux:
                                            tmp_auto_explist_aux.append(
                                                [host_no, port_no, module_type, module_name, module_param,
                                                 module_description])
                                    if module_type == "exploit":
                                        if [host_no, port_no, module_type, module_name, module_param,
                                            module_description] not in tmp_auto_explist_exp:
                                            tmp_auto_explist_exp.append(
                                                [host_no, port_no, module_type, module_name, module_param,
                                                 module_description])
                                else:
                                    if [host_no, port_no, module_type, module_name, module_param,
                                        module_description] not in tmp_manual_explist:
                                        tmp_manual_explist.append(
                                            [host_no, port_no, module_type, module_name, module_param,
                                             module_description])

                if found_flag is False:
                    for name in unique_svc_namelist:
                        tmp_ip = name[0]
                        tmp_port = name[1]
                        tmp_svc_banner = name[2]

                        if host_no == tmp_ip and str(port_no) == str(tmp_port):
                            if tmp_svc_banner.lower() in module_description.lower():
                                if module_param == "":
                                    if module_type == "auxiliary":
                                        if [host_no, port_no, module_type, module_name, module_param,
                                            module_description] not in auto_explist_aux:
                                            found_flag = True
                                            auto_explist_aux.append(
                                                [host_no, port_no, module_type, module_name, module_param,
                                                 module_description])
                                    if module_type == "exploit":
                                        if [host_no, port_no, module_type, module_name, module_param,
                                            module_description] not in auto_explist_exp:
                                            found_flag = True
                                            auto_explist_exp.append(
                                                [host_no, port_no, module_type, module_name, module_param,
                                                 module_description])
                                else:
                                    if [host_no, port_no, module_type, module_name, module_param,
                                        module_description] not in manual_explist:
                                        found_flag = True
                                        manual_explist.append(
                                            [host_no, port_no, module_type, module_name, module_param,
                                             module_description])
                            else:
                                if tmp_svc_banner in module_description:
                                    if module_param == "":
                                        if module_type == "auxiliary":
                                            if [host_no, port_no, module_type, module_name, module_param,
                                                module_description] not in tmp_auto_explist_aux:
                                                tmp_auto_explist_aux.append(
                                                    [host_no, port_no, module_type, module_name, module_param,
                                                     module_description])
                                        if module_type == "exploit":
                                            if [host_no, port_no, module_type, module_name, module_param,
                                                module_description] not in tmp_auto_explist_exp:
                                                tmp_auto_explist_exp.append(
                                                    [host_no, port_no, module_type, module_name, module_param,
                                                     module_description])
                                    else:
                                        if [host_no, port_no, module_type, module_name, module_param,
                                            module_description] not in tmp_manual_explist:
                                            tmp_manual_explist.append(
                                                [host_no, port_no, module_type, module_name, module_param,
                                                 module_description])

            if found_flag is False:
                for tmp_list in tmp_manual_explist:
                    manual_explist.append(tmp_list)

                for tmp_list in tmp_auto_explist_exp:
                    if tmp_list not in auto_explist_exp:
                        auto_explist_exp.append(tmp_list)

                for tmp_list in tmp_auto_explist_aux:
                    if tmp_list not in auto_explist_aux:
                        auto_explist_aux.append(tmp_list)

                tmp_manual_explist = []
                tmp_auto_explist_aux = []
                tmp_auto_explist_exp = []

        if len(manual_explist) < 1 and len(auto_explist_aux) < 1 and len(auto_explist_exp) < 1:
            print("[-] No Metasploit modules found matching criteria")

        print("\n**** Finding MSF Modules based on Port No ****")
        tmp_dict_01 = {}
        if len(unique_svc_bannerlist) > 0:
            print("\n[List of Unique Service Banners]")

            tmp_service_bannerlist = []
            for banner in service_bannerlist:
                if len(banner[1]) > 0:
                    tmp_service_bannerlist.append([banner[0], banner[1]])
            tmp_service_bannerlist = sorted(tmp_service_bannerlist, key=lambda x: banner[1], reverse=True)
            print(tabulate(tmp_service_bannerlist))

            msf_match_dict = {}
            for x in host_port_list:
                for y in msf_csv_list:
                    module_category = y[1]
                    module_name = y[2]
                    if str(x[1]) == y[0]:
                        host_no = x[0]
                        port_no = x[1]

                        if port_no not in tmp_dict_01:
                            tmp_list_x = [module_category + "/" + module_name]
                            tmp_list_y = [host_no + ":" + str(port_no)]
                            tmp_dict_01[port_no] = [tmp_list_x, tmp_list_y]
                        else:
                            [tmp_list_x, tmp_list_y] = tmp_dict_01[port_no]
                            if module_category + "/" + module_name not in tmp_list_x:
                                tmp_list_x.append(module_category + "/" + module_name)
                            if host_no + ":" + str(port_no) not in tmp_list_y:
                                tmp_list_y.append(host_no + ":" + str(port_no))
                            tmp_dict_01[port_no] = [tmp_list_x, tmp_list_y]

        tmp_list_03 = []
        for key, value in tmp_dict_01.items():
            tmp_list_03.append(["\n".join(value[1]), "\n".join(value[0])])
        print("[Matching Ports with Metasploit]")
        print(tabulate(tmp_list_03, headers=["Targets", "Metasploit Module"], tablefmt="grid"))

        tmp_list = []
        if len(auto_explist_exp) > 0:
            tmp_auto_explist_exp = auto_explist_exp
            auto_explist_exp = []

            for x in tmp_auto_explist_exp:
                host_no = x[0]
                port_no = x[1]
                module_category = x[2]
                module_name = x[3]
                module_param = x[4]
                module_description = x[5]

                if self.filter_modulename(module_name):
                    if str(port_no) != "80":
                        if len(os_list) > 0:
                            for y in os_list:
                                if y[0] in host_no:
                                    os_type = y[1]
                                    if "linux" in module_name or "windows" in module_name or "solaris" in module_name or "freebsd" in module_name or "osx" in module_name or "netware" in module_name:
                                        if os_type in module_name:
                                            if [host_no + ":" + port_no, module_category, module_name] not in tmp_list:
                                                tmp_list.append([host_no + ":" + port_no, module_category, module_name])
                                            if [host_no + ":" + port_no, module_category, module_name, module_param,
                                                module_description] not in auto_explist_exp:
                                                auto_explist_exp.append(
                                                    [host_no + ":" + port_no, module_category, module_name,
                                                     module_param,
                                                     module_description])
                                    else:
                                        if [host_no + ":" + port_no, module_category, module_name] not in tmp_list:
                                            tmp_list.append([host_no + ":" + port_no, module_category, module_name])
                                        if [host_no + ":" + port_no, module_category, module_name, module_param,
                                            module_description] not in auto_explist_exp:
                                            auto_explist_exp.append(
                                                [host_no + ":" + port_no, module_category, module_name, module_param,
                                                 module_description])

        if len(auto_explist_aux) > 0:
            tmp_auto_explist_aux = auto_explist_aux
            auto_explist_aux = []

            for x in tmp_auto_explist_aux:
                host_no = x[0]
                port_no = x[1]
                module_category = x[2]
                module_name = x[3]
                module_param = x[4]
                module_description = x[5]

                if self.filter_modulename(module_name):
                    if str(port_no) != "80":
                        if [host_no + ":" + port_no, module_category, module_name] not in tmp_list:
                            tmp_list.append([host_no + ":" + port_no, module_category, module_name])
                        if [host_no + ":" + port_no, module_category, module_name, module_param,
                            module_description] not in auto_explist_aux:
                            auto_explist_aux.append(
                                [host_no + ":" + port_no, module_category, module_name, module_param,
                                 module_description])

    @staticmethod
    def lookup_port_db(number, protocol):
        tmp_result_list = []

        for data in port_module_list:
            port_no = data[0]
            module_type = data[1]
            module_name = data[2]
            module_param = data[3]
            module_description = data[4]
            if str(port_no) == str(number):
                tmp_result_list.append([port_no, module_type, module_name, module_param, module_description])
        return tmp_result_list
