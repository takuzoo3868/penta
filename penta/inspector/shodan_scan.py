#!/usr/bin/env python
import os
import pathlib

import shodan
from dotenv import load_dotenv

dotenv_path = pathlib.Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path)
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")


class ShodanSearch:

    def __init__(self):
        # shodan key
        self.shodanKeyString = SHODAN_API_KEY
        self.shodanApi = shodan.Shodan(self.shodanKeyString)

    def shodan_key_info(self):
        print("[*] Shodan API info...")

        try:
            info = self.shodanApi.info()
            for inf in info:
                print("{}: {}".format(inf, info[inf]))
        except Exception as err:
            print("[-] Error: {}".format(err))

    def shodan_host_info(self, ip):
        self.shodan_key_info()

        try:
            print("\n[*] Shodan Service...")

            host = self.shodanApi.host(ip)

            print("IP: {}".format(host.get('ip_str')))
            print("Country: {} : {}".format(host.get('country_name', 'Unknown'), host.get('country_code3')))
            print("City: {}".format(host.get('city', 'Unknown')))
            print("Longitude: {}".format(host.get('longitude')))
            print("Latitude: {}".format(host.get('latitude')))
            print("Organization: {}".format(host.get('org')))
            print("Operating System: {}".format(host.get('os')))
            print("Updated: {}".format(host.get('updated')))

            for item in host['data']:
                print("\nPort: {}".format(item['port']))
                print("===============================")
                if 'isp' in item.keys():
                    print("ISP: {}".format(item['isp']))
                if 'product' in item.keys():
                    print("Product: {}".format(item['product']))
                print("Data: {}".format(item['data']))

                if 'vulns' in item.keys():
                    print("[+] Vulnerability!!!")
                    for cve_info in item['vulns'].items():
                        print("ID: {}".format(cve_info[0]))
                        print("CVSS: {}".format(cve_info[1].get('cvss')))
                        print("{}".format(cve_info[1].get('summary')))

        except shodan.APIError as err:
            print("[-] API ERROR: {}".format(err))
