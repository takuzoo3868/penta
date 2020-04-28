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


class DBEngine:
    def __init__(self):
        pass

    def get_value_deal_except(self, element, value_name):
        try:
            value = element[value_name]
        except:
            value = ""
        return value

    def shodan_ip_get_services(self, ip):
        shodan_api = shodan.Shodan(SHODAN_API_KEY)
        services = []
        host = shodan_api.host(ip)
        for item in host['data']:
            port = self.get_value_deal_except(item, 'port')
            product = self.get_value_deal_except(item, 'product')
            version = self.get_value_deal_except(item, 'version')
            service = {'ip': ip, 'port': port, 'product': product, 'version': version}
            yield service
        #     services.append(service)
        # return services

    def shodan_service_get_ips(self, service, version=""):
        shodan_api = shodan.Shodan(SHODAN_API_KEY)
        matches = []
        print("[*] shodan search: {} {}".format(service, version))
        results = shodan_api.search(f"{service} {version}")
        for item in results['matches']:
            ip = item['ip_str']
            port = item['port']
            product = service
            version = version
            matche = {'ip': ip, 'port': port, 'product': product, 'version': version}
            matches.append(matche)
        return matches


# test for shodan search DB
if __name__ == "__main__":
    search_engine = DBEngine()
    ip = "89.135.83.205"
    print("[TEST] congratulation,{} have those services:".format(ip))
    services = search_engine.shodan_ip_get_services(ip)
    for service in services:
        print(f"{service['ip']}/{service['port']}/{service['product']}/{service['version']}")

    service = "tomcat"
    version = "7.0"
    print("[TEST] congratulation,those ip have operate {}-{}:".format(service, version))
    ips = search_engine.shodan_service_get_ips(service, version)
    for matche in ips:
        print(f"{matche['ip']}/{matche['port']}/{matche['product']}/{matche['version']}")
