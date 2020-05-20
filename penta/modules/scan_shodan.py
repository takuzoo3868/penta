import logging
import textwrap

from config import FileConfig
from lib.utils import Colors, get_val_deal
import shodan
from tabulate import tabulate


class ShodanSearch:
    def __init__(self):
        config = FileConfig()
        config.load_yaml()
        self.shodan_key_string = config.settings["SHODAN_API_KEY"]
        self.shodan_api = shodan.Shodan(self.shodan_key_string)

    def shodan_key_info(self):
        logging.info("Shodan service access using API key...")

        try:
            info = self.shodan_api.info()
            for i in info:
                print("{}{}: {}{}".format(Colors.DARKGRAY, i, info[i], Colors.END))
        except shodan.APIError as e:
            logging.error(e)

    def shodan_ip_to_service(self, ip):
        self.shodan_key_info()

        host_table = []
        cve_table = []
        try:
            logging.info("Fetch info from shodan.io...")
            host_items = self.shodan_api.host(ip)

            print("IP: {}".format(host_items.get('ip_str')))
            print("Country: {}".format(host_items.get('country_name')))
            print("City:    {}".format(host_items.get('city', 'Unknown')))
            print("Longitude: {}".format(host_items.get('longitude')))
            print("Latitude:  {}".format(host_items.get('latitude')))
            print("Organization: {}".format(host_items.get('org')))
            print("Operating System: {}".format(host_items.get('os')))

            for item in host_items['data']:
                port = get_val_deal(item, 'port')
                product = get_val_deal(item, 'product')
                version = get_val_deal(item, 'version')
                isp = get_val_deal(item, 'isp')
                host_table.append(
                    [
                        port,
                        product,
                        version,
                        isp,
                    ]
                )

                if 'vulns' in item.keys():
                    check_list = []
                    for cve_info in item['vulns'].items():
                        cve_id = cve_info[0]
                        cvss = cve_info[1].get('cvss')
                        summary = cve_info[1].get('summary')
                        if cve_id not in check_list:
                            cve_table.append(
                                [
                                    cve_id,
                                    cvss,
                                    textwrap.fill(summary, 80)
                                ]
                            )
                            check_list.append(cve_id)

        except shodan.APIError as e:
            logging.error(e)

        if len(host_table) == 0:
            logging.info("No opened ports")
        else:
            headers = ["Port", "Product", "Version", "ISP"]
            print(tabulate(host_table, headers, tablefmt="grid"), flush=True)

        if len(cve_table) == 0:
            logging.info("No vulnerabilities")
        else:
            # TODO: query vulndb cve_id
            logging.info("Vulnerability detected.")
            headers = ["ID", "Score", "Info"]
            print(tabulate(cve_table, headers, tablefmt="grid"), flush=True)

    # def shodan_ip_to_service(self, service, version=""):
    #     self.shodan_key_info()

    #     host_table = []
    #     try:
    #         logging.info("Fetch [{}-{}] from shodan.io...".format(service, version))
    #         host_items = self.shodan_api.search("{} {}".format(service, version))

    #         for item in host_items['matches']:
    #             ip = item['ip_str']
    #             port = item['port']
    #             product = get_val_deal(item, 'product')
    #             version = get_val_deal(item, 'version')
    #             host_table.append(
    #                 [
    #                     ip,
    #                     port,
    #                     product,
    #                     version,
    #                 ]
    #             )

    #     except shodan.APIError as e:
    #         logging.error(e)

    #     if len(host_table) == 0:
    #         logging.info("No matched IPs in shodan.io")
    #     else:
    #         headers = ["IP", "Port", "Priduct", "Version"]
    #         print(tabulate(host_table, headers, tablefmt="grid"), flush=True)
