import logging

import requests
from requests.exceptions import RequestException


class Inspect(object):
    def check_option_methods(self, hostname):
        try:
            response = requests.options('http://' + hostname, timeout=5)
            print("[+] {}".format(response.headers['allow']))
        except KeyError:
            logging.error("Not allow methods found")
            pass
        except Exception as err:
            logging.error("Error to connect with {}".format(hostname))
            logging.error(err)
            pass

    def traceroute(self, target):
        url = 'https://api.hackertarget.com/mtr/?q={}'.format(target)
        try:
            response = requests.get(url)
            route = response.text
            print(str(route))
        except RequestException:
            logging.error("Connection error")
            pass
