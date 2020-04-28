#!/usr/bin/env python
import requests

from utils import Colors

try:
    from selenium import webdriver
    from selenium.common.exceptions import WebDriverException
except Exception:
    print("[!] pipenv install selenium")
    exit(1)


class Inspect:

    def check_option_methods(self, hostname):
        try:
            r = requests.options('http://' + hostname, timeout=5)
            print("[+] {}".format(r.headers['allow']))
        except KeyError:
            print("{}[!]{} Not allow methods found!".format(Colors.RED, Colors.END))
            pass
        except Exception as err:
            print("[!] Error to connect with {} for obtain option methods".format(hostname))
            print("{}[!]{} {}".format(Colors.RED, Colors.END, err))
            pass
