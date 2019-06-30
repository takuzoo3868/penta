#!/usr/bin/env python
from datetime import datetime
import requests
import socket
from socket import AF_INET, SOCK_STREAM, setdefaulttimeout

try:
    from selenium import webdriver
    from selenium.common.exceptions import WebDriverException
except Exception as e:
    print("[!] pipenv install selenium")
    exit(1)


class Inspect:

    def check_open_ports(self, ip, hostname, ports):
        time_start = datetime.now()

        print("[ ] Checking ports: {}".format(str(ports)))
        socket.setdefaulttimeout(2)
        try:
            for port in ports:
                con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = con.connect_ex((ip, int(port)))
                if result == 0:
                    print("[+] Port {}:\tOPEN".format(port))
                else:
                    print("[-] Port {}:\tCLOSE".format(port))
                con.close()
        except KeyError:
            print("[!] Error checking ports!")
            pass
        # except socket.gaierror:
        #     print("[!] Hostname could not be resolved")
        #     sys.exit()
        # except socket.error as err:
        #     print("[!] Couldn't connect to server {}".format(err))
        #     sys.exit()

        time_end = datetime.now()
        total = time_end - time_start

        print("[+] Scanning Duration: {}".format(total))
        print("\n[ ] Checking connection port 80")

        self.check_open_port_80(ip, hostname)

    def check_open_port_80(self, ip, host):

        setdefaulttimeout(5)

        template = "{0:16}{1:3}{2:40}"

        # AF_INET:     Set(host, port)
        # SOCK_STREAM: Connection TCP Protocol
        con = socket.socket(AF_INET, SOCK_STREAM)
        try:
            con.connect((ip, 80))
            con.send(b"HEAD / HTTP/1.0\r\n\r\n")
            print("[+] ", template.format(ip, "->", "Open"))

            banner_sum = ''
            while True:
                banner = con.recv(1024).decode("utf-8")
                if not banner:
                    break
                banner_sum += banner_sum + banner
            con.close()
            print(banner_sum)

            # screenshot = cls.take_screenshot(host, str(80))
            # stream = io.BytesIO(screenshot)
            # img = Image.open(stream)
            # img.save("screenshot.png")

        except Exception as err:
            print("[!] ERROR {}".format(err))
            return False

    def take_screenshot(self, host, port):

        global browser, screenshot, state
        setdefaulttimeout(200)

        try:
            browser = webdriver.Firefox(timeout=200)
            browser.implicitly_wait(200)
            print('http://' + host)
            browser.get('http://{0}'.format(host))
            screenshot = browser.get_screenshot_as_png()
            state = True
            browser.quit()

        except WebDriverException as err:
            print("[-] ERROR WebDriver: {}".format(err))
            exit(1)

        except Exception as err:
            state = False
            print("[-] ERROR takeScreenShot: {}".format(err))
            browser.quit()

        if state:
            return screenshot
        else:
            return None

    def check_option_methods(self, hostname):
        try:
            r = requests.options('http://' + hostname, timeout=5)
            print("[+] {}".format(r.headers['allow']))
        except KeyError:
            print("[!] Not allow methods found!")
            pass
        except Exception as err:
            print("[!] Error to connect with {} for obtain option methods".format(hostname))
            print("[!] {}".format(err))
            pass
