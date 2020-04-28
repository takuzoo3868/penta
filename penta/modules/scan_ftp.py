#!/usr/bin/env python
import ftplib
import socket

import nmap

from utils import Colors


class FtpConnector:

    def __init__(self):
        self.nmsc = nmap.PortScanner()

    def ftp_connect_anonymous(self, ip):
        try:
            self.nmsc.scan(hosts=ip, arguments="-T4 -F")

            if self.nmsc[ip]['tcp'][21]['state'] == "open":
                print("FTP 21/tcp {}OPEN{}".format(Colors.LIGHTGREEN, Colors.END))
                response = input(
                    "[*] Would you like connect with anonymous user to {} ?[y/N]".format(ip))
                if response in ['y', 'ye', 'yes']:
                    try:
                        ftp_client = ftplib.FTP(ip, timeout=10)
                        connect = ftp_client.login('anonymous', '')
                        print(connect)
                        print(ftp_client.getwelcome())
                        ftp_client.set_pasv(1)
                        print(ftp_client.retrlines('LIST'))
                        ftp_client.quit()
                    except Exception as err:
                        print("ERROR {}".format(err))
                    except ftplib.all_errors as err:
                        print("ftplib ERROR {}".format(err))
            else:
                print("FTP 21/tcp {}CLOSED{}".format(Colors.RED, Colors.END))
        except KeyError:
            print("[!] Error checking ports!")
            pass
        except socket.gaierror:
            print("[!] Hostname could not be resolved.")
        except socket.error:
            print("[!] Couldn't connect to server")
