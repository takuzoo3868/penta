#!/usr/bin/env python
import pprint
from socket import getfqdn

import dns.resolver
import dns.reversename
import whois

try:
    from ipwhois import IPWhois
except Exception:
    print("[!] pipenv install ipwhois")
    exit(1)


class DnsScanner:

    def __init__(self):
        self.my_resolver = dns.resolver.Resolver()
        self.my_resolver.domain = dns.name.Name("google-public-dns-a.google.com")
        self.my_resolver.nameserver = ['8.8.8.8']

    def check_dns_info(self, ip, hostname):
        print("[ ] Check domain and DNS...")

        try:
            data_whois = whois.whois(ip)
            for key in data_whois.keys():
                if key == "raw":
                    info = data_whois[key][0].split("\n")
                    for i in info:
                        print("[ ] {}".format(i))
                else:
                    print("[+] {} :\t{}".format(key, data_whois[key]))
        except Exception as err:
            print("[!] ERROR {}".format(err))

        try:
            self.host_data(hostname)
            self.obtain_more_data(ip)
            print("\n[ ] Whois info: {}".format(hostname))
            self.dns_whois(hostname)
            print("\n[ ] Whois info: {}".format(ip))
            self.dns_whois(ip)
        except Exception as err:
            print("[!] ERROR {}".format(err))

    def dns_whois(self, host_name):
        print(whois.whois(host_name))

    def host_data(self, host_name):
        print("\n[ ] Information about DNS servers")
        try:
            answers = self.my_resolver.query(host_name, "CNAME")
            for rdata in answers:
                print("[+] CNAME: {}".format(str(rdata.target)))
        except dns.resolver.NoAnswer:
            print("[-] Can not obtain CNAME")

        try:
            answers = self.my_resolver.query(host_name, 'A')
            ip = []
            for rdata in answers:
                n = dns.reversename.from_address(rdata.address)
                try:
                    answers_inv = self.my_resolver.query(n, 'PTR')
                    for rdata_inv in answers_inv:
                        ip += [(rdata.address, str(rdata_inv.target))]
                except dns.resolver.NoAnswer:
                    ip += [(rdata.address, "PTR: No response " + str(n))]
                except dns.resolver.NXDOMAIN:
                    ip += [(rdata.address, "PTR: Domain NX " + str(n))]
                print("[+] IPs: {}".format(ip))
        except dns.resolver.NoAnswer:
            print("[-] Can not obtain IPs")

        try:
            answers = self.my_resolver.query(host_name, 'MX')
            mx = []
            for rdata in answers:
                mx += [str(rdata.exchange)]
            print("[+] MXs: {}".format(mx))
        except dns.resolver.NoAnswer:
            print("[-] Can not obtain MXs")

        try:
            answers = self.my_resolver.query(host_name, 'NS')
            ns = []
            for rdata in answers:
                ns += [str(rdata.target)]
            print("[+] NSs: {}".format(ns))
        except dns.resolver.NoAnswer:
            print("[-] Can not obtain NSs")

        try:
            answers = self.my_resolver.query(host_name, 'SOA')
            for rdata in answers:
                print("[+] SOA: {} {}".format(str(rdata.mname), str(rdata.rname)))
        except dns.resolver.NoAnswer:
            print("[-] Can not obtain SOA")

        try:
            answers = self.my_resolver.query(host_name, 'TXT')
            for rdata in answers:
                print("[+] TXT: {}".format(rdata.strings))
        except dns.resolver.NoAnswer:
            print("[-] Can not obtain TXT")

        try:
            answers = self.my_resolver.query(host_name, 'LOC')
            for rdata in answers:
                print("[+] LOC: Latitud {} Logitud {}".format(rdata.float_latitude, rdata.float_longitude))
        except dns.resolver.NoAnswer:
            print("[-] Can not obtain LOC")

        try:
            answers = self.my_resolver.query(host_name, 'MINFO')
            for rdata in answers:
                print("[+] MINFO: {}".format(rdata.to_text()))
        except dns.resolver.NoAnswer:
            print("[-] Can not obtain MINFO")

        try:
            answers = self.my_resolver.query(host_name, 'HINFO')
            for rdata in answers:
                print("[+] HINFO: {}".format(rdata.to_text()))
        except dns.resolver.NoAnswer:
            print("[-] Can not obtain HINFO")

    def obtain_more_data(self, host):
        print("\n[ ] Information about domain name")

        domain_name = getfqdn(host)
        print("[+] Domain name:{}".format(domain_name))

        data_whois = IPWhois(host).lookup_whois()
        pprint.pprint(data_whois)

        aux = domain_name.split('.')
        dns_q = '{0}.{1}'.format(aux[-2], aux[-1])

        addr = dns.reversename.from_address(host)
        rev_name = "\n[+] Reverser name\n"
        rev_name += str(addr) + "\n"

        try:
            ptr_text = "\n[+] PTR\n"
            for ptr in dns.resolver.query(addr, "PTR"):
                ptr_text += str(ptr) + "\n"
                rev_name += ptr_text

        except Exception:
            pass

        try:
            ns_text = "\n[+] Name servers\n"
            for server in dns.resolver.query(dns_q, 'NS'):
                ns_text += str(server).rstrip('.') + '\n'
                rev_name += ns_text

            print(rev_name)

        except Exception:
            pass
