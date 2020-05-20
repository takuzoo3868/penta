import logging
import re

import dns.resolver
import dns.reversename
from ipwhois import IPWhois
from lib.utils import Colors

RECORDS = [
    "SOA", "A", "AAAA", "MX", "NS", "SRV", "SPF", "TXT", "PTR"
]


class DnsScanner(object):
    def __init__(self, name_server=None, proto="tcp"):
        self.proto = proto
        if name_server:
            self.resolve = dns.resolver.Resolver(configure=False)
            self.resolve.nameserver = name_server
            if len(name_server) > 1:
                self.resolve.rotate = True
        else:
            self.resolve = dns.resolver.Resolver(configure=True)

        self.resolve.timeout = 6.0
        self.resolve.lifetime = 6.0

    def scan(self, ip, hostname):
        logging.info("Check Domain & DNS...")

        if ip == "127.0.0.1":
            logging.warn("127.0.0.1 is already defined as Loopback via RFC 1122")
            return None

        try:
            self.dns_whois(ip)
            record_dict = self.dns_record(hostname)
            DnsScanner.record_print(hostname, record_dict)
        except Exception as e:
            logging.error(e)

        return None

    def dns_whois(self, host_trg):
        logging.info("Whois")
        try:
            result = IPWhois(host_trg).lookup_whois()
            DnsScanner.dns_whois_print(result)
        except Exception as e:
            logging.error(e)
        return

    @staticmethod
    def dns_whois_print(res_data):
        print('{}NIR:{} {}'.format(Colors.DARKGRAY, Colors.END, str(res_data['nir'])))
        print('{}ASN Registry:{} {}'.format(Colors.DARKGRAY, Colors.END, str(res_data['asn_registry'])))
        print('{}ASN:{} {}'.format(Colors.DARKGRAY, Colors.END, str(res_data['asn'])))
        print('{}ASN CIDR:{} {}'.format(Colors.DARKGRAY, Colors.END, str(res_data['asn_cidr'])))
        print('{}ASN Country Code:{} {}'.format(Colors.DARKGRAY, Colors.END, str(res_data['asn_country_code'])))
        print('{}ASN Date:{} {}'.format(Colors.DARKGRAY, Colors.END, str(res_data['asn_date'])))
        print('{}ASN Description:{} {}'.format(Colors.DARKGRAY, Colors.END, str(res_data['asn_description'])))
        for k, v in res_data['nets'][0].items():
            if isinstance(v, list):
                value = ", ".join(v)
            else:
                value = str(v).replace("\n", "")
            key = str(k).upper()
            print("{}{}:{} {}".format(Colors.DARKGRAY, key, Colors.END, value))
        return

    def dns_record(self, host_trg):
        logging.info("DNS Records")
        result_dict = {}
        call_dict = {
            "SOA": self.get_soa(host_trg),
            "A": self.get_a(host_trg),
            "AAAA": self.get_aaaa(host_trg),
            "MX": self.get_mx(host_trg),
            "NS": self.get_ns(host_trg),
            "SRV": self.get_srv(host_trg),
            "SPF": self.get_spf(host_trg),
            "TXT": self.get_txt(host_trg),
            "PTR": self.get_ptr(host_trg),
        }

        for key, value in call_dict.items():
            rtype = key
            result = value
            result_dict[rtype] = result

        return result_dict

    def get_soa(self, host_trg):
        soa_records = []
        tcp = True if self.proto == "tcp" else False
        try:
            answers = self.resolve.query(host_trg, 'SOA', tcp=tcp)
            for ardata in answers.response.answer:
                for rdata in ardata:
                    if rdata.rdtype == 6:
                        soa_records.append([host_trg, str(rdata.mname)])
                        soa_records.append([host_trg, str(rdata.rname)])
        except Exception:
            return soa_records
        return soa_records

    def get_a(self, host_trg):
        address = []
        tcp = True if self.proto == "tcp" else False
        try:
            ipv4_answers = self.resolve.query(host_trg, 'A', tcp=tcp)
            for ardata in ipv4_answers.response.answer:
                for rdata in ardata:
                    if rdata.rdtype == 5:
                        if rdata.target.to_text().endswith('.'):
                            address.append([host_trg, rdata.target.to_text()[:-1], "CNAME"])
                            host_trg = rdata.target.to_text()[:-1]
                        else:
                            address.append([host_trg, rdata.target.to_text(), "CNAME"])
                            host_trg = rdata.target.to_text()
                    else:
                        address.append([host_trg, rdata.address, "A"])
        except Exception:
            return address
        return address

    def get_aaaa(self, host_trg):
        address = []
        tcp = True if self.proto == "tcp" else False
        try:
            ipv6_answers = self.resolve.query(host_trg, 'AAAA', tcp=tcp)
            for ardata in ipv6_answers.response.answer:
                for rdata in ardata:
                    if rdata.rdtype == 5:
                        if rdata.target.to_text().endswith('.'):
                            address.append([host_trg, rdata.target.to_text()[:-1], "CNAME"])
                            host_trg = rdata.target.to_text()[:-1]
                        else:
                            address.append([host_trg, rdata.target.to_text(), "CNAME"])
                            host_trg = rdata.target.to_text()
                    else:
                        address.append([host_trg, rdata.address, "AAAA"])
        except Exception:
            return address
        return address

    def get_ip(self, host_trg):
        ip_addr = []
        ip_addr.extend(self.get_a(host_trg))
        ip_addr.extend(self.get_aaaa(host_trg))
        return ip_addr

    def get_mx(self, host_trg):
        mx_records = []
        tcp = True if self.proto == "tcp" else False
        answers = self.resolve.query(host_trg, 'MX', tcp=tcp)
        for rdata in answers:
            try:
                name = rdata.exchange.to_text()
                ipv4_answers = self.resolve.query(name, 'A', tcp=tcp)
                for addr in ipv4_answers:
                    if name.endswith('.'):
                        mx_records.append([name[:-1], addr.address, rdata.preference])
                    else:
                        mx_records.append([name, addr.address, rdata.preference])
            except Exception:
                pass

        try:
            for rdata in answers:
                name = rdata.exchange.to_text()
                ipv6_answers = self.resolve.query(name, 'AAAA', tcp=tcp)
                for addr in ipv6_answers:
                    if name.endswith('.'):
                        mx_records.append([name[:-1], addr.address, rdata.preference])
                    else:
                        mx_records.append([name, addr.address, rdata.preference])
            return mx_records
        except Exception:
            return mx_records

    def get_ns(self, host_trg):
        name_servers = []
        tcp = True if self.proto == "tcp" else False
        answer = self.resolve.query(host_trg, 'NS', tcp=tcp)
        if answer is not None:
            for rdata in answer:
                name = rdata.target.to_text()[:-1]
                ip_addrs = self.get_ip(name)
                for addr in ip_addrs:
                    if re.search(r'^A', addr[2]):
                        name_servers.append([name, addr[1]])
        return name_servers

    def get_srv(self, host_trg):
        srv_record = []
        tcp = True if self.proto == "tcp" else False
        try:
            answers = self.resolve.query(host_trg, 'SRV', tcp=tcp)
            for answer in answers:
                if answer.target.to_text().endswith('.'):
                    target = answer.target.to_text()[:-1]
                else:
                    target = answer.target.to_text()

                ip_addrs = self.get_ip(target)

                if ip_addrs:
                    for ip in ip_addrs:
                        if re.search('(^A|AAAA)', ip[0]):
                            srv_record.append([host_trg, target, ip[2], str(answer.port), str(answer.weight)])
                else:
                    srv_record.append([host_trg, target, "no_ip", str(answer.port), str(answer.weight)])
        except Exception:
            return srv_record

        return srv_record

    def get_spf(self, host_trg):
        spf_record = []
        tcp = True if self.proto == "tcp" else False
        try:
            answers = self.resolve.query(host_trg, 'SPF', tcp=tcp)
            for rdata in answers:
                name = bytes.join(b'', rdata.strings).decode('utf-8')
                spf_record.append([name])
        except Exception:
            return spf_record

        return spf_record

    def get_txt(self, host_trg):
        txt_record = []
        tcp = True if self.proto == "tcp" else False
        try:
            answers = self.resolve.query(host_trg, 'TXT', tcp=tcp)
            for rdata in answers:
                string = bytes.join(b'', rdata.strings).decode('utf-8')
                txt_record.append([string])
        except Exception:
            return txt_record

        return txt_record

    def get_ptr(self, host_trg):
        found_ptr = []
        tcp = True if self.proto == "tcp" else False

        try:
            ipv4_answers = self.resolve.query(host_trg, 'A', tcp=tcp)
            for rdata in ipv4_answers:
                node = dns.reversename.from_address(rdata.address)
                try:
                    answers = self.resolve.query(node, 'PTR', tcp=tcp)
                    for answer in answers:
                        if answer.target.to_text().endswith('.'):
                            found_ptr.append([answer.target.to_text()[:-1], str(node)])
                        else:
                            found_ptr.append([answer.target.to_text(), str(node)])
                    return found_ptr
                except Exception:
                    return found_ptr
        except Exception:
            return found_ptr

    @staticmethod
    def record_print(host_trg, record_dict: dict):
        print("Host: {}".format(host_trg))
        print("│")

        for record_type, record_list in record_dict.items():
            root_last = (record_type == RECORDS[-1])

            if root_last:
                print("╰─ {}{}{}".format(Colors.BOLD, record_type, Colors.END))
            else:
                print("├─ {}{}{}".format(Colors.BOLD, record_type, Colors.END))

            for index, line in enumerate(record_list):
                if record_type in ("SOA", "A", "AAAA"):
                    line_str = str(line[1])
                else:
                    line_str = " - ".join(map(str, line))
                line_last = (index == len(record_list) - 1)

                rl = " " if root_last else "│"
                # ll = " " if line_last else "│"
                llt = "╰" if line_last else "├"

                print(rl + "  " + llt + "─ " + line_str)
