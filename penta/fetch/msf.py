import concurrent.futures
import logging
import os
import random
import re
import time

from config import FileConfig, GH_URL, MSF_FETCH_PAGE_LIMIT, MSF_MODULE_DEFAULT, MSF_URL
from dateutil import parser
from lib.db import DBInit, MsfDAO
from lib.models import MsfRecord
from lib.utils import get_val, PATH_SPLIT
import requests
from requests.exceptions import RequestException
import requests_html
from tqdm import tqdm


class MsfSelector(object):
    def __init__(self):
        config = FileConfig()
        config.load_yaml()
        self.modules_path = config.settings["METASPLOIT"]["MODULE_PATH"]

    def update(self):
        if os.path.exists(self.modules_path):
            msf_collect = MsfLocalCollector()
        else:
            logging.error("Metasploit framework's dir is not set")
            msf_collect = MsfCollector()

        msf_collect.update()
        return None


class MsfCollector(object):
    def __init__(self):
        config = FileConfig()
        config.load_yaml()
        self.github_api = config.settings["GITHUB_TOKEN"]

        db_init = DBInit()
        db_init.create()
        self.msf_dao = MsfDAO(db_init.session)

        self.session = requests_html.HTMLSession()
        self.session.keep_alive = False
        self.headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.170 Safari/537.36',
        }

    # Request to the server for data crawling or scraping
    def request(self, url):
        time.sleep(random.uniform(0.5, 1.0))
        try:
            page = self.session.get(url, headers=self.headers)
            return page
        except RequestException:
            page = self.request(url)
            return page

    # Function call that executes an update
    def update(self):
        self.fetch()

    # Get the latest msf module list
    def fetch(self):
        url = MSF_URL
        logging.info("Fetching {}".format(url))

        page = self.request(url)

        try:
            module_links = page.html.xpath("//section[@class='vulndb__results']/a/@href")
            self.convert(module_links)
        except Exception as e:
            logging.warning("Exception while parsing modules")
            logging.warning("{}".format(e))

    # Get the msf module list of the specified number of pages
    def traverse(self):
        module_list = []
        for page_num in range(1, MSF_FETCH_PAGE_LIMIT + 1):
            url = "https://www.rapid7.com/db/?type=metasploit&page={}".format(page_num)
            logging.info("Fetching {}".format(url))

            page = self.request(url)

            try:
                modules = page.html.xpath("//section[@class='vulndb__results']/a/@href")
                for module in modules:
                    module_list.append(module)
            except Exception as e:
                logging.warning("Exception while enumerating the list")
                logging.warning("{}".format(e))

        try:
            self.convert(module_list)
        except Exception as e:
            logging.warning("Exception while parsing modules")
            logging.warning("{}".format(e))

    # Insert a record of each module to the database
    def convert(self, module_list):
        items = module_list
        logging.info("Fetched {} modules list".format(len(items)))
        logging.info("Inserting fetched modules...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            futures = {executor.submit(self.parse_msf_module, item): item for item in items}

            for f in tqdm(concurrent.futures.as_completed(futures), total=len(futures)):
                pass

        executor.shutdown()
        self.msf_dao.commit()
        logging.info("Successfully updated")

    # Extracts each element of HTML and converts it to a database model
    def parse_msf_module(self, item):
        url = "https://www.rapid7.com{}".format(item)
        page = self.request(url)

        if page.status_code != 200:
            msf_record = MsfRecord(module_name=item[11:])
            self.msf_dao.add(msf_record)

        element_xpath = {
            'module_title': '//div[@class="vulndb__detail-main"]/h3/text()',
            'module_url': '/html/head/link[@rel="canonical"]/@href',
            'module_devlink': '//section[contains(@class,"vulndb__solution")]/ul/li[1]/a/@href',
            'module_describe': '//div[contains(@class,"vulndb__detail-content")]/p/text()',
            'module_authors': '//div[contains(@class,"vulndb__detail-content")]/ul/li/text()',
            'module_references': '//section[contains(@class,"vulndb__references")]/ul/li//text()',
            'module_platforms': '//div[contains(@class,"vulndb__detail-content")]/p[2]/text()',
            'module_architectures': '//div[contains(@class,"vulndb__detail-content")]/p[3]/text()',
        }

        module_url = get_val(page.html.xpath(element_xpath["module_url"]))
        module_devlink = get_val(page.html.xpath(element_xpath["module_devlink"]))
        module_name = module_devlink[60:]
        module_title = get_val(page.html.xpath(element_xpath["module_title"]))
        module_describe_words = page.html.xpath(element_xpath["module_describe"])[0].split()
        module_describe = ' '.join(module_describe_words)

        module_authors = get_val(page.html.xpath(element_xpath["module_authors"]))

        module_references = get_val(page.html.xpath(element_xpath["module_references"]))
        module_cve = ""
        module_edb = ""

        # Extracting CVEs&EDBs from reference information
        if module_references is not None:
            cve_list = []
            edb_list = []
            pattern = r"CVE-\d{4}-\d+|EDB-\d+"
            numbering_list = re.findall(pattern, module_references)
            exclusion_pattern = r"CVE-\d{4}-\d+,?|EDB-\d+,?"
            module_references = re.sub(exclusion_pattern, "", module_references)

            for item in numbering_list:
                if "CVE" in item:
                    cve_list.append(item)
                elif "EDB" in item:
                    edb_list.append(item)

            if len(cve_list) >= 1:
                module_cve = ','.join(cve_list)
            if len(edb_list) >= 1:
                module_edb = ','.join(edb_list)

        module_platforms = get_val(page.html.xpath(element_xpath["module_platforms"]))
        module_architectures = get_val(page.html.xpath(element_xpath["module_architectures"]))

        modified_date = self.get_modified_date(module_name)
        module_update_date = parser.parse(modified_date).strftime("%Y-%m-%d %H:%M:%S")
        module_collect_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        msf_record = MsfRecord(
            module_name=module_name,
            module_title=module_title,
            module_url=module_url,
            module_describe=module_describe,
            module_authors=module_authors,
            module_cve=module_cve,
            module_edb=module_edb,
            module_references=module_references,
            module_platforms=module_platforms,
            module_architectures=module_architectures,
            module_update_date=module_update_date,
            module_collect_date=module_collect_date
        )

        self.insert_record(msf_record)

    # Run a database query and add a record
    def insert_record(self, record):
        if self.msf_dao.exist(record.module_name):
            self.msf_dao.update(record)
        else:
            self.msf_dao.add(record)

    # Date of site info is not trustworthy, so refer to git's commit log
    def get_modified_date(self, module_name):
        url = GH_URL
        headers = {"Authorization": "token {}".format(self.github_api)}

        repo_args = 'owner: "rapid7", name: "metasploit-framework"'
        ref_args = 'qualifiedName: "refs/heads/master"'
        hist_args = 'first: 1, path: "{}"'.format(module_name)
        gqljson = {
            "query": """
                query {
                    repository(%(repo_args)s) {
                        ref(%(ref_args)s) {
                            target {
                                ... on Commit {
                                    history(%(hist_args)s) {
                                        edges {
                                            node {
                                                committedDate
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            """
            % dict(repo_args=repo_args, ref_args=ref_args, hist_args=hist_args)
        }

        response = requests.post(url=url, json=gqljson, headers=headers)
        json_data = response.json()

        if json_data.get("errors"):
            return None
        elif json_data.get("message") and json_data.get("message") == "Bad credentials":
            logging.warning("GITHUB_TOKEN environment variable is invalid")
            return None

        return json_data["data"]["repository"]["ref"]["target"]["history"]["edges"][0]["node"]["committedDate"]


class MsfLocalCollector(object):
    def __init__(self):
        config = FileConfig()
        config.load_yaml()
        self.modules_path = config.settings["METASPLOIT"]["MODULE_PATH"]

        db_init = DBInit()
        db_init.create()
        self.msf_dao = MsfDAO(db_init.session)
        self.modules_path_list = []

    # Function call that executes an update
    def update(self):
        if os.path.exists(self.modules_path):
            self.fetch(self.modules_path)
        else:
            logging.error("Metasploit module dir not exist")

    # Get all msf modules list from local
    def fetch(self, path):
        logging.info("Fetching {}".format(path))
        self.select_module(path)

        try:
            module_list = self.modules_path_list
            self.convert(module_list)
        except Exception as e:
            logging.warning("Exception while parsing modules")
            logging.warning("{}".format(e))

    # Classifier of the fetched module path
    def select_module(self, path):
        dir_list = os.listdir(path)

        for module in dir_list:
            if module in MSF_MODULE_DEFAULT:
                relevant_path = f"{path}{PATH_SPLIT}{module}"
                self.search_dir_tree(relevant_path)

        logging.info("Successfully updated")

    # Recursively search the directory path tree
    def search_dir_tree(self, path):
        dir_contains = os.listdir(path)

        for dir_or_file in dir_contains:
            target_path = f"{path}{PATH_SPLIT}{dir_or_file}"

            # This version only supports ruby script
            if os.path.isfile(target_path) and target_path.find(".rb") != -1:
                # self.parse_msf_module_local(target_path)
                self.modules_path_list.append(target_path)

            elif os.path.isdir(target_path):
                sub_dir_tree = target_path
                self.search_dir_tree(sub_dir_tree)

    # Insert a record of each module to the database
    def convert(self, module_list):
        items = module_list
        logging.info("Fetched {} modules list".format(len(items)))
        logging.info("Inserting fetched modules...")

        for item in tqdm(items):
            self.parse_msf_module_local(item)

        self.msf_dao.commit()
        logging.info("Successfully updated")

    # Extracts each element of TEXT and converts it to a database model
    def parse_msf_module_local(self, target_file):
        regex_pattern = {
            'module_info': r"initialize[\s\S]*?end\n",
            'module_title': r"['|\"]Name['|\"][ |\t|\S]+['|\"|\)]",
            'module_describe': r"['|\"]Description['|\"][\s\S]*?['|\"|\)],\n|['|\"]Description['|\"][^\}]+},\n",
            'module_authors': r"['|\"]Author['|\"][^\]]+\],\n|['|\"]Author['|\"][ |\t|\S]+['|\"|\)|\]],\n",
            'module_cve': r"['|\"]CVE['|\"],\s['|\"]\d{4}-\d+['|\"]",
            'module_edb': r"['|\"]EDB['|\"],\s['|\"]\d+['|\"]",
            'module_cwe': r"['|\"]CWE['|\"],\s['|\"]\d+['|\"]",
            'module_bid': r"['|\"]BID['|\"],\s['|\"]\d+['|\"]",
            'module_zdi': r"['|\"]ZDI['|\"],\s['|\"]\d{2}-\d+['|\"]",
            'module_msb': r"['|\"]MSB['|\"],\s['|\"]MS\d{2}-\d+['|\"]",
            'module_osvdb': r"['|\"]OSVDB['|\"],\s['|\"]\d+['|\"]",
            'module_wpvdb': r"['|\"]WPVDB['|\"],\s['|\"]\d+['|\"]",
            'module_uscert': r"['|\"]US-CERT-VU['|\"],\s['|\"]\S+['|\"]",
            'module_packet': r"['|\"]PACKETSTORM['|\"],\s['|\"]\S+['|\"]",
            'module_ref_url': r"['|\"]URL['|\"],\s['|\"]\S+['|\"]",
            'module_platforms_fmt': r"['|\"]Platform['|\"][ |\t]+=>[ |\t]%+[^\}]+},\n",
            'module_platforms': r"['|\"]Platform['|\"][ |\t|\S]+['|\"|\)|\]],\n|['|\"]Platform['|\"][^\}]+},\n",
            'module_disclosure_date': r"['|\"]DisclosureDate['|\"][ |\t|\S]+['|\"],*\n",
        }

        file_obj = open(target_file, "r")
        source_code = file_obj.read()
        update_info_code = get_val(re.findall(regex_pattern['module_info'], source_code))

        module_name_start_pos = target_file.find("modules")
        module_name = target_file[module_name_start_pos:]
        module_class = module_name.split(PATH_SPLIT)[1]
        module_url = f"https://www.rapid7.com/db/modules/{module_name}".replace(
            "exploits", "exploit").replace(".rb", "")
        module_title = self.optimize_title(
            get_val(re.findall(regex_pattern['module_title'], update_info_code)))
        module_describe_words = self.optimize_describe(
            get_val(re.findall(regex_pattern['module_describe'], update_info_code))).split()
        module_describe = ' '.join(module_describe_words)

        # TODO: Efficient author's parsing method
        # module_authors = get_val(re.findall(regex_pattern['module_authors'], update_info_code))

        module_cve = self.optimize_ref_id(get_val(re.findall(regex_pattern['module_cve'], update_info_code)))
        module_edb = self.optimize_ref_id(get_val(re.findall(regex_pattern['module_edb'], update_info_code)))

        module_cwe = self.optimize_ref_id(get_val(re.findall(regex_pattern['module_cwe'], update_info_code))).split(",")
        module_bid = self.optimize_ref_id(get_val(re.findall(regex_pattern['module_bid'], update_info_code))).split(",")
        module_zdi = self.optimize_ref_id(get_val(re.findall(regex_pattern['module_zdi'], update_info_code))).split(",")
        module_msb = self.optimize_ref_id(get_val(re.findall(regex_pattern['module_msb'], update_info_code))).split(",")
        module_osvdb = self.optimize_ref_id(
            get_val(re.findall(regex_pattern['module_osvdb'], update_info_code))).split(",")
        module_wpvdb = self.optimize_ref_id(
            get_val(re.findall(regex_pattern['module_wpvdb'], update_info_code))).split(",")
        module_uscert = self.optimize_ref_id(
            get_val(re.findall(regex_pattern['module_uscert'], update_info_code))).split(",")
        module_packet = self.optimize_ref_id(
            get_val(re.findall(regex_pattern['module_packet'], update_info_code))).split(",")

        module_ref_url = self.optimize_ref_url(get_val(re.findall(regex_pattern['module_ref_url'], update_info_code)))
        module_ref_list = module_cwe + module_bid + module_zdi + module_msb + \
            module_osvdb + module_wpvdb + module_uscert + module_packet + module_ref_url
        module_ref_list = list(filter(lambda str: str != '', module_ref_list))
        module_references = get_val(module_ref_list)

        try:
            module_platforms = self.optimize_platforms(re.findall(
                regex_pattern['module_platforms_fmt'], update_info_code)[0])
        except IndexError:
            try:
                module_platforms = self.optimize_platforms(re.findall(
                    regex_pattern['module_platforms'], update_info_code)[0])
            except IndexError:
                module_platforms = ""

        module_remote_ports = self.optimize_remote_port(source_code)

        module_disclosure_date = self.optimize_disclosure_date(
            get_val(re.findall(regex_pattern['module_disclosure_date'], update_info_code)))
        module_collect_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        file_obj.close()

        msf_record = MsfRecord(
            module_name=module_name,
            module_class=module_class,
            module_title=module_title,
            module_url=module_url,
            module_describe=module_describe,
            module_cve=module_cve,
            module_edb=module_edb,
            module_references=module_references,
            module_platforms=module_platforms,
            module_remote_ports=module_remote_ports,
            module_disclosure_date=module_disclosure_date,
            module_collect_date=module_collect_date
        )

        self.insert_record(msf_record)

    # Run a database query and add a record
    def insert_record(self, record):
        if self.msf_dao.exist(record.module_name):
            self.msf_dao.update(record)
        else:
            self.msf_dao.add(record)

    def optimize_title(self, module_title):
        elements = module_title.split("=>")
        try:
            module_title_strip = elements[1].strip()
            module_title_regex = re.match(r"'.+?'|\".+?\"|q\(.+?\)", module_title_strip).group()
            module_title = re.sub(r"['|\"]", "", module_title_regex)
        except Exception:
            try:
                if module_title.find("q(") != -1:
                    start_pos = module_title.find("q(") + 2
                    end_pos = module_title.find(")")
                    module_title = module_title[start_pos:end_pos].strip()
            except Exception:
                module_title = ""
        return module_title

    def optimize_describe(self, module_describe):
        try:
            if module_describe.find("{") != -1:
                start_pos = module_describe.find("{") + 1
                end_pos = module_describe.find("}")
                opt_module_describe = module_describe[start_pos:end_pos].strip()
            elif module_describe.find("q(") != -1:
                start_pos = module_describe.find("q(") + 2
                end_pos = module_describe.find(")")
                opt_module_describe = module_describe[start_pos:end_pos].strip()
            elif module_describe.find("q|") != -1:
                start_pos = module_describe.find("q|") + 2
                end_pos = module_describe.find("|,")
                opt_module_describe = module_describe[start_pos:end_pos].strip()
            elif module_describe.find("%(") != -1:
                start_pos = module_describe.find("%(") + 2
                end_pos = module_describe.find(")")
                opt_module_describe = module_describe[start_pos:end_pos].strip()
            else:
                module_describe_texts = module_describe.split("=>")
                module_describe_strip = module_describe_texts[1].strip()
                try:
                    regex_matched = re.match(r"'.+?'|\".+?\"|\(.+?\)", module_describe_strip)
                    module_describe_regex = regex_matched.group()
                    opt_module_describe = re.sub(r"['|\"]", "", module_describe_regex)
                except AttributeError:
                    opt_module_describe = module_describe_strip.strip("'").strip('"')
        except IndexError:
            opt_module_describe = ""
        return opt_module_describe

    def optimize_ref_id(self, module_ref_item):
        opt_module_ref_id = module_ref_item.replace('"', '').replace("'", "").replace(", ", "-")
        return opt_module_ref_id

    def optimize_ref_url(self, module_ref_url):
        # TODO: Convert ID to URL
        # CWE: 'http://cwe.mitre.org/data/definitions/{id}.html',
        # BID: 'http://www.securityfocus.com/bid/{id}',
        # MSB: 'http://technet.microsoft.com/en-us/security/bulletin/{id}',
        # US-CERT-VU: 'http://www.kb.cert.org/vuls/id/{id}',
        # ZDI: 'http://www.zerodayinitiative.com/advisories/ZDI-{id}',
        # WPVDB: 'https://wpvulndb.com/vulnerabilities/{id}',
        # PACKETSTORM: 'https://packetstormsecurity.com/files/{id}',

        opt_module_url_list = re.sub(r"['|\"]URL['|\"],", "", module_ref_url).strip().replace(
            '"', '').replace("'", "").split(", ")
        return opt_module_url_list

    def optimize_platforms(self, module_platform):
        comment_pos = module_platform.find("#")
        if comment_pos != -1:
            module_platform = module_platform[:comment_pos]

        module_platforms = module_platform.split("=>")
        try:
            parsed_platforms = module_platforms[1].strip()
            if parsed_platforms.find("{") != -1:
                start_pos = parsed_platforms.find("{") + 1
                end_pos = parsed_platforms.find("}")
                parsed_platforms = parsed_platforms[start_pos:end_pos].strip()
            elif parsed_platforms.find("[") != -1:
                start_pos = parsed_platforms.find("[") + 1
                end_pos = parsed_platforms.find("],")
                parsed_platforms = parsed_platforms[start_pos:end_pos].strip()
            elif parsed_platforms.find("(") != -1:
                start_pos = parsed_platforms.find("(") + 1
                end_pos = parsed_platforms.find("),")
                parsed_platforms = parsed_platforms[start_pos:end_pos].strip()
        except IndexError:
            parsed_platforms = ""

        replaced_text = re.sub(r"[,'\"\]}]", "", parsed_platforms)
        striped_text = replaced_text.strip().replace(" ", ",")

        replacements = {
            "aix": "AIX",
            "android": "Android",
            "apple_ios": "Apple_iOS",
            "brocade": "Brocade",
            "bsd": "BSD",
            "bsdi": "BSDi",
            "cisco": "Cisco",
            "firefox": "Firefox",
            "hpux": "HPUX",
            "irix": "Irix",
            "java": "Java",
            "js": "JavaScript",
            "juniper": "Juniper",
            "linux": "Linux",
            "mainframe": "Mainframe",
            "multi": "Multi",
            "netware": "Netware",
            "nodejs": "NodeJS",
            "oepnbsd": "OpenBSD",
            "osx": "OSX",
            "php": "PHP",
            "python": "Python",
            "ruby": "Ruby",
            "solaris": "Solaris",
            "unix": "Unix",
            "windows": "win"
        }
        transformed_text = re.sub("({})".format("|".join(map(re.escape, replacements.keys()))),
                                  lambda m: replacements[m.group()], striped_text)
        opt_module_platforms = transformed_text.replace("win", "Windows")

        return opt_module_platforms

    def optimize_remote_port(self, source_code):
        rport_num = None
        try:
            rport_text = re.findall(r".*RPORT['|\(].*\n", source_code)[0].strip()
            comment_pos = rport_text.find("#")
            if comment_pos != -1:
                rport_text = rport_text[:comment_pos]
            regex_num = int(re.sub(r"\D", "", rport_text))

            if 0 <= regex_num <= 65536:
                rport_num = regex_num
        except (IndexError, ValueError):
            include_dict = {
                "include Rex::Proto::NATPMP": 5351,
                "Rex::Proto::ACPP::DEFAULT_PORT": 5009,
                "Rex::Proto::PJL::DEFAULT_PORT": 9100,
                "include Msf::Auxiliary::Etcd": 2379,
                "include Msf::Auxiliary::MQTT": 1883,
                "include Msf::Auxiliary::NTP": 123,
                "include Msf::Exploit::ORACLE": 1521,
                "include Msf::Exploit::Remote::AFP": 548,
                "include Msf::Exploit::Remote::Arkeia": 617,
                "include Msf::Exploit::Remote::DB2": 50000,
                "include Msf::Exploit::Remote::DCERPC": 135,
                "include Msf::Exploit::Remote::Ftp": 21,
                "include Msf::Exploit::Remote::HttpClient": 80,
                "include Msf::Exploit::Remote::Imap": 143,
                "include Msf::Exploit::Remote::Kerberos::Client": 88,
                "include Msf::Exploit::Remote::MSSQL": 1433,
                "include Msf::Exploit::Remote::MYSQL": 3306,
                "include Msf::Exploit::Remote::NDMP": 10000,
                "include Msf::Exploit::Remote::Pop2": 109,
                "include Msf::Exploit::Remote::Postgres": 5432,
                "include Msf::Exploit::Remote::RealPort": 771,
                "include Msf::Exploit::Remote::SMB::Client": 445,
                "include Msf::Exploit::Remote::Smtp": 25,
                "include Msf::Exploit::Remote::SMTPDeliver": 25,
                "include Msf::Exploit::Remote::SNMPClient": 161,
                "include Msf::Exploit::Remote::SunRPC": 111,
                "include Msf::Exploit::Remote::TNS": 1521,
                "include Msf::Exploit::Remote::Telnet": 23,
                "include Msf::Exploit::Remote::WDBRPC_Client": 17185,
                "include Msf::Exploit::Remote::WinRM": 5985,
            }
            for key, value in include_dict.items():
                if key in source_code:
                    rport_num = value

        return rport_num

    def optimize_disclosure_date(self, module_disclosure_date):
        comment_pos = module_disclosure_date.find("#")
        if comment_pos != -1:
            module_disclosure_date = module_disclosure_date[:comment_pos]

        elements = module_disclosure_date.split("=>")
        try:
            opt_date = elements[1].strip().replace(",", "").strip("'").strip('"')
            opt_date = time.strftime("%Y-%m-%d %H:%M:%S", time.strptime(opt_date, "%b %d %Y"))
        except IndexError:
            opt_date = None
        except ValueError:
            opt_date = None

        return opt_date
