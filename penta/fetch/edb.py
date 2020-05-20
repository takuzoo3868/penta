import asyncio
import concurrent.futures
import csv
import logging
import random
from ssl import SSLCertVerificationError, SSLError
import time

import aiohttp
from aiohttp.client_exceptions import ClientConnectionError, ClientOSError, ServerDisconnectedError
from config import EDB_CSV_URL, EDB_MAP_URL
from lib.db import DBInit, EdbDAO
from lib.models import EdbRecord
from lib.utils import get_random_user_agent, get_val
import requests
from requests.exceptions import RequestException
import requests_html
from requests_html import HTML
from tqdm import tqdm
import ujson


element_xpath = {
    'edb_id': '/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[1]/div/div[1]/div/div/div/div[1]/h6/text()',
    'edb_title': '/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[1]/h1/text()',
    'edb_author': '/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[2]/div/div[1]/div/div/div/div[1]/h6/a/text()',
    'edb_published': '/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[3]/div/div[1]/div/div/div/div[2]/h6/text()',
    'edb_cve': '/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[1]/div/div[1]/div/div/div/div[2]/h6/a/text()',
    'edb_type': '/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[2]/div/div[1]/div/div/div/div[2]/h6/a/text()',
    'edb_platform': '/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[3]/div/div[1]/div/div/div/div[1]/h6/a/text()',
    'edb_vulnerable_app_url': '/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[3]/div/div[2]/div/a/@href',
    'edb_verified': '/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[1]/div/div[2]/div/i/@class',
    'edb_exploit_raw_url': '/html/body/div/div[2]/div[2]/div/div/div[1]/div/div[2]/div[1]/div[2]/div/div[2]/div/a[2]/@href',
}


class EdbSelector(object):
    def update(self):
        from lib.menu import Menu

        menu = Menu(False)
        title = "[*] Please select a mode..."
        menu_list = [
            'Get the most recent Exploits as many as you want',
            'Get all Exploits by csv data feed'
        ]
        mode = menu.show(title, menu_list)

        if mode == 0:
            self.execute_collect()
        elif mode == 1:
            self.execute_csv_collect()
        else:
            print("[!] Incorrect choice")

        return None

    def execute_collect(self):
        edb_collect = EdbCollector()

        while True:
            fetch_num = input("[?] Specify number to fetch Exploits: ")
            try:
                fetch_num = int(fetch_num)
            except ValueError:
                print("[-] Please input number")
                continue

            if 1 <= fetch_num <= 1000:
                str_num = str(fetch_num)
                edb_collect.fetch(str_num)
                break
            elif fetch_num == 0:
                print("[-] non requests")
                break
            else:
                print("[-] Please use csv data feed mode for too many requests")

    def execute_csv_collect(self):
        edb_collect = EdbCsvCollector()
        edb_collect.update()


class EdbCollector(object):
    def __init__(self):
        db_init = DBInit()
        db_init.create()
        self.edb_dao = EdbDAO(db_init.session)

        self.session = requests_html.HTMLSession()
        self.session.keep_alive = False
        self.headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.170 Safari/537.36',
            'Host': 'www.exploit-db.com',
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101 Firefox/60.0',
            'Accept': 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate',
            'Referer': 'https://www.exploit-db.com/',
            'Connection': 'close'
        }

    # Request to the server for data crawling or scraping
    def request(self, url):
        time.sleep(random.uniform(0.4, 0.7))
        try:
            headers = self.headers
            headers['user_agent'] = get_random_user_agent()
            headers['Upgrade-Insecure-Requests'] = '1'
            headers['Cache-Control'] = 'max-age=0'
            response = self.session.get(url, headers=headers, verify=False)
            return response
        except RequestException:
            response = self.request(url)
            return response

    # Function call that executes an update
    def update(self):
        self.fetch()

    # Get a list of the requested number of exploits from the server
    def fetch(self, fetch_len_default=None):
        logging.info("Fetching https://www.exploit-db.com")

        if fetch_len_default is not None:
            fetch_len = fetch_len_default
        else:
            fetch_len = "20"

        # Using XMLHttpRequest to get an ExploitDB list
        url = f'https://www.exploit-db.com/?draw=1&columns%5B0%5D%5Bdata%5D=date_published&columns%5B0%5D%5Bname%5D=date_published&columns%5B0%5D%5Bsearchable%5D=true&columns%5B0%5D%5Borderable%5D=true&columns%5B0%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B0%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B1%5D%5Bdata%5D=download&columns%5B1%5D%5Bname%5D=download&columns%5B1%5D%5Bsearchable%5D=false&columns%5B1%5D%5Borderable%5D=false&columns%5B1%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B1%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B2%5D%5Bdata%5D=application_md5&columns%5B2%5D%5Bname%5D=application_md5&columns%5B2%5D%5Bsearchable%5D=true&columns%5B2%5D%5Borderable%5D=false&columns%5B2%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B2%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B3%5D%5Bdata%5D=verified&columns%5B3%5D%5Bname%5D=verified&columns%5B3%5D%5Bsearchable%5D=true&columns%5B3%5D%5Borderable%5D=false&columns%5B3%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B3%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B4%5D%5Bdata%5D=description&columns%5B4%5D%5Bname%5D=description&columns%5B4%5D%5Bsearchable%5D=true&columns%5B4%5D%5Borderable%5D=false&columns%5B4%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B4%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B5%5D%5Bdata%5D=type_id&columns%5B5%5D%5Bname%5D=type_id&columns%5B5%5D%5Bsearchable%5D=true&columns%5B5%5D%5Borderable%5D=false&columns%5B5%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B5%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B6%5D%5Bdata%5D=platform_id&columns%5B6%5D%5Bname%5D=platform_id&columns%5B6%5D%5Bsearchable%5D=true&columns%5B6%5D%5Borderable%5D=false&columns%5B6%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B6%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B7%5D%5Bdata%5D=author_id&columns%5B7%5D%5Bname%5D=author_id&columns%5B7%5D%5Bsearchable%5D=false&columns%5B7%5D%5Borderable%5D=false&columns%5B7%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B7%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B8%5D%5Bdata%5D=code&columns%5B8%5D%5Bname%5D=code.code&columns%5B8%5D%5Bsearchable%5D=true&columns%5B8%5D%5Borderable%5D=true&columns%5B8%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B8%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B9%5D%5Bdata%5D=id&columns%5B9%5D%5Bname%5D=id&columns%5B9%5D%5Bsearchable%5D=false&columns%5B9%5D%5Borderable%5D=true&columns%5B9%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B9%5D%5Bsearch%5D%5Bregex%5D=false&order%5B0%5D%5Bcolumn%5D=9&order%5B0%5D%5Bdir%5D=desc&start=0&length={fetch_len}&search%5Bvalue%5D=&search%5Bregex%5D=false&author=&port=&type=&tag=&platform=&_=1544231433800'

        headers = self.headers
        headers['X-Requested-With'] = 'XMLHttpRequest'
        page = self.request(url)

        try:
            json_data = ujson.loads(page.content)['data']
            self.convert(json_data)
        except Exception as e:
            logging.warning("Exception while parsing ExploitDB")
            logging.warning("{}".format(e))

    # Insert a record of each exploit to the database
    def convert(self, edb_item):
        items = edb_item
        logging.info("Fetched {} Exploits list".format(len(items)))
        logging.info("Inserting fetched Exploits...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(self.parse_edb_cve, item): item for item in items}

            for f in tqdm(concurrent.futures.as_completed(futures), total=len(futures)):
                pass

        executor.shutdown()
        self.edb_dao.commit()
        logging.info("Successfully updated")

    # Extracts each element of HTML and converts it to a database model
    def parse_edb_cve(self, edb_item):
        raw_id = edb_item['id']
        edb_id = "EDB-{}".format(raw_id)
        edb_url = "https://www.exploit-db.com/exploits/{}/".format(raw_id)

        page = self.request(edb_url)

        try:
            raw_id = page.html.xpath(element_xpath['edb_id'])[0].strip(':').strip()
            edb_id = "EDB-{}".format(raw_id)
        except Exception:
            logging.error("Request error, maybe record have been removed")
            exploit_record = EdbRecord(edb_id=raw_id)
            self.insert_record(exploit_record)

        edb_title = get_val(page.html.xpath(element_xpath['edb_title']))
        edb_author = get_val(page.html.xpath(element_xpath['edb_author']))

        try:
            edb_cve_num = [i.strip() for i in page.html.xpath(element_xpath['edb_cve'])]
            if edb_cve_num != '' and edb_cve_num != 'N/A':
                maped_edb_cve = ["CVE-{}".format(cve_id) for cve_id in edb_cve_num]
                edb_cve = ','.join(maped_edb_cve)
        except Exception:
            edb_cve = 'N/A'

        edb_type = get_val(page.html.xpath(element_xpath['edb_type']))
        edb_platform = get_val(page.html.xpath(element_xpath['edb_platform']))
        edb_verified = get_val(page.html.xpath(element_xpath['edb_verified']))

        if 'mdi-close' in edb_verified:
            edb_verified = 'Unverified'
        else:
            edb_verified = 'Verified'

        edb_exploit_raw_url = 'https://www.exploit-db.com/raw/{}'.format(raw_id)
        edb_vulnerable_app_url = get_val(page.html.xpath(element_xpath['edb_vulnerable_app_url']))

        if edb_vulnerable_app_url != "":
            edb_vulnerable_app_url = 'https://www.exploit-db.com' + edb_vulnerable_app_url

        edb_published = page.html.xpath(element_xpath['edb_published'])[0].strip(':').strip()
        edb_collect_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        exploit_record = EdbRecord(
            edb_id=edb_id,
            edb_title=edb_title,
            edb_url=edb_url,
            edb_author=edb_author,
            edb_cve=edb_cve,
            edb_type=edb_type,
            edb_platform=edb_platform,
            edb_remote_ports="",
            edb_verified=edb_verified,
            edb_vulnerable_app_url=edb_vulnerable_app_url,
            edb_exploit_raw_url=edb_exploit_raw_url,
            edb_published=edb_published,
            edb_collect_date=edb_collect_date
        )
        self.insert_record(exploit_record)

    # Run a database query and add a record
    def insert_record(self, record):
        if self.edb_dao.exist(record.edb_id):
            self.edb_dao.update(record)
        else:
            self.edb_dao.add(record)

    def __del__(self):
        pass


class EdbCsvCollector(object):
    def __init__(self):
        db_init = DBInit()
        db_init.create()
        self.edb_dao = EdbDAO(db_init.session)
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101 Firefox/60.0',
        }

    # Function call that executes an update
    def update(self):
        url = EDB_CSV_URL
        self.fetch(url)

    # Get a list of edb-ids
    def fetch(self, url):
        logging.info("Fetching exploitdb's files_exploits.csv")

        with requests.Session() as session:
            response = session.get(url, headers=self.headers)
            raw_text = response.content.decode('utf-8')

            raw_csv = csv.reader(raw_text.splitlines(), delimiter=',')
            next(raw_csv)
            edb_all_list = list(raw_csv)
            logging.info("Fetched {} Exploits".format(len(edb_all_list)))

        parsed_list, target_url_list, target_edb_list = self.categorize(edb_all_list)

        if parsed_list or target_url_list:
            if parsed_list:
                logging.info("Inserting {} Exploits which might include CVEs".format(len(parsed_list)))
                self.convert_offline(parsed_list)

            if target_url_list:
                logging.info("Inserting {} Exploits of unknown".format(len(target_url_list)))
                self.convert_online(target_url_list, target_edb_list)
        else:
            logging.warn("Notthing to update")

    # Check for the existence of EDB records, determine the existence of CVEs, and store them in a categorized list
    def categorize(self, check_list):
        logging.info("Categorizing the Exploits...")
        parsed_list = []
        target_url_list = []
        target_edb_list = []
        try:
            raw_map_url = EDB_MAP_URL
            raw_map = requests.get(raw_map_url, headers=self.headers)
            edb_cve_map = ujson.loads(raw_map.text)
        except Exception:
            edb_cve_map = self.recover_map_from_db()

        for row in tqdm(check_list):
            e_id, e_file, e_title, e_published, e_author, e_platform, e_type, e_rport = tuple(row)
            e_url = "https://www.exploit-db.com/exploits/" + e_id
            target_id = "EDB-{}".format(e_id)

            if not self.edb_dao.exist(target_id):
                if e_id in edb_cve_map.keys():
                    try:
                        e_cve = get_val(edb_cve_map[e_id])
                    except KeyError:
                        e_cve = 'N/A'

                    parsed_list.append(
                        [
                            e_id,
                            e_title,
                            e_url,
                            e_author,
                            e_cve,
                            e_type,
                            e_platform,
                            e_rport,
                            e_published
                        ]
                    )
                else:
                    target_url_list.append(e_url)
                    target_edb_list.append(
                        [
                            e_id,
                            e_title,
                            e_author,
                            e_type,
                            e_platform,
                            e_rport,
                            e_published
                        ]
                    )
            else:
                # TODO: update of records existing in the DB
                pass

        return parsed_list, target_url_list, target_edb_list

    # Insert an EDB record based on the CSV
    def convert_offline(self, items):
        for item in tqdm(items):
            raw_id, edb_title, edb_url, edb_author, edb_cve, edb_type, edb_platform, edb_rport, edb_published = item
            edb_id = "EDB-{}".format(raw_id)
            edb_verified = 'Unknown'
            edb_exploit_raw_url = 'https://www.exploit-db.com/raw/{}'.format(raw_id)
            edb_collect_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

            exploit_record = EdbRecord(
                edb_id=edb_id,
                edb_title=edb_title,
                edb_url=edb_url,
                edb_author=edb_author,
                edb_cve=edb_cve,
                edb_type=edb_type,
                edb_platform=edb_platform,
                edb_remote_ports=edb_rport,
                edb_verified=edb_verified,
                edb_vulnerable_app_url="",
                edb_exploit_raw_url=edb_exploit_raw_url,
                edb_published=edb_published,
                edb_collect_date=edb_collect_date
            )
            self.insert_record(exploit_record)

        self.edb_dao.commit()
        logging.info("Successfully updated")

    # Insert an EDB record based on the URL
    def convert_online(self, urls, items):
        contents = self.get_htmls(urls=urls, items=items, limit=4)

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.parse_edb_cve, fetched_url, fetched_data, content)
                       for fetched_url, fetched_data, content in contents]

            for f in tqdm(concurrent.futures.as_completed(futures), total=len(futures)):
                pass

        executor.shutdown()
        self.edb_dao.commit()
        logging.info("Successfully updated")

    # Extracts each element of HTML and converts it to a database model
    def parse_edb_cve(self, url, item, html):
        edb_html = HTML(html=html)

        raw_id, edb_title, edb_author, edb_type, edb_platform, edb_rport, edb_published = item

        edb_id = "EDB-{}".format(raw_id)
        edb_url = url
        edb_verified = get_val(edb_html.xpath(element_xpath['edb_verified']))

        try:
            edb_cve_num = [i.strip() for i in edb_html.xpath(element_xpath['edb_cve'])]
            if edb_cve_num:
                maped_edb_cve = ["CVE-{}".format(cve_id) for cve_id in edb_cve_num]
                edb_cve = ','.join(maped_edb_cve)
                tqdm.write("Detected {} <--> {}".format(edb_id, edb_cve))
        except Exception:
            edb_cve = 'N/A'

        if 'mdi-close' in edb_verified:
            edb_verified = 'Unverified'
        else:
            edb_verified = 'Verified'

        edb_exploit_raw_url = 'https://www.exploit-db.com/raw/{}'.format(raw_id)
        edb_vulnerable_app_url = get_val(edb_html.xpath(element_xpath['edb_vulnerable_app_url']))

        if edb_vulnerable_app_url != "":
            edb_vulnerable_app_url = 'https://www.exploit-db.com' + edb_vulnerable_app_url

        edb_collect_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        exploit_record = EdbRecord(
            edb_id=edb_id,
            edb_title=edb_title,
            edb_url=edb_url,
            edb_author=edb_author,
            edb_cve=edb_cve,
            edb_type=edb_type,
            edb_platform=edb_platform,
            edb_remote_ports=edb_rport,
            edb_verified=edb_verified,
            edb_vulnerable_app_url=edb_vulnerable_app_url,
            edb_exploit_raw_url=edb_exploit_raw_url,
            edb_published=edb_published,
            edb_collect_date=edb_collect_date
        )
        self.insert_record(exploit_record)

    # Run a database query and add a record
    def insert_record(self, record):
        if self.edb_dao.exist(record.edb_id):
            self.edb_dao.update(record)
        else:
            self.edb_dao.add(record)

    # Generate Asyncio Processing
    def get_htmls(self, urls, items, limit=3):
        loop = asyncio.get_event_loop()
        results = loop.run_until_complete(self._run(urls, items, limit))
        return results

    # Execution of Asyncio Processing
    async def _run(self, urls, items, limit=1):
        tasks, responses = [], []
        semaphore = asyncio.Semaphore(limit)
        async with aiohttp.ClientSession() as session:
            tasks = [asyncio.create_task(self._bound_fetch(semaphore, url, item, session))
                     for url, item in zip(urls, items)]
            for task in tqdm(asyncio.as_completed(tasks), total=len(tasks)):
                responses.append(await task)
            return responses

    # Apply sefoma to data fetching process
    async def _bound_fetch(self, semaphore, url, item, session):
        async with semaphore:
            return await self._fetch(session, url, item)

    # Fetching response data from the server
    async def _fetch(self, session, url, item):
        headers = self.headers
        headers['user_agent'] = get_random_user_agent()
        headers['Cache-Control'] = 'max-age=0'

        try:
            async with session.get(url, timeout=90, headers=headers) as response:
                await asyncio.sleep(random.uniform(0.4, 0.7))
                if response.status != 200:
                    response.raise_for_status()
                return url, item, await response.text()

        except asyncio.TimeoutError:
            logging.warn("Timeout exceded: {}".format(url))
        except asyncio.CancelledError:
            logging.warn("Task cancelled: {}".format(url))
            await session.close()
        except aiohttp.ClientError or ClientConnectionError or ServerDisconnectedError or ClientOSError:
            logging.error("No internet connection")
            await session.close()
        except aiohttp.client_exceptions.ClientResponseError or SSLError or SSLCertVerificationError:
            logging.error("SSL response error: {}".format(url))
            await session.close()

    # Extracts objects mapping EDB-ID and CVE from the local database
    def recover_map_from_db(self):
        edb_map = {}
        records = self.edb_dao.session.query(EdbRecord.edb_id, EdbRecord.edb_cve).all()

        for record in records:
            raw_id = record.edb_id.replace("EDB-", "")
            if record.edb_cve:
                edb_map[raw_id] = record.edb_cve.split(",")
            else:
                edb_map[raw_id] = ""
        return edb_map
