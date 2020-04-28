import concurrent.futures
import datetime
import logging
import random
import time

from db.db import DBInit, EdbDAO
from models.models import EdbRecord
from requests.exceptions import RequestException
import requests_html
from tqdm import tqdm
import ujson
from utils import get_random_user_agent, get_val

now = datetime.datetime.now()


class EdbCollector:
    def __init__(self):
        self.db_init = DBInit()
        self.edb_dao = EdbDAO(self.db_init.session)

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
        time.sleep(random.uniform(0.5, 1.5))
        try:
            headers = self.headers
            headers['user_agent'] = get_random_user_agent()
            headers['Upgrade-Insecure-Requests'] = '1'
            headers['Cache-Control'] = 'max-age=0'
            response = self.session.get(url, headers=self.headers, verify=False)
            return response
        except RequestException:
            response = self.request(url)
            return response

    # Function call that executes an update
    def minor_update(self):
        self.fetch()

    # Function call that executes an update
    def major_update(self):
        self.fetch("300")

    # Get a list of the requested number of exploits from the server
    def fetch(self, edb_get_record_len=None):
        logging.info("Fetching https://www.exploit-db.com")

        if edb_get_record_len is not None:
            get_record_len = edb_get_record_len
        else:
            get_record_len = "50"

        # Using XMLHttpRequest to get an ExploitDB list
        url = f'https://www.exploit-db.com/?draw=1&columns%5B0%5D%5Bdata%5D=date_published&columns%5B0%5D%5Bname%5D=date_published&columns%5B0%5D%5Bsearchable%5D=true&columns%5B0%5D%5Borderable%5D=true&columns%5B0%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B0%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B1%5D%5Bdata%5D=download&columns%5B1%5D%5Bname%5D=download&columns%5B1%5D%5Bsearchable%5D=false&columns%5B1%5D%5Borderable%5D=false&columns%5B1%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B1%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B2%5D%5Bdata%5D=application_md5&columns%5B2%5D%5Bname%5D=application_md5&columns%5B2%5D%5Bsearchable%5D=true&columns%5B2%5D%5Borderable%5D=false&columns%5B2%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B2%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B3%5D%5Bdata%5D=verified&columns%5B3%5D%5Bname%5D=verified&columns%5B3%5D%5Bsearchable%5D=true&columns%5B3%5D%5Borderable%5D=false&columns%5B3%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B3%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B4%5D%5Bdata%5D=description&columns%5B4%5D%5Bname%5D=description&columns%5B4%5D%5Bsearchable%5D=true&columns%5B4%5D%5Borderable%5D=false&columns%5B4%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B4%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B5%5D%5Bdata%5D=type_id&columns%5B5%5D%5Bname%5D=type_id&columns%5B5%5D%5Bsearchable%5D=true&columns%5B5%5D%5Borderable%5D=false&columns%5B5%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B5%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B6%5D%5Bdata%5D=platform_id&columns%5B6%5D%5Bname%5D=platform_id&columns%5B6%5D%5Bsearchable%5D=true&columns%5B6%5D%5Borderable%5D=false&columns%5B6%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B6%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B7%5D%5Bdata%5D=author_id&columns%5B7%5D%5Bname%5D=author_id&columns%5B7%5D%5Bsearchable%5D=false&columns%5B7%5D%5Borderable%5D=false&columns%5B7%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B7%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B8%5D%5Bdata%5D=code&columns%5B8%5D%5Bname%5D=code.code&columns%5B8%5D%5Bsearchable%5D=true&columns%5B8%5D%5Borderable%5D=true&columns%5B8%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B8%5D%5Bsearch%5D%5Bregex%5D=false&columns%5B9%5D%5Bdata%5D=id&columns%5B9%5D%5Bname%5D=id&columns%5B9%5D%5Bsearchable%5D=false&columns%5B9%5D%5Borderable%5D=true&columns%5B9%5D%5Bsearch%5D%5Bvalue%5D=&columns%5B9%5D%5Bsearch%5D%5Bregex%5D=false&order%5B0%5D%5Bcolumn%5D=9&order%5B0%5D%5Bdir%5D=desc&start=0&length={get_record_len}&search%5Bvalue%5D=&search%5Bregex%5D=false&author=&port=&type=&tag=&platform=&_=1544231433800'

        headers = self.headers
        headers['X-Requested-With'] = 'XMLHttpRequest'
        edb_page = self.request(url)

        try:
            edb_json_data = ujson.loads(edb_page.content)['data']
            self.convert(edb_json_data)
        except Exception as e:
            logging.warning("Exception while parsing ExploitDB")
            logging.warning("{}".format(e))

    # Insert a record of each exploit to the database
    def convert(self, edb_item):
        items = edb_item
        logging.info("Fetched {} Exploits list".format(len(items)))
        logging.info("Inserting fetched Exploits...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
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
