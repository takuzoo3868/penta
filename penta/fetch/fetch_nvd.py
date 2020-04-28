import concurrent.futures
import datetime
import gzip
import logging
import os
import tempfile

from dateutil import parser
from db.db import CveDAO, DBInit
from models.models import CveRecord, CveReferRecord
import requests
from tqdm import tqdm
import ujson


now = datetime.datetime.now()
nvd_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%(year)s.json.gz"
download_chunk_size = 128


class NvdCveCollector:
    def __init__(self):
        db_init = DBInit()
        self.cve_dao = CveDAO(db_init.session)

    # Download CVE files
    def download(self):
        logging.info("Downloads the CVE from the specified year to the present")

        while True:
            from_year = input("[>] Specify Year from 2002 to last year: ")
            try:
                from_year = int(from_year)
            except ValueError:
                print("[-] Please enter the year as a number")
                continue

            if 2002 <= from_year < now.year:
                self.download_years(from_year)
                break

            print("[-] Specify Year from 2002 to LAST YAER. e.g. 2019")

    # Download the file from the specified year to the present
    def download_years(self, start_year):
        for y in range(now.year, int(start_year) - 1, -1):
            self.fetch(y)

    # Download recent CVE files
    def recent(self):
        self.fetch("recent")

    # Importing a modified CVE
    def update(self):
        self.fetch("modified")

    # Get CVE data in gzip format from NVD feed
    # TODO: Metadata matching
    def fetch(self, year):
        url = nvd_url % dict(year=year)
        logging.info("Fetching {}".format(url))

        with tempfile.NamedTemporaryFile() as tf:
            r = requests.get(url, stream=True)
            for chunk in r.iter_content(chunk_size=download_chunk_size):
                tf.write(chunk)
            tf.flush()
            with gzip.open(tf.name, "rb") as gzipjf:
                cve_data = gzipjf.read()
                try:
                    json_data = ujson.loads(cve_data)
                    self.convert(json_data)
                except Exception as e:
                    logging.warning("Exception while parsing NVD CVE feed")
                    logging.warning("{}".format(e))

    # Insert a CVE record into the DB
    def convert(self, cve_data):
        items = cve_data.get("CVE_Items")
        logging.info("Fetched {} CVEs".format(len(items)))
        logging.info("Inserting fetched CVEs")

        with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() * 5) as executor:
            futures = {executor.submit(self.parse_nvd_cve, item): item for item in items}

            for f in tqdm(concurrent.futures.as_completed(futures), total=len(futures)):
                pass

        executor.shutdown()
        self.cve_dao.commit()
        logging.info("Successfully updated")

    # Extracting and formatting CVE information from json
    def parse_nvd_cve(self, cve_item):
        cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
        cve_description = cve_item["cve"]["description"]["description_data"][0]["value"]

        cve_problem_type = ""
        if (cve_item["cve"]["problemtype"]["problemtype_data"] and cve_item["cve"]["problemtype"]["problemtype_data"][0]["description"]):
            cve_problem_type = cve_item["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"]

        cve_mitre_url = "http://cve.mitre.org/cgi-bin/cvename.cgi?name={}".format(cve_id)
        cve_cvedetails_url = "https://www.cvedetails.com/cve/{}".format(cve_id)

        vector_string = None
        severity = None
        base_score = None
        impact_score = None
        exploitability_score = None

        if "baseMetricV3" in cve_item["impact"]:
            cvss_data = cve_item["impact"]["baseMetricV3"]["cvssV3"]

            vector_string = cvss_data["vectorString"]
            severity = cvss_data["baseSeverity"]
            base_score = cvss_data["baseScore"]

            impact_score = cve_item["impact"]["baseMetricV3"]["impactScore"]
            exploitability_score = cve_item["impact"]["baseMetricV3"]["exploitabilityScore"]

        cve_references = NvdCveCollector.parse_cve_refer(
            cve_item["cve"]["references"]["reference_data"])
        cve_publish_date = parser.parse(cve_item['publishedDate']).strftime("%Y-%m-%d %H:%M:%S")
        cve_update_date = parser.parse(cve_item['lastModifiedDate']).strftime("%Y-%m-%d %H:%M:%S")

        cve_record = CveRecord(
            cve_id=cve_id,
            cve_describe=cve_description,
            cve_mitre_url=cve_mitre_url,
            cve_cvedetails_url=cve_cvedetails_url,
            cve_problem_type=cve_problem_type,
            cve_cvssv3_score=base_score,
            cve_cvssv3_severity=severity,
            cve_cvssv3_vector_str=vector_string,
            cve_score_impact=impact_score,
            cve_score_exploitability=exploitability_score,
            cve_references=cve_references,
            cve_publish_date=cve_publish_date,
            cve_update_date=cve_update_date
        )

        self.insert_record(cve_record)

    # Formatting references into database models
    @staticmethod
    def parse_cve_refer(refer_items):
        cve_refer_list = []
        for refer_item in refer_items:
            refer_url = refer_item["url"]
            refer_comment = ""
            refer_comment += refer_item["refsource"]
            maped_tags = map(str, refer_item["tags"])
            refer_tag = ','.join(maped_tags)

            cve_refer_list.append(CveReferRecord(
                refer_url=refer_url,
                refer_comment=refer_comment,
                refer_tag=refer_tag
            ))

        return cve_refer_list

    # Run a database query and add a record
    def insert_record(self, record):
        if self.cve_dao.exist(record.cve_id):
            self.cve_dao.update(record)
        else:
            self.cve_dao.add(record)
