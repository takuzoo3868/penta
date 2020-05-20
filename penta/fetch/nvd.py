import concurrent.futures
import datetime
import gzip
import logging
import os
import tempfile

import config
from dateutil import parser
from lib.db import CveDAO, DBInit
from lib.models import CveCpeRecord, CveRecord, CveReferRecord
from lib.utils import get_version
import requests
from tqdm import tqdm
import ujson


class NvdCveCollector(object):
    def __init__(self):
        db_init = DBInit()
        db_init.create()
        self.cve_dao = CveDAO(db_init.session)
        self.now = datetime.datetime.now()

    # Download CVE files
    def download(self):
        print("[*] Downloads the CVE from the specified year to the present")

        while True:
            from_year = input("[?] Specify Year from 2002 to last year: ")
            try:
                from_year = int(from_year)
            except ValueError:
                print("[-] Please enter the year as a number")
                continue

            if 2002 <= from_year <= self.now.year:
                self.download_years(from_year)
                break

            print("[-] Specify Year from 2002 to LAST YAER. e.g. 2019")

    # Download the file from the specified year to the present
    def download_years(self, start_year):
        for y in range(self.now.year, int(start_year) - 1, -1):
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
        url = config.NVD_URL % dict(year=year)
        logging.info("Fetching {}".format(url))

        with tempfile.NamedTemporaryFile() as tf:
            r = requests.get(url, stream=True)
            for chunk in r.iter_content(chunk_size=config.CHUNK_SIZE):
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

        for f in tqdm(futures, total=len(futures)):
            record = f.result()
            self.insert_record(record)

        executor.shutdown()
        self.cve_dao.commit()
        logging.info("Successfully updated")

    # Extracting and formatting CVE information from json
    def parse_nvd_cve(self, cve_item):
        cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
        cve_description = cve_item["cve"]["description"]["description_data"][0]["value"]

        cve_problem_type = None
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

        cve_cpes = NvdCveCollector.parse_cve_cpe(cve_item["configurations"]["nodes"])
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
            cve_cpes=cve_cpes,
            cve_references=cve_references,
            cve_publish_date=cve_publish_date,
            cve_update_date=cve_update_date
        )

        return cve_record

    # Formatting references into database models
    @staticmethod
    def parse_cve_refer(refer_items):
        cve_refer_list = []
        for item in refer_items:
            refer_url = item["url"]
            refer_comment = ""
            refer_comment += item["refsource"]
            mapped_tags = map(str, item["tags"])
            refer_tag = ','.join(mapped_tags)

            cve_refer_list.append(CveReferRecord(
                refer_url=refer_url,
                refer_comment=refer_comment,
                refer_tag=refer_tag
            ))

        return cve_refer_list

    # Formatting cpes into database models
    @staticmethod
    def parse_cve_cpe(cpe_items):
        cve_cpe_list = []
        for item in cpe_items:
            target = []
            if item["operator"] == "AND":
                for child in item.get("children", []):
                    target += child["cpe_match"]
            target += item.get("cpe_match", [])

            for cpe in target:
                if cpe["vulnerable"]:
                    cpe_uri = cpe["cpe23Uri"]
                    vendor, package, version = NvdCveCollector.parse_cpe(cpe_uri)

                    version_start = get_version(
                        cpe.get("versionStartIncluding"),
                        cpe.get("versionStartExcluding"))
                    version_end = get_version(
                        cpe.get("versionEndIncluding"),
                        cpe.get("versionEndExcluding"))

                    affected_min = version_start if version_start else version
                    affected_max = version_end if version_end else version

                    if affected_min and affected_max:
                        if affected_min == "*" and affected_max == "*":
                            affected_version = "*"
                        elif affected_min == "*":
                            affected_version = "<" + affected_max
                        elif affected_max == "*":
                            affected_version = ">" + affected_min
                        elif affected_min == affected_max:
                            affected_version = affected_min
                        else:
                            affected_version = affected_min + "-" + affected_max

                    cve_cpe_list.append(CveCpeRecord(
                        cpe_uri=cpe_uri,
                        cpe_vendor=vendor,
                        cpe_package=package,
                        cpe_version=affected_version,
                        affect_min=affected_min,
                        affect_max=affected_max
                    ))
        return cve_cpe_list

    @staticmethod
    def parse_cpe(cpe_uri):
        matches = config.CPE_REGEX.match(cpe_uri)
        return matches.group("vendor"), matches.group("package"), matches.group("version")

    # Run a database query and add a record
    def insert_record(self, record):
        if self.cve_dao.exist(record.cve_id):
            self.cve_dao.update(record)
        else:
            self.cve_dao.add(record)
