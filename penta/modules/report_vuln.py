from datetime import datetime, timedelta, timezone
from enum import Enum
import logging
import textwrap

from db.db import CveDAO, DBInit, EdbDAO, MsfDAO
from fetch.fetch_edb import EdbCollector
from fetch.fetch_msf import MsfCollector
from fetch.fetch_nvd import NvdCveCollector
from models.models import CveRecord, EdbRecord, MsfRecord
from sqlalchemy import and_, desc
from tabulate import tabulate
from utils import Colors


class ColouringSeverity(str, Enum):
    UNSPECIFIED: str = "{}UNSPECIFIED{}".format(Colors.DARKGRAY, Colors.END)
    LOW: str = "{}LOW{}".format(Colors.GREEN, Colors.END)
    MEDIUM: str = "{}MEDIUM{}".format(Colors.YELLOW, Colors.END)
    HIGH: str = "{}HIGH{}".format(Colors.RED, Colors.END)
    CRITICAL: str = "{}{}CRITICAL{}".format(Colors.BOLD, Colors.RED, Colors.END)

    @staticmethod
    def from_str(sev_str):
        if isinstance(sev_str, dict):
            sev_str = sev_str["value"]
        if not sev_str:
            return ColouringSeverity.UNSPECIFIED
        for target_str, coloring_str in ColouringSeverity.__members__.items():
            if target_str == sev_str.upper():
                return coloring_str
        return ColouringSeverity.UNSPECIFIED

    def __str__(self):
        return self.value


class DailyReportor:
    def __init__(self):
        db_init = DBInit()
        self.cve_dao = CveDAO(db_init.session)
        self.edb_dao = EdbDAO(db_init.session)
        self.msf_dao = MsfDAO(db_init.session)

    def print_cve_table(self, records):
        table = []
        check_list = []
        headers = ["ID", "CWE", "Severity", "Score", "Info"]
        for record in records:
            cve_id = record.cve_id
            problem_type = record.cve_problem_type
            if "NVD-CWE-" in record.cve_problem_type:
                problem_type = ""
            if cve_id not in check_list:
                table.append(
                    [
                        cve_id,
                        problem_type,
                        ColouringSeverity.from_str(record.cve_cvssv3_severity),
                        record.cve_cvssv3_score,
                        textwrap.fill(record.cve_describe, 65, max_lines=3)
                    ]
                )
                check_list.append(cve_id)
        print(tabulate(table, headers, tablefmt="grid"), flush=True)

    def print_edb_table(self, records):
        table = []
        check_list = []
        headers = ["ID", "Title", "CVE", "Type", "Platform", "Verified"]
        for record in records:
            edb_id = record.edb_id
            if edb_id not in check_list:
                cves = record.edb_cve.replace(',', '\n')
                table.append(
                    [
                        edb_id,
                        textwrap.fill(record.edb_title, 50, max_lines=2),
                        cves,
                        record.edb_type,
                        record.edb_platform,
                        record.edb_verified
                    ]
                )
                check_list.append(edb_id)
        print(tabulate(table, headers, tablefmt="grid"), flush=True)

    def print_msf_table(self, records):
        table = []
        check_list = []
        headers = ["Module", "CVE", "EDB", "Info"]
        for record in records:
            msf_id = record.module_name
            if msf_id not in check_list:
                cves = record.module_cve.replace(',', '\n')
                edbs = record.module_edb.replace(',', '\n')
                table.append(
                    [
                        textwrap.fill(msf_id, 40),
                        cves,
                        edbs,
                        textwrap.fill(record.module_describe, 42, max_lines=5)
                    ]
                )
                check_list.append(msf_id)
        print(tabulate(table, headers, tablefmt="grid"), flush=True)

    # Obtaining the latest information
    def fetch_report(self):
        fetch_nvd = NvdCveCollector()
        fetch_edb = EdbCollector()
        fetch_msf = MsfCollector()

        fetch_nvd.recent()
        fetch_nvd.update()
        fetch_edb.minor_update()
        fetch_msf.update()

        self.view_report()

    # Output the data retrieved from the database
    def view_report(self):
        raw_today = datetime.now(timezone.utc)
        raw_day_before_yesterday = raw_today - timedelta(days=2)
        utc_today = raw_today.strftime("%Y-%m-%d")
        utc_yesterday = raw_day_before_yesterday.strftime("%Y-%m-%d")

        # Obtaining CVEs with existing cvss scores in order of the latest update date
        cve_least_records = self.cve_dao.query(
            CveRecord,
            CveRecord.cve_cvssv3_score.isnot(None)).order_by(desc(CveRecord.cve_update_date)).limit(10).all()

        if len(cve_least_records) == 0:
            logging.info("No scored CVEs")
        else:
            logging.info("Last 10 Scored CVEs")
            self.print_cve_table(cve_least_records)

        # Obtaining EDB records for the last three days
        edb_records = self.edb_dao.query(EdbRecord, and_(
            EdbRecord.edb_published >= utc_yesterday,
            EdbRecord.edb_published <= utc_today
        )).order_by(desc(EdbRecord.edb_id)).all()

        if len(edb_records) == 0:
            logging.info("No updated Exploits")
        else:
            logging.info("Exploits published in the last 3days")
            self.print_edb_table(edb_records)

        # Obtaining msf module records in order of the latest update date
        msf_records = self.msf_dao.query(MsfRecord).order_by(
            desc(MsfRecord.module_update_date)).limit(10).all()

        if len(msf_records) == 0:
            logging.info("No updated Modules")
        else:
            logging.info("Last 10 Modules")
            self.print_msf_table(msf_records)
