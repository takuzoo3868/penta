from sqlalchemy import Column, Float, ForeignKey, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class CveRecord(Base):
    __tablename__ = 'cve_records'

    cve_id = Column(String(15), primary_key=True)
    cve_describe = Column(Text)
    cve_mitre_url = Column(String(255))
    cve_cvedetails_url = Column(String(255))

    cve_problem_type = Column(String(50))
    cve_cvssv3_score = Column(Float)
    cve_cvssv3_severity = Column(String(10))
    cve_cvssv3_vector_str = Column(String(55))
    cve_score_impact = Column(Float)
    cve_score_exploitability = Column(Float)

    cve_references = relationship("CveReferRecord", backref="cve_records")

    cve_publish_date = Column(String(25), index=True)
    cve_update_date = Column(String(25), index=True)


class CveReferRecord(Base):
    __tablename__ = 'cve_records_refer'

    refer_id = Column(Integer, primary_key=True)
    refer_cve = Column(String(15), ForeignKey("cve_records.cve_id"))
    refer_url = Column(String(255))
    refer_comment = Column(String(50))
    refer_tag = Column(String(255))


class EdbRecord(Base):
    __tablename__ = 'edb_records'

    edb_id = Column(String(15), primary_key=True)
    edb_title = Column(String(255))
    edb_url = Column(String(255))
    edb_author = Column(String(100))
    edb_cve = Column(String(255), index=True)
    edb_type = Column(String(50))
    edb_platform = Column(String(50))
    edb_verified = Column(String(15))
    edb_vulnerable_app_url = Column(String(255))
    edb_exploit_raw_url = Column(String(255))
    edb_published = Column(String(25), index=True)
    edb_collect_date = Column(String(25))


class MsfRecord(Base):
    __tablename__ = 'msf_records'

    module_name = Column(String(255), primary_key=True)
    module_class = Column(String(55))
    module_title = Column(String(255))
    module_url = Column(String(255))
    module_describe = Column(Text)
    module_authors = Column(String(255))
    module_cve = Column(String(255), index=True)
    module_edb = Column(String(255), index=True)
    module_references = Column(Text)
    module_platforms = Column(String(55))
    module_architectures = Column(String(55))
    module_remote_ports = Column(String(55))
    module_disclosure_date = Column(String(25))
    module_update_date = Column(String(25), index=True)
    module_collect_date = Column(String(25))
