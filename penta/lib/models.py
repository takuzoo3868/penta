from sqlalchemy import Column, Float, ForeignKey, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class CveRecord(Base):
    __tablename__ = 'cve_records'

    id = Column(Integer, autoincrement=True, primary_key=True)
    cve_id = Column(String, index=True)
    cve_describe = Column(Text)
    cve_mitre_url = Column(String)
    cve_cvedetails_url = Column(String)

    cve_problem_type = Column(String)
    cve_cvssv3_score = Column(Float)
    cve_cvssv3_severity = Column(String)
    cve_cvssv3_vector_str = Column(String)
    cve_score_impact = Column(Float)
    cve_score_exploitability = Column(Float)

    cve_cpes = relationship("CveCpeRecord", backref="cve_records")

    cve_references = relationship("CveReferRecord", backref="cve_records")

    cve_publish_date = Column(String, index=True)
    cve_update_date = Column(String, index=True)


class CveReferRecord(Base):
    __tablename__ = 'cve_records_refer'

    id = Column(Integer, autoincrement=True, primary_key=True)
    refer_cve = Column(String, ForeignKey("cve_records.cve_id"))
    refer_url = Column(String)
    refer_comment = Column(String)
    refer_tag = Column(Text)


class CveCpeRecord(Base):
    __tablename__ = 'cve_records_cpe'

    id = Column(Integer, autoincrement=True, primary_key=True)
    cpe_cve = Column(String, ForeignKey("cve_records.cve_id"))
    cpe_uri = Column(String)
    cpe_vendor = Column(String)
    cpe_package = Column(String)
    cpe_version = Column(String)
    affect_min = Column(String)
    affect_max = Column(String)


class EdbRecord(Base):
    __tablename__ = 'edb_records'

    id = Column(Integer, autoincrement=True, primary_key=True)
    edb_id = Column(String, index=True)
    edb_title = Column(String)
    edb_url = Column(String(60))
    edb_author = Column(String(100))
    edb_cve = Column(String, index=True)
    edb_type = Column(String)
    edb_platform = Column(String)
    edb_remote_ports = Column(Integer)
    edb_verified = Column(String)
    edb_vulnerable_app_url = Column(String)
    edb_exploit_raw_url = Column(String)
    edb_published = Column(String, index=True)
    edb_collect_date = Column(String)


class MsfRecord(Base):
    __tablename__ = 'msf_records'

    id = Column(Integer, autoincrement=True, primary_key=True)
    module_name = Column(String, index=True)
    module_class = Column(String)
    module_title = Column(String)
    module_url = Column(String)
    module_describe = Column(Text)
    module_authors = Column(String)
    module_cve = Column(String, index=True)
    module_edb = Column(String, index=True)
    module_references = Column(Text)
    module_platforms = Column(String)
    module_architectures = Column(String)
    module_remote_ports = Column(Integer)
    module_disclosure_date = Column(String)
    module_update_date = Column(String, index=True)
    module_collect_date = Column(String)
