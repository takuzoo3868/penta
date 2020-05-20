import logging

from lib.models import Base, CveRecord, EdbRecord, MsfRecord
from sqlalchemy import and_, create_engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.sql import exists

# TODO: DB to io.CacheFile
DB_CONNECT_STRING = 'sqlite:///data/vuln_db.sqlite3'


class DBInit(object):
    def __init__(self):
        self.engine = create_engine(
            DB_CONNECT_STRING,
            connect_args={'check_same_thread': False},
            poolclass=StaticPool,
        )
        Session = sessionmaker(bind=self.engine)
        self.session = Session(autoflush=False)

    # Creates the database
    def create(self):
        try:
            Base.metadata.create_all(self.engine, checkfirst=True)
        except Exception as e:
            logging.error(e)

    # Delete the database
    def clear(self):
        for table in Base.metadata.tables:
            logging.info("Delete target: {}".format(table))
        try:
            Base.metadata.drop_all(self.engine)
        except Exception as e:
            logging.error(e)

    # Optimizes the database
    def optimize(self):
        self.engine.execute("VACUUM")


class DBHelper(object):
    def set_env(self, session, model_class, record_key):
        self.session = session
        self.model_class = model_class
        self.record_key = record_key

    # Insert data to be recorded in the database
    def add(self, records=None):
        if records is not None:
            try:
                if not isinstance(records, dict):
                    self.session.add(records)
                elif isinstance(records, dict):
                    self.session.add_all(records)
            except IntegrityError as e:
                logging.error(e)
                self.session.rollback
            except SQLAlchemyError as e:
                logging.error(e)
                self.session.rollback()
                pass

    # Insert data to be recorded in the database
    def add_all(self, records=None):
        if records is not None:
            try:
                self.session.add_all(records)
                self.session.commit()
            except IntegrityError as e:
                logging.error(e)
                self.session.rollback
            except SQLAlchemyError as e:
                logging.error(e)
                self.session.rollback()
                pass

    # Fixing transactional content updates as permanent
    def commit(self):
        try:
            self.session.flush()
            self.session.commit()
        except SQLAlchemyError as e:
            logging.error(e)
            self.session.rollback()

    # Get the records
    def query(self, table_or_column_name=None, filter=None):
        if filter is None:
            result = self.session.query(table_or_column_name)
        else:
            result = self.session.query(table_or_column_name).filter(filter)
        return result

    # Get the first one record
    def query_first(self, table_or_column_name=None, filter=None):
        if filter is None:
            result = self.session.query(table_or_column_name).first()
        else:
            result = self.session.query(table_or_column_name).filter(filter).first()
        return result

    # Confirmation that the record exists.
    def exist(self, key_value):
        try:
            result = self.session.query(exists().where(self.record_key == key_value)).scalar()
            return result
        except SQLAlchemyError as e:
            logging.error(e)

    # Convert a Table object to a dict
    def to_dict(self, row):
        dict_record = {}
        for column in row.__table__.columns:
            data = getattr(row, column.name)
            if data is not None:
                dict_record[column.name] = data

        return dict_record


class CveDAO(DBHelper):
    def __init__(self, session):
        self.session = session
        self.set_env(self.session, CveRecord, CveRecord.cve_id)

    def update(self, record):
        response = self.query(CveRecord, and_(
            CveRecord.cve_id == record.cve_id,
            CveRecord.cve_update_date.isnot(record.cve_update_date)
        ))
        status = response.first()

        try:
            if status is not None:
                record_dict = self.to_dict(record)
                response.update(record_dict)
        except SQLAlchemyError as e:
            logging.error(e)
            self.session.rollback()


class EdbDAO(DBHelper):
    def __init__(self, session):
        self.session = session
        self.set_env(session, EdbRecord, EdbRecord.edb_id)

    def update(self, record):
        response = self.query(EdbRecord, and_(
            EdbRecord.edb_id == record.edb_id,
            EdbRecord.edb_verified.isnot(record.edb_verified)
        ))
        status = response.first()

        try:
            if status is not None:
                record_dict = self.to_dict(record)
                response.update(record_dict)
        except SQLAlchemyError as e:
            logging.error(e)
            self.session.rollback()


class MsfDAO(DBHelper):
    def __init__(self, session):
        self.session = session
        self.set_env(self.session, MsfRecord, MsfRecord.module_name)

    def update(self, record):
        response = self.query(MsfRecord, and_(
            MsfRecord.module_name == record.module_name,
            MsfRecord.module_update_date.isnot(record.module_update_date)
        ))
        status = response.first()

        try:
            if status is not None:
                record_dict = self.to_dict(record)
                response.update(record_dict)
        except SQLAlchemyError as e:
            logging.error(e)
            self.session.rollback()
