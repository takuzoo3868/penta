import inspect
import logging
import os
import re

import yaml


CPE_REGEX = re.compile(
    r"cpe:?:[^:]+:[^:]+:(?P<vendor>[^:]+):(?P<package>[^:]+):(?P<version>[^:]+)"
)
IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
DOMAIN_REGEX = re.compile(
    r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
)

# GitHub
GH_URL = "https://api.github.com/graphql"

# NPM
NPM_URL = "https://registry.npmjs.org/-/npm/v1/security/audits"

# fetch_cve
NVD_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%(year)s.json.gz"
CHUNK_SIZE = 128

# fetch_edb
EDB_CSV_URL = "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv"
EDB_MAP_URL = "https://raw.githubusercontent.com/andreafioraldi/cve_searchsploit/master/cve_searchsploit/exploitdb_mapping.json"

# fetch_msf
MSF_URL = "https://www.rapid7.com/db/modules"
MSF_MODULE_DEFAULT = ["exploits", "auxiliary"]
MSF_FETCH_PAGE_LIMIT = 10


class FileConfig(object):
    def __init__(self, path=None):
        self.PENTA_HOME = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
        self.PENTA = os.path.dirname(self.PENTA_HOME)
        self.settings = None

        if path is None:
            self.path = os.path.join(self.PENTA, "config.yaml")
        else:
            self.path = path

    def load_yaml(self) -> None:
        try:
            with open(self.path, 'r') as cfg:
                self.settings = yaml.load(cfg, Loader=yaml.BaseLoader)
                return None
        except IOError:
            logging.error("Unable to locate configuration file")
        except FileNotFoundError:
            logging.error("Check the example config file and rename to 'config.yaml'")
