#!/usr/bin/env python
import json
import mimetypes
import pathlib
import platform
import random
import re

SYSTEMOS = platform.system()
if "Windows" in SYSTEMOS:
    PATH_SPLIT = "\\"
else:
    PATH_SPLIT = "/"

USER_AGENT = [
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Win64; x64; Trident/4.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5.30729; .NET CLR 3.0.30729;"
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 UBrowser/6.2.4094.1 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101 Firefox/60.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.170 Safari/537.36",
]

CPE_REGEX = re.compile(
    "cpe:?:[^:]+:[^:]+:(?P<vendor>[^:]+):(?P<package>[^:]+):(?P<version>[^:]+)"
)


class Colors:
    DARKGRAY = "\033[90m"
    LIGHTRED = "\033[91m"
    LIGHTGREEN = "\033[92m"
    LIGHTYELLOW = "\033[93m"
    LIGHTBLUE = "\033[94m"
    PINK = "\033[95m"
    LIGHTCYAN = "\033[96m"

    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    PURPLE = "\033[35m"
    CYAN = "\033[36m"
    LIGHTGRAY = "\033[37m"

    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"


class LogHandler:

    def save_logfile(self, new_filename, new_file_content):
        penta_dir_path = pathlib.Path(__file__).parent.parent
        log_dir_path = penta_dir_path / "logs"
        log_file = pathlib.Path(log_dir_path / new_filename)

        pathlib.Path(log_dir_path).mkdir(exist_ok=True)

        with log_file.open(mode="w") as f:
            file_type = mimetypes.guess_type(new_filename)

            if file_type[0] == "application/json":
                json.dump(new_file_content, f)
            else:
                f.write(new_file_content)


def get_version(inc_version, exc_version):
    if inc_version != "" and inc_version != "*":
        return inc_version
    return exc_version


def get_random_user_agent():
    user_agnet = random.choice(USER_AGENT)
    return user_agnet


def get_val(elements):
    if len(elements) == 1:
        try:
            value = elements[0].strip()
        except Exception:
            value = ""
    elif len(elements) > 1:
        value = ','.join(elements)
    else:
        value = ""

    return value
