import codecs
import fcntl
import json
import logging
import mimetypes
import pathlib
import platform
import random
import re
import socket
import struct
import sys

SYSTEMOS = platform.system()
if "Windows" in SYSTEMOS:
    PATH_SPLIT = "\\"
else:
    PATH_SPLIT = "/"

USER_AGENT = [
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Win64; x64; Trident/4.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5.30729; .NET CLR 3.0.30729;"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 "
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3",
    "Mozilla/5.0 (Windows NT 6.0) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.36 Safari/536.5",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1062.0 Safari/536.3",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1092.0 Safari/536.6",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/22.0.1207.1 Safari/537.1",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 UBrowser/6.2.4094.1 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101 Firefox/60.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.170 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.0 Safari/536.3",
    "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3",
    "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1062.0 Safari/536.3",
    "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1090.0 Safari/536.6",
    "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/535.24 (KHTML, like Gecko) Chrome/19.0.1055.1 Safari/535.24"
    "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/19.77.34.5 Safari/537.1",
    "Mozilla/5.0 (X11; CrOS i686 2268.111.0) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.57 "
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.24 (KHTML, like Gecko) Chrome/19.0.1055.1 Safari/535.24",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5",
    "Safari/536.11",
    "Safari/536.3",
]


class Colors(object):
    BLACK = "\033[30m"

    # Foreground colors
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    DARKGRAY = "\033[90m"

    # Misc colors
    PURPLE = "\033[35m"
    CYAN = "\033[36m"

    # Extended colors
    LIGHTMAGENTA = "\033[95m"
    LIGHTBLUE = "\033[94m"
    LIGHTYELLOW = "\033[93m"
    LIGHTGREEN = "\033[92m"
    LIGHTRED = "\033[91m"
    LIGHTCYAN = "\033[96m"
    LIGHTGRAY = "\033[37m"

    # Background Colors
    BG_WHITE = "\033[7m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_GRAY = "\033[100m"
    BG_LGRAY = "\033[2m"
    BG_LRED = "\033[101m"
    BG_LGREEN = "\033[102m"
    BG_LYELLOW = "\033[103m"
    BG_LBLUE = "\033[104m"
    BG_LMAGENTA = "\033[105m"
    BG_LCYAN = "\033[106m"

    # Font types
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    ITALIC = "\033[3m"
    REVERSE = "\033[;7m"

    END = "\033[0m"


class ColorfulHandler(logging.StreamHandler):
    all_level = {
        "DEBUG": "{}DEBUG{}".format(Colors.DARKGRAY, Colors.END),
        "INFO": "{}INFO{}".format(Colors.GREEN, Colors.END),
        "WARNING": "{}WARNINGG{}".format(Colors.YELLOW, Colors.END),
        "ERROR": "{}ERROR{}".format(Colors.RED, Colors.END),
        "CRITICAL": "{}CRITICAL{}".format(Colors.BG_RED, Colors.END)
    }

    def emit(self, record: logging.LogRecord) -> None:
        record.levelname = self.all_level[record.levelname]
        super().emit(record)


def save_logfile(new_filename, new_file_content):
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


def system_exit():
    from lib.menu import Menu

    menu = Menu(False)
    title = "\n[?] Exit penta...?"
    menu_list = [
        '[Return menu]',
        '[Exit]'
    ]
    menu_num = menu.show(title, menu_list)

    if menu_num == 0:
        pass
    elif menu_num == -1 or menu_num == 1:
        logging.info("Stay out of trouble!!!")
        sys.exit(0)


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


def get_val_deal(element, key_name):
    try:
        value = element[key_name]
    except Exception:
        value = ""
    return value


def get_local_ip(interface: str = "wlan0") -> str:
    if "nux" in sys.platform:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            return socket.inet_ntoa(
                fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', interface[:15]))[20:24]
            )

        except IOError:
            print("[!] Error, unable to detect local ip address.")
            print("[!] Check your connection to network.")
            exit()

    elif "darwin" in sys.platform:
        return [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][0]


def is_url(url):
    schema = r"(http(s)?:\/\/)?"
    subdomain = r"([a-zA-Z0-9_-]+\.)+"
    tTLDs = "(com|net|org|edu|int|gov|mil)"
    cTLDs = "ac|ad|ae|af|ag|ai|al|am|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cw|cx|cy|cz|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw"
    oTLDs = "info|news"
    TLDs = tTLDs + "|" + cTLDs + "|" + oTLDs
    IP_addr = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    localhost = "(localhost)"
    port = r"(:[1-9][0-9]*)?"
    path = r"(/(.)*)*"
    URL_REGEX = "^" + schema + "(" + subdomain + TLDs + "|" + IP_addr + "|" + localhost + ")" + port + path + "$"

    if re.search(URL_REGEX, url):
        return True
    else:
        return False


def decode_utf_8_text(text):
    try:
        return codecs.decode(text, 'utf-8')
    except (TypeError, ValueError):
        return text


def encode_utf_8_text(text):
    try:
        return codecs.encode(text, 'utf-8', 'ignore')
    except (TypeError, ValueError):
        return text
