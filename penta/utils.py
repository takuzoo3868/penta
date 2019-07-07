#!/usr/bin/env python
import json
import mimetypes
import pathlib


class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    RED = "\033[31m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
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
