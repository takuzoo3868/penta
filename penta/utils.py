#!/usr/bin/env python
import os
import sys
import json
import mimetypes


class Colors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"


class LogHandler:

    def save_logfile_at_new_dir(self, new_dir_path, new_filename, new_file_content, mode='w'):
        os.makedirs(new_dir_path, exist_ok=True)

        with open(os.path.join(new_dir_path, new_filename), mode) as f:
            file_type = mimetypes.guess_type(new_filename)

            if file_type[0] == "application/json":
                json.dump(new_file_content, f)
            else:
                f.write(new_file_content)
