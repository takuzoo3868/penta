from enum import Enum
import functools
import platform
import sys
import threading
import time


from lib.utils import encode_utf_8_text

Spinner = Enum('Spinner', {
    "dots": {
        "interval": 80,
        "frames": [
            "⠋",
            "⠙",
            "⠹",
            "⠸",
            "⠼",
            "⠴",
            "⠦",
            "⠧",
            "⠇",
            "⠏"
        ]
    },
    "line": {
        "interval": 130,
        "frames": [
            "-",
            "\\",
            "|",
            "/"
        ]
    },
})


# Loading was taken from project Halo.
# MIT License Copyright (c) 2017 Manraj Singh
# (https://github.com/manrajgrover/halo)
class Loading(object):
    CLEAR_LINE = '\033[K'
    SPINNER_PLACEMENTS = ('left', 'right')

    def __init__(self, text="", text_color=None, spinner=None, animation=None, placement='left', interval=-1, enabled=True, stream=sys.stdout):
        self._animation = animation

        self.spinner = spinner
        self.text = text
        self._text_color = text_color

        self._interval = int(interval) if int(interval) > 0 else self._spinner['interval']
        self._stream = stream

        self.placement = placement
        self._frame_index = 0
        self._text_index = 0
        self._spinner_thread = None
        self._stop_spinner = None
        self._spinner_id = None
        self.enabled = enabled

    def __enter__(self):
        self.start()

    def __exit__(self, type, value, traceback):
        self.stop()

    def __call__(self, f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            with self:
                return f(*args, **kwargs)
        return wrapped

    @property
    def spinner(self):
        return self._spinner

    @spinner.setter
    def spinner(self, spinner=None):
        self._spinner = self._get_spinner(spinner)
        self._frame_index = 0
        self._text_index = 0

    @property
    def text(self):
        return self._text['original']

    @text.setter
    def text(self, text):
        self._text = self._get_text(text)

    @property
    def text_color(self):
        return self._text_color

    @text_color.setter
    def text_color(self, text_color):
        self._text_color = text_color

    @property
    def placement(self):
        return self._placement

    @placement.setter
    def placement(self, placement):
        if placement not in self.SPINNER_PLACEMENTS:
            raise ValueError(
                "Unknown spinner placement '{0}', available are {1}".format(placement, self.SPINNER_PLACEMENTS))
        self._placement = placement

    @property
    def spinner_id(self):
        return self._spinner_id

    @property
    def animation(self):
        return self._animation

    @animation.setter
    def animation(self, animation):
        self._animation = animation
        self._text = self._get_text(self._text['original'])

    def _check_stream(self):
        if self._stream.closed:
            return False

        try:
            check_stream_writable = self._stream.writable
        except AttributeError:
            pass
        else:
            return check_stream_writable()

        return True

    def _write(self, s):
        if self._check_stream():
            self._stream.write(s)

    def _get_spinner(self, spinner):
        if spinner and type(spinner) == dict:
            return spinner

        if platform.system() != 'Windows':
            return Spinner['dots'].value
        else:
            return Spinner['line'].value

    def _get_text(self, text):
        stripped_text = text.strip()
        frames = []
        frames = [stripped_text]

        return {
            'original': text,
            'frames': frames
        }

    def clear(self):
        self._write('\r')
        self._write(self.CLEAR_LINE)
        return self

    def _render_frame(self):
        if not self.enabled:
            return

        self.clear()
        frame = self.frame()
        output = '\r{}'.format(frame)
        try:
            self._write(output)
        except UnicodeEncodeError:
            self._write(encode_utf_8_text(output))

    def render(self):
        while not self._stop_spinner.is_set():
            self._render_frame()
            time.sleep(0.001 * self._interval)

        return self

    def frame(self):
        frames = self._spinner['frames']
        frame = frames[self._frame_index]

        self._frame_index += 1
        self._frame_index = self._frame_index % len(frames)

        text_frame = self.text_frame()
        return u'{0} {1}'.format(*[(text_frame, frame) if self._placement == 'right' else (frame, text_frame)][0])

    def text_frame(self):
        if len(self._text['frames']) == 1:
            return self._text['frames'][0]

        frames = self._text['frames']
        frame = frames[self._text_index]

        self._text_index += 1
        self._text_index = self._text_index % len(frames)

        return frame

    def start(self, text=None):
        if text is not None:
            self.text = text

        if self._spinner_id is not None:
            return self

        if not (self.enabled and self._check_stream()):
            return self

        self._stop_spinner = threading.Event()
        self._spinner_thread = threading.Thread(target=self.render)
        self._spinner_thread.setDaemon(True)
        self._render_frame()
        self._spinner_id = self._spinner_thread.name
        self._spinner_thread.start()

        return self

    def stop(self):
        if self._spinner_thread and self._spinner_thread.is_alive():
            self._stop_spinner.set()
            self._spinner_thread.join()

        if self.enabled:
            self.clear()

        self._frame_index = 0
        self._spinner_id = None
        return self
