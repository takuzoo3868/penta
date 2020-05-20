import sys
import termios
import tty

from lib.utils import Colors

# Menu was taken from project cli_utility.
# Apache License 2.0 (c) 2019 bluewingtan
# (https://github.com/bluewingtan/cli_utility)


class Menu(object):
    def __init__(self, help_view: bool = True):
        self.key_exit = ["\x03", "q"]
        self.key_direction_prefix = "\x1b"
        self.key_direction_up = ["\x1b[A", "k", "K"]
        self.key_direction_down = ["\x1b[B", "j", "J"]
        self.key_enter = "\r"
        self.selector_selected_single = " >  "
        self.selector_selected_single_placeholder = "    "
        self.selector_newline = "\n"
        self.selection_finish_position = -1
        self.help_view = help_view

    def _rendering_help(self):
        if self.help_view:
            text = "<up/down>, <k/j>: move, <Enter>: select, <q>: exit\n"
            sys.stdout.write(text)
            sys.stdout.flush()

    def _rendering_menu(self, choose: list, pos: int):
        if pos not in range(len(choose)) and pos != self.selection_finish_position:
            raise IndexError

        render_string = ""

        selector_selected_position = Colors.BOLD + Colors.LIGHTGREEN + self.selector_selected_single
        selector_not_selected_not_position = self.selector_selected_single_placeholder
        selector_not_selected_position = selector_selected_position

        selector_selected_end_not_position = Colors.END + self.selector_newline
        selector_selected_end_position = Colors.END + self.selector_newline

        for index, text in enumerate(choose):
            if pos != index:
                selector = selector_not_selected_not_position
                selector += text + selector_selected_end_not_position
            else:
                selector = selector_not_selected_position
                selector += text + selector_selected_end_position

            render_string += selector

        sys.stdout.write(render_string)
        sys.stdout.flush()

    def _get_input(self):
        ch = sys.stdin.read(1)
        if ch == self.key_direction_prefix:
            ch += sys.stdin.read(2)
        return ch

    def _clear_menu_item(self, item_number: int):
        # \033[nA cursor Move Up n line
        # \033[K  clear the contentfrom cursor to the end of the line
        sys.stdout.write('\033[{}A\033[K'.format(item_number))
        sys.stdout.flush()

    def show(self, title: str, choose: list):
        pos = 0

        self._rendering_help()
        sys.stdout.write("{}\n".format(title))
        sys.stdout.flush()

        self._rendering_menu(choose, pos)

        while True:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                key = self._get_input()
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

            if key in self.key_exit:
                return -1
            elif key == self.key_enter:
                return pos
            elif key in self.key_direction_up:
                pos -= 1
            elif key in self.key_direction_down:
                pos += 1

            if pos < 0:
                pos = len(choose) - 1
            elif pos >= len(choose):
                pos = 0

            self._clear_menu_item(len(choose))
            self._rendering_menu(choose, pos)
