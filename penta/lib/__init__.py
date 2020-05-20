from lib.db import DBInit
from lib.menu import Menu


def db_menu():
    menu = Menu(False)
    title = "======= DB MENU ============================================="
    menu_list = [
        'Optimize DB',
        'Clear DB',
        '[Return]'
    ]
    menu_num = menu.show(title, menu_list)

    db_handle = DBInit()
    if menu_num == 0:
        db_handle.optimize()
    elif menu_num == 1:
        db_handle.clear()
        db_handle.optimize()
        db_handle.create()
    elif menu_num == -1 or menu_num == 2:
        pass

    return None
