#!/usr/bin/python3

from API import ui


# UI code here #
def draw_ui(output):
    u.draw_top_line()
    u.draw_bottom_line()
    u.draw_output(output)
    u.scr.clear()
    u.scr.refresh()


# UI code ends #

# main loop code here #
def main(output):
    # thread1 = threading.Thread(target=get_response())
    # thread2 = threading.Thread(target=u.get_user_input())
    # thread3 = threading.Thread(target=draw_ui())
    # thread1.start()
    # thread2.start()
    # thread3.start()
    while running is True:
        draw_ui(output)
        u.get_user_input()
    u.die()


# main loop code ends #
# main program code here #
if __name__ == "__main__":

    running = True

    output = ["hellodpsadpwokadäjwapi3o2jk1p3op2ä1j45153foifnanlnwsa"]
    u = ui.UI(output)
    main(output)
