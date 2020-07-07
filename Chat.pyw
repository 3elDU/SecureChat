from lib import ServerIPPrompt
from lib import ChatGUI

if __name__ == '__main__':
    try:
        import winsound
    except ImportError:
        import os
        os.system('"Install libraries.bat"')

    s = ServerIPPrompt.Main()
    ip, port, nick, key, pressed = s.getData()
    if pressed:
        g = ChatGUI.Main(ip, port, nick, key)
