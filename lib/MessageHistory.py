from tkinter import *


class Main:
    def __init__(self, texts: Text):
        self.texts = texts

        self.added = 1

    def addNew(self, value, newLine=True):

        if self.added >= 256:
            self.texts.configure(state=NORMAL)
            self.texts.delete('1.0', '1.end + 1 char')
            self.texts.configure(state=DISABLED)
            self.added -= 2

        self.texts.configure(state=NORMAL)

        if newLine:
            self.texts.insert(END, '\n')
        self.texts.insert(END, value)

        self.texts.yview_scroll(1024, UNITS)

        self.texts.configure(state=DISABLED)

        self.added += 1
