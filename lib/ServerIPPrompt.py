from tkinter import *


class Main:
    def __init__(self):
        self.root = Tk()
        self.root.title('SecureChat')
        self.root['bg'] = 'black'
        self.root.resizable(False, False)

        try:
            f = open('DefaultValues.txt')
            c = f.read().split('\n')
            f.close()

            self.ip = c[0]
            self.port = c[1]
            self.nickname = c[2]
            self.key = c[3]

        except FileNotFoundError:
            self.ip = ''
            self.port = 0
            self.nickname = ''
            self.key = ''

        self.submitButtonPressed = False

        self.mainLabel = Label(self.root, text='Please fill these entries:', bg="black", fg="white")
        self.mainLabel.grid(row=0, column=0, columnspan=2)

        self.ipLabel = Label(self.root, text='Server ip:', bg="black", fg="white", width=20, anchor=E)
        self.ipLabel.grid(row=1, column=0, pady=5, sticky=E)

        self.ipEntry = Entry(self.root, justify=CENTER, bg="gray", fg="white", width=45)
        self.ipEntry.grid(row=1, column=1, padx=8)
        self.ipEntry.insert(0, self.ip)

        self.portLabel = Label(self.root, text='Server port:', bg="black", fg="white", width=20, anchor=E)
        self.portLabel.grid(row=2, column=0, pady=5, sticky=E)

        self.portEntry = Entry(self.root, justify=CENTER, bg="gray", fg="white", width=45)
        self.portEntry.grid(row=2, column=1, padx=8)
        self.portEntry.insert(0, str(self.port))

        self.nickLabel = Label(self.root, text='Your nickname:', bg="black", fg="white", width=20, anchor=E)
        self.nickLabel.grid(row=3, column=0, sticky=E, pady=5)

        self.nickEntry = Entry(self.root, justify=CENTER, bg="gray", fg="white", width=45)
        self.nickEntry.grid(row=3, column=1, padx=8)
        self.nickEntry.insert(0, self.nickname)

        self.keyLabel = Label(self.root, text="Path to file with encryption key:", bg="black", fg="white", width=30,
                              anchor=E)
        self.keyLabel.grid(row=4, column=0, pady=5)

        self.keyEntry = Entry(self.root, justify=CENTER, bg="gray", fg="white", width=45)
        self.keyEntry.grid(row=4, column=1, padx=8)
        self.keyEntry.insert(0, self.key)

        self.sumbitButton = Button(self.root, text='Sumbit!', bg="gray", fg="white", width=10)
        self.sumbitButton['command'] = self.submit
        self.sumbitButton.grid(row=5, column=0, columnspan=2, pady=25)

        self.root.mainloop()

    def submit(self):
        self.ip = self.ipEntry.get()
        self.port = int(self.portEntry.get())
        self.nickname = self.nickEntry.get()
        self.key = self.keyEntry.get()

        f = open('DefaultValues.txt', 'w')

        toWrite = ''
        toWrite += self.ip
        toWrite += '\n'
        toWrite += str(self.port)
        toWrite += '\n'
        toWrite += self.nickname
        toWrite += '\n'
        toWrite += self.key

        f.write(toWrite)
        f.close()

        self.root.destroy()

        self.submitButtonPressed = True

    def getData(self):
        return self.ip, self.port, self.nickname, self.key, self.submitButtonPressed
