from tkinter import *
from lib import MessageHistory
from lib import Client
from lib import EncryptionEngine
from lib import ByteEncryptionEngine
from lib.Packet import Packet
from tkinter.messagebox import *
from tkinter.filedialog import *
from PIL import Image, ImageTk
from winsound import *
from threading import Thread
import socket
import traceback
import time


MAX_IMG_WIDTH = 600
MAX_IMG_HEIGHT = 180

PHOTOS = []


class KeyPrompt:
    def __init__(self, msg: str):
        self.toplevel = Toplevel()
        self.toplevel['bg'] = 'black'

        self.lFrame = LabelFrame(self.toplevel, text=msg, bg="black", fg="white")

        self.e = Entry(self.lFrame, width=30, bg="gray", fg="white")
        self.e.grid(row=0, column=0, columnspan=2, padx=50, pady=15)

        self.b = Button(self.lFrame, text='OK', bg="gray", fg="white", width=5)
        self.b.grid(row=1, column=0, pady=15)
        self.b['command'] = self.__stop__

        self.lFrame.grid(row=0, column=0, padx=10, pady=10)
        
        self.result = ''
        self.isDone = False

        while True:
            try:
                self.result = self.e.get()
                self.toplevel.update()
            except:
                break

        self.isDone = True

    def __stop__(self):
        self.toplevel.destroy()

    def getResult(self):
        return int(self.result)

    def getDone(self):
        return self.isDone


soundThreadRunning = False


class SoundPlayerThread(Thread):
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        global soundThreadRunning

        soundThreadRunning = True
        PlaySound("beep.wav", SND_FILENAME)
        soundThreadRunning = False
        exit(0)


"""
class ReceivedPhotos(Thread):
    def __init__(self):
        Thread.__init__(self)

        self.toplevel = Toplevel()

        self.t = Text(self.toplevel, width=50, height=40, bg="black", fg="white")
        self.t.grid(row=0, column=0)

        self.scroll = Scrollbar(self.toplevel, orient="vertical", command=self.t.yview)
        self.t.config(yscrollcommand=self.scroll.set)
        self.scroll.grid(row=0, column=1, sticky=N + S + W)

        im = Image.open("demo1.jpg")
        self.img1 = ImageTk.PhotoImage(im)
        self.lbl1 = Label(image=self.img1)
        self.t.window_create(5.0, window=self.lbl1)

        im2 = Image.open("demo2.jpg")
        self.img2 = ImageTk.PhotoImage(im2)
        self.lbl2 = Label(image=self.img2)
        self.t.window_create(20.0, window=self.lbl2)

        self.alive = True

    def run(self):
        while self.alive:
            try:
                self.toplevel.update()
            except:
                try:
                    self.toplevel.destroy()
                except:
                    pass
                self.alive = False
                exit(0)

    def stop(self):
        self.alive = False
"""


class Main:
    # Menu buttons logic

    # Exit button
    def exit(self):
        self.client.s.send(self.exitPacketBytes + b'--')
        self.client.s.close()
        self.root.destroy()
        self.alive = False

    # "Save chat history to file" button
    def saveToFile(self):
        path = asksaveasfilename()
        if len(path) > 0:
            try:
                f = open(path, 'w')
                f.write(self.text.get(0.0, END))
                f.close()

                showinfo(title="Succefully saved chat history",
                         message="Success. You can find it here: " + path)
            except Exception as e:
                showerror(title="Failed to save chat history",
                          message="Error: " + str(e))

    # "Received files" button
    def receivedFiles(self):
        pass

    def __init__(self, ip, port, nick, key):
        self.ip, self.port, self.nick, self.key = ip, port, nick, key

        try:
            f = open(self.key, 'r', encoding='utf-8')
            c = f.read()
            f.close()

            self.k = EncryptionEngine.Key(eval(c))
            self.encryption = EncryptionEngine.Main(self.k)
        except Exception as e:
            showerror(title="Encryption error!", message=str(e))
            exit(1)

        try:
            self.client = Client.Main(ip, port, nick)
            self.client.connect()
            self.client.setup()
        except Exception as e:
            showerror(title="Connection error!", message=str(e))
            exit(1)

        self.exitPacket = Packet()
        self.exitPacket.add('type', 'command')
        self.exitPacket.add('command', 'exit')
        self.exitPacketBytes = self.exitPacket.asbytes()

        self.windowClosed = False
        self.root = Tk()
        self.root.title('SecureChat 0.83 - ' + self.nick)
        self.root["bg"] = "black"
        self.root.resizable(False, False)

        self.mainmenu = Menu(self.root)
        self.root.config(menu=self.mainmenu)

        self.filemenu = Menu(self.mainmenu, tearoff=0)
        self.filemenu.add_command(label="Save chat history to a file", command=self.saveToFile)
        self.filemenu.add_separator()
        self.filemenu.add_command(label="Exit", command=self.exit)

        self.settingsmenu = Menu(self.mainmenu, tearoff=0)
        self.settingsmenu.add_command(label="Color theme")
        self.settingsmenu.add_command(label="Sound")
        self.settingsmenu.add_command(label="Window size")

        self.chatmenu = Menu(self.mainmenu, tearoff=0)
        self.chatmenu.add_command(label="People in this chat")
        self.chatmenu.add_command(label="All received files", command=self.receivedFiles)

        self.helpmenu = Menu(self.mainmenu, tearoff=0)
        self.helpmenu.add_command(label="About SecureChat")

        self.mainmenu.add_cascade(label="File", menu=self.filemenu)
        self.mainmenu.add_cascade(label="Settings", menu=self.settingsmenu)
        self.mainmenu.add_cascade(label="Chat", menu=self.chatmenu)
        self.mainmenu.add_cascade(label="Help", menu=self.helpmenu)

        i = 0

        self.tFrame = Frame(self.root, bg="black")

        self.text = Text(self.tFrame, state=DISABLED, width=110, height=15, bg="black", fg="white")
        self.text.grid(row=0,column=0, columnspan=3, padx=10, pady=5)

        self.messageHistoryScroll = Scrollbar(self.tFrame, orient="vertical", command=self.text.yview)
        self.text.config(yscrollcommand=self.messageHistoryScroll.set)
        self.messageHistoryScroll.grid(row=0, column=3, sticky=N+S+W)

        self.tFrame.grid(row=0, column=0, columnspan=3)

        self.history = MessageHistory.Main(self.text)

        self.entry = Text(self.root, width=90, height=2, bg="gray", fg="white")
        self.entry.grid(row=i+1, column=0, columnspan=2, padx=10)

        self.sendButton = Button(self.root, text='Send file', bg="gray", fg="white")
        self.sendButton.grid(row=i+1, column=2, padx=10, pady=10)
        self.sendButton['command'] = self.sendFile

        self.root.bind("<Return>", self.send)
        self.root.bind("<Control-Return>", self.insertNewLine)
        self.root.bind("<Control-f>", self.sendFile)

        self.encryptFile = BooleanVar()
        self.encryptFile.set(0)
        self.encryptCheckButton = Checkbutton(self.root, text="Encrypt sended files?",
                                              variable=self.encryptFile,
                                              onvalue=1, offvalue=0,
                                              fg="white", bg="black",
                                              activebackground="black",
                                              activeforeground="white",
                                              selectcolor="gray")
        self.encryptCheckButton.grid(row=i+2, column=2)

        self.threads = []

        self.alive = True

        while self.alive:
            try:
                self.root.update()
                self.client.tick()
                self.updateWithNewData(self.client.getData())
                time.sleep(1 / 25)
            except Exception as e:
                if "invalid command name" not in str(e) and "invoke" not in str(e):
                    Tk().withdraw()
                    showerror(title="Error!",
                              message=str(e))
                self.client.s.send(self.exitPacketBytes + b'--')
                self.client.s.close()
                break

        for thread in self.threads:
            thread.stop()

        exit(0)

    def coloredOutput(self, bg, fg, text):
        try:
            a = []
            for line in text.split('\n'):
                a.append(len(line))

            if len(a) <= 10:
                label = Text(self.text, bg=bg, fg=fg, width=max(a), height=len(a), borderwidth=0)
                label.insert(1.0, text)
                label.configure(state=DISABLED)
            else:
                msg = "~ too many lines! 10 is max, but there's " + str(len(a)) + " lines in this message ~"
                label = Text(self.text, bg="red", fg="white", width=len(msg), height=1, borderwidth=0)
                label.insert(1.0, msg)
                label.configure(state=DISABLED)
        except Exception as e:
            print(e)
            msg = "Formatting error! Maybe your message is not properly formatted?"
            label = Text(self.text, bg="red", fg="white", width=len(msg), height=1, borderwidth=0)
            label.insert(1.0, msg)
            label.configure(state=DISABLED)
        self.text.window_create(END, window=label)

    def insertNewLine(self, _=None):
        self.entry.insert(INSERT, '')

    def send(self, _):
        msg = self.entry.get(0.0, INSERT)
        msg = msg[:len(msg)-1]
        # print('"' + msg + '"')
        self.entry.delete(0.0, END)
        spaces = 0
        for i in msg:
            if i == ' ':
                spaces += 1
        if spaces < len(msg):
            if msg:
                self.entry.delete(0.0, END)

                if '\n' not in msg:
                    s = self.nick + ' -> ' + msg
                else:
                    s = '\n' + self.nick + ' :\n' + msg
                eS = self.encryption.encrypt(s)
                timestamp = time.strftime("[%H:%M:%S] ")

                # [[text, bg, fg]]
                texts = []

                choosingfg = False
                choosingbg = False
                typingtextfg = False
                typingtextbg = False
                normaltext = True

                fg = "white"
                bg = "black"
                nt = ""
                tfg = ""
                tbg = ""

                cfg = ""
                cbg = ""

                print(s)

                for sybmol in range(len(s)):
                    syb = s[sybmol]
                    if syb == "&":
                        if not choosingfg and not typingtextfg:
                            texts.append([nt, "black", "white"])
                            nt = ""
                            normaltext = False
                            choosingfg = True
                            print(1)
                        elif not typingtextfg:
                            normaltext = False
                            choosingfg = False
                            fg = cfg
                            cfg = ""
                            tfg = ""
                            typingtextfg = True
                            print(2)
                        else:
                            normaltext = True
                            typingtextfg = False
                            texts.append([tfg, bg, fg])
                            tfg = ""
                            cfg = ""
                            print(3)
                    elif syb == "^":
                        if not choosingbg and not typingtextbg:
                            texts.append([nt, "black", "white"])
                            nt = ""
                            normaltext = False
                            choosingbg = True
                            print(11)
                        elif not typingtextbg:
                            normaltext = False
                            choosingbg = False
                            bg = cbg
                            cbg = ""
                            tbg = ""
                            typingtextbg = True
                            print(21)
                        else:
                            normaltext = True
                            typingtextbg = False
                            texts.append([tbg, bg, fg])
                            tbg = ""
                            cbg = ""
                            print(31)

                    if syb not in ["&","^"]:
                        if choosingfg:
                            cfg += syb
                        elif typingtextfg:
                            tfg += syb
                        elif choosingbg:
                            cbg += syb
                        elif typingtextbg:
                            tbg += syb
                        elif normaltext:
                            nt += syb

                texts.append([nt, "black", "white"])

                print(texts)

                self.history.addNew(timestamp)
                for i in texts:
                    if i[1] == "black" and i[2] == "white":
                        self.history.addNew(i[0], False)
                    else:
                        if len(i[0]) > 0:
                            self.coloredOutput(i[1], i[2], i[0])
                # self.renderMessages()

                p = Packet()
                p.add("type", "message")
                p.add("content", eS)
                p.add("timestamp", timestamp)
                p.add("encrypted", True)

                self.client.send(p.asstring())

    def sendFile(self, _=None):
        global PHOTOS

        toEncrypt = self.encryptFile.get()

        err = False

        if toEncrypt:
            f = KeyPrompt('Please enter an encryption key.')
            try:
                encryptionKey = f.getResult()
            except:
                showerror(title='Error!', message='You must enter a valid integer value!')
                f.toplevel.destroy()
                err = True

        if not err:
            name = askopenfilename()
            if name:
                nn = name.split('.')
                fileFormat = nn[len(nn)-1]

                f = open(name, 'rb')
                fc = f.read()
                f.close()

                if toEncrypt:
                    c = str(ByteEncryptionEngine.encrypt(fc, encryptionKey)).encode('utf-8')
                else:
                    c = fc

                endKey = self.nick + '-END'

                p = Packet()
                p.add('type', 'file')
                p.add('endkey', endKey)
                p.add('user', self.nick)
                p.add('filename', name)
                p.add('fileformat', fileFormat)
                p.add('encrypted', toEncrypt)
                b = p.asbytes()

                self.client.s.send(b + b'--')

                time.sleep(0.8)

                self.client.s.send(c)
                self.client.s.send(endKey.encode('utf-8'))

                print('Sended file')

                if fileFormat in ['png', 'jpg', 'gif']:
                    try:
                        self.history.addNew("")
                        self.img = Image.open(name)
                        w, h = self.img.size
                        ratio = min(MAX_IMG_WIDTH / w, MAX_IMG_HEIGHT / h)
                        newsize = (w * ratio, h * ratio)
                        self.img.thumbnail(newsize, Image.ANTIALIAS)
                        self.photo = ImageTk.PhotoImage(self.img)
                        PHOTOS.append(self.photo)
                        self.text.image_create(END, image=PHOTOS[len(PHOTOS)-1])
                    except Exception as e:
                        self.coloredOutput("red", "white", "Exception while displaying image thumbnail:\n" + str(e))

                time.sleep(0.5)

    def updateWithNewData(self, newData: list):
        for i in newData:
            mustdisplay = False
            try:
                m = eval(i)
                # print(m)
                if m["type"] == "message":
                    timestamp = ''
                    if m['encrypted']:
                        decrypted = self.encryption.decrypt(m["content"])
                        mustdisplay = True
                    else:
                        mustdisplay = True
                        decrypted = m['content']
                    if 'timestamp' in m:
                        mustdisplay = True
                        timestamp = m['timestamp']
                elif m["type"] == "file":
                    answer = askyesno(title="Download the file?",
                                      message=m['user'] + " sended a file. Do you want do download this file?")
                    if answer:
                        try:
                            p = Packet()
                            p.add('type', 'command')
                            p.add('command', 'getfile')
                            p.add('content', m['filename'])
                            p.add('endkey', m['endkey'])
                            self.client.s.send(p.asbytes() + b'--')
                            f = b''
                            endkey = m['endkey'].encode('utf-8')
                            done = False
                            failed = False
                            t = time.time()
                            while not done:
                                try:
                                    if time.time() - t >= 10:
                                        failed = True
                                        break
                                    d = self.client.s.recv(131072)
                                    f += d
                                    if endkey in f:
                                        done = True
                                except socket.error:
                                    pass

                            if not failed:
                                print('received file!')

                                err = False

                                if not m['encrypted']:
                                    res = f.replace(endkey, b'')
                                else:
                                    p = KeyPrompt('Please enter a decryption key.')
                                    try:
                                        while not p.getDone():
                                            p.toplevel.update()

                                        decryptionKey = p.getResult()
                                    except:
                                        showerror(title='Error!', message='You must enter a valid integer value!')
                                        err = True

                                    if not err:
                                        try:
                                            res = ByteEncryptionEngine.decrypt(eval(f.replace(endkey, b'').decode('utf-8')),
                                                                               decryptionKey)
                                        except:
                                            showerror(title='Error!',
                                                      message='Decryption error. Perhaps you entered invalid key?')
                                            err = True

                                if not err:
                                    path = asksaveasfilename(
                                        filetypes=(
                                            ("Just type a name, dont type a file format", "*.txt"),
                                            ("Just type a name, dont type a file format", "*.*")
                                        )
                                    )

                                    f = open(path + '.' + m['fileformat'], 'wb')
                                    f.write(res)
                                    f.close()

                                    self.history.addNew('You downloaded file from ' + m['user'] + '. You can find it here: ' +
                                                        str(path) + '.' + m['fileformat'])

                                    showinfo(title='Success!', message='Succefully downloaded file. Path: ' + str(path) +
                                             '.' + m['fileformat'])

                                    if m['fileformat'] in ['png', 'jpg', 'gif']:
                                        try:
                                            self.history.addNew("")
                                            self.img = Image.open(path + '.' + m['fileformat'])
                                            w, h = self.img.size
                                            ratio = min(MAX_IMG_WIDTH / w, MAX_IMG_HEIGHT / h)
                                            newsize = (w * ratio, h * ratio)
                                            self.img.thumbnail(newsize, Image.ANTIALIAS)
                                            self.photo = ImageTk.PhotoImage(self.img)
                                            PHOTOS.append(self.photo)
                                            self.text.image_create(END, image=PHOTOS[len(PHOTOS) - 1])
                                        except Exception as e:
                                            self.coloredOutput("red", "white",
                                                               "Exception while displaying image thumbnail:\n"+str(e))
                            else:
                                showwarning(title='Error receiving file',
                                            message='Unable to receive file from server. Please try again.')
                        except:
                            traceback.print_exc()
                elif m["type"] == "error":
                    showerror(title="Error, received from server", message=m["content"])
                    exit(1)
            except:
                if mustdisplay:
                    decrypted = i

            if mustdisplay:
                # [[text, bg, fg]]
                texts = []

                choosingfg = False
                choosingbg = False
                typingtextfg = False
                typingtextbg = False
                normaltext = True

                fg = "white"
                bg = "black"
                nt = ""
                tfg = ""
                tbg = ""

                cfg = ""
                cbg = ""

                s = decrypted

                for sybmol in range(len(s)):
                    syb = s[sybmol]
                    if syb == "&":
                        if not choosingfg and not typingtextfg:
                            texts.append([nt, "black", "white"])
                            nt = ""
                            normaltext = False
                            choosingfg = True
                            print(1)
                        elif not typingtextfg:
                            normaltext = False
                            choosingfg = False
                            fg = cfg
                            cfg = ""
                            tfg = ""
                            typingtextfg = True
                            print(2)
                        else:
                            normaltext = True
                            typingtextfg = False
                            texts.append([tfg, bg, fg])
                            tfg = ""
                            cfg = ""
                            print(3)
                    elif syb == "^":
                        if not choosingbg and not typingtextbg:
                            texts.append([nt, "black", "white"])
                            nt = ""
                            normaltext = False
                            choosingbg = True
                            print(11)
                        elif not typingtextbg:
                            normaltext = False
                            choosingbg = False
                            bg = cbg
                            cbg = ""
                            tbg = ""
                            typingtextbg = True
                            print(21)
                        else:
                            normaltext = True
                            typingtextbg = False
                            texts.append([tbg, bg, fg])
                            tbg = ""
                            cbg = ""
                            print(31)

                    if syb not in ["&", "^"]:
                        if choosingfg:
                            cfg += syb
                        elif typingtextfg:
                            tfg += syb
                        elif choosingbg:
                            cbg += syb
                        elif typingtextbg:
                            tbg += syb
                        elif normaltext:
                            nt += syb

                texts.append([nt, "black", "white"])

                print(texts)

                self.history.addNew(timestamp)
                for i in texts:
                    if i[1] == "black" and i[2] == "white":
                        self.history.addNew(i[0], False)
                    else:
                        if len(i[0]) > 0:
                            self.coloredOutput(i[1], i[2], i[0])
                # self.renderMessages()

                # self.history.addNew(timestamp + decrypted)

                if not soundThreadRunning:
                    thr = SoundPlayerThread()
                    thr.start()

        """
        self.renderMessages()
        """

    """
    def renderMessages(self):
        for i in range(len(self.messages)):
            self.labels[i].configure(text=self.messages[i])
            self.tLabels[i].configure(text=self.timestamps[i])
    """
