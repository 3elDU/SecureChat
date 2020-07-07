import socket
import time
from lib.Packet import Packet


class Main:
    def __init__(self, i, p, nickname, maxTries=1024):

        self.ip = i
        self.port = p
        self.nick = nickname
        self.maxTries = maxTries

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.setblocking(False)

        self.connected = False
        self.alive = True

        self.toSend = []
        self.newData = []

        self.getDataPacket = Packet()
        self.getDataPacket.add("type", "command")
        self.getDataPacket.add("command", "getdata")
        self.getDataString = self.getDataPacket.asstring() + '--'
        self.getDataBytes = self.getDataString.encode('utf-8')

        self.prevTime = 0

    def connect(self):
        self.s.setblocking(True)
        try:
            self.s.connect((self.ip, self.port))
        except socket.error as e:
            raise Exception("Connection error: " + str(e))
        self.s.setblocking(False)

    def setup(self):
        p = Packet()
        p.add("type", "command")
        p.add("command", "setnick")
        p.add("content", self.nick)
        s = p.asstring()

        self.s.setblocking(True)
        try:
            self.s.send(s.encode('utf-8'))
            print('Set nickname.')
        except socket.error as e:
            raise Exception("Nick setting error: " + str(e))
        self.s.setblocking(False)

        time.sleep(1.5)

    def tick(self):
        if len(self.toSend) > 0:
            try:
                # print(self.toSend[0])
                eS = self.toSend[0] + '--'
                self.s.send(eS.encode('utf-8'))
                del self.toSend[0]
            except socket.error:
                pass

        try:
            if time.time() - self.prevTime >= 0.5:
                self.s.send(self.getDataBytes)
                self.prevTime = time.time()
        except socket.error:
            pass

        try:
            d = self.s.recv(131072).decode('utf-8')
            self.newData.append(d)
        except socket.error:
            pass

    def send(self, d):
        self.toSend.append(str(d))

    def getData(self):
        n = self.newData.copy()
        self.newData = []
        return n
