import traceback
import socket
import time
from Packet import *
from threading import Thread


files = {}


class FileReceiver(Thread):
    def __init__(self, connection, fpacket, nickname):
        Thread.__init__(self)

        self.c = connection

        self.done = False
        self.failed = False
        self.file = None
        self.fpacket = fpacket
        self.nick = nickname

        self.type = 'receiver'

    def run(self):
        global files

        f = b''
        key = self.fpacket['endkey'].encode('utf-8')
        s = time.time()
        while True:
            try:
                d = self.c.recv(1073741824)
                f += d
                if time.time() - s >= 10:
                    self.failed = True
                    break
            except:
                pass
            if key in f:
                break

        if not self.failed:
            print('Received file from', self.nick)
            ef = f.replace(key, b'')
            self.file = ef

        self.done = True

        exit(0)


class FileSender(Thread):
    def __init__(self, connection, file, endkey):
        Thread.__init__(self)

        self.c = connection
        self.file = file
        self.endkey = endkey

        self.done = False

        self.type = 'sender'

    def run(self):
        self.c.send(self.file)
        self.c.send(self.endkey)

        print('Succefully sended file!')

        self.done = True

        exit(0)


class NewClient:
    def __init__(self, c: socket.socket, a):
        self.stopped = False

        self.nick = ''

        self.c, self.a = c, a

        self.dataFromThisClient = []
        self.dataFromOtherClients = []
        self.clientThreads = []
        
        self.blocking = False

        self.emptyPackets = 0

    def tick(self):
        for t in self.clientThreads:
            if t.done:
                if t.type == 'sender':
                    if len(self.clientThreads) == 1:
                        self.blocking = False
                    self.clientThreads.remove(t)
                else:
                    if len(self.clientThreads) == 1:
                        self.blocking = False
                    if not t.failed:
                        self.dataFromThisClient.append(str(t.fpacket))

                        files[t.fpacket['filename']] = t.file

                        p2 = Packet()
                        p2.add('type', 'message')
                        p2.add('encrypted', False)
                        p2.add('content', self.nick + " sended a file.")

                        self.dataFromThisClient.append(p2.asstring())

                    self.clientThreads.remove(t)

        # global files

        try:
            if not self.blocking:
                d = self.c.recv(131072).decode('utf-8').split('--')

                for p in d:
                    try:
                        if p:
                            packet = eval(p)

                            if packet['type'] == 'command' and packet['command'] == 'setnick':
                                self.nick = packet["content"]
                                print(self.a[0], 'set himself a nick:', self.nick)
                                pa = Packet()
                                pa.add('type', 'message')
                                pa.add('encrypted', False)
                                pa.add('content', self.nick + " joined the chat!")
                                self.dataFromThisClient.append(pa.asstring())
                            elif packet['type'] == 'command' and packet['command'] == 'getdata':
                                if self.dataFromOtherClients:
                                    toSend = str(self.dataFromOtherClients[0])
                                    print('Sending', toSend, 'to', self.a[0])
                                    self.c.send(toSend.encode('utf-8'))
                                    self.dataFromOtherClients.remove(toSend)
                            elif packet['type'] == 'command' and packet['command'] == 'exit':
                                self.stopped = True
                                pa = Packet()
                                pa.add('type', 'message')
                                pa.add('encrypted', False)
                                pa.add('content', self.nick + " left from the chat!")
                                self.dataFromThisClient.append(pa.asstring())
                                print('Stopped client', self.a[0])
                            elif packet['type'] == 'command' and packet['command'] == 'getfile':
                                self.blocking = True

                                print('Sending file to', self.nick)

                                f = files[packet['content']]
                                endk = packet['endkey'].encode('utf-8')

                                self.c.setblocking(True)

                                t = FileSender(self.c, f, endk)
                                self.clientThreads.append(t)
                                t.start()
                            elif packet['type'] == 'file':
                                self.blocking = True

                                t = FileReceiver(self.c, packet, self.nick)
                                self.clientThreads.append(t)
                                t.start()
                            elif packet['type'] == 'message':
                                self.dataFromThisClient.append(p)
                    except:
                        print('Exception from user', self.nick)
                        traceback.print_exc()
        except:
            pass

    def getData(self):
        d = self.dataFromThisClient.copy()
        self.dataFromThisClient = []
        return d

    def addData(self, data):
        self.dataFromOtherClients.append(data)

    def pause(self):
        self.alive = False

    def run_again(self):
        self.alive = True

    def fullStop(self):
        self.alive = False
        self.fullyStopped = True


class Server:
    def __init__(self, i, p):
        self.s = socket.socket()
        self.s.bind((i, p))
        self.s.listen(16384)
        self.s.setblocking(False)

        self.alive = True

        self.connections = {}
        self.threads = []

        self.lastData = []
        self.lastDataSender = None
        self.lastDataNickname = ''

        self.mainloop()

    def mainloop(self):
        while self.alive:
            try:
                for t in self.threads:
                    t.tick()

                for t in self.threads:
                    d = t.getData()
                    if d:
                        self.lastData = d
                        self.lastDataSender = t
                        self.lastDataNickname = t.nick
                        break

                if self.lastData:
                    for t in self.threads:
                        for i in self.lastData:
                            if t != self.lastDataSender:
                                t.addData(str(i))
                    self.lastData = []
                    self.lastDataSender = None
                    self.lastDataNickname = ''

                for t in self.threads:
                    if t.stopped:
                        self.threads.remove(t)
                        i = t.a
                        self.connections[i].close()
                        print('Closed connection with', i[0])
                        del self.connections[i]

                conn, addr = self.s.accept()
                print('New client:', addr)

                self.connections[addr] = conn

                thread = NewClient(conn, addr)
                self.threads.append(thread)
            except socket.error:
                pass

            if len(self.connections) > 0:
                time.sleep(1 / (len(self.connections) * 5))
            else:
                time.sleep(0.1)


if __name__ == '__main__':
    ip = input('Ip: ')
    if ip == '':
        ip = socket.gethostbyname(socket.gethostname())

    port = input('Port: ')
    if port == '':
        port = 16300
    else:
        port = int(port)

    print('IP:', ip, 'PORT:', port)

    server = Server(ip, port)
