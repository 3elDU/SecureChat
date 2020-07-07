
class Packet:
    def __init__(self, startString=None):
        if startString is not None:
            try:
                self.packet = eval(startString)
            except:
                self.packet = {}
        else:
            self.packet = {}

    def add(self, index, value):
        self.packet[index] = value

    def remove(self, index):
        if index in self.packet:
            del self.packet[index]

    def get(self, index):
        if index in self.packet:
            return self.packet[index]

    def asbytes(self, encoding='utf-8'):
        return str(self.packet).encode(encoding)

    def asstring(self):
        return str(self.packet)
