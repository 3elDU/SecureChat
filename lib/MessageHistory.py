
class Main:
    def __init__(self, labelsList):
        self.labels = labelsList
        self.length = len(labelsList)

    def addNew(self, value):
        for i in range(self.length):
            if i-1 >= 0:
                self.labels[i-1] = self.labels[i]

        self.labels[self.length-1] = value

    def getList(self):
        return self.labels
