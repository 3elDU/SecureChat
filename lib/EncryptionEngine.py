import random


class Key:
    __AllSybmols = list(""" abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZйцукенгшщзхъфывапролджэячсмитьбюёЙЦУКЕНГШЩЗХЪФЫВАПРОЛДЖЭЯЧСМИТЬБЮЁйцукенгшщзхїфівапролджєячсмитьбюЙЦУКЕНГШЩЗХЇФІВАПРОЛДЖЄЯЧСМИТЬБЮ`~1!2@3#4$5%6^7&8*9(0)-_=+[{]};:'"\|,<.>/?№№""")

    def __init__(self, key = None):
        if key is not None:
            self.key = key
        else:
            self.key = self.generateRandom()

    def generateRandom(self):
        key_numbers = {}
        key_letters = {}
        for sybmol in self.__AllSybmols:
            n = random.randint(1000, 1000000)
            while n in key_numbers:
                n = random.randint(1000, 1000000)
            key_numbers[n] = sybmol
            key_letters[sybmol] = n
        return key_letters, key_numbers


class Main:
    __AllSybmols = list(""" abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZйцукенгшщзхъфывапролджэячсмитьбюёЙЦУКЕНГШЩЗХЪФЫВАПРОЛДЖЭЯЧСМИТЬБЮЁйцукенгшщзхїфівапролджєячсмитьбюЙЦУКЕНГШЩЗХЇФІВАПРОЛДЖЄЯЧСМИТЬБЮ`~1!2@3#4$5%6^7&8*9(0)-_=+[{]};:'"\|,<.>/?№№""")

    def __init__(self, key: Key):
        self.key = key.key

    def encrypt(self, string):
        result = []
        for sybmol in string:
            if sybmol == '\n':
                result.append('\n')
            else:
                result.append(self.key[0][sybmol])
        return result

    def decrypt(self, seq):
        result = ''
        for number in seq:
            if number not in self.key[1]:
                if number == '\n':
                    result += '\n'
                elif number in self.__AllSybmols:
                    result += str(number)
                else:
                    result += '0'
            else:
                result += self.key[1][number]
        return result
