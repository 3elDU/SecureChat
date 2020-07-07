
def encrypt(bt, key):
    r = []
    for b in bt:
        r.append(b * key)
    return r


def decrypt(arr, key):
    ba = bytearray()
    for i in arr:
        ba.append(i // key)
    return bytes(ba)
