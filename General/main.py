import base64
from Crypto.Util.number import *


def main():
    test4()


def test1():
    s = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]
    for c in s:
        print(chr(c), end='')


def test2():
    s = '63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d'
    b = bytes.fromhex(s)
    print(b)


def test3():
    s = '72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf'
    b = bytes.fromhex(s)
    b64 = base64.b64encode(b)
    print(b64)


def test4():
    i = 11515195063862318899931685488813747395775516287289682636499965282714637259206269
    b = long_to_bytes(i)
    for c in b:
        print(chr(c), end='')


if __name__ == '__main__':
    main()
