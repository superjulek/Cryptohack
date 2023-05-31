import json
from math import sqrt, log, ceil


def json_recv(r):
    return json.loads(r.recvline().decode())


def json_send(r, hsh):
    r.sendline(json.dumps(hsh).encode())


def test1():
    """
    (1 - p1)**x=0.5
    p1 = 1/2**11
    x = log(0.5, 1-p1)
    """
    p1 = 1/2**11
    x = log(0.5, 1-p1)
    print(ceil(x))


def test2():
    """
     https://www.wolframalpha.com/input/?i=birthday+problem+calculator
    """


def test3():
    """https://www.mscs.dal.ca/~selinger/md5collision/"""
    from pwn import remote
    d1 = 0xd131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70
    d2 = 0xd131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70
    r = remote('socket.cryptohack.org', 13389, level='debug')
    print(r.recvuntil(b'Give me a document to store\n'))
    json_send(r, {'document': hex(d1)[2:]})
    print(r.recvuntil(b'added to system"}\n'))
    json_send(r, {'document': hex(d2)[2:]})
    print(r.recvall())


if __name__ == '__main__':
    test3()
