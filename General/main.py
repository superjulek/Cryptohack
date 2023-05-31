import base64
from Crypto.Util.number import *
from pwn import *
import json
import codecs
import imageio


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


def test5():
    r = remote('socket.cryptohack.org', 13377, level='debug')

    def json_recv():
        return json.loads(r.recvline().decode())

    def json_send(hsh):
        r.sendline(json.dumps(hsh).encode())

    def decode(encoding, data):
        if encoding == "base64":
            decoded = base64.b64decode(data.encode()).decode()
        elif encoding == "hex":
            decoded = bytes.fromhex(data).decode()
        elif encoding == "rot13":
            decoded = codecs.decode(data, 'rot_13')
        elif encoding == "bigint":
            decoded = bytes.fromhex(data.split('x')[1]).decode()
        elif encoding == "utf-8":
            decoded = ''.join([chr(b) for b in data])
        else:
            raise Exception('Unknown encoding')
        return decoded

    while True:
        received = json_recv()

        print("Received type: ")
        print(received["type"])
        print("Received encoded value: ")
        print(received["encoded"])

        to_send = {
            "decoded": decode(received["type"], received["encoded"])
        }
        json_send(to_send)


def test6():
    s = 'label'
    print(''.join([chr(xor(ord(c), 13)[0]) for c in s]))


def test7():
    KEY1 = 'a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313'
    KEY2KEY1 = '37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e'
    KEY2KEY3 = 'c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1'
    FLAGKEY1KEY3KEY2 = '04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf'

    print(xor(bytes.fromhex(FLAGKEY1KEY3KEY2), bytes.fromhex(KEY1), bytes.fromhex(KEY2KEY3)))


def test8():
    s = '73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d'
    for i in range(255):
        print(xor(bytes.fromhex(s), i))


def test9():
    s = '0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104'
    print(xor(bytes.fromhex(s), 'crypto{'.encode()))
    print(xor(bytes.fromhex(s), 'myXORkey'.encode()))


def test10():
    """
    https://www.diffchecker.com/image-diff/
    """
    pass


def test11():
    a = 52920
    b = 66528

    h = a if a > b else b
    l = a + b - h
    while l != 0:
        t = h - l * int(h/l)
        if t > l:
            h = t
        else:
            h = l
            l = t
    print(h)


def test12():
    a = 26513
    b = 32321

    h = a if a > b else b
    l = a + b - h
    n = h
    m = l
    p = [0, 1]
    q = []
    while l != 0:
        q.append(int(h/l))
        if len(q) > 2:
            p.append((p[-2] + - p[-1] * q[-3]) % n)
        t = h - l * q[-1]
        if t > l:
            h = t
        else:
            h = l
            l = t
    q.append(0)
    p.append((p[-2] + - p[-1] * q[-3]) % n)
    print(h)
    print(p)
    print(q)
    u = p[-1]
    v = int((m * u - 1) / n)
    print(u)
    print(-v)


def test13():
    print(11 % 6)
    print(8146798528947 % 17)


def test14():
    print(pow(273246787654, 65536, 65537))


def test15():
    """"
    Note: i
    'll use math notation, so a^b means pow(a,b)
    a ^ (p - 1) = 1(mod
    p)
    a ^ (p - 1) * a ^ -1 = a ^ -1(mod
    p)
    a ^ (p - 2) * a * a ^ -1 = a ^ -1(mod
    p)
    a ^ (p - 2) * 1 = a ^ -1(mod
    p)
    So finally we
    have:
    a ^ (p - 2) = a ^ -1(mod
    p)
    """
    print(pow(3, 13-2, 13))


def test16():
    """
    openssl rsa -in privacy_enhanced_mail.pem -text  -noout
    openssl asn1parse -in privacy_enhanced_mail.pem
    """
    pass


def test17():
    """
     openssl x509 -in 2048b-rsa-example-cert.der -inform der -noout -modulus
    """
    pass


def test18():
    """
    ssh-keygen -f /tmp/bruce_rsa.pub -e -m pem > bruce_rsa.pem
    openssl rsa -in bruce_rsa.pem -pubin --RSAPublicKey_in -text -noout
    """
    pass


def test19():
    """
    openssl rsa -in transparency.pem -inform pem -pubin -outform der | sha256sum
    https://subdomains.whoisxmlapi.com/
    https://search.censys.io/certificates?q=parsed.subject_key_info.fingerprint_sha256%3A+29ab37df0a4e4d252f0cf12ad854bede59038fdd9cd652cbc5c222edd26d77d2
    parsed.subject_key_info.fingerprint_sha256: 29ab37df0a4e4d252f0cf12ad854bede59038fdd9cd652cbc5c222edd26d77d2
    """
    pass


def main():
    test19()


if __name__ == '__main__':
    main()


"""
Write-up:

"Transparency":

1. Zeskanowałem subdomeny cryptohack.org na stronie https://subdomains.whoisxmlapi.com/
2. Jedna z subdomen nazywa się https://thetransparencyflagishere.cryptohack.org/ i tam znalazłem flagę
3. Dla upewnienia się, że to poprawna strona (sugerując się przykładowymi rozwiązaniami) użyłem strony https://search.censys.io/ do sprawdzenia certyfikatów
4. Obliczyłem fingerpint klucza poleceniem: openssl rsa -in transparency.pem -inform pem -pubin -outform der | sha256sum
5. Otrzymałem:

$ openssl rsa -in transparency.pem -in
form pem -pubin -outform der | sha256sum
writing RSA key
29ab37df0a4e4d252f0cf12ad854bede59038fdd9cd652cbc5c222edd26d77d2  -

6. Zweryfikowałem z użyciem wspomnianej strony, czy klucz pasuje do certyifkatu domeny:
https://search.censys.io/certificates?q=parsed.subject_key_info.fingerprint_sha256%3A+29ab37df0a4e4d252f0cf12ad854bede59038fdd9cd652cbc5c222edd26d77d2

"""
