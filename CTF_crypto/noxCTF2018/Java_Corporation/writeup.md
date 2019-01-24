# Java_Corporation
given_server.py:
```py
import socket
import threading
import random
from Crypto.Cipher import AES

key = 'NotGonnaHappen'

class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self):
        self.sock.listen(20)
        while True:
            client, address = self.sock.accept()
            client.settimeout(60)
            threading.Thread(target = self.listenToClient,args = (client,address)).start()

    def getIV(self):
        return ''.join([chr(random.randrange(0, 256)) for i in range(16)])

    def encrypt(self, plaintext):
        iv = self.getIV()
        aes = AES.new(key, AES.MODE_CBC, iv)
        return iv + aes.encrypt(plaintext)

    def decrypt(self, ciphertext):
        aes = AES.new(key, AES.MODE_CBC, ciphertext[:16])
        return aes.decrypt(ciphertext[16:])

    def pkcs5(self, s):
        pad_len = ((-len(s)) % 16)
        if pad_len == 0:
            pad_len = 16

        return s + chr(pad_len) * pad_len

    def check_pad(self, s):
        pad_len = ord(s[-1])
        if pad_len > 16 or pad_len == 0:
            return False

        pad = s[-pad_len:]
        for byte in pad:
            if ord(byte) != pad_len:
                return False

        return True

    def listenToClient(self, client, address):
        while True:
            try:
                length = int(client.recv(2))
                if (length % 16 != 0 or length <= 16):
                    client.close()
                    break
                else:
                    ciphertext = client.recv(length)
                    plaintext = self.decrypt(ciphertext)
                    if self.check_pad(plaintext):
                        client.send('1')
                    else:
                        client.send('0')

            except Exception as e:
                print e
                client.close()
                return False

if __name__ == "__main__":
    ThreadedServer('0.0.0.0', 3141).listen()
```
典型的padding oracle攻击，可以使用[https://github.com/mwielgoszewski/python-paddingoracle](https://github.com/mwielgoszewski/python-paddingoracle)来求解，需要改写下PadBuster()方法。
exp.py
```py
from paddingoracle import BadPaddingException, PaddingOracle
from pwn import *

r = remote('chal.noxale.com', 3141)

with open('Encrypted.txt', 'rb') as f:
    data = f.read()

iv = data[:16]
cipher = data[16:]

class PadBuster(PaddingOracle):
    def __init__(self, **kwargs):
        super(PadBuster, self).__init__(**kwargs)

    def oracle(self, data, **kwargs):
        r.send(bytes(48))
        r.send(iv+data)
        if r.recv(1) == '0':
            raise BadPaddingException

padbuster = PadBuster()
value = padbuster.decrypt(cipher, block_size=16, iv=iv)
print('Decrypted: %r' % (value))
```