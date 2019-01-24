# babycrypto

根据提示联想到xor。
base64解码后，爆破xor即可。
exp.py:
```py
from base64 import b64decode

CIPHERTEXT_FILE = 'ciphertext.txt'

encrypted = None
with open(CIPHERTEXT_FILE, 'r') as f:
  s = f.read()
  encrypted = b64decode(s)

for i in range(256):
  s = ''.join(chr(ord(c) ^ i) for c in encrypted)
  print s
```
flag:
```
flag{diffie-hellman-g0ph3rzraOY1Jal4cHaFY9SWRyAQ6aH}
```