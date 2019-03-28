#!/usr/bin/env python2
def xor_crypt_string(data, key='awesomepassword', encode=False, decode=False):
    from itertools import izip, cycle
    import base64
    if decode:
        data = base64.decodestring(data)
    xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data, cycle(key)))
    if encode:
        return base64.encodestring(xored).strip()
    return xored


secret_data = "239054"
print xor_crypt_string(secret_data, encode=True)
print xor_crypt_string(xor_crypt_string(secret_data, encode=True), decode=True)
