import base64
from Crypto.Util.strxor import strxor

a=['a','b','c','d']
b="1"
c= strxor(a, b)
print c
