from base64 import b64encode

CIPHERTEXT_FILE = 'ciphertext.txt'
ENCRYPTION_BYTE = 255

BASE_TEXT = '''Leon is a programmer who aspires to create programs that help people do less. He wants to put automation first, and scalability alongside. He dreams of a world where the endless and the infinite become realities to mankind, and where the true value of life is preserved.'''


with open('./flag.txt', 'r') as f:
    FLAG =  f.read()


encrypted = ''.join(chr(ord(c) ^ ENCRYPTION_BYTE) for c in BASE_TEXT + FLAG)

with open(CIPHERTEXT_FILE, 'w') as f:
    f.write(b64encode(encrypted))
