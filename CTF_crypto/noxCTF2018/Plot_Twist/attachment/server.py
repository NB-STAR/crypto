import socket
import threading
import random
from Crypto.Cipher import AES

class ThreadedServer(object):
	def __init__(self, host, port):
		self.host = host
		self.port = port
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind((self.host, self.port))
		self.flag = open('flag.txt', 'r').read()

	def listen(self):
		self.sock.listen(20)
		while True:
		    client, address = self.sock.accept()
		    client.settimeout(60)
		    threading.Thread(target = self.listenToClient,args = (client,address)).start()
	
	def getKey(self, r):
		return str(r.getrandbits(32)).rjust(16, '0')

	def pad(self, s):
		return s + chr(0)*((-len(s)) % 16)

	def encrypt(self, key, plaintext):
		aes = AES.new(key, AES.MODE_CBC, self.pad('SuperSecretIV'))
		return aes.encrypt(self.pad(plaintext))		

	def decrypt(self, key, ciphertext):
		aes = AES.new(key, AES.MODE_CBC, self.pad('SuperSecretIV'))
		return aes.decrypt(ciphertext)

	def listenToClient(self, client, address):
		client_flag = self.flag
		r = random.Random()
		key = self.getKey(r)
		client_flag = self.encrypt(key, client_flag)
		while True:
			try:
				client.send('Please insert the decryption key:\n')
				key_guess = client.recv(16)
				if key_guess == key:
					client.send('Correct! Your flag is: ' + self.decrypt(key, client_flag) + '\n')
					client.close()
					break
				else:
					client.send('Wrong! The key was: ' + key + '\n')
					client_flag = self.decrypt(key, client_flag)
					key = self.getKey(r)
					client_flag = self.encrypt(key, client_flag)
			except Exception as e:
				print e
				client.close()
				return False

if __name__ == "__main__":
	ThreadedServer('0.0.0.0', 5115).listen()
