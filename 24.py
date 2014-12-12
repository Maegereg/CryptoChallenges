import random
import time
import xor
from rng import *

class MT19937Cipher:
	def __init__(self):
		self.cipher = MT19937()

	def encrypt(self, plaintext, key):
		self.cipher.setSeed(key)
		keystream = ""
		byteMask = 2**8-1
		while len(keystream) < len(plaintext):
			intToAdd = self.cipher.next()
			keystream += chr(intToAdd&byteMask)+chr((intToAdd>>8)&byteMask)+chr((intToAdd>>16)&byteMask)+chr((intToAdd>>24)&byteMask)
		keystream = keystream[:len(plaintext)]
		return xor.xorByteStrings(keystream, plaintext)

	def decrypt(self, ciphertext, key):
		return self.encrypt(ciphertext, key)

def encryptPlaintextWithRandom(plaintext):
	key = random.randint(0, 2**16-1)
	print key
	fullPlaintext = "".join([chr(random.randint(0, 255)) for i in range(random.randint(4, 10))])+plaintext
	return MT19937Cipher().encrypt(fullPlaintext, key)

def find16ByteKey(ciphertext, ptextFragment):
	cipher = MT19937Cipher()
	for i in range(2**16):
		if ptextFragment in cipher.decrypt(ciphertext, i):
			return i

def generateResetToken():
	key = int(time.time())&(2**16-1)
	generator = MT19937()
	generator.setSeed(key)
	return generator.next()

def checkResetToken(token):
	curTime = int(time.time())&(2**16-1)
	testGenerator = MT19937()
	#check if the token was created in the last hour
	for i in range(curTime-3600, curTime+1):
		testGenerator.setSeed(i)
		if token == testGenerator.next():
			return True
	return False

if __name__ == "__main__":
	cipher = MT19937Cipher()
	print cipher.encrypt("Rocketman was here", 1)
	print cipher.decrypt(cipher.encrypt("Rocketman was here", 1), 1)

	
	plaintext = "AAAAAAAAAAAAAA"
	ciphertext = encryptPlaintextWithRandom(plaintext)
	print find16ByteKey(ciphertext, plaintext)

	token = generateResetToken()
	print checkResetToken(token)
	print checkResetToken(15)
